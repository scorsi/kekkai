//! kekkai-relay (ADR 0005, 0014): forwards `relay_forward` payloads between the listed keys,
//! opaque bytes it cannot read. `--config <path>` (default `/etc/kekkai/relay.toml`, ADR
//! 0016) runs it; `config check` validates the file and exits. Unprivileged: no TUN, no
//! route (ADR 0018).

// The schema layer of kekkai-node (ADR 0019), shared as a file rather than a new crate.
#[path = "../../node/src/log.rs"]
mod log;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kekkai_control::v1::control_service_server::{ControlService, ControlServiceServer};
use kekkai_control::v1::{GetStatusRequest, GetStatusResponse, NodeStatus, RelaySender};
use kekkai_core::keys::public_key_to_text;
use kekkai_core::node::Node;
use kekkai_io::config::{RELAY_DEFAULT_PATH, RelayConfig};
use kekkai_io::metrics::{drops, family};
use kekkai_io::{NoTunnel, PeerInfo, State, clock, systemd, udp};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};
use tracing::info;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

/// The relay's control socket (ADR 0031), beside the lighthouse's.
pub const CONTROL_SOCKET: &str = "/run/kekkai-relay/control.sock";

const USAGE: &str = "usage: kekkai-relay [--config PATH] [config check] | --version";

fn main() -> ExitCode {
    let mut config = PathBuf::from(RELAY_DEFAULT_PATH);
    let mut words = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--config" => match args.next() {
                Some(path) => config = path.into(),
                None => return fail(USAGE),
            },
            _ => words.push(arg),
        }
    }
    std::panic::set_hook(Box::new(|info| log::fatal(&info.to_string())));
    let result = match words.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        [] => run(&config),
        ["config", "check"] => load(&config).map(|_| println!("{}: ok", config.display())),
        _ => Err(USAGE.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e),
    }
}

fn fail(message: &str) -> ExitCode {
    log::fatal(message);
    ExitCode::FAILURE
}

fn load(path: &Path) -> Result<RelayConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let config = RelayConfig::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    config
        .log
        .level
        .parse::<Targets>()
        .map_err(|e| format!("{}: log.level: {e}", path.display()))?;
    Ok(config)
}

fn run(path: &Path) -> Result<(), String> {
    let config = load(path)?;
    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|f| f.parse::<Targets>().ok())
        .unwrap_or_else(|| config.log.level.parse().expect("checked by load"));
    tracing_subscriber::registry()
        .with(log::JsonLayer.with_filter(filter))
        .init();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(serve(config))
}

async fn serve(config: RelayConfig) -> Result<(), String> {
    let key = kekkai_io::load_key(&config.service.private_key_file).map_err(|e| e.to_string())?;
    let mut peers = HashMap::new();
    for peer in &config.peers {
        let name = peer.name.clone();
        peers.insert(peer.key()?, PeerInfo { name });
    }
    let limit = config.service.max_bytes_per_second;
    let node = Node::relay(key, peers.keys().copied().collect(), limit);
    let port = config.service.listen_port;
    let control = Control {
        state: None,
        started: clock::monotonic(),
        node: NodeStatus {
            public_key: public_key_to_text(node.public_key()),
            version: env!("CARGO_PKG_VERSION").into(),
            wire_version: kekkai_core::WIRE_VERSION.into(),
            listen_port: port.into(),
            ..NodeStatus::default()
        },
    };
    let socket = udp::bind(port).map_err(|e| format!("udp port {port}: {e}"))?;
    let listener = systemd::control_listener(Path::new(CONTROL_SOCKET), "kekkai-relay")
        .map_err(|e| format!("{CONTROL_SOCKET}: {e}"))?;
    let mut state = State::new(node, peers);
    // ADR 0014, 0031: aggregate counters only, never where a node is.
    state.log_peers = false;
    let state = Arc::new(Mutex::new(state));
    if let Some(m) = &config.metrics {
        let listener = std::net::TcpListener::bind(m.listen)
            .map_err(|e| format!("metrics.listen {}: {e}", m.listen))?;
        let state = state.clone();
        std::thread::spawn(move || kekkai_io::metrics::serve(listener, &state, render));
    }
    systemd::notify_ready().map_err(|e| format!("sd_notify: {e}"))?;
    info!(
        event = "ready",
        port,
        peers = config.peers.len(),
        rate_limited = limit.is_some()
    );
    tokio::select! {
        r = kekkai_io::run(state.clone(), socket, NoTunnel, kekkai_core::MTU as u16) => r.map_err(|e| e.to_string()),
        r = control.serve(state, listener) => r.map_err(|e| format!("control socket: {e}")),
        () = terminate() => Ok(()),
    }
}

async fn terminate() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    info!(event = "stopping");
}

/// `GetStatus` on the relay's socket (ADR 0031): its own node section and the per-sender
/// counters, by configured name. No endpoint.
struct Control {
    state: Option<Arc<Mutex<State>>>,
    started: Duration,
    node: NodeStatus,
}

impl Control {
    async fn serve(
        mut self,
        state: Arc<Mutex<State>>,
        listener: tokio::net::UnixListener,
    ) -> Result<(), tonic::transport::Error> {
        self.state = Some(state);
        tonic::transport::Server::builder()
            .add_service(ControlServiceServer::new(self))
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await
    }

    fn status(&self) -> GetStatusResponse {
        let now = clock::monotonic();
        let state = self.state.as_ref().expect("set by serve");
        let state = state.lock().expect("no panic while holding the state");
        let mut node = self.node.clone();
        node.uptime = prost_types::Duration::try_from(now.saturating_sub(self.started)).ok();
        GetStatusResponse {
            node: Some(node),
            senders: senders(&state),
            ..GetStatusResponse::default()
        }
    }
}

fn senders(state: &State) -> Vec<RelaySender> {
    state
        .node
        .relay_senders()
        .into_iter()
        .map(|(key, c)| RelaySender {
            public_key: public_key_to_text(&key),
            name: state
                .peers
                .get(&key)
                .map(|p| p.name.clone())
                .unwrap_or_default(),
            connected: state.node.status(&key).is_some_and(|s| s.current),
            forwarded_packets: c.forwarded_packets,
            forwarded_bytes: c.forwarded_bytes,
            dropped_no_route: c.dropped_no_route,
            dropped_rate_limited: c.dropped_rate_limited,
        })
        .collect()
}

#[tonic::async_trait]
impl ControlService for Control {
    async fn get_status(
        &self,
        _: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        Ok(Response::new(self.status()))
    }
}

/// The relay's `/metrics` (ADR 0019, 0031): aggregate counters only, no per-node label
/// (ADR 0014).
fn render(state: &State) -> String {
    let senders = state.node.relay_senders();
    let sum = |f: fn(&kekkai_core::relay::SenderCounters) -> u64| -> u64 {
        senders.iter().map(|(_, c)| f(c)).sum()
    };
    let connected = senders
        .iter()
        .filter(|(k, _)| state.node.status(k).is_some_and(|s| s.current))
        .count();
    let mut out = String::new();
    family(
        &mut out,
        "kekkai_build_info",
        "gauge",
        "Version of this kekkai-relay.",
    );
    let _ = writeln!(
        out,
        "kekkai_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
    family(
        &mut out,
        "kekkai_relay_sessions",
        "gauge",
        "Listed nodes with a live session.",
    );
    let _ = writeln!(out, "kekkai_relay_sessions {connected}");
    family(
        &mut out,
        "kekkai_relay_forwarded_packets_total",
        "counter",
        "relay_forward messages forwarded.",
    );
    let _ = writeln!(
        out,
        "kekkai_relay_forwarded_packets_total {}",
        sum(|c| c.forwarded_packets)
    );
    family(
        &mut out,
        "kekkai_relay_forwarded_bytes_total",
        "counter",
        "Payload bytes forwarded.",
    );
    let _ = writeln!(
        out,
        "kekkai_relay_forwarded_bytes_total {}",
        sum(|c| c.forwarded_bytes)
    );
    family(
        &mut out,
        "kekkai_relay_refused_total",
        "counter",
        "relay_forward messages refused, by reason.",
    );
    let _ = writeln!(
        out,
        "kekkai_relay_refused_total{{reason=\"no_route\"}} {}\n\
         kekkai_relay_refused_total{{reason=\"rate_limited\"}} {}",
        sum(|c| c.dropped_no_route),
        sum(|c| c.dropped_rate_limited)
    );
    drops(&mut out, state);
    out
}

#[cfg(test)]
mod tests {
    use kekkai_core::keys::StaticKey;

    use super::*;

    #[test]
    fn exposition_has_no_per_node_label() {
        let peer = StaticKey::from_bytes([2; 32]).clamped().public();
        let node = Node::relay(StaticKey::from_bytes([1; 32]).clamped(), vec![peer], None);
        let info = PeerInfo { name: "a".into() };
        let state = State::new(node, HashMap::from([(peer, info)]));
        let text = render(&state);
        assert!(text.contains("kekkai_relay_sessions 0\n"), "{text}");
        assert!(text.contains("kekkai_relay_refused_total{reason=\"rate_limited\"} 0\n"));
        assert!(!text.contains("peer="), "{text}");
        let s = senders(&state);
        assert_eq!(
            (s.len(), s[0].name.as_str(), s[0].connected),
            (1, "a", false)
        );
    }
}
