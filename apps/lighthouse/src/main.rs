//! kekkai-lighthouse (ADR 0005, 0012): endpoint registration and lookup for the listed keys.
//! `--config <path>` (default `/etc/kekkai/lighthouse.toml`, ADR 0016) runs it; `config
//! check` validates the file and exits. Unprivileged: no TUN, no route (ADR 0018).

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
use kekkai_control::v1::{GetStatusRequest, GetStatusResponse, NodeStatus, Registration};
use kekkai_core::keys::public_key_to_text;
use kekkai_core::node::Node;
use kekkai_io::config::{LIGHTHOUSE_DEFAULT_PATH, LighthouseConfig};
use kekkai_io::metrics::{drops, family};
use kekkai_io::{NoTunnel, PeerInfo, State, clock, systemd, udp};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};
use tracing::info;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

/// The lighthouse's control socket (ADR 0030), beside the node's `/run/kekkai/`.
pub const CONTROL_SOCKET: &str = "/run/kekkai-lighthouse/control.sock";

const USAGE: &str = "usage: kekkai-lighthouse [--config PATH] [config check] | --version";

fn main() -> ExitCode {
    let mut config = PathBuf::from(LIGHTHOUSE_DEFAULT_PATH);
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

fn load(path: &Path) -> Result<LighthouseConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let config = LighthouseConfig::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
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

async fn serve(config: LighthouseConfig) -> Result<(), String> {
    let key = kekkai_io::load_key(&config.service.private_key_file).map_err(|e| e.to_string())?;
    let mut peers = HashMap::new();
    for peer in &config.peers {
        let name = peer.name.clone();
        peers.insert(peer.key()?, PeerInfo { name });
    }
    let node = Node::lighthouse(key, peers.keys().copied().collect());
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
    let listener = systemd::control_listener(Path::new(CONTROL_SOCKET), "kekkai-lighthouse")
        .map_err(|e| format!("{CONTROL_SOCKET}: {e}"))?;
    let mut state = State::new(node, peers);
    // ADR 0012: aggregate counters only, never where a node is.
    state.log_peers = false;
    let state = Arc::new(Mutex::new(state));
    if let Some(m) = &config.metrics {
        let listener = std::net::TcpListener::bind(m.listen)
            .map_err(|e| format!("metrics.listen {}: {e}", m.listen))?;
        let state = state.clone();
        std::thread::spawn(move || kekkai_io::metrics::serve(listener, &state, render));
    }
    systemd::notify_ready().map_err(|e| format!("sd_notify: {e}"))?;
    info!(event = "ready", port, peers = config.peers.len());
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

/// `GetStatus` on the lighthouse's socket (ADR 0030): its own node section and the
/// unexpired registrations, by configured name.
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
        let registrations = state
            .node
            .registrations(now)
            .into_iter()
            .map(|(key, r)| Registration {
                public_key: public_key_to_text(&key),
                name: state
                    .peers
                    .get(&key)
                    .map(|p| p.name.clone())
                    .unwrap_or_default(),
                observed_endpoint: r.observed.display().to_string(),
                local_endpoints: r.locals.iter().map(|e| e.display().to_string()).collect(),
                last_seen: prost_types::Duration::try_from(now.saturating_sub(r.refreshed)).ok(),
            })
            .collect();
        GetStatusResponse {
            node: Some(node),
            registrations,
            ..GetStatusResponse::default()
        }
    }
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

/// The lighthouse's `/metrics` (ADR 0019): aggregate counters only, no per-node label
/// (ADR 0012).
fn render(state: &State) -> String {
    let now = clock::monotonic();
    let c = state.node.lighthouse_counters();
    let mut out = String::new();
    family(
        &mut out,
        "kekkai_build_info",
        "gauge",
        "Version of this kekkai-lighthouse.",
    );
    let _ = writeln!(
        out,
        "kekkai_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
    family(
        &mut out,
        "kekkai_lighthouse_registrations",
        "gauge",
        "Unexpired registrations.",
    );
    let n = state.node.registrations(now).len();
    let _ = writeln!(out, "kekkai_lighthouse_registrations {n}");
    family(
        &mut out,
        "kekkai_lighthouse_registers_total",
        "counter",
        "lighthouse_register messages received.",
    );
    let _ = writeln!(out, "kekkai_lighthouse_registers_total {}", c.registers);
    family(
        &mut out,
        "kekkai_lighthouse_queries_total",
        "counter",
        "lighthouse_query messages, by whether the key was known or the query over budget.",
    );
    let _ = writeln!(
        out,
        "kekkai_lighthouse_queries_total{{result=\"known\"}} {}\n\
         kekkai_lighthouse_queries_total{{result=\"unknown\"}} {}\n\
         kekkai_lighthouse_queries_total{{result=\"limited\"}} {}",
        c.queries_known, c.queries_unknown, c.queries_limited
    );
    family(
        &mut out,
        "kekkai_lighthouse_punches_total",
        "counter",
        "lighthouse_punch messages sent.",
    );
    let _ = writeln!(out, "kekkai_lighthouse_punches_total {}", c.punches);
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
        let node = Node::lighthouse(StaticKey::from_bytes([1; 32]).clamped(), vec![peer]);
        let info = PeerInfo { name: "a".into() };
        let text = render(&State::new(node, HashMap::from([(peer, info)])));
        assert!(
            text.contains("kekkai_lighthouse_registrations 0\n"),
            "{text}"
        );
        assert!(text.contains("kekkai_lighthouse_queries_total{result=\"known\"} 0\n"));
        assert!(!text.contains("peer="), "{text}");
    }
}
