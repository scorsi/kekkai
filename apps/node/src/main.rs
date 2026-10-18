//! kekkai-node (ADR 0005): the node daemon. `--config <path>` (default
//! `/etc/kekkai/node.toml`, ADR 0016) runs it; `config check` validates the file and exits.

mod control;

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use kekkai_core::node::{Node, PeerConfig};
use kekkai_io::config::{DEFAULT_PATH, NodeConfig};
use kekkai_io::{PeerInfo, State, clock, systemd, udp};
use tracing::{info, warn};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

/// Name of the overlay interface; fixed, not configurable (ADR 0010: annai's resolver module
/// is pointed at it by the deployment).
pub const INTERFACE: &str = "kekkai0";

/// ADR 0015.
#[cfg(target_os = "linux")]
pub const CONTROL_SOCKET: &str = "/run/kekkai/control.sock";
#[cfg(not(target_os = "linux"))]
pub const CONTROL_SOCKET: &str = "/var/run/kekkai/control.sock";

const USAGE: &str = "usage: kekkai-node [--config PATH] [config check] | --version";

fn main() -> ExitCode {
    let mut config = PathBuf::from(DEFAULT_PATH);
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
    eprintln!("kekkai-node: {message}");
    ExitCode::FAILURE
}

/// Reads and validates the file, `[log] level` included.
fn load(path: &Path) -> Result<NodeConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let config = NodeConfig::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    config
        .log
        .level
        .parse::<Targets>()
        .map_err(|e| format!("{}: log.level: {e}", path.display()))?;
    Ok(config)
}

fn run(path: &Path) -> Result<(), String> {
    let config = load(path)?;
    // ADR 0016: RUST_LOG, when set, overrides [log] level.
    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|f| f.parse::<Targets>().ok())
        .unwrap_or_else(|| config.log.level.parse().expect("checked by load"));
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(io::stderr)
                .without_time(),
        )
        .with(filter)
        .init();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(serve(config))
}

async fn serve(config: NodeConfig) -> Result<(), String> {
    let key = kekkai_io::load_key(&config.node.private_key_file).map_err(|e| e.to_string())?;
    let mut peers = HashMap::new();
    let mut peer_configs = Vec::new();
    let mut routes = Vec::new();
    for peer in &config.peers {
        let public_key = peer.key()?;
        let addresses = peer.host_addresses();
        let mut statics = Vec::new();
        for endpoint in &peer.endpoints {
            match tokio::net::lookup_host(endpoint.as_str()).await {
                Ok(found) => statics.extend(found.map(udp::to_socket)),
                Err(e) => warn!(peer = %peer.name, endpoint, error = %e, "endpoint not resolved"),
            }
        }
        routes.extend(&addresses);
        let name = peer.name.clone();
        peers.insert(
            public_key,
            PeerInfo {
                name,
                statics,
                endpoint: None,
            },
        );
        peer_configs.push(PeerConfig {
            public_key,
            addresses,
        });
    }
    let node = Node::new(key, peer_configs);
    let control = control::Control::new(&config, *node.public_key(), clock::monotonic());
    let mtu = config.node.mtu;
    let tunnel =
        open_tunnel(mtu, &config.addresses(), &routes).map_err(|e| format!("{INTERFACE}: {e}"))?;
    let socket = udp::bind(config.node.listen_port)
        .map_err(|e| format!("udp port {}: {e}", config.node.listen_port))?;
    let listener = systemd::control_listener(Path::new(CONTROL_SOCKET))
        .map_err(|e| format!("{CONTROL_SOCKET}: {e}"))?;
    let state = Arc::new(Mutex::new(State { node, peers }));
    // ADR 0018: READY=1 once the interface exists and the socket is bound.
    systemd::notify_ready().map_err(|e| format!("sd_notify: {e}"))?;
    info!(
        interface = INTERFACE,
        port = config.node.listen_port,
        peers = config.peers.len(),
        "ready"
    );
    tokio::select! {
        r = kekkai_io::run(state.clone(), socket, tunnel, mtu) => r.map_err(|e| format!("{INTERFACE}: {e}")),
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
    info!("stopping");
}

#[cfg(target_os = "linux")]
fn open_tunnel(
    mtu: u16,
    addresses: &[IpAddr],
    routes: &[IpAddr],
) -> io::Result<kekkai_io::tun::Tun> {
    kekkai_io::tun::Tun::create(INTERFACE, mtu, addresses, routes)
}

/// macOS `utun` is v0.3.
#[cfg(not(target_os = "linux"))]
fn open_tunnel(_: u16, _: &[IpAddr], _: &[IpAddr]) -> io::Result<NoTunnel> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no TUN support on this platform before v0.3",
    ))
}

#[cfg(not(target_os = "linux"))]
enum NoTunnel {}

#[cfg(not(target_os = "linux"))]
impl kekkai_io::Tunnel for NoTunnel {
    async fn recv(&self, _: &mut [u8]) -> io::Result<usize> {
        match *self {}
    }

    async fn send(&self, _: &[u8]) -> io::Result<()> {
        match *self {}
    }
}
