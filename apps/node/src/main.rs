//! kekkai-node (ADR 0005): the node daemon. `--config <path>` (default
//! `/etc/kekkai/node.toml`, ADR 0016) runs it; `config check` validates the file and exits.

mod control;
mod log;
mod metrics;

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use kekkai_core::inner::Endpoint;
use kekkai_core::node::{LighthouseConfig, Node, PeerConfig};
use kekkai_io::config::{DEFAULT_PATH, NodeConfig};
use kekkai_io::{Locals, PeerInfo, State, clock, systemd, udp};
use tracing::{info, warn};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

/// Name of the overlay interface on Linux; fixed, not configurable (ADR 0010: annai's
/// resolver module is pointed at it by the deployment). On macOS the kernel names it `utunN`.
#[cfg(target_os = "linux")]
pub const INTERFACE: &str = "kekkai0";
#[cfg(not(target_os = "linux"))]
pub const INTERFACE: &str = "utun";

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

/// Errors leave as a log schema line too: the daemon's stderr is the journal (ADR 0019).
fn fail(message: &str) -> ExitCode {
    log::fatal(message);
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
        .with(log::JsonLayer.with_filter(filter))
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
        let mut endpoints = Vec::new();
        for endpoint in &peer.endpoints {
            endpoints.extend(resolve(&peer.name, endpoint).await);
        }
        routes.extend(&addresses);
        let name = peer.name.clone();
        peers.insert(public_key, PeerInfo { name });
        peer_configs.push(PeerConfig {
            public_key,
            addresses,
            allow_inbound: peer.rules()?,
            endpoints,
        });
    }
    let mut node = Node::new(key, peer_configs);
    node.set_udp_flows_max(config.firewall.udp_flows_max);
    let mut lighthouses = Vec::new();
    let mut lighthouse_configs = Vec::new();
    for l in &config.lighthouses {
        let public_key = l.key()?;
        lighthouses.push((public_key, l.endpoint.clone()));
        // shortcut: the first resolved address only; DNS is re-resolved on restart (ADR 0016
        // also asks for keepalive failures, open in the napkin).
        if let Some(endpoint) = resolve("lighthouse", &l.endpoint).await.first() {
            lighthouse_configs.push(LighthouseConfig {
                public_key,
                endpoint: *endpoint,
            });
        }
    }
    node.set_lighthouses(lighthouse_configs);
    let control = control::Control::new(&config, *node.public_key(), clock::monotonic());
    let mtu = config.node.mtu;
    let (tunnel, interface) =
        open_tunnel(mtu, &config.addresses(), &routes).map_err(|e| format!("{INTERFACE}: {e}"))?;
    let socket = udp::bind(config.node.listen_port)
        .map_err(|e| format!("udp port {}: {e}", config.node.listen_port))?;
    let listener = systemd::control_listener(Path::new(CONTROL_SOCKET), "kekkai")
        .map_err(|e| format!("{CONTROL_SOCKET}: {e}"))?;
    let mut state = State::new(node, peers);
    if !lighthouses.is_empty() {
        state.locals = Some(Locals {
            listen_port: config.node.listen_port,
            overlay: config.addresses(),
        });
    }
    state.lighthouses = lighthouses;
    let state = Arc::new(Mutex::new(state));
    if let Some(m) = &config.metrics {
        let listener = std::net::TcpListener::bind(m.listen)
            .map_err(|e| format!("metrics.listen {}: {e}", m.listen))?;
        let state = state.clone();
        std::thread::spawn(move || kekkai_io::metrics::serve(listener, &state, metrics::render));
    }
    // ADR 0018: READY=1 once the interface exists and the socket is bound.
    systemd::notify_ready().map_err(|e| format!("sd_notify: {e}"))?;
    info!(
        event = "ready",
        interface = %interface,
        port = config.node.listen_port,
        peers = config.peers.len()
    );
    tokio::select! {
        r = kekkai_io::run(state.clone(), socket, tunnel, mtu) => r.map_err(|e| format!("{interface}: {e}")),
        r = control.serve(state, listener) => r.map_err(|e| format!("control socket: {e}")),
        () = terminate() => Ok(()),
    }
}

/// A `host:port` from the file, resolved now (ADR 0016); a failure is logged, not fatal.
async fn resolve(owner: &str, endpoint: &str) -> Vec<Endpoint> {
    match tokio::net::lookup_host(endpoint).await {
        Ok(found) => found.map(Endpoint::from).collect(),
        Err(e) => {
            warn!(event = "endpoint-unresolved", peer = %owner, endpoint = %endpoint, err = %e);
            Vec::new()
        }
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

#[cfg(target_os = "linux")]
fn open_tunnel(
    mtu: u16,
    addresses: &[IpAddr],
    routes: &[IpAddr],
) -> io::Result<(kekkai_io::tun::Tun, String)> {
    let tun = kekkai_io::tun::Tun::create(INTERFACE, mtu, addresses, routes)?;
    Ok((tun, INTERFACE.into()))
}

#[cfg(target_os = "macos")]
fn open_tunnel(
    mtu: u16,
    addresses: &[IpAddr],
    routes: &[IpAddr],
) -> io::Result<(kekkai_io::utun::Utun, String)> {
    let utun = kekkai_io::utun::Utun::create(mtu, addresses, routes)?;
    let name = utun.name().to_owned();
    Ok((utun, name))
}
