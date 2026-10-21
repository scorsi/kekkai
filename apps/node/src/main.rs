//! kekkai-node (ADR 0005): the node daemon. `--config <path>` (default
//! `/etc/kekkai/node.toml`, ADR 0016) runs it; `config check` validates the file and exits.

mod control;
mod log;
mod metrics;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kekkai_core::inner::Endpoint;
use kekkai_core::keys::PublicKey;
use kekkai_core::node::{LighthouseConfig, Node, PeerConfig, PeerStatus};
use kekkai_core::{KEEPALIVE_FAILURES_BEFORE_REREGISTER, PERSISTENT_KEEPALIVE};
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
    let mut named = Vec::new();
    let start = clock::monotonic();
    for peer in &config.peers {
        let public_key = peer.key()?;
        named.extend(Named::new(public_key, &peer.name, &peer.endpoints, start));
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
    let mut node = Node::new(key, peer_configs.clone());
    node.set_udp_flows_max(config.firewall.udp_flows_max);
    let mut lighthouses = Vec::new();
    let mut lighthouse_configs = Vec::new();
    for l in &config.lighthouses {
        let public_key = l.key()?;
        lighthouses.push((public_key, l.endpoint.clone()));
        let endpoints = vec![l.endpoint.clone()];
        named.extend(Named::new(public_key, "lighthouse", &endpoints, start));
        // Installed even when unresolved: `status` shows it and `reresolve` retries (§13.1).
        lighthouse_configs.push(LighthouseConfig {
            public_key,
            endpoints: resolve("lighthouse", &l.endpoint).await,
        });
    }
    node.set_lighthouses(lighthouse_configs.clone());
    let mut relays = Vec::new();
    let mut relay_configs = Vec::new();
    for r in &config.relays {
        let public_key = r.key()?;
        relays.push((public_key, r.endpoint.clone()));
        let endpoints = vec![r.endpoint.clone()];
        named.extend(Named::new(public_key, "relay", &endpoints, start));
        relay_configs.push(LighthouseConfig {
            public_key,
            endpoints: resolve("relay", &r.endpoint).await,
        });
    }
    node.set_relays(relay_configs.clone());
    let configs = (peer_configs, lighthouse_configs, relay_configs);
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
    state.relays = relays;
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
        r = control.serve(state.clone(), listener) => r.map_err(|e| format!("control socket: {e}")),
        () = reresolve(state, configs, named) => Ok(()),
        () = terminate() => Ok(()),
    }
}

/// A party whose endpoints include a DNS name (ADR 0016), with its resolution backoff.
struct Named {
    key: PublicKey,
    owner: String,
    /// Every endpoint as written, literals included (they resolve without DNS).
    endpoints: Vec<String>,
    delay: Duration,
    next: Duration,
}

/// §13.1: a stale party is resolved again `RESOLVE_MIN` after start-up, then with a delay
/// doubling up to `RESOLVE_MAX` while it stays stale.
const RESOLVE_MIN: Duration = kekkai_core::REKEY_TIMEOUT;
const RESOLVE_MAX: Duration = Duration::from_secs(300);

impl Named {
    fn new(key: PublicKey, owner: &str, endpoints: &[String], now: Duration) -> Option<Self> {
        let dns = endpoints.iter().any(|e| e.parse::<SocketAddr>().is_err());
        dns.then(|| Self {
            key,
            owner: owner.into(),
            endpoints: endpoints.to_vec(),
            delay: RESOLVE_MIN,
            next: now + RESOLVE_MIN,
        })
    }

    /// Whether to resolve now; advances the backoff when it does.
    fn due(&mut self, status: &PeerStatus, now: Duration) -> bool {
        if !stale(status, now) {
            self.delay = RESOLVE_MIN;
            self.next = now + RESOLVE_MIN;
            return false;
        }
        if now < self.next {
            return false;
        }
        self.next = now + self.delay;
        self.delay = (self.delay * 2).min(RESOLVE_MAX);
        true
    }
}

/// §13.1, ADR 0016 "keepalive failure": a handshake in flight or a session up, and nothing
/// authenticated from the party for as long as three failed registers take. An unresolved
/// lighthouse is always handshaking (§9 last row), hence stale.
fn stale(status: &PeerStatus, now: Duration) -> bool {
    let silence = PERSISTENT_KEEPALIVE * KEEPALIVE_FAILURES_BEFORE_REREGISTER;
    (status.current || status.handshake_in_flight)
        && status
            .last_received
            .is_none_or(|t| now.saturating_sub(t) >= silence)
}

/// Peers, lighthouses and relays, as the node was built with them.
type Configs = (
    Vec<PeerConfig>,
    Vec<LighthouseConfig>,
    Vec<LighthouseConfig>,
);

/// Every `MAX_SLEEP`, a [`reresolve_pass`] with the system clock and resolver.
async fn reresolve(state: Arc<Mutex<State>>, mut configs: Configs, mut named: Vec<Named>) {
    loop {
        tokio::time::sleep(kekkai_io::MAX_SLEEP).await;
        reresolve_pass(&state, &mut configs, &mut named, clock::monotonic, resolve).await;
    }
}

/// Resolves the stale parties of `named` again and replaces their static candidates when
/// the addresses changed, without touching sessions or an in-flight sequence (§13.1).
/// `configs` is the peer, lighthouse and relay list the node was built with.
async fn reresolve_pass(
    state: &Mutex<State>,
    configs: &mut Configs,
    named: &mut [Named],
    now: impl Fn() -> Duration,
    mut resolve: impl AsyncFnMut(&str, &str) -> Vec<Endpoint>,
) {
    for n in named {
        let now = now();
        let status = state.lock().expect("no poison").node.status(&n.key);
        if !status.is_some_and(|s| n.due(&s, now)) {
            continue;
        }
        let mut found = Vec::new();
        for endpoint in &n.endpoints {
            found.extend(resolve(&n.owner, endpoint).await);
        }
        found.dedup();
        let (peers, lighthouses, relays) = configs;
        let mut guard = state.lock().expect("no poison");
        if let Some(p) = peers.iter_mut().find(|p| p.public_key == n.key) {
            if !found.is_empty() && p.endpoints != found {
                p.endpoints = found;
                guard.node.set_peers(peers.clone());
            }
        } else if let Some(l) = lighthouses.iter_mut().find(|l| l.public_key == n.key) {
            if !found.is_empty() && l.endpoints != found {
                l.endpoints = found;
                guard.node.set_lighthouses(lighthouses.clone());
            }
        } else if let Some(r) = relays.iter_mut().find(|r| r.public_key == n.key) {
            if !found.is_empty() && r.endpoints != found {
                r.endpoints = found;
                guard.node.set_relays(relays.clone());
            }
        }
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

#[cfg(test)]
mod tests {
    use kekkai_core::keys::StaticKey;

    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// L4: an unresolved lighthouse is installed with no candidate, shows in the node's
    /// status as handshaking, and is resolved again 5 s after start-up, then with a doubling
    /// delay up to 5 minutes while it stays silent; an answer resets the backoff.
    #[test]
    fn unresolved_lighthouses_are_retried_with_backoff() {
        let lh = StaticKey::from_bytes([3; 32]).clamped().public();
        let mut node = Node::new(StaticKey::from_bytes([1; 32]).clamped(), Vec::new());
        node.set_lighthouses(vec![LighthouseConfig {
            public_key: lh,
            endpoints: Vec::new(),
        }]);
        let out = node.tick(
            secs(0),
            kekkai_core::tai64n::Tai64n::from_unix(1_800_000_000, 0),
        );
        assert!(out.datagrams.is_empty(), "no candidate to send to");
        let status = node.status(&lh).expect("installed although unresolved");
        assert_eq!(kekkai_io::session_state(&status), "handshaking");

        let written = vec!["lighthouse.example.org:4800".to_string()];
        let mut named = Named::new(lh, "lighthouse", &written, secs(0)).expect("a DNS name");
        let tries: Vec<u64> = (0..700).filter(|t| named.due(&status, secs(*t))).collect();
        assert_eq!(tries, [5, 10, 20, 40, 80, 160, 320, 620]);

        let answered = PeerStatus {
            current: true,
            last_received: Some(secs(700)),
            ..status
        };
        assert!(!named.due(&answered, secs(700)));
        assert!(
            !named.due(&answered, secs(774)),
            "silent for less than 75 s"
        );
        assert!(
            !named.due(&answered, secs(775)),
            "stale, first try 5 s after the reset"
        );
        assert!(named.due(&answered, secs(779)));

        let literals = vec![
            "192.0.2.1:4800".to_string(),
            "[2001:db8::1]:4800".to_string(),
        ];
        assert!(Named::new(lh, "lighthouse", &literals, secs(0)).is_none());
    }

    /// R4, §13.1: the re-resolution pass with a controlled resolver. The lighthouse failed to
    /// resolve at start-up and fails again at 5 s; the peer's name moves from E1 to E2 at
    /// 5 s and its in-flight sequence goes on towards E2; the lighthouse resolves at 10 s,
    /// its session comes up, and once it answers it is no longer resolved again. The
    /// peer's sequence survives the lighthouse update.
    #[test]
    fn reresolution_replaces_candidates_and_keeps_the_handshake() {
        let wall =
            |t: Duration| kekkai_core::tai64n::Tai64n::from_unix(1_800_000_000 + t.as_secs(), 0);
        let ep = |s: &str| Endpoint::from(s.parse::<SocketAddr>().unwrap());
        let (e1, e2, el, me) = (
            ep("192.0.2.10:4802"),
            ep("192.0.2.20:4802"),
            ep("192.0.2.30:4800"),
            ep("192.0.2.1:4802"),
        );
        let key = |b: u8| StaticKey::from_bytes([b; 32]).clamped();
        let (p, l) = (key(2).public(), key(3).public());
        let peer = PeerConfig {
            public_key: p,
            addresses: vec!["10.0.0.2".parse().unwrap()],
            allow_inbound: Vec::new(),
            endpoints: vec![e1],
        };
        let unresolved = LighthouseConfig {
            public_key: l,
            endpoints: Vec::new(),
        };
        let mut node = Node::new(key(1), vec![peer.clone()]);
        node.set_lighthouses(vec![unresolved.clone()]);
        let mut lighthouse = Node::lighthouse(key(3), vec![key(1).public()]);
        let mut packet = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1];
        packet.extend([10, 0, 0, 2]);
        let out = node.send_packet(secs(0), wall(secs(0)), &packet).unwrap();
        let to: Vec<Endpoint> = out.datagrams.iter().map(|(e, _)| *e).collect();
        assert_eq!(to, [e1], "message 1 to the start-up address");
        assert!(node.tick(secs(0), wall(secs(0))).datagrams.is_empty());

        let state = Mutex::new(State::new(node, HashMap::new()));
        let mut configs = (vec![peer], vec![unresolved], Vec::new());
        let written = |name: &str| vec![format!("{name}.example.org:4800")];
        let mut named: Vec<Named> = [(p, "peer"), (l, "lighthouse")]
            .into_iter()
            .filter_map(|(k, name)| Named::new(k, name, &written(name), secs(0)))
            .collect();
        let mut answers: HashMap<&str, Vec<Endpoint>> =
            HashMap::from([("peer", vec![e2]), ("lighthouse", Vec::new())]);
        let mut calls: Vec<(Duration, String)> = Vec::new();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut pass = |at: Duration, answers: &HashMap<&str, Vec<Endpoint>>| {
            let resolver = async |owner: &str, _: &str| {
                calls.push((at, owner.to_string()));
                answers[owner].clone()
            };
            runtime.block_on(reresolve_pass(
                &state,
                &mut configs,
                &mut named,
                || at,
                resolver,
            ));
        };
        let tick = |at: Duration| {
            let mut guard = state.lock().unwrap();
            guard.node.tick(at, wall(at)).datagrams
        };
        let status_of = |key: &PublicKey| state.lock().unwrap().node.status(key).unwrap();

        pass(secs(4), &answers);
        pass(secs(5), &answers);
        assert!(
            status_of(&p).handshake_in_flight,
            "the sequence was not restarted"
        );
        let out = tick(secs(6));
        assert!(
            !out.is_empty() && out.iter().all(|(e, _)| *e == e2),
            "{out:?}"
        );
        assert!(!status_of(&l).current);

        answers.insert("lighthouse", vec![el]);
        pass(secs(10), &answers);
        assert!(
            status_of(&p).handshake_in_flight,
            "kept across the lighthouse update"
        );
        let out = tick(secs(12));
        let to_lighthouse: Vec<&Vec<u8>> = out
            .iter()
            .filter(|(e, _)| *e == el)
            .map(|(_, d)| d)
            .collect();
        assert_eq!(to_lighthouse.len(), 1, "{out:?}");
        let reply = lighthouse
            .handle_datagram(secs(12), wall(secs(12)), me, to_lighthouse[0])
            .unwrap();
        for (_, d) in reply.datagrams {
            let mut guard = state.lock().unwrap();
            guard
                .node
                .handle_datagram(secs(12), wall(secs(12)), el, &d)
                .unwrap();
        }
        assert!(status_of(&l).current, "the lighthouse session is up");
        pass(secs(20), &answers);

        let tried = |owner: &str| -> Vec<u64> {
            calls
                .iter()
                .filter(|(_, o)| o == owner)
                .map(|(t, _)| t.as_secs())
                .collect()
        };
        assert_eq!(tried("lighthouse"), [5, 10], "not again once it answered");
        assert_eq!(tried("peer"), [5, 10, 20], "stale: backoff 5, 10, 20");
        assert!(status_of(&p).handshake_in_flight);
    }
}
