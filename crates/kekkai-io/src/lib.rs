//! kekkai-io: the IO layer around `kekkai-core` (ADR 0004, 0023): configuration and key
//! loading, the UDP socket, the TUN device (`tun` feature, node only: Linux TUN, macOS
//! `utun`) and the loop that drives the core's `Node`.

pub mod clock;
pub mod config;
pub mod ifaddrs;
pub mod metrics;
pub mod mss;
pub mod systemd;
#[cfg(all(feature = "tun", target_os = "linux"))]
pub mod tun;
pub mod udp;
#[cfg(all(feature = "tun", target_os = "macos"))]
pub mod utun;

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kekkai_core::inner::Endpoint;
use kekkai_core::keys::{PublicKey, StaticKey};
use kekkai_core::node::{self, Node, PathFailure, PeerStatus};
use kekkai_core::peer::Counters;
use kekkai_core::wire::DropReason;
use tracing::field::display;
use tracing::{debug, info, trace};

/// ADR 0004: the loop never sleeps longer than this, so that a suspend is noticed within a
/// second of resuming and every deadline that passed meanwhile runs at once.
pub const MAX_SLEEP: Duration = Duration::from_secs(1);

/// The IO layer's name for a peer, for logs, metrics and status (ADR 0019), and on a node
/// its addresses and rules as written, for status (ADR 0015). Replaced by a reload (§4.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerInfo {
    pub name: String,
    pub addresses: Vec<String>,
    pub allow_inbound: Vec<String>,
}

/// A route towards the tunnel: a configured peer's host route (spec §11) or a `[pki]`
/// prefix (§4.4), with no host bits set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Route {
    pub address: IpAddr,
    pub length: u8,
}

impl Route {
    /// The `/32` or `/128` of `address`.
    pub fn host(address: IpAddr) -> Self {
        let length = if address.is_ipv4() { 32 } else { 128 };
        Self { address, length }
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.length)
    }
}

/// What the node collects for `lighthouse_register` (spec §13.1) and its keepalives on a
/// change of local addresses (§12.4).
#[derive(Clone, Debug)]
pub struct Locals {
    pub listen_port: u16,
    /// The overlay addresses, never registered.
    pub overlay: Vec<IpAddr>,
}

/// What the loop, the control server and the metrics endpoint share.
pub struct State {
    pub node: Node,
    pub peers: HashMap<PublicKey, PeerInfo>,
    /// Configured lighthouses and their endpoint as written, for logs and status.
    pub lighthouses: Vec<(PublicKey, String)>,
    /// Configured relays and their endpoint as written, for logs and status.
    pub relays: Vec<(PublicKey, String)>,
    /// Local endpoints to collect at every tick: always on a node, never on a lighthouse or
    /// a relay.
    pub locals: Option<Locals>,
    /// `false` on a lighthouse: it logs aggregate counters only, never per-peer events
    /// (ADR 0012, 0019).
    pub log_peers: bool,
    /// Datagrams and tunnel packets the core dropped, by `DropReason` name (ADR 0019).
    pub drops: BTreeMap<&'static str, u64>,
    /// What `log_events` saw of each party at its last check; follows the lists (§4.1).
    seen: HashMap<PublicKey, Seen>,
}

impl State {
    pub fn new(node: Node, peers: HashMap<PublicKey, PeerInfo>) -> Self {
        Self {
            node,
            peers,
            lighthouses: Vec::new(),
            relays: Vec::new(),
            locals: None,
            log_peers: true,
            drops: BTreeMap::new(),
            seen: HashMap::new(),
        }
    }

    /// A node's reload (spec §4.1): replaces the IO lists. A key removed or moved to another
    /// role starts with a fresh log history, as its core state does, so that its counters
    /// are never compared with those of its previous life.
    pub fn set_lists(
        &mut self,
        peers: HashMap<PublicKey, PeerInfo>,
        lighthouses: Vec<(PublicKey, String)>,
        relays: Vec<(PublicKey, String)>,
    ) {
        let role = |s: &Self, k: &PublicKey| {
            let has = |l: &[(PublicKey, String)]| l.iter().any(|(x, _)| x == k);
            (s.peers.contains_key(k), has(&s.lighthouses), has(&s.relays))
        };
        let before: Vec<_> = self.seen.keys().map(|k| (*k, role(self, k))).collect();
        (self.peers, self.lighthouses, self.relays) = (peers, lighthouses, relays);
        for (k, r) in before {
            if role(self, &k) != r {
                self.seen.remove(&k);
            }
        }
    }

    /// A lighthouse's or relay's reload (spec §4.1): replaces its peer list, keys and names.
    /// Returns how many keys were added and removed and how many kept ones were renamed.
    pub fn reload_named_peers(
        &mut self,
        peers: HashMap<PublicKey, PeerInfo>,
    ) -> (usize, usize, usize) {
        let old = &self.peers;
        let added = peers.keys().filter(|k| !old.contains_key(*k)).count();
        let removed = old.keys().filter(|k| !peers.contains_key(*k)).count();
        let renamed = (peers.iter())
            .filter(|(k, p)| old.get(*k).is_some_and(|o| o != *p))
            .count();
        self.node
            .set_lighthouse_peers(peers.keys().copied().collect());
        self.seen.retain(|k, _| peers.contains_key(k));
        self.peers = peers;
        (added, removed, renamed)
    }

    fn count_drop(&mut self, reason: DropReason) {
        *self.drops.entry(reason.as_str()).or_default() += 1;
    }
}

/// A peer's path as logs and metrics name it (ADR 0019): `direct`, `relayed` or `none`.
pub fn path_name(status: &PeerStatus) -> &'static str {
    match status.path {
        Some(node::Path::Direct(_)) => "direct",
        Some(node::Path::Relayed(_)) => "relayed",
        None => "none",
    }
}

/// The session state of a lighthouse or relay as `status` reports it (ADR 0015).
pub fn session_state(status: &PeerStatus) -> &'static str {
    if status.current {
        "connected"
    } else if status.handshake_in_flight {
        "handshaking"
    } else {
        "down"
    }
}

/// The overlay interface as the loop sees it: one IP packet per call.
#[allow(async_fn_in_trait)] // only used through generics on a current-thread runtime
pub trait Tunnel {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    async fn send(&self, packet: &[u8]) -> io::Result<()>;
}

/// No interface: the lighthouse routes no IP packet (spec §10.2).
pub struct NoTunnel;

impl Tunnel for NoTunnel {
    async fn recv(&self, _: &mut [u8]) -> io::Result<usize> {
        std::future::pending().await
    }

    async fn send(&self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
}

/// What `log_events` remembers of a peer between two checks.
#[derive(Debug, Default)]
struct Seen {
    path: &'static str,
    counters: Counters,
    endpoint: Option<Endpoint>,
    failure: Option<PathFailure>,
    state: &'static str,
}

/// Drives the core (ADR 0004): datagrams from `socket`, packets from `tunnel`, and the
/// deadlines, until an IO error on the tunnel. `mtu` is the interface MTU, for MSS clamping.
pub async fn run(
    state: Arc<Mutex<State>>,
    socket: tokio::net::UdpSocket,
    tunnel: impl Tunnel,
    mtu: u16,
) -> io::Result<()> {
    let mut udp_buf = vec![0u8; 1 << 16];
    let mut tun_buf = vec![0u8; 1 << 16];
    let lock = || state.lock().expect("no panic while holding the state");
    let log_peers = lock().log_peers;
    // Absolute, so that received datagrams and packets postpone neither the poll of the local
    // endpoints nor the tick (§12.4, §13.1): a fresh one-second sleep per iteration would.
    let mut poll_at = clock::monotonic();
    loop {
        // A tunnel or socket that is always readable never returns `Pending` (the AsyncFd fast
        // path takes no budget): yield regularly, or the runtime's timers and IO driver starve.
        tokio::task::coop::consume_budget().await;
        let next = lock()
            .node
            .next_deadline()
            .map_or(poll_at, |d| d.min(poll_at));
        let wake = next.saturating_sub(clock::monotonic());
        // Overdue: tick now. A new `sleep(0)` is rounded up to the next millisecond by tokio and
        // can lose to ready input at every iteration.
        let output = if wake.is_zero() {
            tick(&mut lock(), &mut poll_at)
        } else {
            tokio::select! {
                received = socket.recv_from(&mut udp_buf) => {
                    let (n, source) = match received {
                        Ok(r) => r,
                        Err(e) => {
                            debug!(event = "udp-receive-failed", error = %e);
                            continue;
                        }
                    };
                    let mut guard = lock();
                    let result = guard.node.handle_datagram(
                        clock::monotonic(),
                        clock::wall(),
                        Endpoint::from(source),
                        &udp_buf[..n],
                    );
                    match result {
                        Ok(output) => {
                            // Rejected inner content: the transport effects still go out (§8.2).
                            if let Some(reason) = output.dropped {
                                guard.count_drop(reason);
                                trace!(event = "datagram-dropped", reason = reason.as_str());
                            }
                            // Handshakes, endpoints and paths change on received datagrams:
                            // logged now, not at the next tick (v0.6 finding 3). Only the
                            // sender: a full check per datagram costs ~60 ns per listed peer.
                            log_events(&mut guard, output.from);
                            output
                        }
                        Err(reason) => {
                            guard.count_drop(reason);
                            trace!(event = "datagram-dropped", reason = reason.as_str());
                            continue;
                        }
                    }
                }
                read = tunnel.recv(&mut tun_buf) => {
                    let packet = &mut tun_buf[..read?];
                    mss::clamp(packet, mtu);
                    let mut guard = lock();
                    let result = guard
                        .node
                        .send_packet(clock::monotonic(), clock::wall(), packet);
                    match result {
                        Ok(output) => output,
                        Err(reason) => {
                            guard.count_drop(reason);
                            trace!(event = "tunnel-packet-dropped", reason = reason.as_str());
                            continue;
                        }
                    }
                }
                () = tokio::time::sleep(wake) => tick(&mut lock(), &mut poll_at),
            }
        };
        send_datagrams(&socket, output.datagrams, log_peers).await;
        for mut packet in output.packets {
            mss::clamp(&mut packet, mtu);
            if let Err(e) = tunnel.send(&packet).await {
                debug!(event = "tunnel-write-failed", error = %e);
            }
        }
    }
}

/// Polls the local endpoints, ticks the core and logs its events; the next poll is due one
/// second later.
fn tick(state: &mut State, poll_at: &mut Duration) -> node::Output {
    if let Some(locals) = state.locals.clone() {
        // §12.4, §13.1: polled at every tick (at least once a second, traffic or not), so a
        // change is acted upon by the tick below; v0 listens to no OS network event.
        match ifaddrs::local_endpoints(locals.listen_port, &locals.overlay) {
            Ok(found) => state.node.set_local_endpoints(found),
            Err(e) => debug!(event = "local-addresses-failed", error = %e),
        }
    }
    let output = state.node.tick(clock::monotonic(), clock::wall());
    *poll_at = clock::monotonic() + MAX_SLEEP;
    log_events(state, None);
    output
}

/// Sends what the core produced. A failure is logged with its destination only when
/// `log_peers`: a lighthouse never logs where a node is, at any level (ADR 0012, 0030).
async fn send_datagrams(
    socket: &tokio::net::UdpSocket,
    datagrams: Vec<(Endpoint, Vec<u8>)>,
    log_peers: bool,
) {
    for (to, datagram) in datagrams {
        if let Err(e) = socket.send_to(&datagram, to.socket_addr()).await {
            let to = log_peers.then(|| display(to.display()));
            debug!(event = "udp-send-failed", error = %e, to);
        }
    }
}

/// ADR 0019 `info` events: handshake completed, path change, endpoint change, direct-path
/// failure, lighthouse and relay session state. Every party at a tick; `only` the sender of a
/// received datagram, whose changes to other parties wait for the next tick.
fn log_events(state: &mut State, only: Option<PublicKey>) {
    if !state.log_peers {
        return;
    }
    let seen = &mut state.seen;
    let all = only
        .is_none()
        .then(|| state.peers.iter())
        .into_iter()
        .flatten();
    let one = only.and_then(|k| state.peers.get_key_value(&k));
    for (key, peer) in all.chain(one) {
        let Some(status) = state.node.status(key) else {
            continue;
        };
        let (path, c) = (path_name(&status), status.counters);
        let now = Seen {
            path,
            counters: c,
            endpoint: status.endpoint,
            failure: status.last_direct_path_failure,
            state: "",
        };
        let b = seen.insert(*key, now).unwrap_or(Seen {
            path: "none",
            ..Seen::default()
        });
        // shortcut: two handshakes between two checks log once, initiator wins; counters are exact.
        let initiated = c.handshakes_initiated != b.counters.handshakes_initiated;
        if initiated || c.handshakes_responded != b.counters.handshakes_responded {
            info!(
                event = "handshake-completed",
                peer = %peer.name,
                endpoint = status.endpoint.map(|e| display(e.display())),
                initiator = initiated
            );
        }
        if let Some(e) = status.endpoint.filter(|e| Some(*e) != b.endpoint) {
            info!(event = "endpoint-change", peer = %peer.name, endpoint = %e.display());
        }
        if let Some(f) = status
            .last_direct_path_failure
            .filter(|f| Some(*f) != b.failure)
        {
            info!(event = "direct-path-failed", peer = %peer.name, reason = f.as_str());
        }
        if path != b.path {
            let reason = if path == "none" {
                "session-expired"
            } else {
                "handshake-completed"
            };
            info!(event = "path-change", peer = %peer.name, from = b.path, to = path, reason);
        }
    }
    let services = (state.lighthouses.iter().map(|l| (l, true)))
        .chain(state.relays.iter().map(|r| (r, false)))
        .filter(|((key, _), _)| only.is_none_or(|k| k == *key));
    for ((key, endpoint), lighthouse) in services {
        let Some(status) = state.node.status(key) else {
            continue;
        };
        let to = session_state(&status);
        let entry = seen.entry(*key).or_insert_with(|| Seen {
            state: "down",
            ..Seen::default()
        });
        if entry.state != to {
            let from = entry.state;
            if lighthouse {
                info!(event = "lighthouse-session-change", lighthouse = %endpoint, from, to);
            } else {
                info!(event = "relay-session-change", relay = %endpoint, from, to);
            }
            entry.state = to;
        }
    }
}

/// Reads a private key file (one line of standard base64, as `kekkai keygen` writes it) into
/// the opaque value the core takes (ADR 0017). Errors never quote the file's content; the core
/// erases the text (§8.5).
pub fn load_key(path: &Path) -> std::io::Result<StaticKey> {
    let text = std::fs::read_to_string(path)?;
    StaticKey::from_file_text(text).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: not a base64 32-byte key", path.display()),
        )
    })
}

/// ADR 0026, spec §4.1: a daemon's runtime and its `SIGHUP` handler, installed before
/// `load` reads the configuration, so that a `SIGHUP` from the process start on is one
/// pending reload, read from the returned stream once the daemon is ready, and never the
/// default action (exit).
pub fn start<T>(
    load: impl FnOnce() -> Result<T, String>,
) -> Result<(tokio::runtime::Runtime, tokio::signal::unix::Signal, T), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let hangup = {
        let _runtime = runtime.enter();
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .map_err(|e| format!("SIGHUP handler: {e}"))?
    };
    let value = load()?;
    Ok((runtime, hangup, value))
}

#[cfg(test)]
mod loop_tests;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use kekkai_core::keys::StaticKey;
    use kekkai_core::node::Node;

    use super::{PeerInfo, State};

    /// R6, spec §4.1: a `SIGHUP` while the configuration is loading (here delayed) is one
    /// reload once ready: the stream yields once, not zero times (lost, or the process
    /// killed by the default action) and not twice. Runs in a child process of its own:
    /// an installed handler outlives its stream, so in the test process the default action
    /// could not show, and other tests' signals would be counted.
    #[test]
    fn a_hangup_while_loading_is_one_reload_once_ready() {
        const NAME: &str = "tests::a_hangup_while_loading_is_one_reload_once_ready";
        if std::env::var_os("KEKKAI_HANGUP_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([NAME, "--exact", "--nocapture", "--test-threads=1"])
                .env("KEKKAI_HANGUP_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success(), "child: {status}");
            return;
        }
        let (runtime, mut hangup, ()) = super::start(|| {
            // SAFETY: kill(2) on our own pid, no memory involved.
            assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGHUP) }, 0);
            std::thread::sleep(Duration::from_millis(200));
            Ok(())
        })
        .unwrap();
        // Ready: every daemon runs one reload per item of the stream.
        runtime.block_on(async {
            let first = tokio::time::timeout(Duration::from_secs(5), hangup.recv()).await;
            assert_eq!(first, Ok(Some(())), "the start-up SIGHUP was lost");
            let second = tokio::time::timeout(Duration::from_millis(500), hangup.recv()).await;
            assert!(second.is_err(), "the start-up SIGHUP was read twice");
        });
    }

    /// Spec §4.1 on a lighthouse: keys added, removed and renamed.
    #[test]
    fn reload_named_peers() {
        let key = |b: u8| StaticKey::from_bytes([b; 32]).clamped().public();
        let info = |name: &str| PeerInfo {
            name: name.into(),
            ..PeerInfo::default()
        };
        let node = Node::lighthouse(
            StaticKey::from_bytes([9; 32]).clamped(),
            vec![key(1), key(2)],
        );
        let mut state = State::new(
            node,
            HashMap::from([(key(1), info("a")), (key(2), info("b"))]),
        );
        let next = HashMap::from([(key(2), info("b2")), (key(3), info("c"))]);
        assert_eq!(state.reload_named_peers(next), (1, 1, 1));
        assert!(state.node.status(&key(1)).is_none());
        assert!(state.node.status(&key(3)).is_some());
        assert_eq!(state.peers[&key(2)].name, "b2");
    }

    /// R7, spec §4.1: a key removed, even if listed again before the next tick, or moved to
    /// another role, forgets its log history (its next `handshake-completed` compares with
    /// zero counters, like its fresh core state); a kept key keeps it, and the history never
    /// outgrows the lists.
    #[test]
    fn a_reload_resets_the_log_history() {
        let key = |b: u8| StaticKey::from_bytes([b; 32]).clamped().public();
        let (a, b) = (key(1), key(2));
        let info = |name: &str| PeerInfo {
            name: name.into(),
            ..PeerInfo::default()
        };
        let both = HashMap::from([(a, info("a")), (b, info("b"))]);
        let only_b = HashMap::from([(b, info("b"))]);
        let node = Node::new(StaticKey::from_bytes([9; 32]).clamped(), Vec::new());
        let mut state = State::new(node, HashMap::new());
        state.set_lists(both.clone(), Vec::new(), Vec::new());
        let busy = |state: &mut State, k| {
            let mut seen = super::Seen::default();
            seen.counters.handshakes_initiated = 3;
            state.seen.insert(k, seen);
        };
        busy(&mut state, a);
        busy(&mut state, b);
        state.set_lists(only_b.clone(), Vec::new(), Vec::new());
        state.set_lists(both.clone(), Vec::new(), Vec::new());
        assert!(!state.seen.contains_key(&a), "removed and re-added");
        assert_eq!(state.seen[&b].counters.handshakes_initiated, 3, "kept");
        busy(&mut state, a);
        state.set_lists(only_b.clone(), vec![(a, "l".into())], Vec::new());
        assert!(!state.seen.contains_key(&a), "peer to lighthouse");
        busy(&mut state, a);
        state.set_lists(only_b.clone(), Vec::new(), vec![(a, "r".into())]);
        assert!(!state.seen.contains_key(&a), "lighthouse to relay");
        state.reload_named_peers(HashMap::new());
        assert!(state.seen.is_empty(), "a lighthouse's or relay's reload");
    }

    #[test]
    fn load_key() {
        let dir = std::env::temp_dir().join(format!("kekkai-io-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        // keygen.json "rfc7748 alice", with the trailing newline keygen writes.
        std::fs::write(&path, "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=\n").unwrap();
        let key = super::load_key(&path).unwrap();
        assert_eq!(
            kekkai_core::keys::public_key_to_text(&key.public()),
            "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
        );
        std::fs::write(&path, "secret-looking garbage").unwrap();
        let Err(err) = super::load_key(&path) else {
            panic!("garbage accepted")
        };
        let err = err.to_string();
        assert!(!err.contains("garbage"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
