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
use kekkai_core::node::{Node, PathFailure, PeerStatus};
use kekkai_core::peer::Counters;
use kekkai_core::wire::DropReason;
use tracing::field::display;
use tracing::{debug, info, trace};

/// ADR 0004: the loop never sleeps longer than this, so that a suspend is noticed within a
/// second of resuming and every deadline that passed meanwhile runs at once.
pub const MAX_SLEEP: Duration = Duration::from_secs(1);

/// The IO layer's name for a peer, for logs, metrics and status (ADR 0019).
#[derive(Clone, Debug, Default)]
pub struct PeerInfo {
    pub name: String,
}

/// What the node collects for `lighthouse_register` (spec §13.1).
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
    /// Local endpoints to collect at every tick, when a lighthouse is configured.
    pub locals: Option<Locals>,
    /// `false` on a lighthouse: it logs aggregate counters only, never per-peer events
    /// (ADR 0012, 0019).
    pub log_peers: bool,
    /// Datagrams and tunnel packets the core dropped, by `DropReason` name (ADR 0019).
    pub drops: BTreeMap<&'static str, u64>,
}

impl State {
    pub fn new(node: Node, peers: HashMap<PublicKey, PeerInfo>) -> Self {
        Self {
            node,
            peers,
            lighthouses: Vec::new(),
            locals: None,
            log_peers: true,
            drops: BTreeMap::new(),
        }
    }

    fn count_drop(&mut self, reason: DropReason) {
        *self.drops.entry(reason.as_str()).or_default() += 1;
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

/// What `log_events` remembers of a peer between two ticks.
#[derive(Default)]
struct Seen {
    current: bool,
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
    let mut seen: HashMap<PublicKey, Seen> = HashMap::new();
    let lock = || state.lock().expect("no panic while holding the state");
    let log_peers = lock().log_peers;
    loop {
        let next = lock().node.next_deadline();
        let wake = next
            .map_or(MAX_SLEEP, |d| d.saturating_sub(clock::monotonic()))
            .min(MAX_SLEEP);
        let output = tokio::select! {
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
            () = tokio::time::sleep(wake) => {
                let mut guard = lock();
                if let Some(locals) = guard.locals.clone() {
                    // §13.1: polled at every tick, compared by the core at keepalive ticks.
                    match ifaddrs::local_endpoints(locals.listen_port, &locals.overlay) {
                        Ok(found) => guard.node.set_local_endpoints(found),
                        Err(e) => debug!(event = "local-addresses-failed", error = %e),
                    }
                }
                let output = guard.node.tick(clock::monotonic(), clock::wall());
                log_events(&guard, &mut seen);
                drop(guard);
                output
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

/// ADR 0019 `info` events, checked at every tick (at least once a second): handshake
/// completed, path change, endpoint change, direct-path failure, lighthouse session state.
fn log_events(state: &State, seen: &mut HashMap<PublicKey, Seen>) {
    if !state.log_peers {
        return;
    }
    for (key, peer) in &state.peers {
        let Some(status) = state.node.status(key) else {
            continue;
        };
        let (current, c) = (status.current, status.counters);
        let now = Seen {
            current,
            counters: c,
            endpoint: status.endpoint,
            failure: status.last_direct_path_failure,
            state: "",
        };
        let b = seen.insert(*key, now).unwrap_or_default();
        // shortcut: two handshakes within one tick log once, initiator wins; counters are exact.
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
        if current != b.current {
            let (from, to, reason) = if current {
                ("none", "direct", "handshake-completed")
            } else {
                ("direct", "none", "session-expired")
            };
            info!(event = "path-change", peer = %peer.name, from, to, reason);
        }
    }
    for (key, endpoint) in &state.lighthouses {
        let Some(status) = state.node.status(key) else {
            continue;
        };
        let to = session_state(&status);
        let entry = seen.entry(*key).or_insert_with(|| Seen {
            state: "down",
            ..Seen::default()
        });
        if entry.state != to {
            info!(event = "lighthouse-session-change", lighthouse = %endpoint, from = entry.state, to);
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

#[cfg(test)]
mod loop_tests;

#[cfg(test)]
mod tests {
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
