//! kekkai-io: the IO layer around `kekkai-core` (ADR 0004, 0023): configuration and key
//! loading, the UDP socket, the TUN device (`tun` feature, node only: Linux TUN, macOS
//! `utun`) and the loop that drives the core's `Node`.

pub mod clock;
pub mod config;
pub mod mss;
pub mod systemd;
#[cfg(all(feature = "tun", target_os = "linux"))]
pub mod tun;
pub mod udp;
#[cfg(all(feature = "tun", target_os = "macos"))]
pub mod utun;

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kekkai_core::keys::{PublicKey, StaticKey};
use kekkai_core::node::{Node, Output};
use kekkai_core::peer::Counters;
use kekkai_core::wire::DropReason;
use tracing::{debug, info, trace};

/// ADR 0004: the loop never sleeps longer than this, so that a suspend is noticed within a
/// second of resuming and every deadline that passed meanwhile runs at once.
pub const MAX_SLEEP: Duration = Duration::from_secs(1);

/// Where the IO layer sends a peer's datagrams (spec §12.2, §12.4), and its name for logs.
#[derive(Clone, Debug, Default)]
pub struct PeerInfo {
    pub name: String,
    /// Static endpoints from the configuration, resolved at start, in socket form.
    pub statics: Vec<SocketAddr>,
    /// Source of the last authenticated datagram from the peer, in socket form.
    pub endpoint: Option<SocketAddr>,
}

impl PeerInfo {
    /// Message 1 goes to every candidate (§12.2): the static endpoints and the last known
    /// one. Everything else goes to the current endpoint, or the static ones before any.
    fn targets(&self, datagram: &[u8]) -> Vec<SocketAddr> {
        let init = datagram.first() == Some(&kekkai_core::wire::TYPE_HANDSHAKE_INIT);
        match self.endpoint {
            Some(current) if !init => vec![current],
            current => {
                let mut all = self.statics.clone();
                all.extend(current.filter(|c| !self.statics.contains(c)));
                all
            }
        }
    }
}

/// What the loop, the control server and the metrics endpoint share.
pub struct State {
    pub node: Node,
    pub peers: HashMap<PublicKey, PeerInfo>,
    /// Datagrams and tunnel packets the core dropped, by `DropReason` name (ADR 0019).
    pub drops: BTreeMap<&'static str, u64>,
}

impl State {
    pub fn new(node: Node, peers: HashMap<PublicKey, PeerInfo>) -> Self {
        Self {
            node,
            peers,
            drops: BTreeMap::new(),
        }
    }

    fn count_drop(&mut self, reason: DropReason) {
        *self.drops.entry(reason.as_str()).or_default() += 1;
    }
}

/// The overlay interface as the loop sees it: one IP packet per call.
#[allow(async_fn_in_trait)] // only used through generics on a current-thread runtime
pub trait Tunnel {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    async fn send(&self, packet: &[u8]) -> io::Result<()>;
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
    let mut seen: HashMap<PublicKey, (bool, Counters)> = HashMap::new();
    let lock = || state.lock().expect("no panic while holding the state");
    loop {
        let next = lock().node.next_deadline();
        let wake = next
            .map_or(MAX_SLEEP, |d| d.saturating_sub(clock::monotonic()))
            .min(MAX_SLEEP);
        let (output, source) = tokio::select! {
            received = socket.recv_from(&mut udp_buf) => {
                let (n, source) = match received {
                    Ok(r) => r,
                    Err(e) => {
                        debug!(event = "udp-receive-failed", error = %e);
                        continue;
                    }
                };
                let mut guard = lock();
                let result = guard
                    .node
                    .handle_datagram(clock::monotonic(), clock::wall(), &udp_buf[..n]);
                match result {
                    Ok(output) => {
                        // Rejected inner content: the transport effects still go out (§8.2).
                        if let Some(reason) = output.dropped {
                            guard.count_drop(reason);
                            trace!(event = "datagram-dropped", reason = reason.as_str());
                        }
                        (output, Some(source))
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
                    Ok(output) => (output, None),
                    Err(reason) => {
                        guard.count_drop(reason);
                        trace!(event = "tunnel-packet-dropped", reason = reason.as_str());
                        continue;
                    }
                }
            }
            () = tokio::time::sleep(wake) => {
                let mut guard = lock();
                let output = guard.node.tick(clock::monotonic(), clock::wall());
                log_events(&guard, &mut seen);
                drop(guard);
                (output, None)
            }
        };
        let sends = route(&mut lock(), &output, source);
        for (to, datagram) in sends {
            if let Err(e) = socket.send_to(&datagram, to).await {
                debug!(event = "udp-send-failed", error = %e, to = %udp::canonical(to));
            }
        }
        for mut packet in output.packets {
            mss::clamp(&mut packet, mtu);
            if let Err(e) = tunnel.send(&packet).await {
                debug!(event = "tunnel-write-failed", error = %e);
            }
        }
    }
}

/// Applies §12.4 for the authenticated sender and maps each datagram to its targets.
fn route(
    state: &mut State,
    output: &Output,
    source: Option<SocketAddr>,
) -> Vec<(SocketAddr, Vec<u8>)> {
    if let (Some(key), Some(source)) = (output.from, source) {
        if let Some(peer) = state.peers.get_mut(&key) {
            if peer.endpoint != Some(source) {
                info!(
                    event = "endpoint-change",
                    peer = %peer.name,
                    endpoint = %udp::canonical(source)
                );
                peer.endpoint = Some(source);
            }
        }
    }
    let mut sends = Vec::new();
    for (key, datagram) in &output.datagrams {
        if let Some(peer) = state.peers.get(key) {
            for to in peer.targets(datagram) {
                sends.push((to, datagram.clone()));
            }
        }
    }
    sends
}

/// ADR 0019 `info` events, checked at every tick (at least once a second): handshake
/// completed, path change and session expiry.
fn log_events(state: &State, seen: &mut HashMap<PublicKey, (bool, Counters)>) {
    for (key, peer) in &state.peers {
        let Some(status) = state.node.status(key) else {
            continue;
        };
        let (current, c) = (status.current, status.counters);
        let (was_current, b) = seen.insert(*key, (current, c)).unwrap_or_default();
        // shortcut: two handshakes within one tick log once, initiator wins; counters are exact.
        let initiated = c.handshakes_initiated != b.handshakes_initiated;
        if initiated || c.handshakes_responded != b.handshakes_responded {
            info!(
                event = "handshake-completed",
                peer = %peer.name,
                endpoint = peer.endpoint.map(|e| display(udp::canonical(e))),
                initiator = initiated
            );
        }
        if current != was_current {
            let (from, to, reason) = if current {
                ("none", "direct", "handshake-completed")
            } else {
                ("direct", "none", "session-expired")
            };
            info!(event = "path-change", peer = %peer.name, from, to, reason);
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
