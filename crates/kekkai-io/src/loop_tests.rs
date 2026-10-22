//! Two IO loops over loopback UDP, each with an in-memory tunnel: a packet written into one
//! tunnel comes out of the other, and the status counters move (ADR 0004, 0020).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kekkai_core::keys::StaticKey;
use kekkai_core::node::{Node, PeerConfig};
use tokio::net::UnixDatagram;

use crate::{PeerInfo, State, Tunnel, udp};

impl Tunnel for UnixDatagram {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        UnixDatagram::recv(self, buf).await
    }

    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        UnixDatagram::send(self, packet).await.map(drop)
    }
}

fn key(seed: u8) -> StaticKey {
    StaticKey::from_bytes([seed; 32]).clamped()
}

fn ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let len = (20 + payload.len()) as u16;
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

#[tokio::test(flavor = "current_thread")]
async fn two_loops_carry_a_packet_each_way() {
    let keys = [key(1), key(2)];
    let addrs: [IpAddr; 2] = ["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
    let sockets = [udp::bind(0).unwrap(), udp::bind(0).unwrap()];
    let ports: Vec<u16> = sockets
        .iter()
        .map(|s| s.local_addr().unwrap().port())
        .collect();
    let mut outsides = Vec::new();
    let mut states = Vec::new();
    for (i, socket) in sockets.into_iter().enumerate() {
        let other = 1 - i;
        let peer_key = keys[other].public();
        let endpoint: SocketAddr = format!("127.0.0.1:{}", ports[other]).parse().unwrap();
        let node = Node::new(
            keys[i].clone(),
            vec![PeerConfig {
                public_key: peer_key,
                addresses: vec![addrs[other]],
                allow_inbound: vec![kekkai_core::firewall::Rule::Any],
                endpoints: vec![endpoint.into()],
            }],
        );
        let info = PeerInfo {
            name: format!("host{other}"),
            ..PeerInfo::default()
        };
        let state = Arc::new(Mutex::new(State::new(
            node,
            HashMap::from([(peer_key, info)]),
        )));
        let (inside, outside) = UnixDatagram::pair().unwrap();
        tokio::spawn(crate::run(state.clone(), socket, inside, 1280));
        outsides.push(outside);
        states.push(state);
    }
    let timeout = Duration::from_secs(5);
    for (from, to) in [(0, 1), (1, 0)] {
        let src = match addrs[from] {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => unreachable!(),
        };
        let dst = match addrs[to] {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => unreachable!(),
        };
        let packet = ipv4(src, dst, b"hello through the overlay");
        outsides[from].send(&packet).await.unwrap();
        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(timeout, outsides[to].recv(&mut buf))
            .await
            .expect("packet delivered within 5 s")
            .unwrap();
        assert_eq!(&buf[..n], &packet[..]);
    }
    for (i, state) in states.iter().enumerate() {
        let state = state.lock().unwrap();
        let peer = keys[1 - i].public();
        let status = state.node.status(&peer).unwrap();
        assert!(status.current && status.last_handshake.is_some());
        assert!(status.counters.rx_packets > 0 && status.counters.tx_packets > 0);
        let endpoint = status.endpoint.expect("learnt from the peer");
        assert_eq!(endpoint.display().port(), ports[1 - i]);
    }
}

/// Two node loops that know no endpoint of each other find each other through a lighthouse
/// loop (spec §13), all on loopback, and carry a packet.
#[tokio::test(flavor = "current_thread")]
async fn discovery_through_a_lighthouse_loop() {
    use kekkai_core::node::LighthouseConfig;
    let keys = [key(1), key(2)];
    let lighthouse_key = key(3);
    let addrs: [IpAddr; 2] = ["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
    let lh_socket = udp::bind(0).unwrap();
    let lh_port = lh_socket.local_addr().unwrap().port();
    let lh_node = Node::lighthouse(
        lighthouse_key.clone(),
        keys.iter().map(StaticKey::public).collect(),
    );
    let lh_state = Arc::new(Mutex::new(State::new(lh_node, HashMap::new())));
    tokio::spawn(crate::run(
        lh_state.clone(),
        lh_socket,
        crate::NoTunnel,
        1280,
    ));
    let lighthouse = LighthouseConfig {
        public_key: lighthouse_key.public(),
        endpoints: vec![
            format!("127.0.0.1:{lh_port}")
                .parse::<SocketAddr>()
                .unwrap()
                .into(),
        ],
    };
    let mut outsides = Vec::new();
    let mut states = Vec::new();
    for i in 0..2 {
        let other = 1 - i;
        let mut node = Node::new(
            keys[i].clone(),
            vec![PeerConfig {
                public_key: keys[other].public(),
                addresses: vec![addrs[other]],
                allow_inbound: vec![kekkai_core::firewall::Rule::Any],
                endpoints: vec![],
            }],
        );
        node.set_lighthouses(vec![lighthouse.clone()]);
        let state = Arc::new(Mutex::new(State::new(node, HashMap::new())));
        let (inside, outside) = UnixDatagram::pair().unwrap();
        tokio::spawn(crate::run(
            state.clone(),
            udp::bind(0).unwrap(),
            inside,
            1280,
        ));
        outsides.push(outside);
        states.push(state);
    }
    // Both registered.
    for _ in 0..50 {
        if lh_state
            .lock()
            .unwrap()
            .node
            .registrations(crate::clock::monotonic())
            .len()
            == 2
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let packet = ipv4(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        b"found through the lighthouse",
    );
    outsides[0].send(&packet).await.unwrap();
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(5), outsides[1].recv(&mut buf))
        .await
        .expect("packet delivered within 5 s")
        .unwrap();
    assert_eq!(&buf[..n], &packet[..]);
    let status = states[0]
        .lock()
        .unwrap()
        .node
        .status(&keys[1].public())
        .unwrap();
    assert!(status.current && status.endpoint.is_some());
    let counters = lh_state.lock().unwrap().node.lighthouse_counters();
    assert!(counters.queries_known >= 1 && counters.punches >= 1);
}

/// Codex R1 on v0.6 finding 4: the loop collects its local endpoints at least once a second
/// even while datagrams arrive more often than that; each one used to restart a one-second
/// sleep, so the poll (and the tick) waited for the next core deadline.
#[tokio::test(flavor = "current_thread")]
async fn local_endpoints_are_polled_under_continuous_traffic() {
    let socket = udp::bind(0).unwrap();
    let port = socket.local_addr().unwrap().port();
    let mut state = State::new(Node::new(key(1), vec![]), HashMap::new());
    state.locals = Some(crate::Locals {
        listen_port: port,
        overlay: vec![],
    });
    let state = Arc::new(Mutex::new(state));
    tokio::spawn(crate::run(state.clone(), socket, crate::NoTunnel, 1280));
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let to: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    // Not on this host: only a poll replaces it.
    let marker: SocketAddr = "192.0.2.99:1".parse().unwrap();
    // Let the loop start and run its first poll, then plant the marker; this tick consumes
    // the change it makes, so that no zero deadline wakes the loop: only a poll removes it.
    tokio::time::sleep(Duration::from_millis(100)).await;
    {
        let node = &mut state.lock().unwrap().node;
        node.set_local_endpoints(vec![marker.into()]);
        let _ = node.tick(crate::clock::monotonic(), crate::clock::wall());
    }
    for _ in 0..150 {
        // Not a kekkai datagram: dropped, but it wakes the loop every 20 ms.
        sender.send_to(b"noise", to).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let state = state.lock().unwrap();
    assert!(
        state.drops.values().sum::<u64>() >= 100,
        "{:?}",
        state.drops
    );
    assert!(
        !state.node.local_endpoints().contains(&marker.into()),
        "no poll in 3 s of traffic"
    );
}

/// Every field of every event emitted while `f` runs, as `name=value` lines.
fn capture_events(f: impl FnOnce()) -> Vec<String> {
    use std::fmt::{Debug, Write as _};
    use tracing::field::Field;
    use tracing::{Event, Metadata, span};

    struct Capture(Arc<Mutex<Vec<String>>>);
    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }
        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut line = String::new();
            event.record(&mut |field: &Field, value: &dyn Debug| {
                let _ = write!(line, "{field}={value:?} ");
            });
            self.0.lock().unwrap().push(line);
        }
        fn enter(&self, _: &span::Id) {}
        fn exit(&self, _: &span::Id) {}
    }
    let lines = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Capture(lines.clone()), f);
    let lines = lines.lock().unwrap().clone();
    lines
}

/// ADR 0012, 0030 (review finding L3): a failed send names its destination on a node and
/// never on a lighthouse, whatever the log level.
#[test]
fn a_lighthouse_never_logs_a_send_destination() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for log_peers in [true, false] {
        let lines = capture_events(|| {
            runtime.block_on(async {
                let socket = udp::bind(0).unwrap();
                let to: SocketAddr = "127.0.0.1:9".parse().unwrap();
                // Larger than any UDP datagram: the send fails on every platform.
                crate::send_datagrams(&socket, vec![(to.into(), vec![0; 70_000])], log_peers).await;
            });
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("udp-send-failed"), "{lines:?}");
        assert_eq!(lines[0].contains("127.0.0.1"), log_peers, "{lines:?}");
    }
}
