//! The node's `/metrics` exposition (ADR 0019, amended 2026-10-20), served by
//! `kekkai_io::metrics::serve`, following masu's metric convention.

use std::fmt::Write as _;

use kekkai_io::State;
use kekkai_io::metrics::{drops, family, label};

/// The exposition. Series: 1 + 6 per peer + one per drop reason seen (at most 24).
pub fn render(state: &State) -> String {
    let mut peers: Vec<_> = state
        .peers
        .iter()
        .filter_map(|(key, info)| Some((label(&info.name), state.node.status(key)?)))
        .collect();
    peers.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = String::new();
    family(
        &mut out,
        "kekkai_build_info",
        "gauge",
        "Version of this kekkai-node.",
    );
    let _ = writeln!(
        out,
        "kekkai_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
    family(
        &mut out,
        "kekkai_peer_path",
        "gauge",
        "1 when the peer is reached over this path.",
    );
    for (peer, s) in &peers {
        let path = kekkai_io::path_name(s);
        let _ = writeln!(
            out,
            "kekkai_peer_path{{peer=\"{peer}\",via=\"direct\"}} {}\n\
             kekkai_peer_path{{peer=\"{peer}\",via=\"relayed\"}} {}",
            u8::from(path == "direct"),
            u8::from(path == "relayed")
        );
    }
    family(
        &mut out,
        "kekkai_handshakes_total",
        "counter",
        "Handshakes completed (either role) or abandoned after the last retransmit.",
    );
    for (peer, s) in &peers {
        let c = s.counters;
        let ok = c.handshakes_initiated + c.handshakes_responded;
        let _ = writeln!(
            out,
            "kekkai_handshakes_total{{peer=\"{peer}\",result=\"ok\"}} {ok}\n\
             kekkai_handshakes_total{{peer=\"{peer}\",result=\"timeout\"}} {}",
            c.handshake_timeouts
        );
    }
    family(
        &mut out,
        "kekkai_rx_bytes_total",
        "counter",
        "Underlay bytes received from the peer.",
    );
    for (peer, s) in &peers {
        let _ = writeln!(
            out,
            "kekkai_rx_bytes_total{{peer=\"{peer}\"}} {}",
            s.counters.rx_bytes
        );
    }
    family(
        &mut out,
        "kekkai_tx_bytes_total",
        "counter",
        "Underlay bytes sent to the peer.",
    );
    for (peer, s) in &peers {
        let _ = writeln!(
            out,
            "kekkai_tx_bytes_total{{peer=\"{peer}\"}} {}",
            s.counters.tx_bytes
        );
    }
    drops(&mut out, state);
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use kekkai_core::keys::StaticKey;
    use kekkai_core::node::{Node, PeerConfig};
    use kekkai_core::wire::DropReason;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    use kekkai_io::PeerInfo;

    use super::*;

    fn state() -> State {
        let peer = StaticKey::from_bytes([2; 32]).clamped().public();
        let config = PeerConfig {
            public_key: peer,
            addresses: vec!["10.0.0.2".parse().unwrap()],
            ..PeerConfig::default()
        };
        let node = Node::new(StaticKey::from_bytes([1; 32]).clamped(), vec![config]);
        let info = PeerInfo {
            name: "node-\"b\"".into(),
        };
        let mut state = State::new(node, HashMap::from([(peer, info)]));
        state.drops.insert(DropReason::Firewall.as_str(), 77);
        state
    }

    #[test]
    fn exposition() {
        let text = render(&state());
        let version = env!("CARGO_PKG_VERSION");
        let want = format!(
            "# HELP kekkai_build_info Version of this kekkai-node.
# TYPE kekkai_build_info gauge
kekkai_build_info{{version=\"{version}\"}} 1
# HELP kekkai_peer_path 1 when the peer is reached over this path.
# TYPE kekkai_peer_path gauge
kekkai_peer_path{{peer=\"node-\\\"b\\\"\",via=\"direct\"}} 0
kekkai_peer_path{{peer=\"node-\\\"b\\\"\",via=\"relayed\"}} 0
# HELP kekkai_handshakes_total Handshakes completed (either role) or abandoned after the last retransmit.
# TYPE kekkai_handshakes_total counter
kekkai_handshakes_total{{peer=\"node-\\\"b\\\"\",result=\"ok\"}} 0
kekkai_handshakes_total{{peer=\"node-\\\"b\\\"\",result=\"timeout\"}} 0
# HELP kekkai_rx_bytes_total Underlay bytes received from the peer.
# TYPE kekkai_rx_bytes_total counter
kekkai_rx_bytes_total{{peer=\"node-\\\"b\\\"\"}} 0
# HELP kekkai_tx_bytes_total Underlay bytes sent to the peer.
# TYPE kekkai_tx_bytes_total counter
kekkai_tx_bytes_total{{peer=\"node-\\\"b\\\"\"}} 0
# HELP kekkai_dropped_packets_total Datagrams and tunnel packets dropped, by kekkai-core DropReason.
# TYPE kekkai_dropped_packets_total counter
kekkai_dropped_packets_total{{reason=\"firewall\"}} 77
"
        );
        assert_eq!(text, want);
    }

    #[test]
    fn http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(state()));
        std::thread::spawn(move || kekkai_io::metrics::serve(listener, &state, render));
        let get = |request: &str| {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(request.as_bytes()).unwrap();
            let mut reply = String::new();
            s.read_to_string(&mut reply).unwrap();
            reply
        };
        let reply = get("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
        assert!(reply.contains("text/plain; version=0.0.4; charset=utf-8"));
        assert!(reply.ends_with("{reason=\"firewall\"} 77\n"), "{reply}");
        assert!(get("GET / HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 404"));
    }
}
