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
        let node = Node::new(
            keys[i].clone(),
            vec![PeerConfig {
                public_key: peer_key,
                addresses: vec![addrs[other]],
                allow_inbound: vec![kekkai_core::firewall::Rule::Any],
            }],
        );
        let endpoint: SocketAddr = format!("127.0.0.1:{}", ports[other]).parse().unwrap();
        let info = PeerInfo {
            name: format!("host{other}"),
            statics: vec![udp::to_socket(endpoint)],
            endpoint: None,
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
        let endpoint = state.peers[&peer].endpoint.expect("learnt from the peer");
        assert_eq!(udp::canonical(endpoint).port(), ports[1 - i]);
    }
}
