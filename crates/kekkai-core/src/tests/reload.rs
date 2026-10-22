//! §4.1 reload: `set_peers`, `set_lighthouses`, `set_relays` and `set_lighthouse_peers` as a
//! diff of the configured list.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::relay::{Net, ep, key, wall};
use crate::keys::PublicKey;
use crate::node::{LighthouseConfig, Node, PeerConfig};
use crate::wire::DropReason;

const T: Duration = Duration::from_secs(1);

fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

fn peer(k: u8, last: u8) -> PeerConfig {
    PeerConfig {
        public_key: key(k).public(),
        addresses: vec![v4(last)],
        endpoints: vec![ep(last, 4802)],
        ..PeerConfig::default()
    }
}

/// A UDP datagram 10.0.0.`from`:4000 → 10.0.0.`to`:5000 with a 4-byte body.
fn udp(from: u8, to: u8) -> Vec<u8> {
    let mut p = vec![
        0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, from, 10, 0, 0, to,
    ];
    p.extend_from_slice(&4000u16.to_be_bytes());
    p.extend_from_slice(&5000u16.to_be_bytes());
    p.extend_from_slice(&[0, 12, 0, 0, 1, 2, 3, 4]);
    p
}

/// A (0) lists B; B (1) and C (2) list A; all on one network. A and B have a session.
fn net() -> Net {
    let a = Node::new(key(1), vec![peer(2, 2)]);
    let b = Node::new(key(2), vec![peer(1, 1)]);
    let c = Node::new(key(3), vec![peer(1, 1)]);
    let mut net = Net::new(vec![(a, ep(1, 4802)), (b, ep(2, 4802)), (c, ep(3, 4802))]);
    send(&mut net, 0, 2);
    assert!(at(&net, 0, 2).unwrap().current);
    net
}

fn send(net: &mut Net, from: usize, to: u8) {
    let packet = udp(from as u8 + 1, to);
    let out = net.parties[from]
        .0
        .send_packet(T, wall(T), &packet)
        .expect("routed");
    net.run(T, from, out.datagrams);
}

fn at(net: &Net, party: usize, k: u8) -> Option<crate::node::PeerStatus> {
    net.parties[party].0.status(&key(k).public())
}

fn last_drop(net: &Net) -> Option<DropReason> {
    net.outputs
        .iter()
        .rev()
        .find_map(|(_, r)| r.as_ref().err().copied())
}

/// An unchanged peer keeps its session and receiver index, an added one completes a
/// handshake, a removed one is refused and loses its indices.
#[test]
fn a_reload_applies_the_diff_of_the_peer_list() {
    let mut net = net();
    let index = at(&net, 0, 2).unwrap().current_index;
    assert!(index.is_some());
    let handshakes = at(&net, 0, 2).unwrap().counters.handshakes_initiated;

    net.parties[0].0.set_peers(vec![peer(2, 2), peer(3, 3)]);
    let b = at(&net, 0, 2).unwrap();
    assert_eq!(b.current_index, index, "unchanged peer: same session");
    assert_eq!(b.counters.handshakes_initiated, handshakes);
    send(&mut net, 2, 1);
    assert!(
        at(&net, 0, 3).unwrap().current,
        "added peer: handshake accepted"
    );
    send(&mut net, 0, 2);
    assert_eq!(at(&net, 0, 2).unwrap().current_index, index);

    net.parties[0].0.set_peers(vec![peer(3, 3)]);
    assert!(at(&net, 0, 2).is_none());
    assert_eq!(
        net.parties[0].0.send_packet(T, wall(T), &udp(1, 2)),
        Err(DropReason::NoRoute)
    );
    net.outputs.clear();
    send(&mut net, 1, 1);
    assert_eq!(
        last_drop(&net),
        Some(DropReason::UnknownIndex),
        "indices released"
    );
    let later = T + Duration::from_secs(200);
    let out = net.parties[1]
        .0
        .send_packet(later, wall(later), &udp(2, 1))
        .unwrap();
    net.outputs.clear();
    net.run(later, 1, out.datagrams);
    assert_eq!(last_drop(&net), Some(DropReason::IdentityRejected));
}

/// A changed peer keeps its sessions; its routes follow the new addresses and the firewall
/// forgets the flows of the address it lost, not those of an unchanged one.
#[test]
fn a_changed_peer_keeps_its_session() {
    let mut net = net();
    let index = at(&net, 0, 2).unwrap().current_index;
    assert_eq!(
        net.parties[0].0.firewall_status().entries,
        1,
        "A's flow to B"
    );

    net.parties[0].0.set_peers(vec![peer(2, 2)]);
    assert_eq!(
        net.parties[0].0.firewall_status().entries,
        1,
        "unchanged: kept"
    );

    let moved = PeerConfig {
        addresses: vec![v4(9)],
        allow_inbound: vec!["udp/5000".parse().unwrap()],
        ..peer(2, 2)
    };
    net.parties[0].0.set_peers(vec![moved]);
    assert_eq!(at(&net, 0, 2).unwrap().current_index, index);
    assert_eq!(
        net.parties[0].0.firewall_status().entries,
        0,
        "10.0.0.2 left"
    );
    assert_eq!(
        net.parties[0].0.send_packet(T, wall(T), &udp(1, 2)),
        Err(DropReason::NoRoute)
    );
    assert!(net.parties[0].0.send_packet(T, wall(T), &udp(1, 9)).is_ok());
    // B still sends from 10.0.0.2: no longer its address on A (§11).
    net.outputs.clear();
    send(&mut net, 1, 1);
    let out = net.outputs.iter().find(|(i, _)| *i == 0).unwrap();
    assert_eq!(
        out.1.as_ref().unwrap().dropped,
        Some(DropReason::SourceNotPeer)
    );
}

/// A key moving from the peer list to the lighthouse list starts afresh.
#[test]
fn a_role_change_is_a_removal_and_an_addition() {
    let mut net = net();
    let b = key(2).public();
    net.parties[0].0.set_peers(Vec::new());
    net.parties[0].0.set_lighthouses(vec![LighthouseConfig {
        public_key: b,
        endpoints: vec![ep(2, 4802)],
    }]);
    let status = at(&net, 0, 2).unwrap();
    assert!(status.current_index.is_none() && status.counters.handshakes_initiated == 0);

    // Back: the order of the calls does not matter.
    net.parties[0].0.set_peers(vec![peer(2, 2)]);
    net.parties[0].0.set_lighthouses(Vec::new());
    assert!(at(&net, 0, 2).is_some_and(|s| s.sessions == 0));
}

/// A lighthouse forgets a removed node's registration at once; a relay its sender state.
#[test]
fn lighthouse_and_relay_forget_removed_nodes() {
    let (a, b, l) = (key(1), key(2), key(3));
    let lighthouse = LighthouseConfig {
        public_key: l.public(),
        endpoints: vec![ep(3, 4800)],
    };
    let mut na = Node::new(a.clone(), vec![peer(2, 2)]);
    let mut nb = Node::new(b.clone(), vec![peer(1, 1)]);
    na.set_lighthouses(vec![lighthouse.clone()]);
    nb.set_lighthouses(vec![lighthouse]);
    let nl = Node::lighthouse(l.clone(), vec![a.public(), b.public()]);
    let mut net = Net::new(vec![
        (na, ep(1, 4802)),
        (nb, ep(2, 4802)),
        (nl, ep(3, 4800)),
    ]);
    for t in 0..3 {
        net.tick(Duration::from_secs(t));
    }
    let registered = |net: &Net| -> Vec<PublicKey> {
        let now = Duration::from_secs(3);
        net.parties[2]
            .0
            .registrations(now)
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    };
    assert_eq!(registered(&net).len(), 2);
    net.parties[2].0.set_lighthouse_peers(vec![b.public()]);
    assert_eq!(registered(&net), [b.public()]);

    let mut relay = Node::relay(l, vec![a.public(), b.public()], None);
    assert_eq!(relay.relay_senders().len(), 2);
    relay.set_lighthouse_peers(vec![a.public()]);
    assert_eq!(relay.relay_senders(), [(a.public(), Default::default())]);
}
