//! §4.1 reload: `set_peers`, `set_lighthouses`, `set_relays` and `set_lighthouse_peers` as a
//! diff of the configured list.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::relay::{Net, ep, key, relay_net, wall};
use crate::inner::Inner;
use crate::keys::PublicKey;
use crate::node::{LighthouseConfig, Node, Path, PeerConfig};
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

/// A lighthouse forgets a removed node's registration and query budget at once; a relay
/// its sender counters and bucket. Both are populated first, and inspected directly.
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
    let now = Duration::from_secs(3);
    let query = Inner::LighthouseQuery { pubkey: b.public() }.encode();
    let out = net.parties[0]
        .0
        .send_inner_to(now, wall(now), l.public(), &query);
    net.run(now, 0, out);
    let registered = |net: &Net| -> Vec<PublicKey> {
        net.parties[2]
            .0
            .registrations(now)
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    };
    assert_eq!(registered(&net).len(), 2);
    assert_eq!(
        net.parties[2].0.per_key_state().0,
        [a.public()],
        "a's budget"
    );
    net.parties[2].0.set_lighthouse_peers(vec![b.public()]);
    assert_eq!(registered(&net), [b.public()]);
    assert!(net.parties[2].0.per_key_state().0.is_empty(), "budget gone");

    let (mut net, a, b) = relay_net(Some(1_000_000));
    let rk = key(3).public();
    let junk = vec![0xee; 64];
    let forward = Inner::RelayForward {
        to: b,
        payload: &junk,
    }
    .encode();
    let out = net.parties[0].0.send_inner_to(T, wall(T), rk, &forward);
    net.run(T, 0, out);
    let relay = &mut net.parties[2].0;
    assert_eq!(relay.per_key_state().1, [a], "a's counters and bucket");
    relay.set_lighthouse_peers(vec![b]);
    assert!(relay.per_key_state().1.is_empty(), "sender state gone");
    relay.set_lighthouse_peers(vec![a, b]);
    let fresh = relay.relay_senders();
    assert!(
        fresh.iter().all(|(_, c)| *c == Default::default()),
        "{fresh:?}"
    );
}

/// R1, §4.1: a peer that loses an address drops its staged packets. A stages a packet for
/// 10.0.0.2 (B) and initiates; B's message 2 is held while a reload gives 10.0.0.2 to C and
/// 10.0.0.9 to B. Released, it completes the handshake but carries no staged payload to B.
#[test]
fn a_lost_address_drops_the_staged_packets() {
    for owner in [Some(3), None] {
        let mut a = Node::new(key(1), vec![peer(2, 2)]);
        let mut b = Node::new(key(2), vec![peer(1, 1)]);
        let packet = udp(1, 2);
        let m1 = a.send_packet(T, wall(T), &packet).unwrap().datagrams;
        assert_eq!(a.status(&key(2).public()).unwrap().staged_packets, 1);
        let m2 = b
            .handle_datagram(T, wall(T), ep(1, 4802), &m1[0].1)
            .unwrap();
        let moved = PeerConfig {
            addresses: vec![v4(9)],
            ..peer(2, 2)
        };
        a.set_peers(
            [moved]
                .into_iter()
                .chain(owner.map(|k| peer(k, 2)))
                .collect(),
        );
        let status = a.status(&key(2).public()).unwrap();
        assert!(
            status.handshake_in_flight && status.staged_packets == 0,
            "{status:?}"
        );
        let out = a
            .handle_datagram(T, wall(T), ep(2, 4802), &m2.datagrams[0].1)
            .unwrap();
        assert!(
            a.status(&key(2).public()).unwrap().current,
            "handshake kept"
        );
        for (_, d) in out.datagrams {
            let got = b.handle_datagram(T, wall(T), ep(1, 4802), &d).unwrap();
            assert!(!got.packets.contains(&packet), "staged packet reached B");
        }
    }
}

/// R3, §4.1: a key that leaves the relay list (to the peer or the lighthouse list) no
/// longer relays. A↔B is relayed through R; after the move, and once A's new session with R
/// is up, A's traffic for B is never wrapped in a `relay_forward` to R.
#[test]
fn a_former_relay_relays_nothing() {
    for to_peer in [true, false] {
        let (mut net, a, b) = relay_net(None);
        let rk = key(3).public();
        let mut now = T;
        let out = net.parties[0]
            .0
            .send_packet(now, wall(now), &udp(1, 2))
            .unwrap();
        net.run(now, 0, out.datagrams);
        while net.parties[0].0.status(&b).unwrap().path != Some(Path::Relayed(rk)) {
            assert!(now < Duration::from_secs(30), "no relayed session");
            now += Duration::from_millis(500);
            net.tick(now);
        }
        let b_config = PeerConfig {
            public_key: b,
            addresses: vec![v4(2)],
            ..PeerConfig::default()
        };
        let node = &mut net.parties[0].0;
        node.set_relays(Vec::new());
        if to_peer {
            let r = PeerConfig {
                public_key: rk,
                addresses: vec![v4(3)],
                endpoints: vec![ep(3, 4801)],
                ..PeerConfig::default()
            };
            node.set_peers(vec![b_config, r]);
            let out = node.send_packet(now, wall(now), &udp(1, 3)).unwrap();
            net.run(now, 0, out.datagrams);
        } else {
            node.set_lighthouses(vec![LighthouseConfig {
                public_key: rk,
                endpoints: vec![ep(3, 4801)],
            }]);
            net.tick(now);
        }
        assert!(
            net.parties[0].0.status(&rk).unwrap().current,
            "R's new session"
        );
        let forwarded = |net: &Net| {
            let senders = net.parties[2].0.relay_senders();
            senders
                .iter()
                .find(|(k, _)| *k == a)
                .unwrap()
                .1
                .forwarded_packets
        };
        let before = forwarded(&net);
        let out = net.parties[0]
            .0
            .send_packet(now, wall(now), &udp(1, 2))
            .unwrap();
        net.run(now, 0, out.datagrams);
        assert_eq!(forwarded(&net), before, "relayed through a former relay");
        // The direct retry (§12.3) does not wait `DIRECT_RETRY_INTERVAL`.
        let later = now + crate::REKEY_TIMEOUT + Duration::from_secs(1);
        net.tick(later);
        assert!(net.parties[0].0.status(&b).unwrap().handshake_in_flight);
    }
}

/// The deadline cache (§9): a timer set, shortened or removed after `next_deadline` ran is
/// what the next call returns.
#[test]
fn next_deadline_follows_later_changes() {
    let mut a = Node::new(key(1), vec![peer(2, 2)]);
    assert_eq!(a.next_deadline(), None);
    a.send_packet(T, wall(T), &udp(1, 2)).expect("routed");
    let retransmit = a.next_deadline().expect("message 1 in flight");
    assert!(retransmit > T + crate::REKEY_TIMEOUT / 2, "{retransmit:?}");
    // A lighthouse with no session: its handshake is due at once (§9 last row).
    a.set_lighthouses(vec![LighthouseConfig {
        public_key: key(9).public(),
        endpoints: vec![ep(9, 4802)],
    }]);
    assert_eq!(a.next_deadline(), Some(Duration::ZERO));
    a.set_lighthouses(Vec::new());
    assert_eq!(a.next_deadline(), Some(retransmit));
}
