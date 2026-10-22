//! §7.9, §12.3, §12.5 and §12.6 on small deterministic networks: when an attempt sequence,
//! its relay fallback, its deferral and its failure reason start and end.

use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::time::Duration;

use super::relay::{Net, ep, key, relay_net, wall};
use crate::keys::PublicKey;
use crate::node::{LighthouseConfig, Node, Path, PathFailure, PeerConfig};
use crate::wire::{TYPE_DATA, TYPE_HANDSHAKE_INIT};

fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

/// An IPv4/UDP packet from overlay `10.0.0.src` to `10.0.0.dst`.
fn ip_packet(src: u8, dst: u8) -> Vec<u8> {
    let mut p = vec![
        0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, src, 10, 0, 0, dst,
    ];
    p.extend_from_slice(&[0x30, 0x39, 0x30, 0x39, 0, 12, 0, 0, 0, 0, 0, 1]);
    p
}

fn send_packet(net: &mut Net, i: usize, now: Duration, packet: &[u8]) {
    let out = net.parties[i]
        .0
        .send_packet(now, wall(now), packet)
        .expect("routed");
    net.run(now, i, out.datagrams);
}

fn delivered(net: &Net, i: usize, packet: &[u8]) -> bool {
    net.outputs.iter().any(|(j, out)| {
        *j == i
            && out
                .as_ref()
                .is_ok_and(|o| o.packets.iter().any(|p| p == packet))
    })
}

fn peer(k: PublicKey, last: u8, statics: Vec<crate::inner::Endpoint>) -> PeerConfig {
    PeerConfig {
        public_key: k,
        addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))],
        endpoints: statics,
        ..PeerConfig::default()
    }
}

/// Review gate 2 X1, §12.3: accepting the peer's message 1 does not end this node's own
/// sequence nor its fallback. A and B have no direct candidate; their initiations cross
/// through the relay and both responses are lost twice. The sequences keep going through
/// the relay and complete there, without another IP packet.
#[test]
fn crossing_relayed_initiations_survive_lost_responses() {
    let (mut net, a, b) = relay_net(None);
    let rk = key(3).public();
    let lost = Rc::new(Cell::new([0u32; 2]));
    let counted = lost.clone();
    // The relay's copy of a message 2 is the fourth hop of an exchange started by a tick:
    // node -> relay -> node (accepts message 1) -> relay -> node.
    net.lose = Some(Box::new(move |from, to, hop, _| {
        let mut n = counted.get();
        let lose = from == 2 && to < 2 && hop == 3 && n[to] < 2;
        if lose {
            n[to] += 1;
            counted.set(n);
        }
        lose
    }));
    let (ab, ba) = (ip_packet(1, 2), ip_packet(2, 1));
    let start = Duration::from_secs(1);
    send_packet(&mut net, 0, start, &ab);
    send_packet(&mut net, 1, start, &ba);
    // Both nodes tick at the same instants and their outputs cross. With a 700 ms period
    // every deadline `5 s + jitter (≤ 333 ms)` after a tick falls in the same tick gap,
    // whatever the jitter, so both retransmit, and both windows end, in the same tick.
    let mut now = start;
    while now < Duration::from_secs(41) {
        now += ms(700);
        let outs: Vec<_> = (0..3)
            .map(|i| net.parties[i].0.tick(now, wall(now)).datagrams)
            .collect();
        for (i, out) in outs.into_iter().enumerate() {
            net.run(now, i, out);
        }
    }
    assert_eq!(lost.get(), [2, 2], "both responses lost twice");
    for (i, other) in [(0, b), (1, a)] {
        let s = net.parties[i].0.status(&other).unwrap();
        assert!(s.current, "party {i} has a session");
        assert_eq!(s.path, Some(Path::Relayed(rk)));
        assert_eq!(s.staged_packets, 0);
        assert_eq!(s.counters.handshake_timeouts, 0);
    }
    assert!(delivered(&net, 1, &ab) && delivered(&net, 0, &ba));
}

/// Review gate 2 X2, §12.3: a tick that passes both the retransmit deadline and the end of
/// the discovery window sends only the active message 1 through the relay.
#[test]
fn a_late_tick_relays_only_the_active_message_1() {
    let (mut net, a, b) = relay_net(None);
    let start = Duration::from_secs(1);
    send_packet(&mut net, 0, start, &ip_packet(1, 2));
    // After a short suspend: retransmit (5 s + jitter) and window end (3 s) are both due.
    net.tick(start + Duration::from_secs(6));
    let at_b = net.parties[1].0.status(&a).unwrap();
    assert_eq!(
        at_b.counters.handshakes_responded, 1,
        "one message 1 reached B"
    );
    let at_a = net.parties[0].0.status(&b).unwrap();
    assert!(at_a.current, "it was the active one");
}

/// Review gate 2 F3, §12.6: a punch opens a fresh window, so a lighthouse "unknown" that
/// came after the previous window ended does not label this one.
#[test]
fn a_late_unknown_reply_does_not_label_a_punch_window() {
    let (ka, kb, kl) = (key(1), key(2), key(4));
    let (ea, eb, el) = (ep(1, 4802), ep(2, 4802), ep(4, 4800));
    let lighthouse = LighthouseConfig {
        public_key: kl.public(),
        endpoints: vec![el],
    };
    // A knows B's endpoint statically: the punch adds no learnt endpoint.
    let mut na = Node::new(ka.clone(), vec![peer(kb.public(), 2, vec![eb])]);
    na.set_lighthouses(vec![lighthouse.clone()]);
    let nb = Node::new(kb.clone(), vec![peer(ka.public(), 1, vec![ea])]);
    let nl = Node::lighthouse(kl, vec![ka.public(), kb.public()]);
    let mut net = Net::new(vec![(na, ea), (nb, eb), (nl, el)]);
    // No direct path between A and B.
    net.lose = Some(Box::new(|from, to, _, _| from < 2 && to < 2));
    net.tick(Duration::ZERO);
    // A queries B, which is not registered; the query is held past the window.
    let start = Duration::from_secs(1);
    let out = net.parties[0]
        .0
        .send_packet(start, wall(start), &ip_packet(1, 2))
        .unwrap();
    let held: Vec<_> = out
        .datagrams
        .into_iter()
        .filter(|(e, _)| *e == el)
        .collect();
    assert_eq!(held.len(), 1);
    let mut now = start;
    while now < ms(4500) {
        now += ms(500);
        net.tick(now);
    }
    let s = net.parties[0].0.status(&kb.public()).unwrap();
    assert_eq!(s.last_direct_path_failure, Some(PathFailure::Timeout));
    net.run(now, 0, held);
    assert_eq!(net.parties[2].0.lighthouse_counters().queries_unknown, 1);
    // B registers and queries A: the lighthouse punches A at 5 s.
    net.parties[1].0.set_lighthouses(vec![lighthouse]);
    net.tick(now);
    now = Duration::from_secs(5);
    send_packet(&mut net, 1, now, &ip_packet(2, 1));
    assert_eq!(net.parties[2].0.lighthouse_counters().punches, 1);
    while now < ms(8500) {
        now += ms(500);
        net.tick(now);
    }
    let s = net.parties[0].0.status(&kb.public()).unwrap();
    assert!(!s.current);
    assert_eq!(s.last_direct_path_failure, Some(PathFailure::Timeout));
}

/// Review gate 2 F4, §12.5: a punch's handshake deferred by the §7.9 pacing keeps the window
/// of its trigger, so the window may record `timeout` and fall back to the relay before the
/// deferred message 1 leaves; that first message 1 then also goes through the relay.
#[test]
fn a_deferred_punch_handshake_may_fall_back_before_it_starts() {
    let (ka, kb, kl, kr) = (key(1), key(2), key(4), key(3));
    let (ea, eb, el, er) = (ep(1, 4802), ep(2, 4802), ep(4, 4800), ep(3, 4801));
    let service = |k: &crate::keys::StaticKey, e| LighthouseConfig {
        public_key: k.public(),
        endpoints: vec![e],
    };
    let mut na = Node::new(ka.clone(), vec![peer(kb.public(), 2, vec![eb])]);
    let mut nb = Node::new(kb.clone(), vec![peer(ka.public(), 1, vec![ea])]);
    for n in [&mut na, &mut nb] {
        n.set_lighthouses(vec![service(&kl, el)]);
        n.set_relays(vec![service(&kr, er)]);
    }
    let both = vec![ka.public(), kb.public()];
    let nl = Node::lighthouse(kl, both.clone());
    let nr = Node::relay(kr.clone(), both, None);
    let mut net = Net::new(vec![(na, ea), (nb, eb), (nl, el), (nr, er)]);
    net.tick(Duration::ZERO);
    // At 1 s A completes a direct handshake; B never sees it confirmed, and the
    // lighthouse's punch of B (A's query) is lost.
    let cut = Rc::new(Cell::new(false));
    let phase = cut.clone();
    net.lose = Some(Box::new(move |from, to, hop, _| {
        let direct = from < 2 && to < 2;
        if phase.get() {
            // No direct path any more, and B's own relayed attempts never reach A.
            direct || (from == 3 && to == 0 && hop == 1)
        } else {
            (from == 0 && to == 1 && hop == 2) || (from == 2 && to == 1)
        }
    }));
    let start = Duration::from_secs(1);
    send_packet(&mut net, 0, start, &ip_packet(1, 2));
    let s = net.parties[0].0.status(&kb.public()).unwrap();
    assert!(s.current && s.counters.handshakes_initiated == 1);
    cut.set(true);
    // 1.5 s later B has traffic for A: its query makes the lighthouse punch A, whose
    // handshake the pacing defers to 6 s (§7.9).
    let punch = ms(2500);
    send_packet(&mut net, 1, punch, &ip_packet(2, 1));
    let mut now = punch;
    while now < ms(5500) {
        now += ms(500);
        net.tick(now);
    }
    // The window (2.5 s + 3 s) ended before any message 1 of that attempt left.
    let s = net.parties[0].0.status(&kb.public()).unwrap();
    assert_eq!(s.last_direct_path_failure, Some(PathFailure::Timeout));
    assert!(!s.handshake_in_flight);
    assert_eq!(s.counters.handshakes_initiated, 1);
    // At 6 s the deferred message 1 goes direct (lost) and through the relay at once.
    net.tick(Duration::from_secs(6));
    let s = net.parties[0].0.status(&kb.public()).unwrap();
    assert_eq!(s.counters.handshakes_initiated, 2);
    assert_eq!(s.path, Some(Path::Relayed(kr.public())));
}

/// Review gate 2 F8, §7.9, §12.5 rule 1: the handshake of an IP packet refused by the
/// `REKEY_TIMEOUT` pacing is deferred like any other rediscovery's, and starts without
/// another packet.
#[test]
fn a_paced_trigger_1_handshake_is_deferred() {
    let (ka, kb) = (key(1), key(2));
    let (ea, eb) = (ep(1, 4802), ep(2, 4802));
    let na = Node::new(ka.clone(), vec![peer(kb.public(), 2, vec![eb])]);
    let nb = Node::new(kb.clone(), vec![peer(ka.public(), 1, vec![ea])]);
    let mut net = Net::new(vec![(na, ea), (nb, eb)]);
    // 0: B's staged packet after its handshake is lost, so A holds an unconfirmed session.
    // 1: nothing passes. 2: B's data passes. 3: A's traffic passes. B's message 1s never.
    let phase = Rc::new(Cell::new(0u8));
    let p = phase.clone();
    net.lose = Some(Box::new(move |from, _, hop, d| match p.get() {
        0 => from == 1 && hop == 2,
        1 => true,
        2 => from == 0 || d[0] != TYPE_DATA,
        _ => from == 1 && d[0] == TYPE_HANDSHAKE_INIT,
    }));
    send_packet(&mut net, 1, Duration::ZERO, &ip_packet(2, 1));
    phase.set(1);
    let mut now = Duration::ZERO;
    while now < Duration::from_secs(176) {
        now += Duration::from_secs(1);
        net.tick(now);
    }
    // A's own sequence starts at 176 s (lost) ...
    send_packet(&mut net, 0, now, &ip_packet(1, 2));
    // ... and B's data at 179 s confirms A's session created at 0 s, which ends it.
    phase.set(2);
    send_packet(&mut net, 1, Duration::from_secs(179), &ip_packet(2, 1));
    let s = net.parties[0].0.status(&kb.public()).unwrap();
    assert!(s.current && !s.handshake_in_flight);
    // At 180.5 s that session is gone and the last message 1 is 4.5 s old.
    phase.set(3);
    let late = ip_packet(1, 2);
    now = ms(180_500);
    send_packet(&mut net, 0, now, &late);
    let s = net.parties[0].0.status(&kb.public()).unwrap();
    assert!(!s.current && !s.handshake_in_flight && s.staged_packets == 1);
    while now < Duration::from_secs(182) {
        now += ms(500);
        net.tick(now);
    }
    let s = net.parties[0].0.status(&kb.public()).unwrap();
    assert!(s.current && s.counters.handshakes_initiated == 1);
    assert!(delivered(&net, 1, &late));
}
