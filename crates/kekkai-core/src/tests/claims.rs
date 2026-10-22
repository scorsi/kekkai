//! §14.1 on a node, against a compromised relay (threat model 4.3, review gate 2 X3/F1): the
//! claimed sender of a `relay_forwarded` must be a configured peer and the party its payload
//! authenticates as, checked before any state of that party changes; nothing nested; a
//! relayed packet never moves an endpoint. The relay builds arbitrary inner messages here.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::paths::ip_packet;
use super::relay::{Net, ep, key, wall};
use crate::firewall::Rule;
use crate::inner::{Endpoint, Inner};
use crate::keys::PublicKey;
use crate::node::{LighthouseConfig, Node, Output, Path, PeerConfig, PeerStatus};
use crate::wire::{DropReason, TYPE_DATA, TYPE_HANDSHAKE_INIT, TYPE_HANDSHAKE_RESP};

const A: usize = 0;
const B: usize = 1;
const R: usize = 2;
const C: usize = 3;
const L: usize = 4;

struct Keys {
    a: PublicKey,
    b: PublicKey,
    r: PublicKey,
    c: PublicKey,
    l: PublicKey,
}

fn endpoint(i: usize) -> Endpoint {
    [
        ep(1, 4802),
        ep(2, 4802),
        ep(3, 4801),
        ep(5, 4802),
        ep(4, 4800),
    ][i]
}

/// A, B and C (overlay 10.0.0.{1,2,5}) behind relay R, all listed by it; B also lists C and
/// uses lighthouse L. The node↔service sessions are up.
fn net() -> (Net, Keys) {
    let (ka, kb, kr, kc, kl) = (key(1), key(2), key(3), key(5), key(4));
    let peer = |k: PublicKey, last: u8, i: usize| PeerConfig {
        public_key: k,
        addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))],
        allow_inbound: vec![Rule::Any],
        endpoints: vec![endpoint(i)],
    };
    let service = |k: PublicKey, i: usize| {
        vec![LighthouseConfig {
            public_key: k,
            endpoints: vec![endpoint(i)],
        }]
    };
    let mut na = Node::new(ka.clone(), vec![peer(kb.public(), 2, B)]);
    let mut nb = Node::new(
        kb.clone(),
        vec![peer(ka.public(), 1, A), peer(kc.public(), 5, C)],
    );
    let mut nc = Node::new(kc.clone(), vec![peer(kb.public(), 2, B)]);
    for n in [&mut na, &mut nb, &mut nc] {
        n.set_relays(service(kr.public(), R));
    }
    nb.set_lighthouses(service(kl.public(), L));
    let listed = vec![ka.public(), kb.public(), kc.public()];
    let nr = Node::relay(kr.clone(), listed, None);
    let nl = Node::lighthouse(kl.clone(), vec![kb.public()]);
    let parties = vec![na, nb, nr, nc, nl];
    let mut net = Net::new(
        parties
            .into_iter()
            .enumerate()
            .map(|(i, n)| (n, endpoint(i)))
            .collect(),
    );
    net.tick(Duration::ZERO);
    let keys = Keys {
        a: ka.public(),
        b: kb.public(),
        r: kr.public(),
        c: kc.public(),
        l: kl.public(),
    };
    for (i, service) in [(A, keys.r), (B, keys.r), (C, keys.r), (B, keys.l)] {
        assert!(net.parties[i].0.status(&service).unwrap().current);
    }
    net.outputs.clear();
    (net, keys)
}

const T: Duration = Duration::from_secs(1);

/// What `i` would send for `packet`, without delivering it: its one datagram of type `ty`.
fn capture(net: &mut Net, i: usize, packet: &[u8], ty: u8) -> Vec<u8> {
    let out = net.parties[i].0.send_packet(T, wall(T), packet).unwrap();
    let mut of_type = out.datagrams.into_iter().filter(|(_, d)| d[0] == ty);
    let (_, d) = of_type.next().expect("one datagram of that type");
    assert!(of_type.next().is_none());
    d
}

/// The relay wraps `payload` as `relay_forwarded { from }` to B: B's result.
fn relabel(net: &mut Net, keys: &Keys, from: PublicKey, payload: &[u8]) -> Output {
    let inner = Inner::RelayForwarded { from, payload }.encode();
    let out = net.parties[R].0.send_inner_to(T, wall(T), keys.b, &inner);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, endpoint(B));
    net.parties[B]
        .0
        .handle_datagram(T, wall(T), endpoint(R), &out[0].1)
        .expect("R's packet is authentic")
}

/// B's view of `peer`.
fn at_b(net: &Net, peer: &PublicKey) -> PeerStatus {
    net.parties[B].0.status(peer).unwrap()
}

/// A direct A↔B session, both sides confirmed.
fn direct_ab(net: &mut Net, keys: &Keys) {
    let out = net.parties[A]
        .0
        .send_packet(T, wall(T), &ip_packet(1, 2))
        .unwrap();
    net.run(T, A, out.datagrams);
    assert!(at_b(net, &keys.a).current);
    assert_eq!(at_b(net, &keys.a).path, Some(Path::Direct(endpoint(A))));
    net.outputs.clear();
}

/// The refusal of a relabelled payload: dropped as R's content, nothing sent, the outer
/// R↔B effects kept (one more authenticated packet from R, R's endpoint).
fn assert_refused(out: &Output, keys: &Keys, r_before: PeerStatus, net: &Net) {
    assert_eq!(out.from, Some(keys.r));
    assert_eq!(out.dropped, Some(DropReason::NotAccepted));
    assert!(out.datagrams.is_empty() && out.packets.is_empty());
    let r = at_b(net, &keys.r);
    assert_eq!(r.counters.rx_packets, r_before.counters.rx_packets + 1);
    assert_eq!((r.last_received, r.endpoint), (Some(T), Some(endpoint(R))));
}

/// X3.1: A's real message 1 relabelled `from = C`. B changes nothing of A or C, and A's
/// message 1 with the same timestamp is still accepted afterwards.
#[test]
fn a_relabelled_message_1_changes_nothing() {
    let (mut net, keys) = net();
    let m1 = capture(&mut net, A, &ip_packet(1, 2), TYPE_HANDSHAKE_INIT);
    let (a, c, r, n) = (
        at_b(&net, &keys.a),
        at_b(&net, &keys.c),
        at_b(&net, &keys.r),
        net.parties[B].0.index_count(),
    );
    let out = relabel(&mut net, &keys, keys.c, &m1);
    assert_refused(&out, &keys, r, &net);
    assert_eq!((at_b(&net, &keys.a), at_b(&net, &keys.c)), (a, c));
    assert_eq!(net.parties[B].0.index_count(), n);
    // §7.4: the same timestamp passes, so `last_timestamp` did not move.
    let out = net.parties[B]
        .0
        .handle_datagram(T, wall(T), endpoint(A), &m1)
        .unwrap();
    assert_eq!(out.from, Some(keys.a));
    assert_eq!(out.datagrams.len(), 1);
    assert_eq!(out.datagrams[0].0, endpoint(A));
    assert_eq!(out.datagrams[0].1[0], TYPE_HANDSHAKE_RESP);
}

/// X3.2: A's real message 2 to B relabelled `from = C`: B's handshake stays in flight and
/// the genuine message 2 still completes it.
#[test]
fn a_relabelled_message_2_changes_nothing() {
    let (mut net, keys) = net();
    let m1 = capture(&mut net, B, &ip_packet(2, 1), TYPE_HANDSHAKE_INIT);
    let out = net.parties[A]
        .0
        .handle_datagram(T, wall(T), endpoint(B), &m1)
        .unwrap();
    let m2 = out.datagrams[0].1.clone();
    assert_eq!(m2[0], TYPE_HANDSHAKE_RESP);
    let (a, c, r, n) = (
        at_b(&net, &keys.a),
        at_b(&net, &keys.c),
        at_b(&net, &keys.r),
        net.parties[B].0.index_count(),
    );
    assert!(a.handshake_in_flight && !a.current);
    let out = relabel(&mut net, &keys, keys.c, &m2);
    assert_refused(&out, &keys, r, &net);
    assert_eq!((at_b(&net, &keys.a), at_b(&net, &keys.c)), (a, c));
    assert_eq!(net.parties[B].0.index_count(), n);
    let out = net.parties[B]
        .0
        .handle_datagram(T, wall(T), endpoint(A), &m2)
        .unwrap();
    assert_eq!(out.from, Some(keys.a));
    assert!(at_b(&net, &keys.a).current);
}

/// X3.2: a `data` packet of the established A↔B session relabelled `from = C`: A's
/// session, replay state, endpoint and path are untouched; the genuine packet still passes.
#[test]
fn a_relabelled_data_packet_changes_nothing() {
    let (mut net, keys) = net();
    direct_ab(&mut net, &keys);
    let packet = ip_packet(1, 2);
    let data = capture(&mut net, A, &packet, TYPE_DATA);
    let (a, c, r) = (
        at_b(&net, &keys.a),
        at_b(&net, &keys.c),
        at_b(&net, &keys.r),
    );
    let out = relabel(&mut net, &keys, keys.c, &data);
    assert_refused(&out, &keys, r, &net);
    assert_eq!((at_b(&net, &keys.a), at_b(&net, &keys.c)), (a, c));
    // §8.4: the counter was not marked.
    let out = net.parties[B]
        .0
        .handle_datagram(T, wall(T), endpoint(A), &data)
        .unwrap();
    assert_eq!((out.from, out.packets), (Some(keys.a), vec![packet]));
}

/// X3.3: a `from` that is not a configured peer: the lighthouse, the relay itself, B's own
/// key, an unlisted key. The lighthouse's and the relay's genuine packets, whose
/// authenticated party would match, still pass directly afterwards.
#[test]
fn a_relay_forwarded_from_a_non_peer_is_refused() {
    let (mut net, keys) = net();
    let keepalive = Inner::Keepalive.encode();
    let from_l = net.parties[L]
        .0
        .send_inner_to(T, wall(T), keys.b, &keepalive);
    let from_r = net.parties[R]
        .0
        .send_inner_to(T, wall(T), keys.b, &keepalive);
    let m1 = capture(&mut net, A, &ip_packet(1, 2), TYPE_HANDSHAKE_INIT);
    let stranger = key(9).public();
    let cases = [
        (keys.l, &from_l[0].1),
        (keys.r, &from_r[0].1),
        (keys.b, &m1),
        (stranger, &m1),
    ];
    for (from, payload) in cases {
        let (a, l, r, n) = (
            at_b(&net, &keys.a),
            at_b(&net, &keys.l),
            at_b(&net, &keys.r),
            net.parties[B].0.index_count(),
        );
        let out = relabel(&mut net, &keys, from, payload);
        assert_refused(&out, &keys, r, &net);
        assert_eq!((at_b(&net, &keys.a), at_b(&net, &keys.l)), (a, l));
        assert_eq!(net.parties[B].0.index_count(), n);
    }
    for (i, d) in [(L, &from_l[0].1), (R, &from_r[0].1)] {
        let out = net.parties[B]
            .0
            .handle_datagram(T, wall(T), endpoint(i), d)
            .unwrap();
        assert_eq!(out.dropped, None, "party {i}");
    }
}

/// X3.4: inside its A↔B session, through the relay, A sends `relay_forwarded { from = C }`
/// carrying C's real message 1: no nested relaying, C is untouched, and C's message 1 still
/// passes directly afterwards.
#[test]
fn a_node_refuses_nested_relaying() {
    let (mut net, keys) = net();
    direct_ab(&mut net, &keys);
    let m1 = capture(&mut net, C, &ip_packet(5, 2), TYPE_HANDSHAKE_INIT);
    let nested = Inner::RelayForwarded {
        from: keys.c,
        payload: &m1,
    }
    .encode();
    let data = net.parties[A].0.send_inner_to(T, wall(T), keys.b, &nested);
    assert_eq!(data.len(), 1);
    let (c, r, n) = (
        at_b(&net, &keys.c),
        at_b(&net, &keys.r),
        net.parties[B].0.index_count(),
    );
    let out = relabel(&mut net, &keys, keys.a, &data[0].1);
    assert_refused(&out, &keys, r, &net);
    assert_eq!(at_b(&net, &keys.c), c);
    assert_eq!(net.parties[B].0.index_count(), n);
    let out = net.parties[B]
        .0
        .handle_datagram(T, wall(T), endpoint(C), &m1)
        .unwrap();
    assert_eq!(out.from, Some(keys.c));
}

/// X3.5, §12.4: a relayed packet moves its session's path to the relay and keeps the
/// enclosed peer's known endpoint.
#[test]
fn a_relayed_packet_keeps_the_endpoint() {
    let (mut net, keys) = net();
    direct_ab(&mut net, &keys);
    let packet = ip_packet(1, 2);
    let data = capture(&mut net, A, &packet, TYPE_DATA);
    let out = relabel(&mut net, &keys, keys.a, &data);
    assert_eq!((out.dropped, out.packets), (None, vec![packet]));
    let a = at_b(&net, &keys.a);
    assert_eq!(a.endpoint, Some(endpoint(A)));
    assert_eq!(a.path, Some(Path::Relayed(keys.r)));
}
