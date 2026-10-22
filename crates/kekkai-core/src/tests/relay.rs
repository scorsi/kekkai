//! The relay role (§14.2), its token bucket and the lighthouse's query budget (§13.2).

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use proptest::prelude::*;

use crate::inner::{Endpoint, Inner};
use crate::keys::{PublicKey, StaticKey};
use crate::node::{LighthouseConfig, Node, Output, PeerConfig};
use crate::relay::Bucket;
use crate::tai64n::Tai64n;
use crate::wire::DropReason;
use crate::{DIRECT_PATH_TIMEOUT, MAX_RELAY_PAYLOAD};

pub(super) fn wall(now: Duration) -> Tai64n {
    Tai64n::from_unix(1_800_000_000 + now.as_secs(), now.subsec_nanos())
}

pub(super) fn ep(last: u8, port: u16) -> Endpoint {
    Endpoint::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), port)
}

/// Decides that a datagram is lost: `(from, to, hop, bytes)`, `hop` counting from 0 for
/// what the call to [`Net::run`] started with.
pub(super) type Lose = Box<dyn FnMut(usize, usize, usize, &[u8]) -> bool>;

/// Parties on one network, each at its endpoint; datagrams are delivered until none is left.
pub(super) struct Net {
    pub(super) parties: Vec<(Node, Endpoint)>,
    /// Outputs of every delivery, by receiving party.
    pub(super) outputs: Vec<(usize, Result<Output, DropReason>)>,
    pub(super) lose: Option<Lose>,
}

impl Net {
    pub(super) fn new(parties: Vec<(Node, Endpoint)>) -> Self {
        Self {
            parties,
            outputs: Vec::new(),
            lose: None,
        }
    }

    pub(super) fn run(&mut self, now: Duration, from: usize, mut queue: Vec<(Endpoint, Vec<u8>)>) {
        let mut sender = vec![(from, 0); queue.len()];
        while let Some((to, d)) = queue.pop() {
            let (from, hop) = sender.pop().expect("one per datagram");
            let source = self.parties[from].1;
            let Some(i) = self.parties.iter().position(|(_, e)| *e == to) else {
                continue;
            };
            if self
                .lose
                .as_mut()
                .is_some_and(|lose| lose(from, i, hop, &d))
            {
                continue;
            }
            let result = self.parties[i]
                .0
                .handle_datagram(now, wall(now), source, &d);
            if let Ok(out) = &result {
                for (e, d) in &out.datagrams {
                    queue.push((*e, d.clone()));
                    sender.push((i, hop + 1));
                }
            }
            self.outputs.push((
                i,
                result.map(|mut o| {
                    o.datagrams.clear();
                    o
                }),
            ));
        }
    }

    pub(super) fn tick(&mut self, now: Duration) {
        for i in 0..self.parties.len() {
            let out = self.parties[i].0.tick(now, wall(now));
            self.run(now, i, out.datagrams);
        }
    }
}

pub(super) fn key(b: u8) -> StaticKey {
    StaticKey::from_bytes([b; 32]).clamped()
}

/// Node A (0), node B (1) and a relay (2) listing both, which each node configures.
pub(super) fn relay_net(limit: Option<u64>) -> (Net, PublicKey, PublicKey) {
    let (a, b, r) = (key(1), key(2), key(3));
    let peer = |k: &StaticKey, last: u8| PeerConfig {
        public_key: k.public(),
        addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))],
        ..PeerConfig::default()
    };
    let relay = LighthouseConfig {
        public_key: r.public(),
        endpoints: vec![ep(3, 4801)],
    };
    let mut na = Node::new(a.clone(), vec![peer(&b, 2)]);
    let mut nb = Node::new(b.clone(), vec![peer(&a, 1)]);
    na.set_relays(vec![relay.clone()]);
    nb.set_relays(vec![relay]);
    let nr = Node::relay(r, vec![a.public(), b.public()], limit);
    let mut net = Net::new(vec![
        (na, ep(1, 4802)),
        (nb, ep(2, 4802)),
        (nr, ep(3, 4801)),
    ]);
    net.tick(Duration::ZERO);
    let rk = key(3).public();
    for i in 0..2 {
        assert!(
            net.parties[i].0.status(&rk).unwrap().current,
            "relay session {i}"
        );
    }
    net.outputs.clear();
    (net, a.public(), b.public())
}

/// ADR 0014, §10.6: the relay copies the payload without parsing it. A payload that is no
/// outer message at all is forwarded byte for byte and only B's §5.6 refuses it.
#[test]
fn the_relay_forwards_opaque_bytes() {
    let (mut net, a, b) = relay_net(None);
    let now = Duration::from_secs(1);
    let rk = key(3).public();
    let junk = vec![0xee; 64];
    let forward = Inner::RelayForward {
        to: b,
        payload: &junk,
    }
    .encode();
    let out = net.parties[0].0.send_inner_to(now, wall(now), rk, &forward);
    net.run(now, 0, out);
    let senders = net.parties[2].0.relay_senders();
    let from_a = senders.iter().find(|(k, _)| *k == a).unwrap().1;
    assert_eq!((from_a.forwarded_packets, from_a.forwarded_bytes), (1, 64));
    // B authenticated R's packet, then dropped the payload at the first §5.6 check.
    let at_b: Vec<_> = net.outputs.iter().filter(|(i, _)| *i == 1).collect();
    assert_eq!(at_b.len(), 1);
    let out = at_b[0].1.as_ref().expect("R's data packet is authentic");
    assert_eq!(out.from, Some(rk));
    assert_eq!(out.dropped, Some(DropReason::UnknownVersion));
    // Silence towards an unlisted destination, counted.
    let stranger = key(9).public();
    let forward = Inner::RelayForward {
        to: stranger,
        payload: &junk,
    }
    .encode();
    net.outputs.clear();
    let out = net.parties[0].0.send_inner_to(now, wall(now), rk, &forward);
    net.run(now, 0, out);
    assert_eq!(net.outputs.len(), 1, "nothing left the relay");
    let at_r = net.outputs[0].1.as_ref().unwrap();
    assert_eq!(at_r.dropped, Some(DropReason::NoRoute));
    let from_a = net.parties[2].0.relay_senders()[0..2]
        .iter()
        .find(|(k, _)| *k == a)
        .unwrap()
        .1;
    assert_eq!(from_a.dropped_no_route, 1);
}

/// §10.2: a relay accepts no `relay_forwarded`; only nodes do, from their relay.
#[test]
fn a_relay_refuses_relay_forwarded() {
    let (mut net, _, b) = relay_net(None);
    let now = Duration::from_secs(1);
    let junk = vec![0xee; 64];
    let forwarded = Inner::RelayForwarded {
        from: b,
        payload: &junk,
    };
    let rk = key(3).public();
    let out = net.parties[1]
        .0
        .send_inner_to(now, wall(now), rk, &forwarded.encode());
    net.run(now, 1, out);
    let at_r = net.outputs.iter().find(|(i, _)| *i == 2).unwrap();
    assert_eq!(
        at_r.1.as_ref().unwrap().dropped,
        Some(DropReason::NotAccepted)
    );
}

/// §14.2 step 2: a limited sender gets one second's worth of bytes, then the refill rate.
#[test]
fn the_relay_rate_limit_counts_its_drops() {
    let (mut net, a, b) = relay_net(Some(1000));
    let rk = key(3).public();
    let payload = vec![0xee; 100];
    let forward = Inner::RelayForward {
        to: b,
        payload: &payload,
    }
    .encode();
    let send = |net: &mut Net, at: Duration| {
        let out = net.parties[0].0.send_inner_to(at, wall(at), rk, &forward);
        net.run(at, 0, out);
    };
    let t = Duration::from_secs(1);
    for _ in 0..15 {
        send(&mut net, t);
    }
    let counters = |net: &Net| {
        let senders = net.parties[2].0.relay_senders();
        senders.iter().find(|(k, _)| *k == a).unwrap().1
    };
    let c = counters(&net);
    assert_eq!((c.forwarded_packets, c.dropped_rate_limited), (10, 5));
    let later = t + Duration::from_millis(500);
    for _ in 0..10 {
        send(&mut net, later);
    }
    let c = counters(&net);
    assert_eq!((c.forwarded_packets, c.dropped_rate_limited), (15, 10));
}

/// §13.2, threat model L7: a lighthouse answers at most twice its listed keys' worth of
/// queries from one sender at once, refilled by the listed count every
/// `DIRECT_PATH_TIMEOUT`; the rest is dropped unanswered and counted.
#[test]
fn the_lighthouse_query_budget() {
    let (a, b, l) = (key(1), key(2), key(4));
    let lighthouse = LighthouseConfig {
        public_key: l.public(),
        endpoints: vec![ep(4, 4800)],
    };
    let peer = PeerConfig {
        public_key: b.public(),
        ..PeerConfig::default()
    };
    let mut na = Node::new(a.clone(), vec![peer]);
    na.set_lighthouses(vec![lighthouse]);
    let nl = Node::lighthouse(l.clone(), vec![a.public(), b.public()]);
    let mut net = Net::new(vec![(na, ep(1, 4802)), (nl, ep(4, 4800))]);
    net.tick(Duration::ZERO);
    let query = Inner::LighthouseQuery { pubkey: b.public() }.encode();
    let t = Duration::from_secs(1);
    for _ in 0..10 {
        let out = net.parties[0]
            .0
            .send_inner_to(t, wall(t), l.public(), &query);
        net.run(t, 0, out);
    }
    let c = net.parties[1].0.lighthouse_counters();
    assert_eq!(c.queries_unknown, 4, "2 × 2 listed keys");
    assert_eq!(c.queries_limited, 6);
    let later = t + DIRECT_PATH_TIMEOUT;
    for _ in 0..3 {
        let out = net.parties[0]
            .0
            .send_inner_to(later, wall(later), l.public(), &query);
        net.run(later, 0, out);
    }
    let c = net.parties[1].0.lighthouse_counters();
    assert_eq!((c.queries_unknown, c.queries_limited), (6, 7));
}

proptest! {
    /// Over any window, a bucket grants at most `burst` plus the window's refill.
    #[test]
    fn bucket_bound(
        burst in 1u64..5000,
        per_ms in 1u64..5000,
        takes in prop::collection::vec((0u64..3000, 0u64..2000), 1..200),
    ) {
        let per = Duration::from_millis(per_ms);
        let mut bucket = Bucket::default();
        let mut now = Duration::ZERO;
        let mut granted: Vec<(Duration, u64)> = Vec::new();
        for (step, cost) in takes {
            now += Duration::from_millis(step);
            if bucket.take(now, burst, per, cost) {
                granted.push((now, cost));
            }
        }
        for (i, (start, _)) in granted.iter().enumerate() {
            let mut sum = 0u128;
            for (t, cost) in &granted[i..] {
                sum += u128::from(*cost);
                let window = (*t - *start).as_nanos();
                let bound = u128::from(burst) + window * u128::from(burst) / per.as_nanos();
                prop_assert!(sum <= bound + 1, "{} > {}", sum, bound);
            }
        }
    }
}

#[test]
fn a_relayed_payload_bound_is_the_spec_bound() {
    assert_eq!(MAX_RELAY_PAYLOAD, crate::MAX_DATAGRAM - 16 - 1 - 32 - 16);
}
