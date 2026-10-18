//! Property tests (ADR 0020 tier 1): codecs round-trip and reject, the replay window
//! matches its model, TLV canonical form, session counters, and the timer invariants of §9.

use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use proptest::prelude::*;

use crate::handshake::SessionKeys;
use crate::inner::{Endpoint, Inner};
use crate::keys::{PublicKey, StaticKey};
use crate::mac1::Mac1Key;
use crate::node::{Node, PeerConfig};
use crate::session::{ReplayWindow, Role, Session};
use crate::tai64n::Tai64n;
use crate::tlv::{self, CRITICAL, Tlv, TlvError};
use crate::wire::{self, DropReason, Outer};
use crate::{
    COUNTER_WINDOW_SIZE, MAX_DATAGRAM, MAX_ENDPOINTS, MAX_LOCAL_ENDPOINTS, MAX_RELAY_PAYLOAD,
    REJECT_AFTER_MESSAGES, REKEY_TIMEOUT, WIRE_VERSION,
};

// ---- TLV (§6) ----

type OwnedTlv = (u8, Vec<u8>);

fn tlv_list() -> impl Strategy<Value = Vec<OwnedTlv>> {
    (
        prop::collection::btree_set(any::<u8>(), 0..6),
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..300), 6),
    )
        .prop_map(|(types, values)| types.into_iter().zip(values).collect())
}

fn borrow(list: &[OwnedTlv]) -> Vec<Tlv<'_>> {
    list.iter()
        .map(|(ty, v)| Tlv { ty: *ty, value: v })
        .collect()
}

fn encode(list: &[OwnedTlv]) -> Vec<u8> {
    let mut out = Vec::new();
    tlv::encode(&borrow(list), &mut out);
    out
}

proptest! {
    #[test]
    fn tlv_round_trip(list in tlv_list()) {
        let known: Vec<u8> = list.iter().map(|(ty, _)| *ty).collect();
        let bytes = encode(&list);
        prop_assert_eq!(tlv::decode(&bytes, &known).unwrap(), borrow(&list));
        let all: Vec<u8> = (0..=255).collect();
        prop_assert_eq!(tlv::decode(&bytes, &all).unwrap(), borrow(&list));
    }

    #[test]
    fn tlv_unknown_types(list in tlv_list(), known_mask in any::<u64>()) {
        // Types with a set mask bit are known; the others are unknown and must be skipped
        // (non-critical) or reject the list (critical).
        let known: Vec<u8> = list
            .iter()
            .map(|(ty, _)| *ty)
            .filter(|ty| known_mask & (1 << (ty % 64)) != 0)
            .collect();
        let expected: Vec<&OwnedTlv> = list.iter().filter(|(ty, _)| known.contains(ty)).collect();
        let unknown_critical = list
            .iter()
            .any(|(ty, _)| !known.contains(ty) && ty & CRITICAL != 0);
        let bytes = encode(&list);
        let result = tlv::decode(&bytes, &known);
        if unknown_critical {
            prop_assert_eq!(result, Err(TlvError::UnknownCritical));
        } else {
            let got: Vec<(u8, Vec<u8>)> =
                result.unwrap().iter().map(|t| (t.ty, t.value.to_vec())).collect();
            prop_assert_eq!(got, expected.into_iter().cloned().collect::<Vec<_>>());
        }
    }

    #[test]
    fn tlv_non_canonical_rejected(list in tlv_list().prop_filter("two TLVs", |l| l.len() >= 2), at in any::<prop::sample::Index>(), duplicate in any::<bool>()) {
        let mut list = list;
        let i = at.index(list.len() - 1);
        if duplicate {
            let copy = list[i].clone();
            list.insert(i + 1, copy);
        } else {
            list.swap(i, i + 1);
        }
        // Bypass encode's debug assertion: write the bytes by hand.
        let mut bytes = Vec::new();
        for (ty, v) in &list {
            bytes.push(*ty);
            bytes.extend_from_slice(&(v.len() as u16).to_be_bytes());
            bytes.extend_from_slice(v);
        }
        let all: Vec<u8> = (0..=255).collect();
        prop_assert_eq!(tlv::decode(&bytes, &all), Err(TlvError::NotCanonical));
    }

    #[test]
    fn tlv_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let all: Vec<u8> = (0..=255).collect();
        if let Ok(list) = tlv::decode(&bytes, &all) {
            let mut again = Vec::new();
            tlv::encode(&list, &mut again);
            prop_assert_eq!(&again, &bytes, "a list that parses is canonical and re-encodes to itself");
        }
        let _ = tlv::decode(&bytes, &[1]);
    }
}

// ---- Outer messages (§5) ----

proptest! {
    #[test]
    fn outer_handshake_round_trip(index in any::<u32>(), other in any::<u32>(), noise in prop::collection::vec(any::<u8>(), 96..=MAX_DATAGRAM - 40), key in any::<[u8; 32]>()) {
        let mac1 = Mac1Key::for_receiver(&key);
        let init = wire::encode_handshake_init(index, &noise, &mac1);
        match wire::parse(&init).unwrap() {
            Outer::HandshakeInit(m) => {
                prop_assert_eq!(m.sender_index, index);
                prop_assert_eq!(m.noise, &noise[..]);
                prop_assert_eq!(m.verify_mac1(&mac1), Ok(()));
            }
            _ => prop_assert!(false, "type 1"),
        }
        let noise = &noise[..noise.len().min(MAX_DATAGRAM - 44)];
        let resp = wire::encode_handshake_resp(index, other, noise, &mac1);
        match wire::parse(&resp).unwrap() {
            Outer::HandshakeResp(m) => {
                prop_assert_eq!((m.sender_index, m.receiver_index), (index, other));
                prop_assert_eq!(m.noise, noise);
                prop_assert_eq!(m.verify_mac1(&mac1), Ok(()));
            }
            _ => prop_assert!(false, "type 2"),
        }
    }

    #[test]
    fn outer_data_round_trip(index in any::<u32>(), counter in any::<u64>(), ciphertext in prop::collection::vec(any::<u8>(), 17..=MAX_DATAGRAM - 16)) {
        let mut d = wire::data_header(index, counter).to_vec();
        d.extend_from_slice(&ciphertext);
        match wire::parse(&d).unwrap() {
            Outer::Data(m) => {
                prop_assert_eq!((m.receiver_index, m.counter), (index, counter));
                prop_assert_eq!(m.ciphertext, &ciphertext[..]);
            }
            _ => prop_assert!(false, "type 4"),
        }
    }

    #[test]
    fn outer_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..1500)) {
        let result = wire::parse(&bytes);
        if bytes.len() < 4 || bytes.len() > MAX_DATAGRAM {
            prop_assert_eq!(result.err(), Some(DropReason::BadLength));
        } else if bytes[1] != WIRE_VERSION {
            prop_assert_eq!(result.err(), Some(DropReason::UnknownVersion));
        } else if ![1, 2, 4].contains(&bytes[0]) {
            prop_assert_eq!(result.err(), Some(DropReason::UnknownType));
        } else {
            let min = [0, 136, 92, 0, 33][usize::from(bytes[0])];
            prop_assert_eq!(result.is_ok(), bytes.len() >= min);
        }
    }
}

// ---- Inner messages (§10) ----

#[derive(Clone, Debug)]
enum OwnedInner {
    IpPacket(Vec<u8>),
    Keepalive,
    Register(Vec<Endpoint>),
    Query(PublicKey),
    QueryReply(PublicKey, Vec<Endpoint>, Option<u32>),
    Punch(PublicKey, Vec<Endpoint>),
    Forward(PublicKey, Vec<u8>),
    Forwarded(PublicKey, Vec<u8>),
}

impl OwnedInner {
    fn borrow(&self) -> Inner<'_> {
        match self {
            OwnedInner::IpPacket(p) => Inner::IpPacket(p),
            OwnedInner::Keepalive => Inner::Keepalive,
            OwnedInner::Register(e) => Inner::LighthouseRegister {
                endpoints: e.clone(),
            },
            OwnedInner::Query(k) => Inner::LighthouseQuery { pubkey: *k },
            OwnedInner::QueryReply(k, e, l) => Inner::LighthouseQueryReply {
                pubkey: *k,
                endpoints: e.clone(),
                last_seen: *l,
            },
            OwnedInner::Punch(k, e) => Inner::LighthousePunch {
                pubkey: *k,
                endpoints: e.clone(),
            },
            OwnedInner::Forward(k, p) => Inner::RelayForward { to: *k, payload: p },
            OwnedInner::Forwarded(k, p) => Inner::RelayForwarded {
                from: *k,
                payload: p,
            },
        }
    }
}

fn endpoint() -> impl Strategy<Value = Endpoint> {
    (any::<bool>(), any::<[u8; 16]>(), any::<u16>()).prop_map(|(v4, a, port)| {
        let address = if v4 {
            IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]))
        } else {
            IpAddr::V6(Ipv6Addr::from(a))
        };
        Endpoint::new(address, port)
    })
}

fn inner() -> impl Strategy<Value = OwnedInner> {
    let ip = (
        prop_oneof![Just(0x40u8), Just(0x60u8)],
        prop::collection::vec(any::<u8>(), 0..1279),
    )
        .prop_map(|(first, rest)| {
            let mut p = vec![first];
            p.extend(rest);
            OwnedInner::IpPacket(p)
        });
    let payload = prop::collection::vec(any::<u8>(), 4..=MAX_RELAY_PAYLOAD);
    prop_oneof![
        ip,
        Just(OwnedInner::Keepalive),
        prop::collection::vec(endpoint(), 0..=MAX_LOCAL_ENDPOINTS).prop_map(OwnedInner::Register),
        any::<[u8; 32]>().prop_map(OwnedInner::Query),
        (
            any::<[u8; 32]>(),
            prop::collection::vec(endpoint(), 0..=MAX_ENDPOINTS),
            any::<Option<u32>>()
        )
            .prop_map(|(k, e, l)| OwnedInner::QueryReply(k, e, l)),
        (
            any::<[u8; 32]>(),
            prop::collection::vec(endpoint(), 1..=MAX_ENDPOINTS)
        )
            .prop_map(|(k, e)| OwnedInner::Punch(k, e)),
        (any::<[u8; 32]>(), payload.clone()).prop_map(|(k, p)| OwnedInner::Forward(k, p)),
        (any::<[u8; 32]>(), payload).prop_map(|(k, p)| OwnedInner::Forwarded(k, p)),
    ]
}

proptest! {
    #[test]
    fn inner_round_trip(message in inner()) {
        let inner = message.borrow();
        let bytes = inner.encode();
        prop_assert_eq!(Inner::decode(&bytes), Ok(inner));
    }

    #[test]
    fn inner_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..1400)) {
        if let Ok(inner) = Inner::decode(&bytes) {
            let again = inner.encode();
            prop_assert_eq!(Inner::decode(&again), Ok(inner));
        }
    }
}

// ---- Replay window (§8.4) and session counters (§8.2) ----

/// The §8.4 properties as a model: accepted at most once, nothing further than the window
/// behind the highest accepted counter, nothing at or above `REJECT_AFTER_MESSAGES`.
#[derive(Default)]
struct WindowModel {
    highest: u64,
    seen: HashSet<u64>,
}

impl WindowModel {
    fn accept(&mut self, counter: u64) -> bool {
        let ok = counter < REJECT_AFTER_MESSAGES
            && (counter > self.highest || self.highest - counter < COUNTER_WINDOW_SIZE)
            && !self.seen.contains(&counter);
        if ok {
            self.highest = self.highest.max(counter);
            self.seen.insert(counter);
        }
        ok
    }
}

fn counter_moves() -> impl Strategy<Value = Vec<(bool, u64)>> {
    prop::collection::vec(
        (
            any::<bool>(),
            prop_oneof![
                4 => 0u64..64,
                3 => 0u64..COUNTER_WINDOW_SIZE + 200,
                1 => 0u64..u64::MAX,
            ],
        ),
        1..300,
    )
}

proptest! {
    #[test]
    fn replay_window_matches_model(moves in counter_moves()) {
        let mut window = ReplayWindow::new();
        let mut model = WindowModel::default();
        for (forward, delta) in moves {
            let counter = if forward {
                model.highest.saturating_add(delta)
            } else {
                model.highest.saturating_sub(delta)
            };
            let expected = model.accept(counter);
            prop_assert_eq!(window.check(counter), expected, "counter {}", counter);
            if expected {
                window.mark(counter);
            }
        }
    }

    #[test]
    fn session_counters_never_repeat(n in 1usize..64, tamper in any::<prop::sample::Index>()) {
        let keys = SessionKeys { send: [1; 32], recv: [2; 32], handshake_hash: [0; 32] };
        let mirror = SessionKeys { send: [2; 32], recv: [1; 32], handshake_hash: [0; 32] };
        let mut a = Session::new(keys, Role::Initiator, 1, 2, Duration::ZERO, true);
        let mut b = Session::new(mirror, Role::Responder, 2, 1, Duration::ZERO, true);
        let packets: Vec<Vec<u8>> = (0..n).map(|_| a.seal(Duration::ZERO, &[2]).unwrap()).collect();
        let counters: Vec<u64> = packets
            .iter()
            .map(|p| match wire::parse(p).unwrap() {
                Outer::Data(d) => d.counter,
                _ => unreachable!(),
            })
            .collect();
        prop_assert_eq!(&counters, &(0..n as u64).collect::<Vec<_>>());
        let t = tamper.index(n);
        let mut forged = packets[t].clone();
        *forged.last_mut().unwrap() ^= 1;
        prop_assert_eq!(b.open(Duration::ZERO, counters[t], &forged[16..]), Err(DropReason::BadTag));
        for (p, c) in packets.iter().zip(&counters) {
            prop_assert!(b.open(Duration::ZERO, *c, &p[16..]).is_ok(), "a forgery does not burn the counter");
            prop_assert_eq!(b.open(Duration::ZERO, *c, &p[16..]), Err(DropReason::CounterRejected));
        }
    }
}

// ---- Timers (§9) on two nodes ----

#[derive(Clone, Copy, Debug)]
enum Op {
    Send(usize),
    Tick(usize),
    /// Deliver the oldest datagram queued towards node `to`.
    Deliver(usize),
    Drop(usize),
    Advance(u64),
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(
        prop_oneof![
            1 => (0..2usize).prop_map(Op::Send),
            1 => (0..2usize).prop_map(Op::Tick),
            3 => (0..2usize).prop_map(Op::Deliver),
            1 => (0..2usize).prop_map(Op::Drop),
            1 => (0..12_000u64).prop_map(Op::Advance),
        ],
        1..120,
    )
}

fn wall(now: Duration) -> Tai64n {
    Tai64n::from_unix(1_767_225_600 + now.as_secs(), now.subsec_nanos())
}

fn ipv4(src: u8, dst: u8) -> Vec<u8> {
    let mut p = vec![
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, src, 10, 0, 0, dst,
    ];
    p.extend_from_slice(&[0; 8]);
    p
}

/// Queues the datagrams `from` produced and checks the structural invariants of §7.5, §7.9
/// and §8.1 on both nodes.
fn check(
    nodes: &[Node; 2],
    keys: &[PublicKey; 2],
    queues: &mut [VecDeque<Vec<u8>>; 2],
    last_message_1: &mut [Option<Duration>; 2],
    out: Vec<(PublicKey, Vec<u8>)>,
    from: usize,
    now: Duration,
) -> Result<(), TestCaseError> {
    for (to, d) in out {
        prop_assert_eq!(to, keys[1 - from]);
        if d[0] == wire::TYPE_HANDSHAKE_INIT {
            if let Some(t) = last_message_1[from] {
                prop_assert!(
                    now - t >= REKEY_TIMEOUT,
                    "message 1s are REKEY_TIMEOUT apart"
                );
            }
            last_message_1[from] = Some(now);
        }
        queues[1 - from].push_back(d);
    }
    for (i, node) in nodes.iter().enumerate() {
        let s = node.status(&keys[1 - i]).unwrap();
        prop_assert!(s.sessions <= 3);
        prop_assert_eq!(
            node.index_count(),
            s.sessions + usize::from(s.handshake_in_flight)
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn timer_invariants(ops in ops()) {
        let (ka, kb) = (StaticKey::generate(), StaticKey::generate());
        let (pa, pb) = (ka.public(), kb.public());
        let config = |k: PublicKey, host: u8| PeerConfig { public_key: k, addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, host))] };
        let mut nodes = [Node::new(ka, vec![config(pb, 2)]), Node::new(kb, vec![config(pa, 1)])];
        let keys = [pa, pb];
        let mut queues: [VecDeque<Vec<u8>>; 2] = Default::default();
        let mut last_message_1: [Option<Duration>; 2] = [None; 2];
        let mut now = Duration::ZERO;
        for op in ops {
            match op {
                Op::Send(i) => {
                    let out = nodes[i].send_packet(now, wall(now), &ipv4(i as u8 + 1, 2 - i as u8)).unwrap();
                    check(&nodes, &keys, &mut queues, &mut last_message_1, out.datagrams, i, now)?;
                }
                Op::Tick(i) => {
                    let out = nodes[i].tick(now, wall(now));
                    check(&nodes, &keys, &mut queues, &mut last_message_1, out.datagrams, i, now)?;
                    prop_assert!(nodes[i].next_deadline().is_none_or(|d| d > now), "every passed deadline ran");
                    prop_assert!(nodes[i].tick(now, wall(now)).datagrams.is_empty(), "tick is idempotent");
                }
                Op::Deliver(i) => {
                    if let Some(d) = queues[i].pop_front() {
                        if let Ok(out) = nodes[i].handle_datagram(now, wall(now), &d) {
                            check(&nodes, &keys, &mut queues, &mut last_message_1, out.datagrams, i, now)?;
                        }
                    }
                }
                Op::Drop(i) => {
                    queues[i].pop_front();
                }
                Op::Advance(ms) => now += Duration::from_millis(ms),
            }
        }
    }
}
