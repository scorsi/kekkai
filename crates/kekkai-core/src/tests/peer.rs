//! Two peers driven against each other with explicit time: slots, confirmation, rekey,
//! expiry, staging and the timers of §9.

use std::time::Duration;

use crate::handshake;
use crate::inner::Inner;
use crate::keys::{PublicKey, StaticKey};
use crate::mac1::Mac1Key;
use crate::peer::{Ctx, IndexTable, Peer};
use crate::session::Role;
use crate::tai64n::Tai64n;
use crate::wire::{self, DropReason, Outer};
use crate::{
    KEEPALIVE_TIMEOUT, MAX_STAGED_PACKETS, MAX_TIMER_HANDSHAKES, NEW_HANDSHAKE_TIMEOUT,
    PERSISTENT_KEEPALIVE, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_TIMEOUT, REKEY_TIMEOUT_JITTER,
};

const PACKET: &[u8] = &[
    0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0x66, 0xde, 10, 0, 0, 1, 10, 0, 0, 2, 8, 0, 0xf7, 0xff, 0,
    0, 0, 0,
];

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

/// The wall clock follows the monotonic one from a fixed date.
fn wall(now: Duration) -> Tai64n {
    Tai64n::from_unix(1_767_225_600 + now.as_secs(), now.subsec_nanos())
}

/// The inner plaintext of a data packet, if any, and the datagrams to send back.
type Received = (Option<Vec<u8>>, Vec<Vec<u8>>);

/// One party with a single configured peer: what the node layer will do around `Peer`.
struct Party {
    key: StaticKey,
    mac1: Mac1Key,
    indices: IndexTable,
    peer: Peer,
}

impl Party {
    fn new(key: StaticKey, remote: PublicKey) -> Self {
        let mac1 = Mac1Key::for_receiver(&key.public());
        Self {
            key,
            mac1,
            indices: IndexTable::new(),
            peer: Peer::new(remote),
        }
    }

    fn send_ip(&mut self, now: Duration) -> Vec<Vec<u8>> {
        let mut ctx = Ctx {
            now,
            wall: wall(now),
            local: &self.key,
            indices: &mut self.indices,
        };
        self.peer.send_ip(&mut ctx, PACKET)
    }

    fn tick(&mut self, now: Duration) -> Vec<Vec<u8>> {
        let mut ctx = Ctx {
            now,
            wall: wall(now),
            local: &self.key,
            indices: &mut self.indices,
        };
        self.peer.tick(&mut ctx)
    }

    /// §5.6 then the per-type processing; returns the inner plaintext of a data packet and
    /// the datagrams to send back.
    fn receive(&mut self, now: Duration, datagram: &[u8]) -> Result<Received, DropReason> {
        let mut ctx = Ctx {
            now,
            wall: wall(now),
            local: &self.key,
            indices: &mut self.indices,
        };
        match wire::parse(datagram)? {
            Outer::HandshakeInit(init) => {
                init.verify_mac1(&self.mac1)?;
                let pending =
                    handshake::read_init(&self.key, &init, &vec![self.peer.remote_static])?;
                Ok((None, vec![self.peer.accept_init(&mut ctx, pending)?]))
            }
            Outer::HandshakeResp(resp) => {
                resp.verify_mac1(&self.mac1)?;
                assert_eq!(
                    ctx.indices.owner(resp.receiver_index),
                    Some(&self.peer.remote_static)
                );
                Ok((None, self.peer.handle_resp(&mut ctx, &resp)?))
            }
            Outer::Data(data) => {
                assert_eq!(
                    ctx.indices.owner(data.receiver_index),
                    Some(&self.peer.remote_static)
                );
                let (inner, out) = self.peer.handle_data(&mut ctx, &data)?;
                Ok((Some(inner), out))
            }
        }
    }

    fn receive_ok(&mut self, now: Duration, datagram: &[u8]) -> Received {
        self.receive(now, datagram).expect("accepted")
    }
}

fn parties() -> (Party, Party) {
    let (ka, kb) = (StaticKey::generate(), StaticKey::generate());
    let (pa, pb) = (ka.public(), kb.public());
    (Party::new(ka, pb), Party::new(kb, pa))
}

/// A initiates at `now`; returns with both sides confirmed and A's packet delivered to B.
fn connected(now: Duration) -> (Party, Party) {
    let (mut a, mut b) = parties();
    let msg1 = a.send_ip(now);
    assert_eq!(msg1.len(), 1, "message 1 only");
    assert_eq!(msg1[0][0], wire::TYPE_HANDSHAKE_INIT);
    assert_eq!(a.peer.staged_packets(), 1);
    let (_, msg2) = b.receive_ok(now, &msg1[0]);
    assert_eq!(msg2.len(), 1);
    assert_eq!(msg2[0][0], wire::TYPE_HANDSHAKE_RESP);
    assert!(
        b.peer.current().is_none(),
        "a responder session waits in next"
    );
    let (_, data) = a.receive_ok(now, &msg2[0]);
    assert_eq!(data.len(), 1, "the staged packet goes out");
    assert_eq!(data[0][0], wire::TYPE_DATA);
    assert_eq!(a.peer.staged_packets(), 0);
    assert!(!a.peer.has_in_flight_handshake());
    assert_eq!(
        a.peer.current().map(|s| (s.role, s.confirmed)),
        Some((Role::Initiator, true))
    );
    let (inner, out) = b.receive_ok(now, &data[0]);
    assert_eq!(
        inner.as_deref(),
        Some(Inner::IpPacket(PACKET).encode().as_slice())
    );
    assert!(out.is_empty());
    assert_eq!(
        b.peer.current().map(|s| (s.role, s.confirmed)),
        Some((Role::Responder, true))
    );
    (a, b)
}

#[test]
fn handshake_then_data_both_ways() {
    let t0 = secs(10);
    let (mut a, mut b) = connected(t0);
    let data = b.send_ip(t0);
    assert_eq!(data.len(), 1);
    let (inner, _) = a.receive_ok(t0, &data[0]);
    assert_eq!(
        inner.as_deref(),
        Some(Inner::IpPacket(PACKET).encode().as_slice())
    );
    assert_eq!(
        a.receive(t0, &data[0]).unwrap_err(),
        DropReason::CounterRejected,
        "replayed data"
    );
    assert_eq!(
        (a.indices.len(), b.indices.len()),
        (1, 1),
        "one receiving index per side"
    );
}

#[test]
fn replayed_and_foreign_message_1_are_silent() {
    let (mut a, mut b) = parties();
    let msg1 = a.send_ip(secs(0)).remove(0);
    b.receive_ok(secs(0), &msg1);
    assert_eq!(
        b.receive(secs(1), &msg1).unwrap_err(),
        DropReason::TimestampNotNewer
    );
    let mut stranger = Party::new(StaticKey::generate(), b.key.public());
    let probe = stranger.send_ip(secs(2)).remove(0);
    assert_eq!(
        b.receive(secs(2), &probe).unwrap_err(),
        DropReason::IdentityRejected
    );
    let mut bad_mac = msg1.clone();
    bad_mac[20] ^= 1;
    assert_eq!(
        b.receive(secs(3), &bad_mac).unwrap_err(),
        DropReason::BadMac1
    );
}

#[test]
fn initiator_rekeys_and_old_sessions_expire() {
    let t0 = secs(0);
    let (mut a, mut b) = connected(t0);
    let t1 = t0 + REKEY_AFTER_TIME;
    let out = a.send_ip(t1);
    assert_eq!(
        out.len(),
        2,
        "the packet on the old session and a new message 1"
    );
    assert_eq!(
        (out[0][0], out[1][0]),
        (wire::TYPE_DATA, wire::TYPE_HANDSHAKE_INIT)
    );
    b.receive_ok(t1, &out[0]);
    let (_, msg2) = b.receive_ok(t1, &out[1]);
    let (_, keepalive) = a.receive_ok(t1, &msg2[0]);
    assert_eq!(a.peer.current().map(|s| s.created), Some(t1));
    assert_eq!(a.indices.len(), 2, "current and previous");
    let (inner, _) = b.receive_ok(t1, &keepalive[0]);
    assert_eq!(inner.as_deref(), Some(&[crate::inner::KEEPALIVE][..]));
    assert_eq!(
        b.peer.current().map(|s| (s.role, s.created)),
        Some((Role::Responder, t1))
    );
    assert_eq!(b.indices.len(), 2);
    let t2 = t0 + REJECT_AFTER_TIME;
    let out = a.tick(t2);
    assert_eq!(
        out.len(),
        1,
        "only the persistent keepalive of the new session"
    );
    assert_eq!(out[0].len(), 33);
    assert_eq!(a.indices.len(), 1, "the session created at t0 is discarded");
    let t3 = t2 + secs(1000);
    assert!(
        a.tick(t3).is_empty(),
        "nothing to send after a long suspend"
    );
    assert!(a.peer.current().is_none());
    assert!(a.indices.is_empty());
    assert_eq!(a.peer.next_deadline(), None);
    let out = a.send_ip(t3);
    assert_eq!(out.len(), 1, "re-handshakes on demand");
    assert_eq!(out[0][0], wire::TYPE_HANDSHAKE_INIT);
}

#[test]
fn keepalive_and_new_handshake_timers() {
    let t0 = secs(0);
    let (mut a, mut b) = connected(t0);
    assert_eq!(
        b.peer.next_deadline(),
        Some(t0 + KEEPALIVE_TIMEOUT),
        "passive keepalive after A's data"
    );
    assert_eq!(
        a.peer.next_deadline(),
        Some(t0 + NEW_HANDSHAKE_TIMEOUT),
        "data sent, nothing received yet"
    );
    assert!(b.tick(t0 + secs(9)).is_empty());
    let keepalive = b.tick(t0 + KEEPALIVE_TIMEOUT);
    assert_eq!(keepalive.len(), 1);
    assert_eq!(keepalive[0].len(), 33);
    let (inner, _) = a.receive_ok(t0 + KEEPALIVE_TIMEOUT, &keepalive[0]);
    assert_eq!(inner.as_deref(), Some(&[crate::inner::KEEPALIVE][..]));
    assert_eq!(
        a.peer.next_deadline(),
        Some(t0 + PERSISTENT_KEEPALIVE),
        "the keepalive answered; no ping-pong"
    );
    let out = a.tick(t0 + PERSISTENT_KEEPALIVE);
    assert_eq!(out.len(), 1, "persistent keepalive");
    assert_eq!(out[0].len(), 33);

    // Data that gets no answer at all triggers a handshake 15 s later.
    let t1 = t0 + secs(60);
    a.send_ip(t1);
    assert!(a.tick(t1 + NEW_HANDSHAKE_TIMEOUT - secs(1)).is_empty());
    let out = a.tick(t1 + NEW_HANDSHAKE_TIMEOUT);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0][0], wire::TYPE_HANDSHAKE_INIT);
}

#[test]
fn responder_rekeys_when_the_initiator_did_not() {
    let t0 = secs(0);
    let (mut a, mut b) = connected(t0);
    let t1 = t0 + crate::RESPONDER_REKEY_AFTER_TIME;
    let data = a.send_ip(t1);
    let (_, out) = b.receive_ok(t1, &data[0]);
    assert_eq!(out.len(), 1, "the responder initiates");
    assert_eq!(out[0][0], wire::TYPE_HANDSHAKE_INIT);
    let (_, msg2) = a.receive_ok(t1, &out[0]);
    let (_, keepalive) = b.receive_ok(t1, &msg2[0]);
    a.receive_ok(t1, &keepalive[0]);
    assert_eq!(
        a.peer.current().map(|s| (s.role, s.created)),
        Some((Role::Responder, t1))
    );
    assert_eq!(
        b.peer.current().map(|s| (s.role, s.created)),
        Some((Role::Initiator, t1))
    );
}

#[test]
fn retransmits_then_abandons() {
    let t0 = secs(0);
    let (mut a, _) = parties();
    for _ in 0..MAX_STAGED_PACKETS + 2 {
        a.send_ip(t0);
    }
    assert_eq!(
        a.peer.staged_packets(),
        MAX_STAGED_PACKETS,
        "the oldest staged packets are dropped"
    );
    assert_eq!(a.indices.len(), 1, "one in-flight handshake");
    let mut sent = 1;
    let last = loop {
        let deadline = a.peer.next_deadline().expect("retransmit pending");
        assert!(
            deadline >= t0 + REKEY_TIMEOUT * sent
                && deadline < t0 + (REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER) * sent
        );
        let out = a.tick(deadline);
        if out.is_empty() {
            break deadline;
        }
        assert_eq!(out[0][0], wire::TYPE_HANDSHAKE_INIT);
        sent += 1;
    };
    assert_eq!(sent, MAX_TIMER_HANDSHAKES);
    assert!(last >= t0 + secs(90));
    assert!(!a.peer.has_in_flight_handshake());
    assert_eq!(
        a.peer.staged_packets(),
        0,
        "staged packets dropped on abandon"
    );
    assert!(a.indices.is_empty());
    assert_eq!(a.peer.next_deadline(), None);
    let out = a.send_ip(last + secs(1));
    assert_eq!(out.len(), 1, "the next packet starts over");
}

#[test]
fn staged_packets_flow_when_the_session_opens() {
    let t0 = secs(0);
    let (mut a, mut b) = parties();
    let msg1 = a.send_ip(t0).remove(0);
    assert!(
        a.send_ip(t0 + secs(1)).is_empty(),
        "no second message 1 within REKEY_TIMEOUT"
    );
    let (_, msg2) = b.receive_ok(t0, &msg1);
    let (_, data) = a.receive_ok(t0 + secs(1), &msg2[0]);
    assert_eq!(data.len(), 2);
    let counters: Vec<u64> = data
        .iter()
        .map(|d| match wire::parse(d).unwrap() {
            Outer::Data(d) => d.counter,
            _ => panic!("data"),
        })
        .collect();
    assert_eq!(
        counters,
        [0, 1],
        "counters are consecutive and never reused"
    );
}
