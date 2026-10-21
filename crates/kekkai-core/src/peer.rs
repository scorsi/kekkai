//! Per-peer state (§7.5 to §9): session slots, the in-flight handshake, staged packets, the
//! `last_timestamp` entry and every timer. Routing a datagram to its peer (by decrypted
//! static key for message 1, by index otherwise) is the party-level caller's job.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use crate::handshake::{Initiator, Pending};
use crate::inner::{self, Inner};
use crate::keys::{self, PublicKey, StaticKey};
use crate::session::{Role, Session};
use crate::tai64n::Tai64n;
use crate::wire::{Data, DropReason, HandshakeResp};
use crate::{
    KEEPALIVE_TIMEOUT, MAX_STAGED_PACKETS, MAX_TIMER_HANDSHAKES, NEW_HANDSHAKE_TIMEOUT,
    PERSISTENT_KEEPALIVE, REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES,
    REKEY_AFTER_TIME, REKEY_TIMEOUT, REKEY_TIMEOUT_JITTER, RESPONDER_REKEY_AFTER_TIME,
};

/// The party-wide index table of §7.5: every live receiving session and in-flight handshake
/// owns one random 32-bit index, unique across the party, so `data` and `handshake_resp`
/// reach their peer without trial decryption.
#[derive(Default)]
pub struct IndexTable {
    owners: HashMap<u32, PublicKey>,
}

impl IndexTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Draws a fresh index for `owner`; a collision is resolved by drawing again.
    pub fn allocate(&mut self, owner: PublicKey) -> u32 {
        loop {
            if let Entry::Vacant(slot) = self.owners.entry(random_u32()) {
                let index = *slot.key();
                slot.insert(owner);
                return index;
            }
        }
    }

    pub fn release(&mut self, index: u32) {
        self.owners.remove(&index);
    }

    /// The peer a `receiver_index` belongs to.
    pub fn owner(&self, index: u32) -> Option<&PublicKey> {
        self.owners.get(&index)
    }

    pub fn len(&self) -> usize {
        self.owners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    keys::fill_random(&mut b);
    u32::from_be_bytes(b)
}

fn jitter() -> Duration {
    let span = REKEY_TIMEOUT_JITTER.as_millis() as u64 + 1;
    Duration::from_millis(u64::from(random_u32()) % span)
}

/// What every call needs from the party (ADR 0004): the monotonic instant, the wall clock
/// already encoded (read only to build message 1, §7.4), the static key and the index table.
pub struct Ctx<'a> {
    pub now: Duration,
    pub wall: Tai64n,
    pub local: &'a StaticKey,
    pub indices: &'a mut IndexTable,
}

struct InFlight {
    initiator: Initiator,
    /// Message 1 copies sent so far, the first one included.
    attempts: u32,
    deadline: Duration,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Current,
    Previous,
    Next,
}

/// Traffic counters of one peer (§12.6), datagram sizes on the underlay, every outer type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    /// Data packets refused by the replay window (§8.4).
    pub replay_rejections: u64,
    /// `ip_packet`s from this peer refused by the inbound firewall (§15).
    pub firewall_drops: u64,
    /// Completed handshakes as initiator (§7.7) and as responder (§7.6).
    pub handshakes_initiated: u64,
    pub handshakes_responded: u64,
    /// Handshakes abandoned after `MAX_TIMER_HANDSHAKES` attempts (§7.9).
    pub handshake_timeouts: u64,
}

/// One configured peer. Holds at most three sessions (§8.1) plus one in-flight initiator
/// handshake (ADR 0008) and `MAX_STAGED_PACKETS` staged packets.
pub struct Peer {
    pub remote_static: PublicKey,
    current: Option<Session>,
    previous: Option<Session>,
    next: Option<Session>,
    in_flight: Option<InFlight>,
    staged: VecDeque<Vec<u8>>,
    /// §7.4: survives session expiry; lost on restart.
    last_timestamp: Tai64n,
    last_init_sent: Option<Duration>,
    new_handshake_at: Option<Duration>,
    passive_keepalive_at: Option<Duration>,
    /// §12.6, kept by the party-level caller.
    pub counters: Counters,
    /// §12.6: instant of the last completed handshake, either role.
    pub last_handshake: Option<Duration>,
}

impl Peer {
    pub fn new(remote_static: PublicKey) -> Self {
        Self {
            remote_static,
            current: None,
            previous: None,
            next: None,
            in_flight: None,
            staged: VecDeque::new(),
            last_timestamp: Tai64n::default(),
            last_init_sent: None,
            new_handshake_at: None,
            passive_keepalive_at: None,
            counters: Counters::default(),
            last_handshake: None,
        }
    }

    pub fn current(&self) -> Option<&Session> {
        self.current.as_ref()
    }

    pub fn has_in_flight_handshake(&self) -> bool {
        self.in_flight.is_some()
    }

    pub fn staged_packets(&self) -> usize {
        self.staged.len()
    }

    /// §11 outbound: sends `packet` as `ip_packet` on `current`, or stages it and initiates
    /// (§8.7). Applies the initiator rekey rule (§8.6). Returns the datagrams to send.
    pub fn send_ip(&mut self, ctx: &mut Ctx<'_>, packet: &[u8]) -> Vec<Vec<u8>> {
        self.expire(ctx);
        let inner = Inner::IpPacket(packet).encode();
        let mut out = Vec::with_capacity(2);
        if self.current.as_ref().is_some_and(|s| s.can_send(ctx.now)) {
            out.extend(self.seal_on_current(ctx, &inner, false));
        } else {
            if self.staged.len() == MAX_STAGED_PACKETS {
                self.staged.pop_front();
            }
            self.staged.push_back(inner);
            out.extend(self.initiate(ctx));
        }
        out
    }

    /// §7.6 steps 3 to 8 for a message 1 that [`crate::handshake::read_init`] accepted for
    /// this peer's key. Returns message 2.
    pub fn accept_init(
        &mut self,
        ctx: &mut Ctx<'_>,
        pending: Pending,
    ) -> Result<Vec<u8>, DropReason> {
        self.expire(ctx);
        if !pending.timestamp.is_newer_than(&self.last_timestamp) {
            return Err(DropReason::TimestampNotNewer);
        }
        let (remote_index, timestamp) = (pending.remote_index, pending.timestamp);
        let local_index = ctx.indices.allocate(self.remote_static);
        let (datagram, keys) = pending.respond(local_index);
        Self::retire(&mut self.next, ctx.indices);
        self.next = Some(Session::new(
            keys,
            Role::Responder,
            local_index,
            remote_index,
            ctx.now,
            false,
        ));
        self.last_timestamp = timestamp;
        self.last_handshake = Some(ctx.now);
        self.counters.handshakes_responded += 1;
        self.after_authenticated_receive();
        Ok(datagram)
    }

    /// §7.7. The caller did §5.6 and routed by `receiver_index`. Returns the staged packets
    /// or a keepalive on the new session.
    pub fn handle_resp(
        &mut self,
        ctx: &mut Ctx<'_>,
        resp: &HandshakeResp<'_>,
    ) -> Result<Vec<Vec<u8>>, DropReason> {
        self.expire(ctx);
        let flight = self
            .in_flight
            .as_mut()
            .filter(|f| f.initiator.sender_index == resp.receiver_index);
        let keys = flight
            .ok_or(DropReason::UnknownIndex)?
            .initiator
            .finish(resp)?;
        let flight = self.in_flight.take().expect("checked above");
        // The handshake's index becomes the session's local index: no release.
        let session = Session::new(
            keys,
            Role::Initiator,
            flight.initiator.sender_index,
            resp.sender_index,
            ctx.now,
            true,
        );
        self.promote(session, ctx);
        self.last_handshake = Some(ctx.now);
        self.counters.handshakes_initiated += 1;
        self.after_authenticated_receive();
        if self.staged.is_empty() {
            return Ok(self.send_keepalive(ctx));
        }
        Ok(self.send_staged(ctx))
    }

    /// §8.2 steps 1 to 5 and the responder rekey rule (§8.6). Returns the inner plaintext
    /// (for [`Inner::decode`] and §10.2 by the caller) and any datagram to send.
    pub fn handle_data(
        &mut self,
        ctx: &mut Ctx<'_>,
        data: &Data<'_>,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), DropReason> {
        self.expire(ctx);
        let slot = self
            .slot_of(data.receiver_index)
            .ok_or(DropReason::UnknownIndex)?;
        let session = self.slot_mut(slot).as_mut().expect("slot_of found it");
        let inner = session.open(ctx.now, data.counter, data.ciphertext)?;
        self.after_authenticated_receive();
        if inner.first() != Some(&inner::KEEPALIVE) && self.passive_keepalive_at.is_none() {
            self.passive_keepalive_at = Some(ctx.now + KEEPALIVE_TIMEOUT);
        }
        let mut out = Vec::new();
        let responder_rekey = slot == Slot::Current
            && self.current.as_ref().is_some_and(|s| {
                s.role == Role::Responder && s.age(ctx.now) >= RESPONDER_REKEY_AFTER_TIME
            });
        if responder_rekey {
            out.extend(self.initiate(ctx));
        }
        if slot == Slot::Next {
            // Step 5: the confirmed responder session ends any in-flight sequence (not an
            // abandonment) and carries the staged packets; no keepalive if there is none.
            let mut session = self.next.take().expect("slot_of found it");
            session.confirmed = true;
            self.promote(session, ctx);
            self.abort_in_flight(ctx);
            out.extend(self.send_staged(ctx));
        }
        Ok((inner, out))
    }

    /// Runs every deadline that has passed (§9). The IO layer calls it at least about once
    /// per second and after every `next_deadline`.
    pub fn tick(&mut self, ctx: &mut Ctx<'_>) -> Vec<Vec<u8>> {
        self.expire(ctx);
        let now = ctx.now;
        let mut out = Vec::new();
        if let Some(attempts) = self
            .in_flight
            .as_ref()
            .filter(|f| f.deadline <= now)
            .map(|f| f.attempts)
        {
            self.abort_in_flight(ctx);
            if attempts >= MAX_TIMER_HANDSHAKES {
                self.counters.handshake_timeouts += 1;
                self.staged.clear();
            } else {
                out.push(self.send_message_1(ctx, attempts + 1));
            }
        }
        if self.new_handshake_at.is_some_and(|t| t <= now) {
            self.new_handshake_at = None;
            out.extend(self.initiate(ctx));
        }
        if self.passive_keepalive_at.is_some_and(|t| t <= now) {
            self.passive_keepalive_at = None;
            out.extend(self.send_keepalive(ctx));
        }
        if self.persistent_keepalive_at().is_some_and(|t| t <= now) {
            out.extend(self.send_keepalive(ctx));
        }
        out
    }

    /// The earliest pending deadline (§9), or `None` when nothing is pending.
    pub fn next_deadline(&self) -> Option<Duration> {
        let reject = self.sessions().map(|s| s.created + REJECT_AFTER_TIME).min();
        [
            self.in_flight.as_ref().map(|f| f.deadline),
            self.new_handshake_at,
            self.passive_keepalive_at,
            self.persistent_keepalive_at(),
            reject,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn persistent_keepalive_at(&self) -> Option<Duration> {
        self.current
            .as_ref()
            .filter(|s| s.confirmed && s.sending_counter() < REJECT_AFTER_MESSAGES)
            .map(|s| s.last_sent.unwrap_or(s.created) + PERSISTENT_KEEPALIVE)
    }

    /// §8.5 on reload: a peer removed from the list loses its sessions, handshake and
    /// staged packets; the indices are released and the keys zeroized by the drops.
    pub fn forget(&mut self, indices: &mut IndexTable) {
        for slot in [&mut self.current, &mut self.previous, &mut self.next] {
            Self::retire(slot, indices);
        }
        if let Some(flight) = self.in_flight.take() {
            indices.release(flight.initiator.sender_index);
        }
        self.staged.clear();
    }

    pub(crate) fn sessions(&self) -> impl Iterator<Item = &Session> {
        [&self.current, &self.previous, &self.next]
            .into_iter()
            .flatten()
    }

    fn slot_of(&self, local_index: u32) -> Option<Slot> {
        [
            (Slot::Current, &self.current),
            (Slot::Previous, &self.previous),
            (Slot::Next, &self.next),
        ]
        .into_iter()
        .find(|(_, s)| s.as_ref().is_some_and(|s| s.local_index == local_index))
        .map(|(slot, _)| slot)
    }

    fn slot_mut(&mut self, slot: Slot) -> &mut Option<Session> {
        match slot {
            Slot::Current => &mut self.current,
            Slot::Previous => &mut self.previous,
            Slot::Next => &mut self.next,
        }
    }

    /// §8.5: discards every session older than `REJECT_AFTER_TIME`, so a clock that jumped
    /// forward by a long suspend expires everything at the next call.
    fn expire(&mut self, ctx: &mut Ctx<'_>) {
        for slot in [&mut self.current, &mut self.previous, &mut self.next] {
            if slot.as_ref().is_some_and(|s| !s.is_live(ctx.now)) {
                Self::retire(slot, ctx.indices);
            }
        }
    }

    /// Drops a session: its index is released and its keys are zeroized by the drop.
    fn retire(slot: &mut Option<Session>, indices: &mut IndexTable) {
        if let Some(session) = slot.take() {
            indices.release(session.local_index);
        }
    }

    /// A new confirmed session becomes `current`, `current` becomes `previous`, the old
    /// `previous` is discarded (§8.5).
    fn promote(&mut self, session: Session, ctx: &mut Ctx<'_>) {
        Self::retire(&mut self.previous, ctx.indices);
        self.previous = self.current.take();
        self.current = Some(session);
    }

    /// §7.9: a trigger starts an attempt sequence unless one is in flight (it is left
    /// unchanged: only its retransmit deadline advances it) or a message 1 went out less
    /// than `REKEY_TIMEOUT` ago.
    fn initiate(&mut self, ctx: &mut Ctx<'_>) -> Option<Vec<u8>> {
        if self.in_flight.is_some()
            || self
                .last_init_sent
                .is_some_and(|t| ctx.now.saturating_sub(t) < REKEY_TIMEOUT)
        {
            return None;
        }
        Some(self.send_message_1(ctx, 1))
    }

    /// Builds a fresh message 1 (new ephemeral, timestamp and index) and arms the retransmit timer.
    fn send_message_1(&mut self, ctx: &mut Ctx<'_>, attempts: u32) -> Vec<u8> {
        let index = ctx.indices.allocate(self.remote_static);
        let (initiator, datagram) = Initiator::new(ctx.local, &self.remote_static, index, ctx.wall);
        self.in_flight = Some(InFlight {
            initiator,
            attempts,
            deadline: ctx.now + REKEY_TIMEOUT + jitter(),
        });
        self.last_init_sent = Some(ctx.now);
        datagram
    }

    fn abort_in_flight(&mut self, ctx: &mut Ctx<'_>) {
        if let Some(flight) = self.in_flight.take() {
            ctx.indices.release(flight.initiator.sender_index);
        }
    }

    /// §8.7: the staged packets, in FIFO order, each once, on the new `current`.
    fn send_staged(&mut self, ctx: &mut Ctx<'_>) -> Vec<Vec<u8>> {
        let staged: Vec<Vec<u8>> = self.staged.drain(..).collect();
        staged
            .iter()
            .flat_map(|inner| self.seal_on_current(ctx, inner, false))
            .collect()
    }

    fn send_keepalive(&mut self, ctx: &mut Ctx<'_>) -> Vec<Vec<u8>> {
        self.seal_on_current(ctx, &Inner::Keepalive.encode(), true)
    }

    /// Seals `inner` on `current` if it can send, then applies the initiator rekey rule
    /// (§8.6) to that send, keepalives included: message 1 follows the packet.
    fn seal_on_current(
        &mut self,
        ctx: &mut Ctx<'_>,
        inner: &[u8],
        keepalive: bool,
    ) -> Vec<Vec<u8>> {
        let Some(session) = self.current.as_mut().filter(|s| s.can_send(ctx.now)) else {
            return Vec::new();
        };
        let rekey = session.role == Role::Initiator
            && (session.age(ctx.now) >= REKEY_AFTER_TIME
                || session.sending_counter() >= REKEY_AFTER_MESSAGES);
        let mut out: Vec<Vec<u8>> = session.seal(ctx.now, inner).into_iter().collect();
        self.after_send(ctx.now, keepalive);
        if rekey {
            out.extend(self.initiate(ctx));
        }
        out
    }

    /// Sending anything cancels the passive keepalive; sending data arms "new handshake" (§9).
    fn after_send(&mut self, now: Duration, keepalive: bool) {
        self.passive_keepalive_at = None;
        if !keepalive && self.new_handshake_at.is_none() {
            self.new_handshake_at = Some(now + NEW_HANDSHAKE_TIMEOUT);
        }
    }

    /// Any authenticated packet from the peer answers the "new handshake" timer (§9).
    fn after_authenticated_receive(&mut self) {
        self.new_handshake_at = None;
    }
}
