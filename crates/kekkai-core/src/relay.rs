//! The relay's per-sender state (§14.2) and the token bucket shared with the lighthouse's
//! query budget (§13.2). The forwarding itself is done by [`crate::node::Node`] in its relay
//! role (§10.2). The relay copies `relay_forward` payloads as opaque bytes: nothing here
//! holds, derives or reads a key of a session between two nodes.

use std::collections::HashMap;
use std::time::Duration;

use crate::keys::PublicKey;

/// A token bucket refilled with `burst` tokens every `per`, holding at most `burst`; a new
/// bucket is full. Exact integer arithmetic: the level is kept in token-nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bucket {
    level: u128,
    at: Duration,
}

impl Default for Bucket {
    fn default() -> Self {
        Self {
            level: u128::MAX,
            at: Duration::ZERO,
        }
    }
}

impl Bucket {
    /// Takes `cost` tokens if the bucket holds them at `now`; otherwise takes nothing.
    pub fn take(&mut self, now: Duration, burst: u64, per: Duration, cost: u64) -> bool {
        let per = per.as_nanos().max(1);
        let elapsed = now.saturating_sub(self.at).as_nanos();
        self.level = self
            .level
            .saturating_add(elapsed.saturating_mul(u128::from(burst)))
            .min(u128::from(burst) * per);
        self.at = self.at.max(now);
        let cost = u128::from(cost) * per;
        if self.level < cost {
            return false;
        }
        self.level -= cost;
        true
    }
}

/// What the relay counts per sender (§14.2): forwarded `relay_forward`s, their payload
/// bytes, and the drops.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SenderCounters {
    pub forwarded_packets: u64,
    pub forwarded_bytes: u64,
    /// Destination unlisted or without a live session with the relay (§14.2 step 1).
    pub dropped_no_route: u64,
    /// Over the per-sender rate limit (§14.2 step 2).
    pub dropped_rate_limited: u64,
}

/// The relay role's whole state beside its sessions with the listed nodes: per sender, the
/// counters and the rate-limit bucket. No key material, by construction.
pub(crate) struct Forwarder {
    /// Payload bytes per second per sender; `None`: no limit (ADR 0014).
    pub(crate) limit: Option<u64>,
    pub(crate) senders: HashMap<PublicKey, (SenderCounters, Bucket)>,
}

impl Forwarder {
    pub(crate) fn new(limit: Option<u64>) -> Self {
        Self {
            limit,
            senders: HashMap::new(),
        }
    }

    /// §14.2 step 2: whether `sender` may forward `bytes` now; counts a refusal.
    pub(crate) fn admit(&mut self, sender: PublicKey, now: Duration, bytes: usize) -> bool {
        let (counters, bucket) = self.senders.entry(sender).or_default();
        let ok = self
            .limit
            .is_none_or(|limit| bucket.take(now, limit, Duration::from_secs(1), bytes as u64));
        if !ok {
            counters.dropped_rate_limited += 1;
        }
        ok
    }

    pub(crate) fn counters(&mut self, sender: PublicKey) -> &mut SenderCounters {
        &mut self.senders.entry(sender).or_default().0
    }
}
