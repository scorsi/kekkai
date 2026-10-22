//! The lighthouse's registrations (§13.2): `pubkey → { observed, locals, refreshed }`, in
//! memory only, expiring `LIGHTHOUSE_ENTRY_TIMEOUT` after the last refresh. The messages are
//! handled by [`crate::node::Node`] in its lighthouse role (§10.2).

use std::collections::HashMap;
use std::time::Duration;

use crate::inner::Endpoint;
use crate::keys::PublicKey;
use crate::relay::Bucket;
use crate::{DIRECT_PATH_TIMEOUT, LIGHTHOUSE_ENTRY_TIMEOUT};

/// One registered node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// UDP source of the last authenticated datagram from the node (§13.2).
    pub observed: Endpoint,
    /// The node's own local endpoints, at most `MAX_LOCAL_ENDPOINTS`.
    pub locals: Vec<Endpoint>,
    pub refreshed: Duration,
}

impl Registration {
    /// `[observed, locals...]` without repeating the observed one (§13.2).
    pub fn endpoints(&self) -> Vec<Endpoint> {
        let mut all = vec![self.observed];
        all.extend(self.locals.iter().filter(|e| **e != self.observed));
        all
    }
}

/// Aggregate counters, the only thing a lighthouse reports about its activity (ADR 0012).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LighthouseCounters {
    pub registers: u64,
    pub queries_known: u64,
    pub queries_unknown: u64,
    pub punches: u64,
    /// Queries over the sender's budget, dropped unanswered (§13.2).
    pub queries_limited: u64,
}

#[derive(Default)]
pub(crate) struct Registry {
    entries: HashMap<PublicKey, Registration>,
    pub(crate) counters: LighthouseCounters,
    /// Per-sender query budgets (§13.2).
    budgets: HashMap<PublicKey, Bucket>,
}

impl Registry {
    pub(crate) fn register(
        &mut self,
        key: PublicKey,
        observed: Endpoint,
        locals: Vec<Endpoint>,
        now: Duration,
    ) {
        self.counters.registers += 1;
        self.entries.insert(
            key,
            Registration {
                observed,
                locals,
                refreshed: now,
            },
        );
    }

    /// An authenticated datagram from `key` came from `from`: a node that moved is answered
    /// with its new address before its next register (§13.2). Does not refresh the entry.
    pub(crate) fn observe(&mut self, key: &PublicKey, from: Endpoint) {
        if let Some(r) = self.entries.get_mut(key) {
            r.observed = from;
        }
    }

    /// §13.2 query budget: `2 × listed` queries, refilled by `listed` every
    /// `DIRECT_PATH_TIMEOUT`, per querier; a well-behaved node queries each of its peers at
    /// most once per `DIRECT_PATH_TIMEOUT` (§12.5). Counts a refusal.
    pub(crate) fn budget(&mut self, querier: PublicKey, now: Duration, listed: usize) -> bool {
        let listed = listed.max(1) as u64;
        let ok = self.budgets.entry(querier).or_default().take(
            now,
            2 * listed,
            DIRECT_PATH_TIMEOUT * 2,
            1,
        );
        if !ok {
            self.counters.queries_limited += 1;
        }
        ok
    }

    /// The unexpired entry of `key`.
    pub(crate) fn lookup(&self, key: &PublicKey, now: Duration) -> Option<&Registration> {
        self.entries
            .get(key)
            .filter(|r| now < r.refreshed + LIGHTHOUSE_ENTRY_TIMEOUT)
    }

    /// A reload removed `key` from the peer list (spec §4.1).
    pub(crate) fn forget(&mut self, key: &PublicKey) {
        self.entries.remove(key);
        self.budgets.remove(key);
    }

    /// Drops expired entries and those of keys no longer listed.
    pub(crate) fn expire(&mut self, now: Duration, listed: impl Fn(&PublicKey) -> bool) {
        self.entries
            .retain(|k, r| listed(k) && now < r.refreshed + LIGHTHOUSE_ENTRY_TIMEOUT);
        self.budgets.retain(|k, _| listed(k));
    }

    pub(crate) fn entries(&self, now: Duration) -> Vec<(PublicKey, Registration)> {
        let mut all: Vec<_> = self
            .entries
            .iter()
            .filter(|(k, _)| self.lookup(k, now).is_some())
            .map(|(k, r)| (*k, r.clone()))
            .collect();
        all.sort_by_key(|e| e.0);
        all
    }
}
