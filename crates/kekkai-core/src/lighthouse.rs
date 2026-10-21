//! The lighthouse's registrations (§13.2): `pubkey → { observed, locals, refreshed }`, in
//! memory only, expiring `LIGHTHOUSE_ENTRY_TIMEOUT` after the last refresh. The messages are
//! handled by [`crate::node::Node`] in its lighthouse role (§10.2).

use std::collections::HashMap;
use std::time::Duration;

use crate::LIGHTHOUSE_ENTRY_TIMEOUT;
use crate::inner::Endpoint;
use crate::keys::PublicKey;

/// One registered node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// UDP source of the authenticated `lighthouse_register` datagram.
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
}

#[derive(Default)]
pub(crate) struct Registry {
    entries: HashMap<PublicKey, Registration>,
    pub(crate) counters: LighthouseCounters,
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

    /// The unexpired entry of `key`.
    pub(crate) fn lookup(&self, key: &PublicKey, now: Duration) -> Option<&Registration> {
        self.entries
            .get(key)
            .filter(|r| now < r.refreshed + LIGHTHOUSE_ENTRY_TIMEOUT)
    }

    /// Drops expired entries and those of keys no longer listed.
    pub(crate) fn expire(&mut self, now: Duration, listed: impl Fn(&PublicKey) -> bool) {
        self.entries
            .retain(|k, r| listed(k) && now < r.refreshed + LIGHTHOUSE_ENTRY_TIMEOUT);
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
