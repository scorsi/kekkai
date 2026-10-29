//! TAI64N handshake timestamps (§7.4).

use crate::{TAI64_OFFSET, TAI64N_NSEC_ALIGN};

/// `seconds (8, big endian) || nanoseconds (4, big endian)`. The derived ordering is the
/// bytewise (`memcmp`) comparison of §7.4; the default value is the initial `last_timestamp`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tai64n(pub [u8; 12]);

impl Tai64n {
    /// Encodes a wall-clock reading. Nanoseconds are aligned down to [`TAI64N_NSEC_ALIGN`]
    /// so that about 24 bits of clock precision are hidden from peers.
    pub fn from_unix(unix_seconds: u64, nanoseconds: u32) -> Self {
        // Overflow needs a Unix time past 2^62 seconds: wrapping keeps the function total.
        let seconds = TAI64_OFFSET.wrapping_add(unix_seconds);
        let nanoseconds = nanoseconds - nanoseconds % TAI64N_NSEC_ALIGN;
        let mut bytes = [0u8; 12];
        bytes[..8].copy_from_slice(&seconds.to_be_bytes());
        bytes[8..].copy_from_slice(&nanoseconds.to_be_bytes());
        Self(bytes)
    }

    /// The wall clock in whole Unix seconds (§4.3 step 8), as encoded by [`Self::from_unix`].
    pub fn unix_seconds(&self) -> u64 {
        let seconds = u64::from_be_bytes(self.0[..8].try_into().expect("8 bytes"));
        seconds.wrapping_sub(TAI64_OFFSET)
    }

    /// Responder rule: a message 1 is accepted only if its timestamp is bytewise strictly
    /// greater than the last accepted one from the same static key.
    pub fn is_newer_than(&self, last_accepted: &Tai64n) -> bool {
        self > last_accepted
    }
}
