//! kekkai-core: the sans-IO protocol core (ADR 0004).
//!
//! This crate implements `docs/spec/protocol.md`; section numbers in comments refer to it.
//! It owns no socket, thread, timer or file: the IO layer feeds datagrams and the two clocks
//! in and gets datagrams and deadlines out. Monotonic time is a [`Duration`] elapsed since an
//! arbitrary origin fixed by the IO layer (suspend-aware); the wall clock enters only as a
//! [`tai64n::Tai64n`] when a handshake is initiated (§7.4).

#![forbid(unsafe_code)]

use std::time::Duration;

pub mod firewall;
pub mod handshake;
pub mod inner;
pub mod keys;
pub mod lighthouse;
pub mod mac1;
pub mod node;
pub mod peer;
pub mod relay;
mod resolver;
pub mod session;
pub mod tai64n;
pub mod tlv;
pub mod wire;

#[cfg(test)]
mod tests;

// §3 Constants.

/// Wire version written in every outer header and bound by the Noise prologue.
pub const WIRE_VERSION: u8 = 1;
/// Noise prologue: ASCII `kekkai` followed by [`WIRE_VERSION`] as one byte (§7.1).
pub const PROLOGUE: &[u8; 7] = b"kekkai\x01";
/// Noise protocol name (§2).
pub const NOISE_PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// Pre-shared key at psk position 2, all zeros in v0 (§7.1).
pub const PSK: [u8; 32] = [0; 32];
/// Label hashed with the receiver's static public key into the `mac1` key (§5.5).
pub const MAC1_LABEL: &[u8] = b"kekkai mac1";
/// TAI64 label plus the 10 leap seconds of the TAI epoch (§7.4).
pub const TAI64_OFFSET: u64 = 0x4000_0000_0000_000a;
/// Handshake timestamps are aligned down to this many nanoseconds (§7.4).
pub const TAI64N_NSEC_ALIGN: u32 = 1 << 24;

/// Receive-side replay window, in packets (§8.4).
pub const COUNTER_WINDOW_SIZE: u64 = 8192 - 64;
/// An initiator rekeys once its sending counter reaches this value (§8.6).
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// No counter at or above this value is ever sent or accepted (§8.4, §8.6):
/// `2^64 − COUNTER_WINDOW_SIZE − 1`.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - COUNTER_WINDOW_SIZE;

pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const REKEY_TIMEOUT_JITTER: Duration = Duration::from_millis(333);
pub const MAX_TIMER_HANDSHAKES: u32 = 18;
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub const PERSISTENT_KEEPALIVE: Duration = Duration::from_secs(25);
/// `REJECT_AFTER_TIME − KEEPALIVE_TIMEOUT − REKEY_TIMEOUT`: the responder's rekey safety net (§8.6).
pub const RESPONDER_REKEY_AFTER_TIME: Duration = Duration::from_secs(165);
/// `KEEPALIVE_TIMEOUT + REKEY_TIMEOUT`: data sent without any answer triggers a handshake (§9).
pub const NEW_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// A rediscovery that completes no handshake within this delay records a direct-path
/// failure (§12.6); the relay fallback starts there in v0.5 (§12.3).
pub const DIRECT_PATH_TIMEOUT: Duration = Duration::from_secs(3);
/// While relayed, a direct path is retried this often (§12.3, v0.5).
pub const DIRECT_RETRY_INTERVAL: Duration = Duration::from_secs(60);
/// A lighthouse registration expires this long after its last refresh (§13.2).
pub const LIGHTHOUSE_ENTRY_TIMEOUT: Duration = Duration::from_secs(75);
/// Consecutive failed keepalives towards a lighthouse that trigger §12.5 rule 4.
pub const KEEPALIVE_FAILURES_BEFORE_REREGISTER: u32 = 3;
/// Most candidate endpoints of one in-flight handshake (§17).
pub const MAX_CANDIDATES: usize = 32;

/// Overlay MTU; configurable downwards only (§17).
pub const MTU: usize = 1280;
/// Largest datagram accepted or produced (§17).
pub const MAX_DATAGRAM: usize = 1378;
/// Largest payload of a `relay_forward` (§14, §17).
pub const MAX_RELAY_PAYLOAD: usize = 1313;
/// Most endpoints in one `endpoints` TLV (§10.5).
pub const MAX_ENDPOINTS: usize = 16;
/// Most local endpoints a node registers (§13.1).
pub const MAX_LOCAL_ENDPOINTS: usize = 8;
/// IP packets staged per peer while a handshake is in flight (§8.7).
pub const MAX_STAGED_PACKETS: usize = 128;
