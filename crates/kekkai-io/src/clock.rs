//! The two clocks of ADR 0004: a suspend-aware monotonic clock for every timer, the wall
//! clock only for the handshake timestamp (spec §7.4).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kekkai_core::tai64n::Tai64n;

/// Linux `CLOCK_BOOTTIME`; elsewhere `CLOCK_MONOTONIC`, which on macOS keeps counting during
/// sleep (it is `mach_continuous_time`).
#[cfg(target_os = "linux")]
const CLOCK: libc::clockid_t = libc::CLOCK_BOOTTIME;
#[cfg(not(target_os = "linux"))]
const CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC;

/// Monotonic time since the clock's origin; time spent suspended counts.
pub fn monotonic() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid timespec; the clock id exists on every supported target.
    let ret = unsafe { libc::clock_gettime(CLOCK, &mut ts) };
    assert_eq!(ret, 0, "clock_gettime cannot fail with a valid clock id");
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// The wall clock as a handshake timestamp.
pub fn wall() -> Tai64n {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Tai64n::from_unix(now.as_secs(), now.subsec_nanos())
}
