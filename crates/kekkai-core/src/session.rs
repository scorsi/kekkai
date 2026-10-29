//! Sessions and transport (§8): one completed handshake, its counter, its replay window.

use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::handshake::SessionKeys;
use crate::wire::{self, DropReason};
use crate::{COUNTER_WINDOW_SIZE, REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME};

const WORDS: u64 = 128;
const BITS_PER_WORD: u64 = 64;

/// Sliding window over the counter space (§8.4), as Linux WireGuard's `counter_validate`:
/// `last` is the highest counter accepted, the bitmap covers the `WORDS × 64` counters below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayWindow {
    last: u64,
    bitmap: [u64; WORDS as usize],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            last: 0,
            bitmap: [0; WORDS as usize],
        }
    }

    /// Pre-check: would `counter` be accepted now? Nothing is recorded.
    pub fn check(&self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        if counter > self.last {
            return true;
        }
        if self.last - counter >= COUNTER_WINDOW_SIZE {
            return false;
        }
        !self.bit(counter)
    }

    /// Records an accepted counter, only after the AEAD succeeded and `check` passed.
    pub fn mark(&mut self, counter: u64) {
        debug_assert!(self.check(counter), "mark() after a passing check()");
        if counter > self.last {
            let current_word = self.last / BITS_PER_WORD;
            let top = (counter / BITS_PER_WORD - current_word).min(WORDS);
            for i in 1..=top {
                self.bitmap[((current_word + i) % WORDS) as usize] = 0;
            }
            self.last = counter;
        }
        self.bitmap[(counter / BITS_PER_WORD % WORDS) as usize] |= 1 << (counter % BITS_PER_WORD);
    }

    fn bit(&self, counter: u64) -> bool {
        self.bitmap[(counter / BITS_PER_WORD % WORDS) as usize] & (1 << (counter % BITS_PER_WORD))
            != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// One session (§8.1). The sending counter is private and only ever incremented, so a nonce
/// cannot be reused under a key by construction; the ciphers zeroize their keys on drop.
pub struct Session {
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    pub local_index: u32,
    pub remote_index: u32,
    pub(crate) sending_counter: u64,
    window: ReplayWindow,
    pub created: Duration,
    pub confirmed: bool,
    pub role: Role,
    pub last_sent: Option<Duration>,
    pub last_received: Option<Duration>,
    /// With a PKI, the fingerprint of the certificate the peer sent in the handshake that
    /// made the session (§8.1).
    pub fingerprint: Option<[u8; 32]>,
}

impl Session {
    pub fn new(
        keys: SessionKeys,
        role: Role,
        local_index: u32,
        remote_index: u32,
        created: Duration,
        confirmed: bool,
    ) -> Self {
        Self {
            send: ChaCha20Poly1305::new((&keys.send).into()),
            recv: ChaCha20Poly1305::new((&keys.recv).into()),
            local_index,
            remote_index,
            sending_counter: 0,
            window: ReplayWindow::new(),
            created,
            confirmed,
            role,
            last_sent: None,
            last_received: None,
            fingerprint: None,
        }
    }

    pub fn age(&self, now: Duration) -> Duration {
        now.saturating_sub(self.created)
    }

    /// Live: younger than `REJECT_AFTER_TIME`. The counter bound of §8.1 is enforced by the
    /// window on receipt and by `seal` on send.
    pub fn is_live(&self, now: Duration) -> bool {
        self.age(now) < REJECT_AFTER_TIME
    }

    /// Data is sent only on a live, confirmed session whose counter is not exhausted (§8.1, §8.3).
    pub fn can_send(&self, now: Duration) -> bool {
        self.is_live(now) && self.confirmed && self.sending_counter < REJECT_AFTER_MESSAGES
    }

    #[cfg(test)]
    pub(crate) fn window(&self) -> &ReplayWindow {
        &self.window
    }

    pub fn sending_counter(&self) -> u64 {
        self.sending_counter
    }

    /// §8.2 sending: the counter advances before encryption and never rolls back. `None` once
    /// the counter reached `REJECT_AFTER_MESSAGES` (§8.5): the session can no longer send.
    pub fn seal(&mut self, now: Duration, inner: &[u8]) -> Option<Vec<u8>> {
        if self.sending_counter >= REJECT_AFTER_MESSAGES {
            return None;
        }
        let counter = self.sending_counter;
        self.sending_counter += 1;
        let mut packet = Vec::with_capacity(wire::DATA_HEADER_LEN + inner.len() + 16);
        packet.extend_from_slice(&wire::data_header(self.remote_index, counter));
        packet.extend(
            self.send
                .encrypt(&nonce(counter), inner)
                .expect("ChaCha20-Poly1305 encryption is total"),
        );
        self.last_sent = Some(now);
        Some(packet)
    }

    /// §8.2 receiving, steps 2 to 4: window pre-check, decrypt, then mark. A forged packet
    /// with a fresh counter does not burn that counter.
    pub fn open(
        &mut self,
        now: Duration,
        counter: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DropReason> {
        if !self.window.check(counter) {
            return Err(DropReason::CounterRejected);
        }
        let inner = self
            .recv
            .decrypt(&nonce(counter), ciphertext)
            .map_err(|_| DropReason::BadTag)?;
        self.window.mark(counter);
        self.last_received = Some(now);
        Ok(inner)
    }
}

/// `0x00000000 || counter as u64 little endian` (§8.2, the Noise layout).
fn nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n.into()
}
