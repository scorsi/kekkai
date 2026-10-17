//! `mac1` and the zero `mac2` slot (§5.5): keyed BLAKE2s-128 over every byte before the slot.

use blake2::digest::Mac;
use blake2::digest::consts::U16;
use blake2::{Blake2s256, Blake2sMac, Digest};

use crate::MAC1_LABEL;
use crate::keys::PublicKey;
use crate::wire::DropReason;

/// The two 16-byte MAC slots at the end of every handshake message.
pub const MAC_SLOTS_LEN: usize = 32;

/// `mac1_key = BLAKE2s(MAC1_LABEL || receiver_static_public_key)`. Depends only on the
/// receiver's static key, so a party computes its own once.
#[derive(Clone)]
pub struct Mac1Key([u8; 32]);

impl Mac1Key {
    /// The receiver is the party the message is sent to: the responder for `handshake_init`,
    /// the initiator for `handshake_resp`.
    pub fn for_receiver(receiver_static_public: &PublicKey) -> Self {
        Self(
            Blake2s256::new()
                .chain_update(MAC1_LABEL)
                .chain_update(receiver_static_public)
                .finalize()
                .into(),
        )
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `mac1 = BLAKE2s(key = mac1_key, out = 16, covered)` where `covered` is the message
    /// without its two MAC slots.
    pub fn compute(&self, covered: &[u8]) -> [u8; 16] {
        Blake2sMac::<U16>::new_from_slice(&self.0)
            .expect("a 32-byte key fits BLAKE2s")
            .chain_update(covered)
            .finalize()
            .into_bytes()
            .into()
    }

    /// Checks the `mac1` slot of a whole handshake message in constant time, before any
    /// Diffie-Hellman. `mac2` is not checked in v0. Not authentication: anyone who knows the
    /// receiver's public key can compute it.
    pub fn verify(&self, message: &[u8]) -> Result<(), DropReason> {
        let covered_len = message
            .len()
            .checked_sub(MAC_SLOTS_LEN)
            .ok_or(DropReason::BadLength)?;
        Blake2sMac::<U16>::new_from_slice(&self.0)
            .expect("a 32-byte key fits BLAKE2s")
            .chain_update(&message[..covered_len])
            .verify_slice(&message[covered_len..covered_len + 16])
            .map_err(|_| DropReason::BadMac1)
    }
}
