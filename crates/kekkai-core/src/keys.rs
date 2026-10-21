//! Identity keys (§4, ADR 0017).

use base64::{Engine as _, engine::general_purpose::STANDARD};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::Dh;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::resolver::X25519;

/// A static X25519 public key.
pub type PublicKey = [u8; 32];

/// A static X25519 private key, received from the IO layer as an opaque value, never a path
/// (ADR 0017). Zeroized on drop; deliberately not `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StaticKey([u8; 32]);

impl StaticKey {
    /// Accepts any 32 bytes: X25519 clamps internally, so an unclamped key yields the same
    /// public key as its clamped form (§4).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// `kekkai keygen`: 32 random bytes, clamped (§4).
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        fill_random(&mut bytes);
        clamp(&mut bytes);
        Self(bytes)
    }

    /// The same key in clamped form.
    pub fn clamped(&self) -> Self {
        let mut bytes = self.0;
        clamp(&mut bytes);
        Self(bytes)
    }

    /// `X25519(k, 9)`, through the handshake's X25519 so that the two cannot disagree. The
    /// resolver object holding the key copy is erased when it drops here (§8.5).
    pub fn public(&self) -> PublicKey {
        let mut dh = X25519::default();
        dh.set(&self.0);
        dh.pubkey()
            .try_into()
            .expect("X25519 public keys are 32 bytes")
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Text form: standard base64 with padding, one line (§4).
    pub fn to_text(&self) -> String {
        STANDARD.encode(self.0)
    }

    /// Parses the text form; `None` unless it decodes to exactly 32 bytes.
    pub fn from_text(text: &str) -> Option<Self> {
        decode_key(text).map(Self)
    }

    /// [`Self::from_text`] for the content of a key file, which is erased before returning,
    /// on success and on failure (§8.5).
    pub fn from_file_text(mut text: String) -> Option<Self> {
        let key = Self::from_text(&text);
        text.zeroize();
        key
    }
}

/// Clears bits 0, 1, 2 of byte 0 and bit 7 of byte 31, sets bit 6 of byte 31 (§4).
pub fn clamp(key: &mut [u8; 32]) {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
}

/// Text form of a public key: standard base64 with padding, one line (§4).
pub fn public_key_to_text(key: &PublicKey) -> String {
    STANDARD.encode(key)
}

/// Parses the text form of a public key; `None` unless it decodes to exactly 32 bytes.
pub fn public_key_from_text(text: &str) -> Option<PublicKey> {
    decode_key(text)
}

/// Decodes into a stack buffer that is erased on every path (§8.5); 33 bytes is the decoder's
/// estimate for a 44-character key, and longer input is refused before any byte is written.
fn decode_key(text: &str) -> Option<[u8; 32]> {
    let mut buf = Zeroizing::new([0u8; 33]);
    let len = STANDARD.decode_slice(text.trim(), buf.as_mut()).ok()?;
    (len == 32).then(|| buf[..32].try_into().expect("32 bytes"))
}

/// Fills `dest` from the OS random source, through snow's resolver so the core has a single
/// source of randomness.
pub(crate) fn fill_random(dest: &mut [u8]) {
    DefaultResolver
        .resolve_rng()
        .expect("snow's default resolver provides an RNG")
        .try_fill_bytes(dest)
        .expect("the OS random source failed");
}
