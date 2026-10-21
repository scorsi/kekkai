//! kekkai's `snow` crypto resolver (§8.5, ADR 0028 amendment 2026-10-21): the same X25519,
//! ChaCha20-Poly1305 and BLAKE2s as `snow`'s default resolver, with objects that erase the
//! secrets they hold on drop and their scratch before each call returns. Randomness is
//! delegated to `snow`'s default resolver.

use blake2::Blake2s256;
use blake2::digest::Digest;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use curve25519_dalek::montgomery::MontgomeryPoint;
use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use zeroize::{Zeroize, ZeroizeOnDrop};

const TAG_LEN: usize = 16;
const BLOCK_LEN: usize = 64;
const HASH_LEN: usize = 32;

pub(crate) struct Resolver;

impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        DefaultResolver.resolve_rng()
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        matches!(choice, DHChoice::Curve25519).then(|| Box::<X25519>::default() as Box<dyn Dh>)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        matches!(choice, HashChoice::Blake2s).then(|| Box::<Blake2s>::default() as Box<dyn Hash>)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        matches!(choice, CipherChoice::ChaChaPoly).then(|| {
            Box::new(ChaChaPoly(ChaCha20Poly1305::new(&[0; 32].into()))) as Box<dyn Cipher>
        })
    }
}

/// X25519 through `curve25519-dalek`, as `snow`'s `Dh25519`; the private key is erased on drop.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub(crate) struct X25519 {
    privkey: [u8; 32],
    pubkey: [u8; 32],
}

impl X25519 {
    fn derive_pubkey(&mut self) {
        self.pubkey = MontgomeryPoint::mul_base_clamped(self.privkey).to_bytes();
    }
}

impl Dh for X25519 {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        32
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn set(&mut self, privkey: &[u8]) {
        self.privkey.copy_from_slice(&privkey[..32]);
        self.derive_pubkey();
    }

    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), snow::Error> {
        rng.try_fill_bytes(&mut self.privkey)?;
        self.derive_pubkey();
        Ok(())
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    fn privkey(&self) -> &[u8] {
        &self.privkey
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        let point: [u8; 32] = pubkey[..32].try_into().expect("32-byte slice");
        let mut shared = MontgomeryPoint(point).mul_clamped(self.privkey);
        out[..32].copy_from_slice(&shared.0);
        shared.0.zeroize();
        Ok(())
    }
}

/// ChaCha20-Poly1305 holding the `chacha20poly1305` AEAD object, which erases its key on drop
/// (so also when `set` replaces it). Nonce: 4 zero bytes then the counter in LE64, as `snow`.
struct ChaChaPoly(ChaCha20Poly1305);

fn nonce(n: u64) -> chacha20poly1305::Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce.into()
}

impl Cipher for ChaChaPoly {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8; 32]) {
        self.0 = ChaCha20Poly1305::new(key.into());
    }

    fn encrypt(&self, n: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let len = plaintext.len();
        out[..len].copy_from_slice(plaintext);
        let tag = self
            .0
            .encrypt_in_place_detached(&nonce(n), authtext, &mut out[..len])
            .expect("snow bounds the plaintext length");
        out[len..len + TAG_LEN].copy_from_slice(&tag);
        len + TAG_LEN
    }

    fn decrypt(
        &self,
        n: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, snow::Error> {
        let len = ciphertext.len() - TAG_LEN;
        out[..len].copy_from_slice(&ciphertext[..len]);
        self.0
            .decrypt_in_place_detached(
                &nonce(n),
                authtext,
                &mut out[..len],
                ciphertext[len..].into(),
            )
            .map_err(|_| snow::Error::Decrypt)?;
        Ok(len)
    }
}

/// BLAKE2s with `hmac` and `hkdf` overridden to erase their pads, inner digest and temporary
/// key. The `blake2` hasher state itself is not erased (§8.5 "Not covered").
#[derive(Default)]
struct Blake2s(Blake2s256);

impl Hash for Blake2s {
    fn name(&self) -> &'static str {
        "BLAKE2s"
    }

    fn block_len(&self) -> usize {
        BLOCK_LEN
    }

    fn hash_len(&self) -> usize {
        HASH_LEN
    }

    fn reset(&mut self) {
        Digest::reset(&mut self.0);
    }

    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        self.0.finalize_into_reset((&mut out[..HASH_LEN]).into());
    }

    fn hmac(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) {
        assert!(
            key.len() <= BLOCK_LEN,
            "unexpectedly large key length for hmac"
        );
        let mut ipad = [0x36u8; BLOCK_LEN];
        let mut opad = [0x5cu8; BLOCK_LEN];
        for (i, k) in key.iter().enumerate() {
            ipad[i] ^= k;
            opad[i] ^= k;
        }
        let mut inner = [0u8; HASH_LEN];
        self.reset();
        self.input(&ipad);
        self.input(data);
        self.result(&mut inner);
        self.input(&opad);
        self.input(&inner);
        self.result(out);
        ipad.zeroize();
        opad.zeroize();
        inner.zeroize();
    }

    fn hkdf(
        &mut self,
        chaining_key: &[u8],
        input_key_material: &[u8],
        outputs: usize,
        out1: &mut [u8],
        out2: &mut [u8],
        out3: &mut [u8],
    ) {
        let mut temp_key = [0u8; HASH_LEN];
        let mut input = [0u8; HASH_LEN + 1];
        self.hmac(chaining_key, input_key_material, &mut temp_key);
        self.hmac(&temp_key, &[1], out1);
        if outputs >= 2 {
            input[..HASH_LEN].copy_from_slice(&out1[..HASH_LEN]);
            input[HASH_LEN] = 2;
            self.hmac(&temp_key, &input, out2);
        }
        if outputs >= 3 {
            input[..HASH_LEN].copy_from_slice(&out2[..HASH_LEN]);
            input[HASH_LEN] = 3;
            self.hmac(&temp_key, &input, out3);
        }
        temp_key.zeroize();
        input.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_private_key_is_erased() {
        fn erased_on_drop<T: ZeroizeOnDrop>() {}
        erased_on_drop::<X25519>();
        let mut dh = X25519::default();
        dh.set(&[7; 32]);
        assert_eq!(dh.privkey(), &[7; 32]);
        dh.zeroize();
        assert_eq!(dh.privkey(), &[0; 32]);
    }

    #[test]
    fn same_outputs_as_snow_default_resolver() {
        let ours = Resolver;
        let theirs = DefaultResolver;
        let mut a = ours.resolve_hash(&HashChoice::Blake2s).unwrap();
        let mut b = theirs.resolve_hash(&HashChoice::Blake2s).unwrap();
        for key_len in [0, 1, 32, 63, 64] {
            for data_len in [0, 1, 33, 64, 65, 200] {
                let key: Vec<u8> = (0..key_len).map(|i| i as u8 ^ 0xa5).collect();
                let data: Vec<u8> = (0..data_len).map(|i| i as u8).collect();
                let (mut x, mut y) = ([0u8; 64], [0u8; 64]);
                a.hmac(&key, &data, &mut x);
                b.hmac(&key, &data, &mut y);
                assert_eq!(x, y, "hmac key {key_len} data {data_len}");
                for outputs in 1..=3 {
                    let (mut x, mut y) = ([[0u8; 64]; 3], [[0u8; 64]; 3]);
                    let [x1, x2, x3] = &mut x;
                    a.hkdf(&key, &data, outputs, x1, x2, x3);
                    let [y1, y2, y3] = &mut y;
                    b.hkdf(&key, &data, outputs, y1, y2, y3);
                    assert_eq!(x, y, "hkdf key {key_len} data {data_len} outputs {outputs}");
                }
            }
        }
        let peer = MontgomeryPoint::mul_base_clamped([9; 32]).to_bytes();
        let mut x = ours.resolve_dh(&DHChoice::Curve25519).unwrap();
        let mut y = theirs.resolve_dh(&DHChoice::Curve25519).unwrap();
        x.set(&[3; 32]);
        y.set(&[3; 32]);
        assert_eq!(x.pubkey(), y.pubkey());
        let (mut p, mut q) = ([0u8; 32], [0u8; 32]);
        x.dh(&peer, &mut p).unwrap();
        y.dh(&peer, &mut q).unwrap();
        assert_eq!(p, q);
    }
}
