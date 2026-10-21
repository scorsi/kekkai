# ADR 0028 — Non-cryptographic dependencies of kekkai-core

Status: Accepted — 2026-10-17

## Context

ADR 0003 fixes the cryptographic building blocks: `snow` for the Noise handshake and the
RustCrypto crates for the hand-written glue. Implementing the core (v0.1b) needed two things
outside that list: the base64 text form of keys (spec §4) and a JSON reader for the test
vectors (ADR 0020 says both test suites load JSON files but names no crate). Any extra
dependency is an ADR, not a `cargo add` (ADR 0002, 0003).

## Options considered

- Hand-written base64 and a hand-written JSON reader: more code to review for no gain.
- `x25519-dalek` for public-key derivation and `rand_core` for indices and jitter: two more
  direct dependencies, when `snow` already exposes both through its `CryptoResolver`.
- `snow`'s `TransportState` for data packets: it owns its own nonce, which the session must
  control (the counter travels in the header and the replay window reorders, spec §8.2, §8.4).

## Decision

- `kekkai-core` depends on **`base64`** (standard alphabet with padding, spec §4) as its only
  non-cryptographic runtime dependency, and on **`serde`** and **`serde_json`** as
  dev-dependencies to load `docs/spec/vectors/*.json`.
- The RustCrypto crates used directly are exactly those `snow` already pulls: **`blake2`**
  (`mac1`), **`chacha20poly1305`** (transport AEAD) and **`zeroize`** (keys). They are the
  "RustCrypto crates" of ADR 0003; this list is recorded so that `cargo tree` can be checked
  against it. No `subtle`: the constant-time `mac1` comparison is `digest::Mac::verify_slice`.
- X25519 public keys and every random byte (indices, jitter) come from `snow`'s default
  resolver, so the core has one DH implementation and one randomness source.
- `snow` is built with the `risky-raw-split` feature: the handshake hands its two transport
  keys to the session type, which owns the sending counter and the replay window and runs
  the AEAD of spec §8.2 itself.

## Consequences

- The direct dependency list of `kekkai-core` is: `snow`, `blake2`, `chacha20poly1305`,
  `zeroize`, `base64`; tests add `serde`, `serde_json`. Anything else is a new ADR.
- The transport AEAD and nonce formation are glue in the sense of ADR 0021 and are covered by
  `handshake.json` (`data_packets`, `rejected`).
- The test tools named in ADR 0020 (`proptest`, cargo-fuzz / `libfuzzer-sys` in the `fuzz`
  crate) are covered by ADR 0020 and need no new ADR.

## Amendment — 2026-10-21: kekkai's own `snow` resolver, for key erasure

Review gate 1 (ADR 0021) found that `snow` 0.10 erases none of its secrets: its default
resolver keeps the static and ephemeral private keys and the cipher keys in plain arrays
that are freed without being overwritten (findings C1, F2). The owner decided to fix what
can be fixed from outside `snow`:

- `kekkai-core` supplies its own `snow::resolvers::CryptoResolver` and builds every
  handshake state with it (`Builder::with_resolver`). Its X25519 (`Dh`), ChaCha20-Poly1305
  (`Cipher`) and BLAKE2s (`Hash`) objects erase what they hold on drop and their scratch
  before each call returns; the `Hash` object overrides `hmac` and `hkdf` to erase their
  intermediates. `resolve_rng` delegates to `snow`'s default resolver, so the core keeps one
  randomness source. The exact erasure lifecycle and what stays uncovered (`snow`'s
  `SymmetricState` and stack temporaries, the `blake2` hasher state) are in spec §8.5.
- Crates: **`curve25519-dalek`** (X25519 through `MontgomeryPoint::mul_base_clamped` and
  `mul_clamped`, the same calls as `snow`'s default resolver, so the core still has one
  X25519 implementation), **`chacha20poly1305`** (whose AEAD object already erases its key
  on drop), **`blake2`** and **`zeroize`**. `curve25519-dalek` becomes a direct dependency;
  it is already in the dependency set (4.1.3, pulled by `snow`) and is declared with
  `default-features = false` as `snow` does, so `cargo tree` gains no crate.
  `x25519-dalek` is still not used. The direct dependency list of `kekkai-core` becomes:
  `snow`, `curve25519-dalek`, `blake2`, `chacha20poly1305`, `zeroize`, `base64`.
- `kekkai-io` gains no dependency: its key loader hands the file text to `kekkai-core`,
  which erases it and the decoded bytes once the `StaticKey` is built or parsing fails.
- The bullet "X25519 public keys ... come from `snow`'s default resolver" above is
  replaced by this amendment for X25519; random bytes still come from that resolver.
- `noise_ikpsk2.json` and `handshake.json` must reproduce unchanged through the kekkai
  resolver; that is its correctness check.
