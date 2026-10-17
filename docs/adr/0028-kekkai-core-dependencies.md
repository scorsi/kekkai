# ADR 0028 — Non-cryptographic dependencies of kekkai-core

Status: Proposed — 2026-10-17

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
