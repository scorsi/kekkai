# ADR 0003 — Cryptographic foundations and protocol specification

Status: Accepted — 2026-10-13

## Context

A home-grown protocol is a learning goal, but inventing cryptography is not. Reviewers must be able to compare the design with known constructions.

## Options considered

- Reuse WireGuard's protocol as is (boringtun or a kernel module): proven, but leaves no room for the inner control protocol, relaying and identity extension the project needs.
- Design on top of the Noise framework with standard primitives, through a maintained Rust implementation.
- Design a custom key exchange: rejected outright.

## Decision

- The protocol is **built only on proven building blocks**. Complete list of primitives the spec may cite; nothing else is used:
  - **Noise framework**, pattern `IKpsk2`, through the `snow` crate (0007).
  - **X25519** for the handshake's Diffie-Hellman.
  - **ChaCha20-Poly1305** as the Noise AEAD and for the transport.
  - **BLAKE2s** as the Noise hash and, in keyed mode, as the MAC of `mac1`, `mac2` and the cookie (0009).
  - **XChaCha20-Poly1305** (24-byte nonce) for `cookie_reply`, reserved and not sent in v0 (0007, 0009).
  - **Ed25519** for signatures: certificates in v1 only; no node signs anything in v0 (0017).
  - **TAI64N** as the handshake timestamp format (0007).

  **No invented primitive, no custom mode of operation.** Everything outside Noise (`mac1`, `mac2`, cookie) is hand-written glue around `snow` using the RustCrypto crates, and is treated as cryptographic code for review purposes (0021).
- The **protocol specification is a document in its own right**, `docs/spec/protocol.md`, with a shared test-vector directory `docs/spec/vectors/`. The code implements the spec; the spec is what reviewers read.
- The specification covers at least: notation, cryptographic suite, handshake (0007), sessions and timers (0008), wire format and inner protocol (0009), lighthouse messages (0012), NAT traversal procedure (0013), relay messages (0014), constants, registries of message and TLV types, and test vectors.

## Consequences

- A change to the protocol is a change to the spec first, then to the code, then to the vectors.
- Review requests (0021) always ship the spec and the threat model with the code.
