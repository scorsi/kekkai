# ADR 0007 — Handshake

Status: Accepted — 2026-10-13

## Context

The handshake is frozen in v0 and must carry certificates in v1 without change. It must satisfy "silent to the unknown" (0006) while costing one round trip. Identities in v0 are static X25519 keys listed in a Nix-generated configuration.

## Options considered

- **Noise IK** (WireGuard): one round trip; the initiator must know the responder's static key in advance; the initiator's identity is encrypted to the responder; the responder never replies to an unknown initiator.
- **Noise XX**: no prior knowledge, identities travel encrypted in payloads, which suits certificates naturally; but 1.5 round trips, and the responder reveals its static key to any active initiator, so a scanner can fingerprint a lighthouse. Violates "silent to the unknown".
- **Noise IX** (Nebula): one round trip, no identity hiding at all.

## Decision

- Pattern **`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`**, through `snow`. This is exactly WireGuard's instantiation, chosen so that its published analyses (Donenfeld and Milner's Tamarin model, Dowling and Paterson) apply to the handshake unchanged; BLAKE2s over SHA-256 for that reason alone. The pre-shared key is all zeros in v0; the psk slot is the entry point for a post-quantum hybrid later (a KEM-derived psk, as Rosenpass does), without changing the pattern.
- **Prologue** binds the protocol name and the wire version (`kekkai` + version, 0009).
- **Anti-replay of message 1**: the message 1 payload carries a standard 12-byte TAI64N timestamp (8-byte seconds since the TAI epoch, `0x400000000000000a` + Unix seconds, then 4-byte nanoseconds, big endian). A responder rejects a message 1 whose timestamp is not strictly greater (bytewise `memcmp`) than the last accepted one from that static key, and stores the new one only on success: WireGuard's rule. Precision is reduced as in the Linux kernel implementation (`drivers/net/wireguard/noise.c`, `tai64n_now`): the nanoseconds are aligned down to the largest power of two not above `1e9 / INITIATIONS_PER_SECOND` with `INITIATIONS_PER_SECOND = 50`, that is 2^24 ns (about 16.8 ms), to avoid leaking a precise clock.
- **Payloads are TLV lists** (encoding in 0009). v0: message 1 carries the timestamp TLV only, message 2 is empty. v1 adds a certificate TLV in both. An unknown non-critical TLV is ignored; an unknown **critical** TLV (high bit of the type set) makes the handshake fail **silently**. The critical bit is set by the sender. The v1 certificate TLV is **non-critical**: a v0 receiver skips it and authenticates on the static key alone, while a v1 receiver's identity trait decides whether a missing certificate is a rejection. Requiring a certificate is therefore a receiver-side policy, never a wire-level flag, which is what makes a mixed v0 and v1 network possible during migration. Non-canonical TLV lists are rejected. TLV types are registered in the spec.
- **Identity verification is behind a trait**: it receives the peer's static key and the handshake TLVs and answers accept or reject. v0 implementation: "is this key in the peer list". v1: certificate verification against a CA, groups, expiry. The handshake code does not change between the two.
- **Denial of service**: no cookie in v0. Handshake messages carry WireGuard's `mac1` (keyed on the receiver's static public key, checked before any Diffie-Hellman) and a zero `mac2` slot; a `cookie_reply` message type is reserved (0009) so that the cookie mechanism can be added when a real need appears.
- **Clocks**: the core receives two clocks from the IO layer (0004): a monotonic one for every timer, and the wall clock only to produce TAI64N. If the wall clock goes backwards (a host booting before NTP has run), the node's own message 1s carry timestamps older than the last one its peers accepted and are rejected until the clock passes that value; the node can still answer handshakes initiated by its peers. WireGuard's behaviour, accepted in v0, with a warning logged when a peer stops answering handshakes for longer than `REJECT_AFTER_TIME`.
- **Certificates and the lighthouse (v1 reasoning, recorded now)**: with IK, a node must know a peer's static key before initiating. In v1 the lighthouse will distribute certificates signed by the CA, and each node verifies them itself. A compromised lighthouse can therefore withhold a certificate, never forge an identity, which stays within the denial-of-service class of 0006.

## Consequences

- A node without the lighthouse can only reach statically configured peers (acceptable: configuration is the source of truth in v0).
- A responder performs two X25519 operations per message 1 before authenticating; accepted in v0 (0006).
- Handshake messages are the only place where the wire version is interpreted (0009).
