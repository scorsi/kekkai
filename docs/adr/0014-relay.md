# ADR 0014 — Relay

Status: Accepted — 2026-10-13

## Context

When no direct path exists (symmetric NAT on both sides, CGNAT, hostile firewall), traffic must go through a public host that must not be able to read it, and must not be an open relay (0006).

## Options considered

- A DERP-like relay with its own framing and TLS sessions: a second protocol to secure.
- The relay as an ordinary Noise peer that forwards opaque payloads of the A↔B session.

## Decision

- **The relay is a peer like any other.** Each node keeps a permanent Noise session with each configured relay. To reach B through relay R, A sends in its A↔R session the inner message `relay_forward { to: pubkey_B, payload }` where `payload` is a complete outer packet of the A↔B session (handshake or data). R re-emits it as `relay_forwarded { from: pubkey_A, payload }` inside its R↔B session. The A↔B handshake therefore runs through R exactly as it would directly.
- **Double encryption**: R sees only ciphertext of the A↔B session. R needs no coordination: A and B only have to be connected to the same relay, which the shared configuration guarantees.
- A packet received through `relay_forwarded` **never updates the peer's endpoint**; it marks the path as relayed through R. Only packets received directly move an endpoint (0013).
- **Relay list**: configured as a list from the start, one element supported in v0. Later: try relays in configuration order, the first that carries a complete handshake wins (same rule as 0013).
- **Quotas**: only listed peers can use the relay, so abuse means a compromised node. A **per-sender maximum rate** is configurable, disabled by default; per-sender byte counters exist regardless, for observability.
- **What the relay learns and keeps**: public keys of both ends, source addresses, sizes, timing, counters. Nothing on disk, aggregate counters only in logs (0006).
- **Transport**: UDP only in v0. The core treats datagrams abstractly so a TCP/443 adapter can be added later without touching the wire format (0027).
- **Proof that the relay sees only ciphertext** (milestone v0.5): a `tcpdump` capture on the relay host during a ping with a known payload pattern, asserting the pattern is absent; a unit test asserting the relay's state holds no key material of a node pair; and a review that `kekkai-relay` depends on no tunnel-decryption code path.

## Consequences

- MTU budget accounts for the second encryption layer (0009).
- Relay CPU cost is one ChaCha20-Poly1305 decrypt and encrypt per packet, acceptable on a small VPS.

## Amendment — 2026-10-21: "no dependency on the tunnel decryption path"

Owner decision: "tunnel" means the node's TUN path. The relay links `kekkai-core`'s session code
for its own authenticated sessions with each node, but never decrypts the payloads it carries
(they are opaque `relay_forward`/`relay_forwarded` bytes between two nodes), has no `tun` feature
and no dependency on `kekkai-node`. The `relay-has-no-tunnel` flake check enforces the latter.
