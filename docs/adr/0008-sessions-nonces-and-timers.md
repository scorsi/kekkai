# ADR 0008 — Sessions, nonces and timers

Status: Accepted — 2026-10-13

## Context

After the handshake, the transport needs nonce management, replay protection, rekeying and session expiry. These values are easy to get subtly wrong and are well analysed in WireGuard.

## Options considered

- Invent values and justify them: no benefit, more review burden.
- Copy WireGuard's constants, which the reviewers know.

## Decision

- **Nonce**: a 64-bit counter per session direction, never reused; the counter travels in the header (0009).
- **Replay window**: sliding bitmap window as in the Linux kernel implementation, `COUNTER_WINDOW_SIZE = 8192 − 64 = 8128` packets per receiving session.
- **Session identification**: each side picks a random 32-bit **receiver index** at handshake time; data packets carry the receiver's index, so there is no trial decryption.
- **Timers** (WireGuard values, `drivers/net/wireguard/messages.h`): `REKEY_AFTER_TIME = 120 s`, `REKEY_AFTER_MESSAGES = 2^60`, `REJECT_AFTER_TIME = 180 s`, `REJECT_AFTER_MESSAGES = 2^64 − COUNTER_WINDOW_SIZE − 1`, `REKEY_TIMEOUT = 5 s` with jitter up to 333 ms, `MAX_TIMER_HANDSHAKES = 18` (abandon after 90 s), passive `KEEPALIVE_TIMEOUT = 10 s` (answer received data that got no reply), and a persistent keepalive of 25 s towards every peer with a session, every lighthouse and every relay (0013). A new session replaces the old one once the first authenticated packet arrives on it; the old one is kept until `REJECT_AFTER_TIME` to absorb reordering.
- **Concurrent initiations** (both sides initiate at once): as in WireGuard, both handshakes may complete and both sessions exist; each side sends on the most recently established session and accepts on any live one; the loser expires by the timers above. No tie-break rule. Written in the spec.
- **Static key rotation**: out of v0. Rotating a node's identity means a new key in secrets, a new public key in configuration and a redeployment.

## Consequences

- All constants live in one place in the spec and in the core, and the deterministic simulation (0020) drives time explicitly to exercise each of them.
- The session store is bounded: at most two sessions per peer plus one in-flight handshake.
