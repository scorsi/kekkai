# ADR 0013 — NAT traversal, path selection and roaming

Status: Accepted — 2026-10-13

## Context

Hosts sit behind consumer NATs, CGNAT and hypervisor NATs, on Wi-Fi, and move. Direct paths are preferred, relays (0014) are the fallback.

## Options considered

- Full ICE with RTT-based candidate ranking: a lot of code for a handful of nodes.
- Tailscale-style symmetric-NAT port prediction: clever, fragile, later if ever.
- "Try every candidate, first complete handshake wins", with a relay fallback.

## Decision

- **Candidates** to reach peer B: static endpoints from configuration, endpoints returned by the lighthouse (observed and local), IPv4 and IPv6. A sends `handshake_init` to all candidates in parallel; B, told by `lighthouse_punch`, sends towards A's candidates. **The first completed handshake wins** and the path is kept until the session is lost.
- **Relay fallback**: if no direct handshake completes within **3 s**, A goes through a relay (0014). While relayed, A retries a direct path every **60 s** and switches as soon as one completes. If a direct session dies (rejected after 180 s without valid traffic, 0008) the same 3 s window applies before falling back again. Both constants are configurable.
- **Symmetric NAT**: nothing special. If one side is symmetric the candidates sometimes work; if both are, the relay takes over.
- **Roaming**: any authenticated data packet **received directly** updates the peer's endpoint to the observed source address (WireGuard's rule). A packet of the A↔B session that arrives inside `relay_forwarded` updates the **path** (relayed through R), never the endpoint: the observed source there is the relay's, inside the A↔R session (0014).
- **Full rediscovery** (lighthouse query, every candidate in parallel, relay fallback) is triggered for a peer by any of: the first IP packet towards a peer without a session; a handshake towards a peer that gets no answer within `REKEY_TIMEOUT` (one retransmission), which is what revives a session whose endpoint was a LAN address the node has left; a change of the node's own local addresses (already collected for `lighthouse_register`, polled at every keepalive tick in v0), which also re-registers immediately and applies to every active peer; three consecutive failed keepalives towards the lighthouse, which re-registers and rediscovers every active peer. v0 does not listen to OS network-change events; that comes with iOS.
- **Keepalives**: 25 s towards every peer with an active session, every lighthouse and every relay, always on, no option. Keepalives are authenticated data packets and **count as traffic**: as long as both sides are up a session never idles out; it rekeys every `REKEY_AFTER_TIME`, as WireGuard does under persistent keepalive. A session expires after 180 s only when the peer stops answering, and is recreated on demand by the first IP packet towards that peer. The public entry point therefore always holds a live session with every node, and an inbound public connection never waits for discovery. The radio wake-ups on battery are accepted in v0; a power-saving mode is an iOS-era concern.
- `status --json` reports per peer the current `path` (`direct`, `relayed` with the relay's key, or `none`) and the **reason of the last direct-path failure** (0015); milestone tests assert on it.

## Consequences

- No RTT measurement, no candidate priority: the simplest rule that gives a direct path when one exists.
- The deterministic simulation (0020) covers cone and symmetric NATs before any `nixosTest` does.
