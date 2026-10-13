# ADR 0012 — Lighthouse protocol

Status: Accepted — 2026-10-13

## Context

Nodes behind NAT do not know their public endpoint and cannot find each other. A STUN-like observer is needed, authenticated and silent to strangers (0006).

## Options considered

- Separate STUN and a signalling channel: two protocols to secure.
- One authenticated service inside the Noise transport, learning endpoints from the source address of authenticated packets.

## Decision

- The lighthouse receives the **same peer list** (names and public keys) as nodes and accepts handshakes only from listed keys. It has no notion of overlay addresses in v0; everything is indexed by public key.
- Messages, all inner messages (0009):
  - `lighthouse_register { local_endpoints }`, sent by a node on every keepalive (25 s). The lighthouse stores `pubkey → { observed_endpoint, local_endpoints, last_seen }`. The observed endpoint is the source address of the authenticated packet. Local endpoints let two nodes on the same LAN or hypervisor bridge talk directly.
  - `lighthouse_query { pubkey }` → `lighthouse_query_reply { pubkey, endpoints, last_seen }` or "unknown". The reply body is a TLV list so that a certificate can be added in v1 (0027).
  - `lighthouse_punch { from_pubkey, endpoints }`, sent by the lighthouse to the queried node so that it sends towards the initiator and opens its own NAT.
- An entry expires after **3 missed keepalives** (75 s).
- **Authorization**: any authenticated node may query any listed peer in v0. Restricting queries to mutual listing is a policy that groups bring in v1.
- **Multi-lighthouse**: nodes configure a **list** of lighthouses from the start. v0 supports a single element. Later: register with all, query all, take the union; lighthouses never synchronize with each other.
- A node keeps a **permanent session** with each configured lighthouse; the keepalive both refreshes the registration and holds the NAT mapping open.
- The lighthouse persists nothing and logs only aggregate counters (0006).

## Consequences

- The lighthouse is a small, stateless-on-disk service; a restart loses registrations that return within 25 s.
- The lighthouse becomes the directory of public keys and certificates in v1 (0007), which does not change its trust level.
