# ADR 0011 — Per-peer inbound firewall

Status: Accepted — 2026-10-13

## Context

A compromised node is a legitimate peer (0006). Without a filter, it reaches every port of every other node. Groups and certificates are v1; v0 needs something static.

## Options considered

- Allow everything between listed peers, optional allow-list per peer: least configuration, no containment.
- Default deny inbound, each peer declares what it may reach: verbose in Nix, real containment.
- Delegate entirely to the host firewall: works on NixOS, not uniformly on macOS, and the rules would live outside the peer list.

## Decision

- **Default deny** for traffic entering a node from the tunnel, except ICMP and ICMPv6, always allowed.
- Each peer entry carries `allow_inbound`, a list of `proto/port` rules (`tcp/22`, `udp/53`, `tcp/*`, `any`), applied to packets whose source overlay address belongs to that peer.
- The firewall applies to **inbound tunnel traffic only**; outbound is never filtered.
- **Replies to flows the node initiated are always accepted**, with the minimum state needed:
  - TCP: only segments that open a flow (SYN without ACK) are checked against the rules; other segments pass. A stray non-SYN segment from a peer reaches the kernel, which answers with a reset; harmless and documented.
  - UDP: an outbound datagram records its 5-tuple in a flow table for 60 s; inbound datagrams matching an entry pass, others are checked against the rules. The table is **bounded**: a configured maximum (`firewall.udp_flows_max`, default 4096 entries, about 256 KB) and, when full, **the oldest entry is evicted** so that new outbound flows always get an entry; an evicted flow's late replies are then subject to the rules. A counter of evictions is exposed in `status --json` (0015). Sizes and behaviour are in the spec.
  - **IP fragments**: only the first fragment (offset 0) carries ports and is checked against the rules; when accepted, `(source, destination, protocol, identification)` is recorded in the same bounded table for 30 s and non-initial fragments matching an entry pass. Non-initial fragments without an entry are dropped. Same rule for IPv6 Fragment extension headers. Against the classic fragment attacks (RFC 1858 for IPv4, RFC 7112 for IPv6), two more rejections: a **first fragment that does not contain the complete transport header** (ports, and flags for TCP; for IPv6 the whole extension header chain plus the transport header in the first fragment) is dropped and records nothing; a **non-initial fragment whose offset overlaps the transport header** region is dropped, so overlapping fragments cannot rewrite ports or flags. These cases are property-test and fuzz inputs (0020). Fragments are rare on the overlay since the sender's TUN MTU is 1280 and TCP MSS is clamped, but UDP datagrams above the MTU produce them.
- Implemented in the core, so the behaviour is identical on Linux and macOS and covered by the deterministic tests (0020). The host firewall remains free to add its own rules on the interface.

## Consequences

- The deployment's shared peer list carries the rules; exposing a service on the overlay is an explicit decision.
- The UDP flow table is the only connection state in v0 and is bounded (0027, iOS memory).
