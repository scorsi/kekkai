# ADR 0027 — Future work and the constraints it imposes on v0

Status: Accepted — 2026-10-13

Superseded in part by [0034](0034-certificates-groups-expiry-and-revocation.md) — 2026-10-24: the first bullet (certificates, groups, expiry, revocation) is decided there; the constraints listed for it stay in force.

## Context

Several features are explicitly out of v0 but must not be made impossible by a structural choice.

## Options considered

- Implement the hooks now: scope creep.
- Record, per feature, the smallest constraint on v0 that keeps the door open.

## Decision

Out of v0, with the constraint v0 honours for each:

- **Certificates, groups, expiry, revocation (v1)**: the author's preference is a **minimal home-grown certificate format** over X.509, to avoid an X.509 parser's attack surface; decided after v0.7. Already in place: identity verification behind a trait (0007); canonical TLV payloads in handshake messages (0009) so a TLV subset can be signed; the certificate TLV will be non-critical and the identity trait on the receiving side decides whether it is required, so v0 and v1 nodes coexist during migration (0007); TLV body in the lighthouse reply so it can carry a certificate (0012); registries of TLV and inner message types in the spec (0009); per-peer rules expressed so that a group can replace a peer name later (0011).
- **Connection tracking in the firewall**: the UDP flow table of 0011 is the seed; TCP state later.
- **TCP/443 or QUIC fallback**: the core treats datagrams abstractly; a TCP adapter adds length framing in `kekkai-io`; the wire format does not change (0004, 0014).
- **Post-quantum hybrid handshake**: the psk slot of IKpsk2, all zeros in v0, receives a KEM-derived key later (0007).
- **Multi-lighthouse and multi-relay**: lists in configuration from the start, one element supported (0012, 0014).
- **Reload**: peer list as a replaceable value of the core (0004), delivered in the real-network milestone (0026).
- **Hardware-backed key at rest**: the core receives an opaque `StaticKey`, never a path (0017).
- **TUN owned by systemd-networkd, capability-free daemon** (0018).
- **Internal DNS**: nothing in kekkai, ever; annai owns names, zones and resolver configuration (0010). The only DNS-related code kekkai will carry is the tunnel DNS settings of the iOS app, which point at annai, because nothing else can set them there.
- **Subnet routing and exit nodes**: routing table keyed by prefix already; only `/32` and `/128` accepted in v0 (0010).
- **iOS and iPadOS** (SwiftUI app, Packet Tunnel Provider, internal TestFlight or Ad Hoc only): the Network Extension has a memory limit of about 50 MB, so the core keeps **bounded, configured buffers and no unbounded queue**; `kekkai-core` has no tokio, no socket, no thread; its public surface has no generics and no async so UniFFI can wrap it; `tracing` is the only logging facade; **overlapping wire versions** will be needed because the app always lags behind the hosts (0024); power-saving keepalives and OS network-change events come with it (0013).
- **Denial-of-service cookies**: `cookie_reply` reserved in the wire format (0009).
- **Metrics endpoint**: counters instrumented once in the core (0019).
- **Other operating systems, any GUI**: nothing reserved.

## Consequences

- Each constraint above is a line item a reviewer can check in v0.1 and v0.2.
- Adding one of these features starts with a new ADR that supersedes the relevant parts of this one.
