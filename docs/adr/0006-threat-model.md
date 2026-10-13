# ADR 0006 — Threat model

Status: Accepted — 2026-10-13

## Context

Nodes live on untrusted shared LANs, behind consumer routers and CGNAT, and on a public VPS. The full threat model is a v0.1 deliverable (`docs/threat-model.md`); this ADR fixes its scope so that the protocol decisions can refer to it.

## Options considered

- A WireGuard-only threat model (network attacker): too narrow, since kekkai adds two infrastructure roles that can be compromised.
- A full-blown model including host compromise, traffic analysis and volumetric denial of service: out of reach for a one-person project and would drive design decisions no reviewer could verify.

## Decision

Attacker classes and the guarantee expected against each:

- **Network attacker, passive or active** (shared LAN, Internet, ISP, CGNAT): confidentiality, integrity and mutual authentication of all traffic; a passive observer cannot learn which node initiated a session; **a kekkai port is silent to anyone without a listed key** (no reply to an unknown or malformed packet, including unknown protocol versions). This is an explicit requirement.
- **Compromised lighthouse**: learns only metadata (public keys, endpoints, presence times). Cannot read, inject or impersonate. Can withhold or lie about endpoints, which is at worst denial of service. With certificates later, it distributes signed certificates each node verifies itself, so this class does not grow (0007).
- **Compromised relay**: learns the public keys of both ends, source addresses, sizes, timing and byte counters. Can drop or delay, never read or modify. It persists nothing and logs only aggregate counters.
- **Compromised node**: a legitimate peer. It reaches what the per-peer inbound firewall of every other node allows it (0011). Revocation in v0 is removing its key from the configuration and redeploying.

Explicitly out of scope in v0: volumetric denial of service, traffic analysis (no padding, 0009), compromise of a running host (a process with the node's privileges reads the key). CPU exhaustion of the responder by handshake floods is accepted in v0, with a cookie message type reserved in the wire format (0007). Handshake messages carry `mac1` (0009): it lets a receiver drop, before any Diffie-Hellman, a message from anyone who does not know its static public key, so scanners and strangers cost one keyed hash. **`mac1` is not authentication**: an attacker who knows the peer list, or has observed a public key, computes it; authentication comes only from the Noise handshake, and silence towards such an attacker is guaranteed by the handshake failing, not by `mac1`.

Key at rest: an attacker with the disk of a host whose disk is not encrypted reads the identity key. This is an accepted risk in v0 with a documented mitigation path (0017). Which hosts are concerned is deployment-specific and not documented here (0025).

## Consequences

- Every protocol ADR names the attacker class it addresses.
- The relay and lighthouse code must be structurally unable to hold session keys of a node pair; this is checked by tests and review (0014, 0020).
