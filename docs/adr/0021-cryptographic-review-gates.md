# ADR 0021 — Cryptographic review gates

Status: Accepted — 2026-10-13

## Context

The cryptographic core is written by an AI assistant under the author's direction. Independent review is required before real use, and it is expensive, so it must be scheduled.

## Options considered

- Review at every milestone: too costly.
- One review before the real network: late, a handshake flaw found then invalidates several milestones.
- Two gates with defined scope.

## Decision

- Process: the assistant writes the cryptographic core; the author reads it; then a review by a second model (Fable) and a peer review by a third (Codex). **Reviewers receive the spec (`docs/spec/protocol.md`), the threat model (`docs/threat-model.md`), the diff and the list of test vectors**, never the code alone.
- **Gate 1, end of v0.1**: handshake, transport, replay protection, rekey, **and the hand-written glue around `snow`**: `mac1` and the zero `mac2` slot, the TAI64N timestamp handling, the TLV codec. `snow` does not cover these; they are implemented with RustCrypto crates, their exact formulas are in the spec, they have dedicated test vectors, and the review brief names them explicitly as the parts no published analysis covers. Passing it **authorizes real use on a local network** (the macOS milestone, between two hosts on a hypervisor bridge).
- **Gate 2, end of v0.5**: the complete protocol with lighthouse, NAT traversal and relay. Passing it **authorizes exposure to the Internet** (the public entry point, the real-network milestone).
- Other milestones get the author's review only.
- Findings become spec changes, then code, then vectors; a gate is passed when no finding of severity "must fix" remains.

## Consequences

- v0.3 cannot be deployed between real hosts before gate 1; v0.6 cannot start before gate 2.
- The spec and threat model must be complete enough at v0.1 to be reviewable on their own.
