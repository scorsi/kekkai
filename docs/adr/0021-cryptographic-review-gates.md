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

## Amendment — 2026-10-21: review gate 1

### First round

Reviewed commit `51b6e08` (diff `af458a7..51b6e08`), with the spec, the threat model and the
vectors, by two independent reviewers:

- **Codex**: verdict **FAIL** (C1 to C4 must fix, C5 to C7 should fix).
- **Fable**: verdict **PASS** (no must fix; F1 to F3 should fix, F4 to F12 notes).

Owner decisions (2026-10-21):

- **C1 / F2** (`snow` erases none of its secrets): kekkai supplies its own `snow`
  `CryptoResolver` whose X25519, ChaCha20-Poly1305 and BLAKE2s objects erase what they hold
  (ADR 0028, amendment 2026-10-21); spec §8.5 states the erasure lifecycle and what stays
  uncovered.
- **C2** (`mac1` of message 2 identifies the initiator to an observer holding candidate
  public keys): **accepted and documented**, as in WireGuard; no protocol change (ADR 0006,
  amendment 2026-10-21).

The specification side landed in `27b3aa7`, the resolver in `4a4791d`, the code, test and
vector fixes in `ee8761a`. The status column below is the final disposition after the second
round.

| Finding | Severity | Resolution | Final status |
| --- | --- | --- | --- |
| C1 | must fix | Spec §8.5 key erasure; ADR 0028 amendment; threat model §5, §7. Code: kekkai resolver, raw-split arrays and key-loader text erased | resolved with residual note (accepted) |
| C2 | must fix | Accepted. Spec §5.5, §7.1, §16; threat model §2, §4.1, §5; ADR 0006 amendment. Receiver recognition check over existing `handshake.json` bytes (§19) | accepted (documented); regression test landed |
| C3 | must fix | Spec §8.4: read-only `check`, `update` only after the AEAD, no window change before authentication; §8.2 steps 2 to 4. Regression test specified in §8.4 | resolved |
| C4 | must fix | Spec §8.2 step 5, §8.7: staged packets flushed on responder confirmation; an in-flight handshake is cleared then (not an abandonment) | resolved |
| C5 | should fix | Spec §7.9: attempt sequences, ordinary triggers never reset a sequence in flight (stricter than WireGuard); §12.5 trigger 2; ADR 0008 amendment | resolved |
| C6 | should fix | Spec §6, §18.3, §18.4: the critical bit is part of the type; `t \| 0x80` is not known because `t` is; no critical type assigned in v0. Matches the code | resolved |
| C7 | should fix | Spec §19: 64-bit counter fields are decimal strings in every entry | resolved |
| F1 | should fix | Spec §8.2 (closing paragraph), §10.1, §16: transport effects and produced datagrams stand when `inner` is rejected; endpoint updated (§12.4) | resolved |
| F2 | should fix | Same as C1 (includes `load_key` temporaries) | resolved with residual note (accepted) |
| F3 | should fix | Same as C6 | resolved |
| F4 | note | Spec §8.4 and ADR 0008 amendment: one packet stricter than Linux, kept | accepted (documented) |
| F5 | note | Threat model §4.1: three X25519 operations before `verify`, three to answer; "public key" wording; ADR 0007 amendment | accepted (documented) |
| F6 | note | Spec §5: `reserved` is covered by `mac1` on handshake messages | resolved |
| F7 | note | Same as C5 | resolved |
| F8 | note | Spec §7.1: all-zero DH outputs not rejected, harmless under `IK` with the peer list; threat model §7 | accepted (documented) |
| F9 | note | Spec §7.4: no range check on the timestamp; self-lockout until the responder restarts; threat model §5 | accepted (documented) |
| F10 | note | Spec §19: each reviewer's independent reproduction recorded under its name (corrected by C8); a durable second implementation is future work, not a task | accepted (documented) |
| F11 | note | Spec §1: the wall clock is used, not necessarily read, for one purpose only | resolved |
| F12 | note | Spec §3, §7.1: the `PROLOGUE` literal must change with `WIRE_VERSION`; pinned by `handshake.json` | resolved |

Also clarified from the reviews' "checked" sections: spec §7.7 step 2, a TLV failure after
a successful Noise read of message 2 leaves a flight that only its retransmission recovers.

### Second round

Reviewed commit `ee8761a` (diff `51b6e08..ee8761a`), 2026-10-21:

- **Codex**: verdict **PASS** under the revised threat model. C2 to C7 resolved; C1 partly
  mitigated, its residual secrets accepted by the ADR 0028 amendment, closed as a gate
  blocker. New finding C8.
- **Fable** (effort xhigh): verdict **PASS**. New findings R1 and R2.

| Finding | Severity | Resolution | Final status |
| --- | --- | --- | --- |
| C8 | should fix | Spec §19 and the F10 row above claimed both reviewers reproduced the glue; §19 now attributes each independent check to the reviewer that made it | resolved |
| R1 | note | `ChaCha20-Poly1305` decrypt in the kekkai resolver subtracts the tag length without a local guard; unreachable, `snow` rejects short ciphertexts first, identical to `snow`'s default resolver | no action |
| R2 | should fix | Same as C8 | resolved |

Also from the second round: spec §8.5 no longer says `snow` fills two transport cipher
states on completion; on the raw-split path they are never keyed and hold no secret.

**Accepted residual risk (C1, F2):** `snow`'s chaining key, its checkpoint copies, its DH,
HKDF and split scratch and the BLAKE2s hasher state may survive in freed memory, and the
final chaining key determines both transport keys; a Noise implementation that erases its
own symmetric state is out of v0 scope.

**Gate 1 status: PASSED on 2026-10-21 — authorizes real use on a local network only (v0.3
between two hosts on a hypervisor bridge); not Internet exposure (gate 2, end of v0.5).**
