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

## Amendment — 2026-10-21: review gate 2 brief

Gate 2 covers the complete protocol at the end of v0.5 (decision above). What the
reviewers receive, as for gate 1, never the code alone:

- **Specification**: `docs/spec/protocol.md` as amended for v0.5 (status line of that
  date): every section, with §9, §10.2, §12 (paths, candidates, §12.3 relay fallback and
  direct retry, §12.4 roaming, §12.5 rediscovery triggers, §12.6 reporting), §13
  (lighthouse, with the §13.2 query budget), §14 (relay), §16 and §17 new or changed since
  gate 1.
- **Threat model**: `docs/threat-model.md` as amended for v0.5, sections 4.2 to 4.4 and
  9 ("What reviewers should look at (gate 2)").
- **Diff**: `71692fe..` the last v0.5 commit, that is all of v0.4 (lighthouse, discovery,
  hole punching, roaming, their review fixes) and v0.5 (relay). The gate-1 files
  (`handshake`, `session`, `wire`, `mac1`, `tai64n`, `tlv`, `resolver` in `kekkai-core`)
  changed in that range only by the `DropReason::RateLimited` variant and its name in
  `wire.rs`; `peer.rs` only gained accessors in v0.4.
- **Vectors**: unchanged files `keygen.json`, `tai64n.json`, `tlv.json`,
  `noise_ikpsk2.json`, `handshake.json`, `wire.json` (whose `inner_messages` hold the four
  lighthouse messages and `relay_forward` / `relay_forwarded`, frozen since v0.1),
  `replay.json`. v0.5 adds no codec. The behaviour of §12 to §14 is pinned instead by the
  deterministic simulation (`crates/kekkai-core/tests/simulation.rs`: cone, symmetric and
  mixed NATs, moves, lighthouse and relay restarts, relay fallback, direct upgrade, rate
  limit, silence), unit tests (`src/tests/relay.rs`: opaque forwarding, unlisted
  destinations, rate-limit and query-budget arithmetic) and a property test of the token
  bucket.
- **Integration evidence**: the nixosTests `nat-direct`, `roaming` (v0.4, passed),
  `nat-relayed` and `relay-upgrade` (v0.5), with their results.

The parts no published analysis covers, which the brief names explicitly:

1. The relayed receive path (§14.1, §12.4): a payload re-entering §5.6 on path
   `relayed(R)`, the claimed-sender check before any state change, no nesting, a relayed
   packet never moving an endpoint, responses following the path of what triggered them.
2. The relay role (§14.2): opaque forwarding, per-sender state without key material, the
   rate limit, silence towards unlisted keys and destinations, no amplification.
3. Path selection (§12.2, §12.3, §12.5): candidate admission, the rediscovery triggers and
   their pacing, the relay fallback tied to one attempt sequence, the direct retry, and
   competing direct and relayed sessions.
4. The lighthouse protocol (§13): what is registered and observed, who is told what, the
   punch, and the query budget that bounds it.

WireGuard's analyses keep covering the handshake and transport (gate 1); the lighthouse and
relay messages ride inside those sessions and add no cryptography.

## Amendment — 2026-10-22: review gate 2

### First round

Reviewed commit `754b131` (diff `71692fe..754b131`), with the spec, the threat model and the
vectors, by two independent reviewers:

- **Codex**: verdict **FAIL** (X1 must fix; X2 to X4 should fix).
- **Fable** (effort xhigh): verdict **PASS** (no must fix; F1 should fix, F2 to F8 notes).

The reports diverged on X1. The orchestrator checked it in the code: `accept_init` updated
`last_handshake` when it created an unconfirmed responder session, and `receive` ended the
attempt sequence (its learnt candidates, deferral and relay fallback) on that change, while
the outgoing message 1 stayed in flight. Fable's reading, that this cleanup happened on
responder confirmation, was incorrect. X1 is confirmed.

Owner decisions (2026-10-22):

- **F4** and **F5**: documented only (spec §12.5 and §12.3), no code change.
- **F6**: endpoints are validated at admission (node) and at register (lighthouse), and
  threat model 4.4 states what a compromised node's registered endpoints still allow.
- **F8**: trigger 1 goes through the §7.9 deferral like every other rediscovery.
- The lighthouse daemon does not set its own local endpoints, so the own-endpoint filter on
  registers stays empty in v0 (see N1 below).

The fixes landed in `b791f80` (X1, X2, F3, F8 code; F4, F5 spec), `80b7eda` (X3 / F1 tests)
and `66d8b50` (F6 code; X4, F2, F6, F7 spec and threat model). The status column below is
the final disposition after the second round.

| Finding | Severity | Resolution | Final status |
| --- | --- | --- | --- |
| X1 | must fix | Spec §12.2, §12.3, §12.5: an attempt sequence, its learnt candidates and its relay fallback end on its own completion (§7.7), on the confirmation of a responder session (§8.2 step 5) or on abandonment (§7.9); accepting the peer's message 1 (§7.6) ends neither. Code no longer keys the end on a `last_handshake` change. Test: crossing initiations with lost responses recover through the relay without another IP packet (`src/tests/paths.rs`) | resolved |
| X2 | should fix | Spec §12.3: at a window end only the message 1 current after every due retransmission goes through the relay, never the one it replaced. Test of a wake-up crossing both deadlines | resolved |
| X3 | should fix | Tests only, spec §14.1 and §12.4 unchanged (`src/tests/claims.rs`): message 1, message 2 and data relabelled under another `from` refused before any state of either peer changes, outer relay-session effects kept; `from` = lighthouse, relay, own key or unlisted key refused; nested `relay_forwarded` at a node refused; a relayed packet keeps the enclosed peer's endpoint | resolved |
| X4 | should fix | Spec §13.2, threat model 4.2, 4.4 and section 5: the punch bound is a `2 × L` burst then `L` per `DIRECT_PATH_TIMEOUT`; a punch costs its target one resend of an in-flight message 1 (at most 16 endpoints) or one new attempt sequence (at most 32 candidates, with its retransmissions, paced by §7.9). Test of a punch starting a sequence with a full candidate set | resolved |
| F1 | should fix | Same as X3 | resolved |
| F2 | note | Threat model 4.3: a relayed payload costs what it would cost directly (three X25519 for a message 1 with a valid `mac1`) plus the claimed-sender comparison | resolved |
| F3 | note | Code: a punch that opens a rediscovery window resets the stale "unknown" flag, so the failure reported (§12.6) is `timeout`, not `lighthouse_unknown` | resolved |
| F4 | note | Spec §12.5: the window of a deferred attempt runs from its trigger, so it may record `timeout` and fall back before its first message 1 leaves; the peer may then stay relayed until the next direct retry (§12.3) | accepted (documented) |
| F5 | note | Spec §12.3: the fallback is evaluated at each window end only; with no live relay session at that instant the sequence stays direct until a later window end or abandonment | accepted (documented) |
| F6 | note | Spec §12.2 (validity) and §13.1: unspecified, multicast, limited-broadcast, port-0 and own local endpoints dropped silently before admission and at register; threat model 4.2, 4.4. Tests in `src/tests/endpoints.rs`, one per refused class at admission and at register | resolved |
| F7 | note | Spec §17: per-peer relayed-session paths and the retained last message 1 listed | resolved |
| F8 | note | Code and spec §12.5: trigger 1's handshake, refused by the §7.9 pacing, is deferred like any other rediscovery | resolved |

### Second round

Reviewed commit `66d8b50` (diff `bdbd9c6..66d8b50`; `bdbd9c6` is an unrelated change under
`nix/`), 2026-10-22, by a fresh Codex review: verdict **PASS**. X1 to X4 and F1 to F8 are
closed; no new must fix or should fix. Fable was not re-run for the second round.

| Finding | Severity | Resolution | Final status |
| --- | --- | --- | --- |
| N1 | note | If a caller populated the lighthouse's local endpoints, the exact own-endpoint comparison would drop an identical private tuple advertised from a different LAN. The shipped lighthouse sets none (spec §13.1); owner decision to keep it so | no action |

Integration evidence (run by the orchestrator on the aarch64-linux builder, 2026-10-22):
the nixosTests `nat-relayed`, `relay-upgrade`, `nat-direct`, `roaming` and `two-nodes`
passed on `b791f80`; `nat-direct`, `roaming`, `nat-relayed` and `relay-upgrade` passed on
`66d8b50`. Unit and simulation: 66 core tests and 34 simulations green.

**Accepted residual risk:** the F4 and F5 availability limits (a deferred attempt may fall
back before its first message 1; the fallback is evaluated at window ends only) and the F6
boundaries (static endpoints are trusted, the source endpoints of authenticated datagrams
are not filtered, the own-address filter covers only the stored local list).

**Gate 2 status: PASSED on 2026-10-22 — authorizes exposure to the Internet (the public
entry point, the real-network milestone, v0.6).**
