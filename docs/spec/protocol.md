# kekkai protocol specification

Wire version **1**. Status: v0 draft, amended after review gate 1 (2026-10-21, ADR 0021), after the
independent review of v0.4 (2026-10-21: §9 register timer, §12.2 admission, §13.1, §13.2)
and for v0.5 (2026-10-21: §12.3 relay fallback and direct retry, §12.4, §13.2 query
budget, §14, §16, §17), the version submitted to review gate 2.

This document is the normative description of the protocol spoken by `kekkai-node`,
`kekkai-lighthouse` and `kekkai-relay`. The code implements this document; a change to the
protocol is a change here first, then to the code, then to the vectors under
[`vectors/`](vectors/) (ADR 0003). The design decisions behind each section are in
[`docs/adr/`](../adr/); the attacker classes it answers are in
[`docs/threat-model.md`](../threat-model.md).

Sections marked **(v0.3)**, **(v0.4)** or **(v0.5)** describe behaviour whose
implementation is accepted in a later milestone; the wire format and registries they use
are frozen now so that the core never changes its parsers.

Contents

1. [Notation](#1-notation)
2. [Cryptographic suite](#2-cryptographic-suite)
3. [Constants](#3-constants)
4. [Identity keys](#4-identity-keys)
5. [Outer messages](#5-outer-messages)
6. [TLV encoding](#6-tlv-encoding)
7. [Handshake](#7-handshake)
8. [Sessions and transport](#8-sessions-and-transport)
9. [Timers](#9-timers)
10. [Inner protocol](#10-inner-protocol)
11. [Routing](#11-routing)
12. [Paths, NAT traversal and roaming](#12-paths-nat-traversal-and-roaming)
13. [Lighthouse procedures](#13-lighthouse-procedures)
14. [Relay procedures](#14-relay-procedures)
15. [Per-peer inbound firewall](#15-per-peer-inbound-firewall)
16. [Silence](#16-silence)
17. [Bounds](#17-bounds)
18. [Registries](#18-registries)
19. [Test vectors](#19-test-vectors)

---

## 1. Notation

- `a || b` is concatenation. `len(x)` is a length in bytes. `x[i..j]` is the byte range
  from `i` inclusive to `j` exclusive. `x[..n]` is the first `n` bytes.
- Integers on the wire are **big endian** unless stated otherwise; the only exception is
  the AEAD nonce of §8.2, whose layout is the Noise specification's.
- `u8`, `u16`, `u32`, `u64` are unsigned integers of that width. A field written `name (n)`
  is `n` bytes long.
- `BLAKE2s(data)` is BLAKE2s with a 32-byte output and no key. `BLAKE2s(key = k, out = n,
  data)` is keyed BLAKE2s with an `n`-byte output. `HMAC-BLAKE2s`, `HKDF` are the
  Noise specification's definitions over BLAKE2s (block size 64).
- `DH(priv, pub)` is X25519. `X25519(k, 9)` is the public key of `k`.
- `AEAD(k, n, ad, pt)` is ChaCha20-Poly1305 (RFC 8439) with the 32-byte key `k`, the 12-byte
  nonce `n`, associated data `ad` and plaintext `pt`; its output is `pt` encrypted followed
  by the 16-byte tag.
- Time: **monotonic** time is a suspend-aware monotonic clock of the host; **wall** time is
  UTC as the host knows it. Every duration and deadline in this document is monotonic; the
  wall clock is used for exactly one purpose, §7.4 (an implementation may sample it more
  often, but no other decision depends on its value).
- **MUST**, **MUST NOT**, **SHOULD**, **MAY** are used in the RFC 2119 sense.
- **Drop silently** means: the datagram or packet is discarded, nothing is sent in reaction,
  no state changes except a counter (§16).

Roles: a **node** terminates tunnels and routes IP packets; a **lighthouse** registers and
returns endpoints; a **relay** forwards opaque payloads. All three run the same core and
the same handshake; §10.2 says which inner messages each role accepts. "Peer" below means
any identity a party is configured to talk to, whatever its role, unless a role is named.

## 2. Cryptographic suite

The complete list of primitives. Nothing else is used (ADR 0003).

| Use | Primitive |
| --- | --- |
| Key agreement and handshake | Noise `IKpsk2`, protocol name `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` (Noise revision 34) |
| Diffie-Hellman | X25519 (RFC 7748) |
| AEAD, handshake and transport | ChaCha20-Poly1305 (RFC 8439) |
| Hash, HKDF, `mac1` | BLAKE2s (RFC 7693) |
| `cookie_reply` (reserved, §5.6) | XChaCha20-Poly1305 |
| Handshake timestamp | TAI64N |
| Signatures | none in v0 (Ed25519 is reserved for v1 certificates) |

The Noise handshake is implemented by the `snow` crate. Everything outside Noise (`mac1`,
the zero `mac2` slot, the TAI64N timestamp, the TLV codec, the outer and inner codecs, the
replay window) is hand-written glue; its formulas are in this document and have dedicated
vectors (§19), because no published analysis covers it (ADR 0021).

## 3. Constants

| Name | Value | Where |
| --- | --- | --- |
| `WIRE_VERSION` | 1 | §5 |
| `PROLOGUE` | `"kekkai" \|\| WIRE_VERSION` as one byte: `6b656b6b6169 01` (pinned by `handshake.json`, §7.1) | §7.1 |
| `PSK` | 32 zero bytes | §7.1 |
| `MAC1_LABEL` | ASCII `kekkai mac1` (11 bytes) | §5.5 |
| `TAI64_OFFSET` | `0x400000000000000a` | §7.4 |
| `INITIATIONS_PER_SECOND` | 50 | §7.4 |
| `TAI64N_NSEC_ALIGN` | 2^24 ns (16 777 216) | §7.4 |
| `COUNTER_WINDOW_SIZE` | 8192 − 64 = 8128 | §8.4 |
| `REKEY_AFTER_MESSAGES` | 2^60 | §8.6 |
| `REJECT_AFTER_MESSAGES` | 2^64 − `COUNTER_WINDOW_SIZE` − 1 | §8.4, §8.6 |
| `REKEY_AFTER_TIME` | 120 s | §9 |
| `REJECT_AFTER_TIME` | 180 s | §9 |
| `REKEY_TIMEOUT` | 5 s | §9 |
| `REKEY_TIMEOUT_JITTER` | up to 333 ms | §9 |
| `MAX_TIMER_HANDSHAKES` | 18 | §9 |
| `KEEPALIVE_TIMEOUT` | 10 s | §9 |
| `PERSISTENT_KEEPALIVE` | 25 s | §9 |
| `DIRECT_PATH_TIMEOUT` | 3 s | §12.3, §12.5 |
| `DIRECT_RETRY_INTERVAL` | 60 s | §12.3 |
| `LIGHTHOUSE_ENTRY_TIMEOUT` | 75 s (3 × `PERSISTENT_KEEPALIVE`) | §13 |
| `KEEPALIVE_FAILURES_BEFORE_REREGISTER` | 3 (failed registers) | §9, §12.5 |
| Lighthouse query budget | per querier: `2 × L` queries, refilled by `L` every `DIRECT_PATH_TIMEOUT`, `L` the number of listed keys | §13.2 |
| Relay rate limit | per sender: `relay.max_bytes_per_second` payload bytes, one second's worth as burst; none by default | §14.2 |
| `UDP_FLOW_TIMEOUT` | 60 s | §15 |
| `FRAGMENT_ENTRY_TIMEOUT` | 30 s | §15 |
| `UDP_FLOWS_MAX` | 4096 entries, configurable (`firewall.udp_flows_max`) | §15 |
| `MTU` | 1280, configurable downwards only | §17 |
| `MAX_DATAGRAM` | 1378 | §17 |
| `MAX_RELAY_PAYLOAD` | 1313 | §14, §17 |
| `MAX_LOCAL_ENDPOINTS` | 8 | §13.1 |
| `MAX_ENDPOINTS` | 16 | §10.5 |
| `MAX_STAGED_PACKETS` | 128 per peer | §8.7 |
| Default UDP ports | lighthouse 4800, relay 4801, node 4802 | ADR 0005 |

Timer values are WireGuard's (ADR 0008); they are copied so that WireGuard's analyses of
their interplay apply.

`DIRECT_PATH_TIMEOUT` and `DIRECT_RETRY_INTERVAL` are constants in v0, not configuration
options (amended 2026-10-21, ADR 0013 amendment of that date).

## 4. Identity keys

- Every party has one **static X25519 key pair**, used only in the handshake. A host that
  runs several roles has one key per role.
- `kekkai keygen` draws 32 random bytes and writes them **clamped**: bits 0, 1 and 2 of
  byte 0 cleared, bit 7 of byte 31 cleared, bit 6 of byte 31 set.
- `kekkai pubkey` and every loader accept any 32 bytes and compute `X25519(k, 9)`; X25519
  clamps its scalar internally, so a stored key that was not clamped yields the same public
  key as its clamped form.
- Text form of a key, private or public: standard base64 with padding (RFC 4648 §4), one
  line, as WireGuard.
- The core receives the private key as an opaque `StaticKey` value from the IO layer, never
  a path (ADR 0017).
- **Identity verification** is a function `verify(static_public_key, handshake_tlvs) →
  accept | reject` consulted by the handshake (§7.6). v0: accept iff the key is in the
  party's configured list (a node: peers, lighthouses and relays; a lighthouse or a relay:
  its peer list). The list is a replaceable value (ADR 0004): a reload replaces it without
  touching existing sessions of keys that remain listed.

Vectors: [`vectors/keygen.json`](vectors/keygen.json).

## 5. Outer messages

Every datagram is exactly one outer message. Every outer message starts with the 4-byte
common header:

```
type (1) | version (1) | reserved (2)
```

`reserved` is zero on send and is never interpreted on receipt. On `data` it is not
authenticated (§5.4) and any value is accepted. On handshake messages it is covered by
`mac1` (§5.5) like every other header byte, so a value changed in transit is a `mac1`
mismatch and the message is dropped (§5.6 step 5). `version` is `WIRE_VERSION`. Four types
are assigned (§18.1).

### 5.1 `handshake_init` (type 1)

```
type=1 | version | reserved | sender_index (4)
| ephemeral (32) | enc_static (48) | enc_payload (len(tlvs) + 16)
| mac1 (16) | mac2 (16)
```

`ephemeral || enc_static || enc_payload` is Noise message 1 (§7.2). Length: `136 +
len(tlvs)`; in v0 the TLV list is the 15-byte timestamp TLV, so the message is **151
bytes**. Minimum length 136.

### 5.2 `handshake_resp` (type 2)

```
type=2 | version | reserved | sender_index (4) | receiver_index (4)
| ephemeral (32) | enc_payload (len(tlvs) + 16)
| mac1 (16) | mac2 (16)
```

`ephemeral || enc_payload` is Noise message 2 (§7.2). Length: `92 + len(tlvs)`; in v0 the
TLV list is empty, so the message is **92 bytes**. Minimum length 92.

### 5.3 `cookie_reply` (type 3), reserved

```
type=3 | version | reserved | receiver_index (4) | nonce (24) | enc_cookie (32)
```

64 bytes. **Not sent and not processed in v0**: a received `cookie_reply` is dropped
silently exactly like an unknown type. The layout, the `mac2` slot and the type number are
reserved so that WireGuard's cookie mechanism can be added without a wire version change.

### 5.4 `data` (type 4)

```
type=4 | version | reserved | receiver_index (4) | counter (8)
| ciphertext (len(inner) + 16)
```

The header is 16 bytes. `ciphertext = AEAD(k, nonce(counter), "", inner)` where `inner =
inner_type (1) || body` (§10) and `nonce` is defined in §8.2. The associated data is
**empty**: the header is not authenticated; `receiver_index` only selects the session and
`counter` is the nonce, so a modified header makes the AEAD fail or the replay window
reject. Minimum length **33 bytes** (a keepalive).

### 5.5 `mac1` and `mac2`

Handshake messages end with two 16-byte MAC slots.

```
mac1_key = BLAKE2s(MAC1_LABEL || receiver_static_public_key)          (32 bytes)
mac1     = BLAKE2s(key = mac1_key, out = 16, message[..len(message) − 32])
```

- The **receiver** is the party the message is sent to: the responder for
  `handshake_init`, the initiator for `handshake_resp`. `mac1` covers every byte before the
  `mac1` slot, including the variable-length TLV payload.
- A receiver computes `mac1` with its own static public key and compares in constant time
  **before any Diffie-Hellman**. A mismatch drops the message silently.
- `mac1` is not authentication: anyone who knows the receiver's public key computes it. It
  only prices a probe at one keyed hash for the sender and one for the receiver (threat
  model §4.1).
- `mac1` **identifies its receiver to anyone holding candidate public keys**. The covered
  bytes and the tag travel in clear, so a passive observer who holds a list of candidate
  public keys finds the receiver of every handshake message with two BLAKE2s computations
  per candidate: the responder from message 1 and the **initiator from message 2**. No
  private key, active probe or Noise decryption is needed. This is the same property as
  WireGuard's `mac1` and is **accepted** (owner decision after review gate 1, 2026-10-21;
  threat model §4.1); identity hiding (§7.1) holds only against observers without such
  candidates. Changing it would be a separately reviewed protocol change, not a v0 fix.
- `mac2` is 16 zero bytes on send and **not checked** on receipt in v0.

`mac1_key` depends only on the receiver's static key and SHOULD be computed once.

### 5.6 Parsing and dropping

A receiver processes a datagram in this order and **drops silently** at the first failure:

1. `len(datagram) < 4` or `len(datagram) > MAX_DATAGRAM`.
2. `version ≠ WIRE_VERSION`. (0 is invalid, and any other value is a version this party
   does not speak; ADR 0024.)
3. `type` not in {1, 2, 4}.
4. Length not valid for the type: `handshake_init` shorter than 136, `handshake_resp`
   shorter than 92, `data` shorter than 33.
5. For handshake messages, `mac1` mismatch (§5.5).
6. The per-type processing of §7 and §8.

The version byte is also bound by the Noise prologue (§7.1), so a mismatch an attacker
rewrites in the header fails in the handshake as well.

Vectors: [`vectors/wire.json`](vectors/wire.json) (`outer_headers`),
[`vectors/handshake.json`](vectors/handshake.json) (`rejected`).

## 6. TLV encoding

Used by handshake payloads (§7.3) and by the lighthouse messages (§10.5).

```
type (1) | length (2) | value (length)
```

No alignment, no padding. A **TLV list** is zero or more TLVs back to back, filling exactly
the enclosing field. Parsing rules:

- **Canonical form is mandatory**: the full `type` bytes (critical bit included) are in
  strictly increasing order; a duplicate type or a decrease is a parse error.
- A TLV whose `length` runs past the end of the list, or a trailing fragment shorter than 3
  bytes, is a parse error (`truncated`).
- The high bit of `type` (`0x80`) is the **critical bit**, set by the sender when the
  message must not be processed by a receiver that does not understand that TLV. A receiver
  that meets an **unknown critical** TLV rejects the whole message; an unknown non-critical
  TLV is skipped. "Unknown" is relative to the registry of the enclosing message (§18); a
  type known in one registry is unknown in another.
- **The critical bit is part of the type.** A registry row assigns one full `type` byte.
  That `t` (1 to 127) is known does **not** make `t | 0x80` known: `t | 0x80` is known only
  if the registry assigns it as a row of its own, and it is then a different type from `t`
  (it may follow `t` in the same list under the ordering rule above). In v0 no registry
  assigns a type with the critical bit set, so every TLV of type 128 to 255 is an unknown
  critical TLV and rejects its message: a `timestamp` sent as `0x81` rejects message 1, with
  or without a `0x01` timestamp beside it.
- A known TLV whose value has the wrong length for its type is a parse error.
- A TLV type that is defined for a message but is not expected in it (for example a
  timestamp in `handshake_resp`) is treated as unknown.

Any parse error drops the enclosing message silently. The registries assign types from
**1**; `0` is never assigned. Values are opaque bytes; a registry defines the layout of
each.

Vectors: [`vectors/tlv.json`](vectors/tlv.json).

## 7. Handshake

### 7.1 Noise instantiation

- Pattern `IKpsk2`, protocol name `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`:

  ```
  IKpsk2:
    <- s
    ...
    -> e, es, s, ss        (handshake_init)
    <- e, ee, se, psk      (handshake_resp)
  ```

  The initiator MUST know the responder's static public key beforehand (it is in its
  configuration). The initiator's static key travels encrypted in message 1, so a passive
  observer who holds **no candidate public keys** cannot learn it. That is the whole of
  kekkai's identity hiding: the initiator's address is visible, and `mac1` lets an
  observer who holds candidate public keys recognize the receiver of each message, the
  responder from message 1 and the initiator from message 2 (§5.5; accepted, as in
  WireGuard). An active probe learns nothing from a responder that never answers it.
- **Prologue**: `PROLOGUE = "kekkai" || version`, where `version` is the one byte sent in
  the outer header (`6b656b6b616901` for wire version 1). Both sides mix it as the Noise
  prologue. A header rewritten to another version fails here even if the receiver spoke
  both versions.
- **Pre-shared key**: `PSK`, 32 zero bytes, at psk position 2 (mixed by the responder
  before the message 2 payload). With a zero key the construction is exactly WireGuard's
  handshake, so its published analyses apply; the slot is the entry point for a
  post-quantum hybrid later (ADR 0027).
- Pre-message: the responder's static public key is mixed as `<- s`.
- Payloads are the TLV lists of §7.3, encrypted by Noise as the message payloads.
- After message 2 is processed on both sides, `Split()` yields two transport keys:
  `k_i2r` (first output, initiator to responder) and `k_r2i` (second output, responder to
  initiator). The Noise handshake hash is not used on the wire.
- **All-zero DH outputs are not rejected**, unlike Linux WireGuard (`snow`'s X25519 returns
  the scalar multiplication as is; the Noise specification allows either). Under `IK` with
  `verify` on a static list this has no security effect: every key derivation of a
  handshake mixes at least one DH the attacker cannot compute (`es`/`ss` for message 1
  against an honest responder, `ee`/`se` for message 2 against an honest initiator), and a
  listed peer that sends a low-order ephemeral only weakens the forward secrecy of its own
  sessions. Identity keys are assumed generated by `kekkai keygen` (threat model §7); a
  low-order configured identity is not supported.
- `PROLOGUE` MAY be held as a literal by an implementation; it MUST then change together
  with `WIRE_VERSION`. The `prologue` field of `handshake.json` pins the bytes, so a
  divergence fails the vectors.

With `snow`: `Builder::new(name).prologue(PROLOGUE).local_private_key(s)
.remote_public_key(rs).psk(2, PSK)`, `build_initiator()` or `build_responder()`,
`write_message` / `read_message` for the two messages, then `into_transport_mode()`.

### 7.2 Message layout mapping

| Outer field | Noise content |
| --- | --- |
| `handshake_init.ephemeral` | initiator's ephemeral public key `e` |
| `handshake_init.enc_static` | initiator's static public key encrypted after `es` (32 + 16) |
| `handshake_init.enc_payload` | message 1 TLV list encrypted after `ss` (len + 16) |
| `handshake_resp.ephemeral` | responder's ephemeral public key `e` |
| `handshake_resp.enc_payload` | message 2 TLV list encrypted after `psk` (len + 16) |

Every `e` token also calls `MixKey(e.public_key)` because the pattern carries a psk
modifier (Noise §9.2). This is `snow`'s behaviour; the reference vectors were produced
independently and match the published vector for this suite (§19).

### 7.3 Handshake payloads

Both payloads are TLV lists (§6) against the handshake TLV registry (§18.3).

- Message 1 in v0: exactly the `timestamp` TLV (type 1, 12-byte value, §7.4). A message 1
  without a timestamp TLV is rejected (responder-side rule, not a wire flag). The timestamp
  TLV is sent **without** the critical bit.
- Message 2 in v0: the empty list (`enc_payload` is the 16-byte tag alone).
- v1 will add a `certificate` TLV (type 2, **non-critical**) to both messages: a v0 receiver
  skips it and authenticates on the static key alone; a v1 receiver's identity function
  decides whether its absence is a rejection. Requiring a certificate is receiver policy,
  never a wire flag (ADR 0007).

### 7.4 Timestamp and anti-replay of message 1

The wall clock is read **only** here.

```
seconds     = TAI64_OFFSET + unix_seconds                      (u64, big endian)
nanoseconds = unix_nanoseconds − (unix_nanoseconds mod 2^24)    (u32, big endian)
timestamp   = seconds || nanoseconds                            (12 bytes)
```

`2^24` is the largest power of two not above `1e9 / INITIATIONS_PER_SECOND`; the
alignment removes about 24 bits of clock precision from what a peer can observe (Linux
`tai64n_now`). Two message 1s built within the same 16.8 ms window carry the same
timestamp; this never happens in normal operation because retransmissions are
`REKEY_TIMEOUT` apart, and the same message 1 is deliberately sent to every candidate
endpoint (§12.2).

Responder rule: for each static key it has accepted a message 1 from, the responder keeps
`last_timestamp` (12 bytes, initially all zero). A message 1 whose timestamp is not
**bytewise strictly greater** (`memcmp`) than `last_timestamp` for that key is dropped
silently. `last_timestamp` is updated only when message 1 is fully accepted (§7.6 step 8).
The table is bounded by the peer list (one entry per listed key) and survives session
expiry; it is lost on restart, which only means a replayed message 1 captured before the
restart is accepted once (WireGuard's accepted property).

The receiver applies no range check to either field: the 12 bytes are an opaque sequence
label compared with `memcmp`. A listed peer that sends a timestamp far in the future, or
nanoseconds outside 0 to 999 999 999 (for example `ff…ff`), makes that responder's
`last_timestamp` for its own key unreachable and locks **itself** out of initiating towards
that responder until the responder restarts; no other key's entry is affected. This is
WireGuard's behaviour and is accepted (self-inflicted; threat model §5). A sender builds
`nanoseconds` from a valid clock reading (0 to 999 999 999 before alignment).

A node whose wall clock steps backwards emits timestamps its peers reject until the clock
passes the last accepted value; it still answers handshakes initiated by its peers, whose
timestamps come from their clocks. Timers (§9) never read the wall clock, so steps do not
affect them. The node logs a warning when a peer has not answered its handshakes for more
than `REJECT_AFTER_TIME`.

Vectors: [`vectors/tai64n.json`](vectors/tai64n.json).

### 7.5 Indices

Each side picks a **random 32-bit `sender_index`** for the receiving half of the session it
is establishing: the initiator in `handshake_init`, the responder in `handshake_resp`,
which also echoes the initiator's as `receiver_index`. On `data`, `receiver_index` is the
index chosen by the party that receives the packet (§8.1).

An index MUST be unique among the party's live receiving sessions and in-flight handshakes
(any value, zero included); a collision is resolved by drawing again. Indices are looked
up in one table for the whole party, so a `data` or `handshake_resp` is routed to its
session without trial decryption.

### 7.6 Processing `handshake_init` (responder)

After §5.6, for a message that arrived on path `P` (§12.1):

1. Run Noise `read_message` on `ephemeral || enc_static || enc_payload`. Any failure
   (static decryption, payload decryption) drops silently.
2. Call `verify(initiator_static, tlvs)` (§4) after parsing the TLV list against the
   handshake registry: a parse error, an unknown critical TLV or a rejection drops silently.
   In v0 this is the peer-list lookup; an unlisted key gets no answer.
3. The timestamp TLV MUST be present; apply the rule of §7.4. A failure drops silently.
   Steps 2 and 3 run after step 1 because the static key is known only after decryption.
4. Pick a `sender_index` (§7.5). Build message 2 (empty TLV list) with Noise
   `write_message`, then `mac1` keyed on the initiator's static public key, zero `mac2`.
5. `Split()`; create a session (§8.3) in the **next** slot of that peer with: receiving key
   `k_i2r`, sending key `k_r2i`, local index = our `sender_index`, remote index = the
   initiator's `sender_index`, `created = now`, `confirmed = false`, `role = responder`,
   `path = P`. Any previous unconfirmed `next` session is replaced.
6. Send message 2 on `P` (directly to the datagram's source, or wrapped for the relay it
   came through, §14).
7. If `P` is direct, set the peer's endpoint to the datagram's source address (§12.4).
8. Store `last_timestamp` for this static key.

A responder does not retransmit message 2; if it is lost, the initiator's retransmission
produces a new one. A message 1 is processed even when a confirmed session with that peer
exists: a peer that lost its state, or a concurrent initiation (§7.8), always gets through.

### 7.7 Processing `handshake_resp` (initiator)

After §5.6:

1. `receiver_index` MUST equal the `sender_index` of an in-flight initiator handshake of
   this party; otherwise drop silently (a late duplicate from another candidate endpoint
   falls here).
2. Run Noise `read_message` on `ephemeral || enc_payload`; parse the TLV list; apply the
   unknown-critical rule. Any failure drops silently and leaves the in-flight handshake in
   place (the retransmission timer applies). A Noise failure leaves the handshake state as
   it was, so the genuine response can still complete it. A TLV failure **after** a
   successful Noise read leaves a Noise state that has consumed message 2 and can no longer
   complete; it produces no session and no output, and only the retransmission (a fresh
   message 1, §7.9) recovers.
3. `verify` is not called again: the responder's identity is the configured static key the
   handshake was built against and `IK` authenticates it.
4. `Split()`; create a session in the **current** slot (the former current moves to
   **previous**, the former previous is discarded) with: sending key `k_i2r`, receiving key
   `k_r2i`, local index = our `sender_index`, remote index = the responder's
   `sender_index`, `created = now`, `confirmed = true`, `role = initiator`, `path` = the
   path the response arrived on.
5. The in-flight handshake is cleared; its retransmission timer is cancelled.
6. If the path is direct, set the peer's endpoint to the datagram's source address.
7. Send the staged packets (§8.7) on the new session; if there is none, send a
   **keepalive**, so that the responder can confirm (§8.3).

### 7.8 Concurrent initiations

Both sides may initiate at once; both handshakes may complete and both sessions then
exist. Each side **sends on its most recently confirmed session** and **accepts on any
live session**. There is no tie-break and, with symmetric concurrent initiations, no loser:
the session a side confirmed last is the one the other side initiated, so each side sends
as a responder and receives as an initiator on its `previous`, and neither rekey rule of
§8.6 fires. Both sessions expire at `REJECT_AFTER_TIME`; the next packet is staged (§8.7)
and a fresh handshake follows, with no packet lost, as in WireGuard.

### 7.9 Initiation and retransmission

At most **one in-flight initiator handshake per peer** exists. It carries an **attempt
count** and a **retransmit deadline**.

- **Initiation triggers** are: an IP packet staged for the peer (§8.7, §11), the rekey
  rules (§8.6), the new-handshake timer (§9), the lighthouse and relay session rule (§9),
  a rediscovery (§12.5) and a punch (§13.3).
- A trigger while **no** handshake is in flight starts an **attempt sequence**, unless a
  message 1 was sent to that peer less than `REKEY_TIMEOUT` ago (then nothing happens): a
  fresh message 1 is built with attempt count 1, sent, and the retransmit deadline is set to
  `REKEY_TIMEOUT` plus a random jitter of at most `REKEY_TIMEOUT_JITTER`. A rediscovery
  (§12.5) or a punch (§13.3) refused that way is **deferred**, not lost: the sequence
  starts `REKEY_TIMEOUT` after that message 1 (one pending deferral per peer), unless a
  handshake with the peer completed or a sequence started meanwhile.
- A trigger while a handshake **is** in flight leaves it unchanged: same message 1, same
  attempt count, same deadline. A rediscovery or a punch may only widen its candidates and
  send the existing message 1 to the new ones (§12.5, §13.3); this is not an attempt.
- Only the **retransmit deadline** advances the sequence. When it passes and the attempt
  count is below `MAX_TIMER_HANDSHAKES`, a **fresh message 1** is built (new ephemeral, new
  timestamp, new `sender_index`, so that a late response to an earlier copy fails §7.7
  step 1), the attempt count is incremented and a new deadline is set. When it passes and
  the count has reached `MAX_TIMER_HANDSHAKES` (about 90 s after the first attempt), the
  handshake is **abandoned**: the staged packets are dropped, a handshake timeout is
  counted, and the peer's path becomes `none` with the reason `abandoned` (§12.6).
- The sequence also ends, without abandonment, when a response completes it (§7.7 step 5)
  or when a responder session of that peer is confirmed (§8.2 step 5).
- After an abandonment the next trigger starts a new sequence at once (the last message 1
  is at least `REKEY_TIMEOUT` old by construction).

Every message 1 is sent to every candidate path of §12.2.

This is stricter than WireGuard, which resets its attempt counter on every initiation that
is not a retry: kekkai keeps the budget per sequence so that an unreachable peer always
ends in an abandonment that §12.6 can report and trigger 2 of §12.5 can count on, while
under steady traffic the first packet after an abandonment starts a new sequence at once,
so the peer is retried as often as in WireGuard.

## 8. Sessions and transport

### 8.1 Session

A session is one completed handshake. It holds: the two transport keys, the local receiving
index, the remote receiving index, a 64-bit **sending counter** (starts at 0), a **replay
window** (§8.4), `created` (monotonic), `confirmed`, `role` (initiator or responder),
`path` (§12.1), and `last_sent` / `last_received` instants.

Per peer, a party holds at most three slots:

| Slot | Content |
| --- | --- |
| `current` | the session used for sending |
| `previous` | the session `current` replaced, kept to absorb reordering until it expires |
| `next` | a responder-side session that has not yet received its first packet |

The initiator-side in-flight handshake state (§7.9) is held beside the slots, not in one of
them, so that a concurrent initiation (§7.8) keeps both the peer's message 1 and the party's
own handshake: at most three sessions plus one in-flight handshake per peer (§17, ADR 0008).

A session is **live** while `now − created < REJECT_AFTER_TIME` and its receive counter
state has not reached `REJECT_AFTER_MESSAGES`. Data is accepted on any live session in any
slot; data is sent only on `current` when it is live and confirmed.

### 8.2 Data packets

Sending `inner` (§10) on session `S`:

```
counter = S.sending_counter; S.sending_counter += 1     (before any failure can occur)
nonce   = 0x00000000 || counter as u64 little endian    (12 bytes, Noise layout)
packet  = 0x04 || 0x01 || 0x0000 || S.remote_index (4, big endian) || counter (8, big endian)
          || AEAD(S.sending_key, nonce, "", inner)
```

A counter value is **never reused** under a key: the increment happens before the
encryption and a failed or dropped send does not roll it back; the session type exposes no
way to set the counter. The counter is written big endian in the header and little endian
in the nonce; both carry the same value.

Receiving a `data` packet:

1. `receiver_index` MUST select a live session of this party; otherwise drop silently.
2. The counter MUST pass `check` (§8.4), which reads the window and changes nothing.
3. `AEAD` decrypt with the session's receiving key and `nonce(counter)`; failure drops
   silently and leaves the window exactly as it was.
4. `update` the window with the counter (§8.4). Update `last_received`. Apply the path and
   endpoint rules of §12.4. Record traffic for the timers (§9) and apply the responder rule
   of §8.6.
5. If the session was `next` and unconfirmed: it becomes `current` (`current` moves to
   `previous`, the old `previous` is discarded) and `confirmed = true`. If an in-flight
   initiator handshake towards that peer exists, it is cleared as in §7.7 step 5 (its index
   released, its retransmit deadline cancelled); this is not an abandonment, so nothing is
   recorded for §12.6 and no handshake timeout is counted. A late response to it then fails
   §7.7 step 1. Then the staged packets are sent on the new `current` in FIFO order (§8.7),
   each under the ordinary sending rules (counter, `last_sent`, §8.6). No keepalive is
   added when the queue is empty: the confirming packet already proved the session.
6. Process `inner` (§10).

Steps 4 and 5 are the transport outcome of an authenticated packet and stand whatever step
6 decides. If `inner` is rejected (§10.1, §10.2, §11, §15), only that content is dropped
silently: the window update, the endpoint and path update of §12.4, the traffic record,
the confirmation, and every datagram steps 4 and 5 produced (a message 1 from the
responder rule of §8.6, the staged packets of step 5) are kept and sent.

Vectors: [`vectors/handshake.json`](vectors/handshake.json) (`data_packets`).

### 8.3 Confirmation

An initiator's session is confirmed as soon as message 2 is processed. A responder's session
is confirmed by the first authenticated `data` packet it receives (the initiator sends one
immediately, §7.7 step 7). A responder MUST NOT send on an unconfirmed session; it keeps
sending on its previous `current` (if live) meanwhile, so that an attacker replaying an old
message 1 cannot hijack the responder's sending direction.

### 8.4 Replay protection

Per receiving session, a sliding window over the counter space as in the Linux WireGuard
implementation (`counter_validate`, RFC 6479 style):

- State: `last` (highest counter accepted, initially 0 with the bit for 0 unset) and a
  bitmap of 8192 bits in 128 words of 64 bits.
- Two separate operations. Word `w(c)` of counter `c` is `(c / 64) mod 128`; its bit is
  `c mod 64`.
- `check(counter)`, **read-only**, run before decryption (§8.2 step 2):
  1. If `counter ≥ REJECT_AFTER_MESSAGES`: reject.
  2. If `counter > last`: accept.
  3. If `last − counter ≥ COUNTER_WINDOW_SIZE`: reject (too old).
  4. If the bit of `counter` is set: reject (already seen). Otherwise accept.
- `update(counter)`, run **only after the AEAD succeeded** (§8.2 step 4), for a counter
  that passed `check`:
  1. If `counter > last`: clear the words that follow `w(last)` up to and including
     `w(counter)`, that is `min(counter / 64 − last / 64, 128)` words, wrapping around the
     ring; then `last = counter`.
  2. Set the bit of `counter`.
- **No window state changes before authentication**: no word is cleared, `last` is not
  advanced and no bit is set until the AEAD has succeeded. A packet that fails the AEAD,
  whatever its counter, leaves `last` and all 128 words bit for bit as they were, so a
  forged packet can neither burn a fresh counter nor slide the window.

The window is derived from Linux WireGuard's `counter_validate` (RFC 6479 style), split
into the two operations above, with one boundary difference: Linux rejects only
`last − counter > COUNTER_WINDOW_SIZE` and so accepts a counter exactly
`COUNTER_WINDOW_SIZE` behind `last`; kekkai rejects it (step 3 uses `≥`). The window is one
packet narrower than Linux's; this is stricter, safe, and pinned by `replay.json`.

Properties: a counter is accepted at most once; any counter `COUNTER_WINDOW_SIZE` or more
behind the highest accepted one is rejected; reordering within the window is tolerated; an
unauthenticated packet never changes the window.

Required regression test (review gate 1, C3), on one receiving session through the real
decrypt path: accept counter 0; offer a packet with counter `REJECT_AFTER_MESSAGES − 1`
and a bad tag, which is rejected; assert `last` and the bitmap are unchanged; accept
counter 1; reject a replay of 0. Then, on a fresh session, cross the ring boundary:
accept counter 8150 (word 127); offer a bad-tag packet with counter 8342 (word 2, which if
applied would clear words 0 to 2 across the wrap and move `last`); assert the window is
unchanged; accept counter 30 (8120 behind 8150, inside the window, but too old if `last`
had moved to 8342); reject a replay of 8150.

Vectors: [`vectors/replay.json`](vectors/replay.json).

### 8.5 Session replacement, expiry and key erasure

- A new confirmed session becomes `current`; the old `current` becomes `previous` and the
  old `previous` is discarded with its keys erased (below).
- A session is discarded when `now − created ≥ REJECT_AFTER_TIME`, or when its sending
  counter reaches `REJECT_AFTER_MESSAGES` (it then cannot send; it is still allowed to
  receive until it expires in time), or when a reload removes its peer from the list.
- Keys of discarded sessions are erased as stated below.
- A monotonic clock that jumps forward by more than `REJECT_AFTER_TIME` in one step (a long
  suspend) expires every session on the next tick; the core then re-handshakes on demand
  (§12.5) without waiting out any timer.

**Key erasure.** Erasure is defence in depth: a process with the node's privileges is out
of scope (threat model §4.5), but what erasure removes cannot be disclosed later by a read
of freed memory, a core dump or swap, and forward secrecy of recorded traffic depends on
it at the implementation level. **Erased** means overwritten through `zeroize` (writes the
compiler may not remove) before the memory is released. `kekkai-core` drives `snow` with
its own `CryptoResolver` (ADR 0028, amendment 2026-10-21) whose X25519, ChaCha20-Poly1305
and BLAKE2s objects erase what they hold; randomness still comes from `snow`'s default
resolver.

| Secret | Held by | Erased |
| --- | --- | --- |
| Static private key | `StaticKey` and each of its clones | on drop |
| Copy of the static private key inside a handshake state | the resolver's X25519 object (`Dh::set`) | when the handshake state is dropped |
| Ephemeral private key | the resolver's X25519 object (`Dh::generate`) | when the handshake state is dropped |
| Static key copy used to derive a public key (`StaticKey::public`, §4) | a resolver X25519 object | before the function returns |
| Handshake cipher key `k` of the Noise `CipherState` (on the raw-split path `snow` never keys its two transport cipher states, so they hold no secret) | the resolver's ChaCha20-Poly1305 objects | when replaced by `Cipher::set`, and when the handshake state is dropped |
| HMAC and HKDF intermediates computed by the hash object (key-xor-pad blocks, inner digest, HKDF temporary key) | the resolver's BLAKE2s object, which overrides `Hash::hmac` and `Hash::hkdf` | before each call returns |
| Local scratch of the resolver objects (generated bytes, DH result before it is copied out) | the resolver | before each call returns |
| The two raw `Split()` outputs returned by `snow` | `kekkai-core` | the returned arrays right after they are copied into `SessionKeys` |
| Transport keys | `SessionKeys` and the two transport AEAD objects of a session | when the session is discarded (above), when its peer is removed, and at shutdown |
| Key file text and decoded bytes | `kekkai-io`'s key loader and the text decoder of `kekkai-core` (§4) | as soon as the `StaticKey` is built, and on every parse failure |

A **handshake state** (an initiator's in-flight handshake, or a responder's state between
`read_message` and `Split()`) is dropped, and erased as above, on every way out:
completion (§7.6 step 5, §7.7 step 4, after the raw split), failure (any Noise or TLV
failure of message 1, §7.6 steps 1 to 3; an unlisted key; a stale timestamp), replacement
by a retransmission (§7.9), abandonment (§7.9), clearing on responder confirmation (§8.2
step 5), and removal of the peer.

**Not covered**, stated plainly. These copies stay in released memory until reused:

- `snow`'s `SymmetricState`: the chaining key `ck` and the handshake hash `h` are plain
  arrays owned by `snow` (0.10, `symmetricstate.rs`), copied by value on every checkpoint
  of `read_message` and `write_message`. The final `ck` determines both transport keys. A
  resolver cannot reach them.
- `snow`'s own stack temporaries: the DH result buffer of each token
  (`HandshakeState::dh`), the HKDF outputs and cipher-key arrays of `mix_key`,
  `mix_key_and_hash` and `split`, and the 64-byte outputs inside
  `dangerously_get_raw_split`.
- The state and block buffer of the `blake2` hasher object (`blake2` 0.10 has no erasure
  support); after an HMAC they may hold a block derived from `ck`.
- Copies made inside `curve25519-dalek`'s scalar multiplication, which takes the scalar
  by value.
- Copies the compiler makes (moves, registers, stack spills) and pages the operating
  system writes to swap or core dumps (service hardening, ADR 0018).

Closing the first two needs a change to `snow` or another Noise implementation; that is a
future decision with its own ADR, not part of v0. Erasure changes no byte on the wire: all
vectors (§19) are unchanged by it, and `noise_ikpsk2.json` and `handshake.json` are the
check that the kekkai resolver computes the same primitives as `snow`'s default one.

### 8.6 Rekey

- **Initiator rule**: when about to send on a `current` session whose `role` is initiator
  and `now − created ≥ REKEY_AFTER_TIME`, or whose sending counter `≥
  REKEY_AFTER_MESSAGES`, the party initiates a new handshake (§7.9) and still sends the
  packet on the current session.
- **Responder rule**: when a party receives a packet on a `current` session whose `role`
  is responder and `now − created ≥ REJECT_AFTER_TIME − KEEPALIVE_TIMEOUT − REKEY_TIMEOUT`
  (165 s), it initiates a new handshake. This safety net only acts when the initiator has
  not rekeyed on time.
- A session older than `REJECT_AFTER_TIME` is never used for sending; the sender initiates
  instead and stages the packet (§8.7).

The two rules keep "the initiator rekeys" as the normal course, which is what the timer
analysis of WireGuard assumes.

### 8.7 Staged packets

IP packets towards a peer without a usable `current` session are **staged** in a bounded
FIFO of `MAX_STAGED_PACKETS` per peer; a full queue drops the oldest. They are sent, in
FIFO order and each exactly once, as soon as a confirmed session becomes `current`, by
either path: initiator completion (§7.7 step 7) or responder confirmation (§8.2 step 5).
The queue is then empty. They are dropped when the handshake is abandoned (§7.9). Nothing
else is ever queued in the core.

## 9. Timers

All timers are monotonic (ADR 0004). The core exposes the earliest pending deadline; the IO
layer wakes at least about once per second, feeds the current instant and lets the core
process every deadline that has passed, so a suspend never delays an expiry by more than
one wake-up (ADR 0004).

| Timer | Fires when | Action |
| --- | --- | --- |
| Retransmit | `REKEY_TIMEOUT` + jitter after a message 1 with no valid response | Rebuild and resend message 1 (§7.9); after `MAX_TIMER_HANDSHAKES`, abandon. After the **first** unanswered timeout, also trigger rediscovery (§12.5). |
| Rekey (initiator) | On send, session age ≥ `REKEY_AFTER_TIME` or counter ≥ `REKEY_AFTER_MESSAGES` | Initiate (§8.6) |
| Rekey (responder) | On receive, session age ≥ 165 s | Initiate (§8.6) |
| Reject | Session age ≥ `REJECT_AFTER_TIME` | Discard the session (§8.5) |
| New handshake | `KEEPALIVE_TIMEOUT + REKEY_TIMEOUT` (15 s) after sending a non-keepalive `data` packet without receiving any authenticated packet from that peer since | Initiate; a peer that stopped answering is detected here |
| Passive keepalive | `KEEPALIVE_TIMEOUT` after receiving a non-keepalive `data` packet, if nothing was sent to that peer since | Send a keepalive |
| Persistent keepalive | `PERSISTENT_KEEPALIVE` since the last packet sent on `current` | Send a keepalive; always on, towards every peer with a `current` session, every lighthouse and every relay. Towards a lighthouse the register timer sends first, so this one never fires while registers go out |
| Register | Towards a lighthouse with a `current` session: `PERSISTENT_KEEPALIVE` after the previous register tick or the last `lighthouse_register` sent, whichever is later; other traffic on the session (queries, passive keepalives, rekeys) does not postpone it | §13.1: count a failed register, compare the local endpoints (§12.5 rule 3), send `lighthouse_register` |
| Lighthouse session | A node has no live session with a configured lighthouse or relay | Initiate towards its configured endpoint; retry under the retransmit rules; keep trying forever at `REKEY_TIMEOUT` pace after each abandonment (the session is permanent) |

Keepalives are authenticated `data` packets and **count as traffic** for `last_received`,
the window and the "new handshake" timer, but a received keepalive does not trigger the
passive keepalive (that would ping-pong). With both sides sending persistent keepalives a
session never idles out; it rekeys every `REKEY_AFTER_TIME` and expires only when the peer
is gone.

A **failed register** (the "failed keepalive" of ADR 0013) is a register tick at which no
authenticated packet has been received from that lighthouse since the previous register
tick or the last `lighthouse_register` sent, whichever is later; a register tick at which
`current` cannot send counts as failed too (it sends nothing and re-arms the timer).
`KEEPALIVE_FAILURES_BEFORE_REREGISTER` consecutive failed registers trigger §12.5 rule 4
and reset the count; a register tick that is not failed resets it too. (A lighthouse always
answers a `lighthouse_register` within `KEEPALIVE_TIMEOUT` through the passive keepalive
rule, since the register is a non-keepalive packet.) With no `current` session towards the
lighthouse the register timer is not armed; the lighthouse session row applies and the
register sent at handshake completion (§13.1) re-arms it.

## 10. Inner protocol

### 10.1 Framing

The plaintext of every `data` packet is `inner_type (1) || body`. Inner types are
registered in §18.2. An unassigned inner type, or a body that does not parse for its type,
drops the packet silently after the counter was marked (the packet was authentic; only its
content is unusable). The transport effects of §8.2 steps 4 and 5 stand, including the
datagrams they produced and the endpoint update of §12.4.

### 10.2 Acceptance by role

| Inner type | Node accepts from | Lighthouse accepts | Relay accepts |
| --- | --- | --- | --- |
| `ip_packet` | peers | no | no |
| `keepalive` | anyone with a session | yes | yes |
| `lighthouse_register` | no | from any listed key | no |
| `lighthouse_query` | no | from any listed key | no |
| `lighthouse_query_reply` | a configured lighthouse | no | no |
| `lighthouse_punch` | a configured lighthouse | no | no |
| `relay_forward` | no | no | from any listed key, direct sessions only |
| `relay_forwarded` | a configured relay, direct sessions only | no | no |

"Peers" are entries of the node's `[[peers]]` list; a lighthouse or relay is not a peer
for `ip_packet` even when the same host also runs a node (it has its own key). Anything
else in the table drops silently. A party configured as both peer and relay of another is
not supported in v0.

### 10.3 `ip_packet` (1)

`body` is one complete IPv4 or IPv6 packet. The receiver determines the family from the
version nibble; anything else is malformed. Processing: §11 then §15, then delivery to the
tunnel interface.

### 10.4 `keepalive` (2)

Empty body. The packet is 33 bytes on the wire.

### 10.5 Lighthouse messages (3 to 6)

All four bodies are TLV lists (§6) against the lighthouse TLV registry (§18.4):

| TLV | Type | Value |
| --- | --- | --- |
| `pubkey` | 1 | a static public key (32) |
| `endpoints` | 2 | `n` endpoints of 18 bytes, `0 ≤ n ≤ MAX_ENDPOINTS` |
| `last_seen` | 3 | `u32` seconds elapsed since the entry was last refreshed |
| `certificate` | 4 | reserved for v1, non-critical |

An **endpoint** is `address (16) || port (2)`: the address is an IPv6 address, an IPv4
address being written as its IPv4-mapped form `::ffff:a.b.c.d` (the underlay socket is dual
stack with mapped addresses, ADR 0010). The `endpoints` value length MUST be a multiple of
18.

| Message | Required TLVs | Optional TLVs | Meaning |
| --- | --- | --- | --- |
| `lighthouse_register` (3) | — | `endpoints` (the sender's local endpoints, at most `MAX_LOCAL_ENDPOINTS`) | "Here I am"; the observed endpoint is the datagram's source, and follows the sender's later authenticated datagrams (§13.2) |
| `lighthouse_query` (4) | `pubkey` | — | "Where is this key?" |
| `lighthouse_query_reply` (5) | `pubkey` | `endpoints`, `last_seen` | Known: both optional TLVs present, the observed endpoint first, then the registered local ones. Unknown or expired: `pubkey` alone |
| `lighthouse_punch` (6) | `pubkey`, `endpoints` | — | "This key is trying to reach you at these endpoints; send towards them" |

A message missing a required TLV is malformed. Procedures: §13.

### 10.6 Relay messages (7 and 8)

```
relay_forward   (7): to_pubkey (32)   || payload
relay_forwarded (8): from_pubkey (32) || payload
```

`payload` is one complete outer message (§5) of the session between the two end nodes,
`4 ≤ len(payload) ≤ MAX_RELAY_PAYLOAD`. The relay never parses it beyond its length.
Procedures: §14.

Vectors: [`vectors/wire.json`](vectors/wire.json) (`inner_messages`).

## 11. Routing

- A node has a routing table `overlay prefix → peer`, built from the configuration: each
  peer's `addresses`, which are `/32` and `/128` only in v0. The node's own addresses are
  not in the table.
- **Outbound**: an IP packet from the tunnel interface is looked up by destination. No
  match: drop (not silently towards the host: the IO layer MAY let the kernel generate the
  usual unreachable error; the core only reports the drop). Match: §15 records outbound UDP
  flows, then the packet is sent as `ip_packet` on the peer's `current` session, or staged
  (§8.7) and a handshake is initiated.
- **Inbound**: the source address of a received `ip_packet` MUST map to the peer the
  session belongs to (cryptokey routing, as WireGuard's allowed IPs); otherwise drop
  silently. Then §15, then delivery.
- Only IPv4 and IPv6 unicast packets are routed. Multicast and broadcast destinations are
  dropped on both sides.

## 12. Paths, NAT traversal and roaming

### 12.1 Path

A **path** is how a datagram reached or leaves this party: `direct(endpoint)`, the UDP
source or destination address; or `relayed(R)`, inside a `relay_forwarded` from or a
`relay_forward` to relay `R`. Each session records its `path`, set when its handshake
completed (§7.6 step 5, §7.7 step 4) and updated by every authenticated packet received
on it (§12.4). A peer's reported `path` (ADR 0013, `status --json`) is its `current`
session's path, or `none`.

Each peer also has at most one **endpoint**, the address used for direct sending; it is
updated only by directly received authenticated packets (§12.4). A session whose path is
`direct` sends to the peer's endpoint, whatever address its own packets last came from.

### 12.2 Candidates

To reach a peer `B`, node `A` builds the candidate set: the static `endpoints` of `B` from
configuration (DNS names resolved by the IO layer at start and on keepalive failure), `B`'s
last known endpoint, and every endpoint received in a `lighthouse_query_reply` or a
`lighthouse_punch` for `B`, both families. Candidates are **not ranked**. Message 1 of the
in-flight handshake is sent to **all** candidates known at the time, and to any candidate
learnt later while the handshake is in flight. **The first completed handshake wins**; its
session becomes `current` and its path is kept until the session is lost.

The same message 1 reaching `B` by several candidates (or also through a relay, §12.3) is
accepted once: the copies carry the same timestamp and fail §7.4. `B` answers on the path
of the first copy: its source address, or the relay it came through (§14.1). Late
responses to `A` fail §7.7 step 1.

The endpoints learnt from lighthouse replies and punches are kept as candidates of `B` until
a handshake with `B` completes (in either role: a valid response, §7.7, or the confirmation
of a responder session, §8.2 step 5; accepting `B`'s message 1, §7.6, which only creates an
unconfirmed `next` session, is not a completion) or the attempt sequence is abandoned
(§7.9); the end of a rediscovery's `DIRECT_PATH_TIMEOUT` window (§12.5) does not drop them,
and a retransmission within the sequence goes to them too. A candidate learnt while a
message 1 is in flight receives **that** message 1 (the same bytes), not a new one, and
does not change the sequence's attempt count or retransmit deadline.

**Admission.** The candidate set is ordered: static endpoints, then the last known
endpoint, then the learnt endpoints in the order they arrived; duplicates are skipped and
the set holds at most 32 entries (§17). An endpoint received when the set is full is **not
admitted** and nothing is evicted; it is forgotten. The same set serves the immediate
sends of §12.2 and §13.3 and every retransmission: a received endpoint that was not
admitted is never sent to, and an admitted one is sent to by every later retransmission
of the sequence. Admitted learnt endpoints keep their place when the static endpoints are
replaced (§13.1): the statics and the last known endpoint fill the room the learnt ones
leave, so a refresh may drop a static or the last known endpoint, never an admitted
learnt one.

### 12.3 Relay fallback and direct retry (v0.5)

**Fallback.** When a running rediscovery (§12.5) reaches `DIRECT_PATH_TIMEOUT` without a
completed handshake (the instant §12.6 records the failure) and `A` has a configured relay
`R` whose `current` session can send, the attempt sequence towards `B` **falls back to the
relay**: if a message 1 is in flight, the same bytes are sent at once through `R` (§14.1);
every later message 1 of the sequence (its retransmissions, a deferred start, §7.9) goes to
the direct candidates **and** through `R`. The in-flight message 1 is the one current
after every retransmission due at that instant (§7.9): when the same wake-up passes both
the retransmit deadline and `DIRECT_PATH_TIMEOUT`, only the fresh message 1 goes through
`R`, never the one it replaced. The fallback belongs to the sequence: it ends when the
sequence ends, by its own completion (§7.7), because a confirmed responder session ended
it (§8.2 step 5), or by abandonment (§7.9), and whenever no sequence is in flight or
deferred; a later sequence starts direct only. Accepting `B`'s message 1 (§7.6) ends
neither: crossing initiations whose responses are lost keep their fallback and retry
through `R`.

The fallback is evaluated at each window end only: if no relay session can send at that
instant (a relay restart, its §9 re-handshake in flight), the sequence stays direct until a
later rediscovery window of the same sequence ends with a live relay session, or until it
is abandoned; a relay session that comes back meanwhile does not change the sequence.
With several relays configured (not in v0) the smallest key among the live ones is used.
A handshake completing through `R` yields a session with `path = relayed(R)`.

A message 1 that is not part of a fallen-back sequence goes to the direct candidates only:
a rekey (§8.6) or a "new handshake" (§9) of a relayed session first tries directly; if it is
unanswered, its first retransmit deadline starts a rediscovery (§12.5 rule 2) and the
fallback follows `DIRECT_PATH_TIMEOUT` later, while the relayed session still carries
traffic.

**Direct retry.** While a peer's `current` session is relayed, the node starts a
rediscovery of that peer (§12.5: a lighthouse query, a fresh in-flight handshake under the
§7.9 pacing) `DIRECT_RETRY_INTERVAL` after it first saw the relayed path, and again every
`DIRECT_RETRY_INTERVAL` after the previous retry, until `current` is direct or gone. The
retry's own sequence is direct only for its first `DIRECT_PATH_TIMEOUT`, then falls back as
above. Its lighthouse query makes the lighthouse punch the peer (§13.2 step 3), so both
sides send towards each other's current address. If a direct handshake completes, its
session becomes `current` and traffic switches at once. If only the relayed one completes,
it replaces the previous relayed session, so a relayed session normally lives about
`DIRECT_RETRY_INTERVAL + DIRECT_PATH_TIMEOUT` and the 120 s rekey seldom fires on it.

**Competing sessions.** The session of the **last** completed handshake becomes `current`
(§8.5), whatever its path: within one sequence only the first copy of message 1 is
accepted, so its direct and relayed copies never both complete; two crossing sequences
(the peer was punched, or retries on its own) may complete one directly and one through the
relay, and then each side sends on the session the other initiated (§7.8) until the next
handshake. A direct path found that way is kept or found again by the next retry, within
`DIRECT_RETRY_INTERVAL`.

With no relay configured or no live relay session, the handshake keeps retrying directly
until abandoned.

### 12.4 Roaming

On every authenticated packet (a valid `data`, a fully accepted `handshake_init`, a valid
`handshake_resp`) received from a peer:

- received **directly**: the peer's endpoint becomes the datagram's source address and the
  session's path becomes `direct(source)` (WireGuard's rule);
- received **inside `relay_forwarded` from `R`**: the session's path becomes `relayed(R)`;
  the endpoint is **not** touched (the datagram's source was the relay's, inside the
  `A↔R` session). The `relay_forwarded` packet itself is an authenticated packet of the
  `A↔R` session and moves `R`'s endpoint as any other.

Sending on a session follows its path: directly to the peer's endpoint, or wrapped for `R`
(§14.1); a datagram produced while handling a packet (message 2, the staged packets of
§7.7 and §8.2 step 5, a keepalive) follows the path that packet set. Only the `current`
session sends `data` (§8.2), so the reported path is the path of everything a peer sends.

### 12.5 Rediscovery triggers

A **rediscovery** of peer `B` is: send `lighthouse_query { B }` to every lighthouse with a
live session (§13.2), then run §12.2 (and §12.3 when applicable) with a fresh in-flight
handshake, keeping an in-flight one if it exists and merely widening its candidates. It is
triggered by any of:

1. an IP packet towards `B` while `B` has no live `current` session;
2. a message 1 towards `B` unanswered after its first `REKEY_TIMEOUT`: the retransmit
   deadline of an attempt sequence passed once (§7.9; ordinary traffic never restarts a
   sequence, so this always happens for an unanswered peer); this is what revives a session
   whose endpoint was a LAN address the node has left, or whose peer moved;
3. a change of the node's own local addresses (§13.1), detected when a
   `lighthouse_register` carries a list that differs from the previous one: at a register
   tick (§9), hence at most `PERSISTENT_KEEPALIVE` after the change plus one IO wake-up
   whatever other traffic the node exchanges with the lighthouse, or earlier at the
   register that follows a handshake with the lighthouse (§13.1): that register is the
   re-registration, and the node rediscovers **every peer with a live session**;
4. `KEEPALIVE_FAILURES_BEFORE_REREGISTER` consecutive failed registers towards a lighthouse
   (§9): the node re-handshakes with the lighthouse, re-registers and rediscovers every
   peer with a live session;
5. receipt of a `lighthouse_punch` for `B` (§13.3), which starts or widens a handshake
   towards the given endpoints even if a session with `B` exists. The punch already
   carries what a query would return, so this trigger sends no `lighthouse_query`.

A rediscovery **runs** from its trigger until a handshake with `B` completes (in either
role, as in §12.2: accepting `B`'s message 1 does not end it) or `DIRECT_PATH_TIMEOUT`
elapses (§12.6). A trigger that fires while a rediscovery of `B` runs
joins it: no new query, the in-flight handshake is kept or started as above. This bounds
the queries of trigger 1 to one per `DIRECT_PATH_TIMEOUT` whatever the traffic. A
handshake that the `REKEY_TIMEOUT` pacing of §7.9 refuses (a message 1 went out less than
`REKEY_TIMEOUT` ago, typically the handshake that just completed) is deferred to the end
of that pacing (§7.9); if it is unanswered, its first retransmit deadline is trigger 2. So
a move that lands just after a handshake still leads, without traffic, to an attempt
within `REKEY_TIMEOUT` of the trigger and to a fresh query `REKEY_TIMEOUT` later. This
holds for trigger 1 too: its handshake is the one the staged packet starts (§8.7), and when
the pacing refuses it, it is deferred like any other.

The window of a deferred attempt still runs from its trigger, not from its first message
1. It may therefore end before that message 1 leaves: the failure is then recorded as
`timeout` (§12.6) although no message 1 of that attempt was sent, and with a live relay
session the sequence falls back (§12.3), so its first message 1 goes to the direct
candidates and through `R` at once. Since candidates are not ranked, the relayed copy may
complete first, and the peer then stays relayed until the next direct retry (§12.3).

v0 does not listen to OS network-change events.

### 12.6 Reporting

Per peer, the core keeps: `path` (§12.1), `endpoint`, the instant of the last completed
handshake, counters of packets and bytes in and out, the number of replay rejections, and
the **reason of the last direct-path failure**, one of: `no_candidates`, `timeout` (no
candidate answered within `DIRECT_PATH_TIMEOUT`), `abandoned` (§7.9), `lighthouse_unknown`
(the lighthouse did not know the peer). These feed `status --json` (ADR 0015).

The reason is recorded when a running rediscovery (§12.5) reaches `DIRECT_PATH_TIMEOUT`
without a completed handshake: `lighthouse_unknown` if a lighthouse answered "unknown" and
no endpoint was learnt; otherwise `no_candidates` if the candidate set is empty; otherwise
`timeout`. `abandoned` is recorded when §7.9 abandons an attempt sequence. A later success
does not clear it: it is the **last** failure, and `path` says whether a session exists.

## 13. Lighthouse procedures (v0.4)

### 13.1 Registration (node side)

A node keeps a **permanent session** with each configured lighthouse (§9, last row). At
every register tick (§9), `PERSISTENT_KEEPALIVE` after the previous one whatever else the
session carried, the node sends `lighthouse_register` carrying its current local
endpoints: `(address, listen_port)` for every unicast address of the host's interfaces,
excluding loopback, link-local and the overlay addresses themselves, at most
`MAX_LOCAL_ENDPOINTS` (the IO layer collects them; the core only compares the list of
every register sent, whatever caused it, with the previous register's for trigger 3 of
§12.5; the list is compared as a set). A node also sends a `lighthouse_register` as soon
as a handshake with the lighthouse completed and its `current` session can send (for a
responder, once that session is confirmed, §8.3); that register arms the register timer.

Bounds that follow, with no loss: while the session lives, an entry is refreshed at least
every `PERSISTENT_KEEPALIVE`, well within `LIGHTHOUSE_ENTRY_TIMEOUT`; a change of local
addresses is acted upon (rule 3 of §12.5) at most `PERSISTENT_KEEPALIVE` after it, plus one
IO wake-up; the re-registration and the query of that rediscovery leave at once, so a peer
reachable through the lighthouse's answer or punch is reached about one round trip later.

The IO layer resolves a lighthouse endpoint written as a DNS name at start, keeps every
address returned as a static candidate (§12.2), and resolves it again (exponential backoff
from `REKEY_TIMEOUT` to 5 minutes) while it is unresolved or while no authenticated packet
has arrived from the lighthouse for `KEEPALIVE_FAILURES_BEFORE_REREGISTER` ×
`PERSISTENT_KEEPALIVE` with a handshake in flight or a session up; a peer's DNS endpoints
follow the same rule (ADR 0016). New addresses replace the static candidates without
restarting an in-flight attempt sequence or displacing an admitted learnt candidate
(§12.2).

### 13.2 Lighthouse state and answers

The lighthouse keeps `pubkey → { observed_endpoint, local_endpoints, refreshed }` for each
registered key; `observed_endpoint` is the UDP source of the last authenticated datagram
received from that key (a `lighthouse_register`, a query, a keepalive: the lighthouse's own
endpoint for it, §12.4); only a `lighthouse_register` sets `local_endpoints` and
`refreshed`. A node that moved is therefore answered with its new address as soon as it has
reached the lighthouse from there, the address its punch (step 3) goes to: the querier and
the target learn each other's current address together and send towards each other at the
same time. Answered with an older address, the querier would not send to the target's new
one while the target, punched there, sends to the querier's NAT: unanswered, those
datagrams can make the querier's NAT map its later flow towards the target to another port
(a Linux NAT router that accepts them at input keeps a conntrack entry that holds the port),
and the handshake never completes. An entry **expires** `LIGHTHOUSE_ENTRY_TIMEOUT` after
`refreshed`; expired entries answer as unknown. The lighthouse holds nothing on disk and
logs only aggregate counters.

On `lighthouse_query { K' }` from key `K` (source address `S`):

1. If `K'` is not in the lighthouse's peer list, or has no unexpired entry: reply
   `lighthouse_query_reply { pubkey = K' }` to `K` and stop.
2. Reply `lighthouse_query_reply { pubkey = K', endpoints = [observed, locals...],
   last_seen = now − refreshed }` to `K`, in whole seconds rounded down, saturated at
   2^32 − 1. A local endpoint equal to the observed one is not repeated.
3. If `K' ≠ K` and the lighthouse has a live session with `K'`, send `lighthouse_punch {
   pubkey = K, endpoints = [S, locals of K...] }` to `K'`, where the locals are those of
   `K`'s own registration if it has one (again without repeating `S`).

Any authenticated node may query any listed key in v0 (ADR 0012). Queries from keys that
are not in the peer list never reach this step: they have no session.

**Query budget** (decided for v0.5, ADR 0031; it closes the open point left by the v0.4
review). Before step 1, the lighthouse charges the querier one token from its bucket: at
most `2 × L` tokens, refilled continuously at `L` tokens per `DIRECT_PATH_TIMEOUT`, `L` the
number of listed keys (at least 1), full when first used. A query that finds the bucket
empty is **dropped silently and counted** (`queries_limited`): no reply, no punch. A node
that follows §12.5 queries each of its peers at most once per running rediscovery, hence
about once per `DIRECT_PATH_TIMEOUT` per peer, and rules 3 and 4 query every live peer at
once, one query per peer: with a lighthouse that lists the whole mesh that is at most
`L − 1`, and the budget never refuses it. A compromised listed node is held to
`L` punches per `DIRECT_PATH_TIMEOUT` across all targets, and each target resends at most
one message 1 copy per punch to at most `MAX_ENDPOINTS` endpoints (§13.3): the
amplification the open point described is now bounded by the configuration, not by the
compromised node's sending rate. Registers and keepalives are not budgeted; they carry no
answer beyond a passive keepalive.

### 13.3 Punch (node side)

On `lighthouse_punch { K, endpoints }` from a configured lighthouse: if `K` is a configured
peer, add `endpoints` to the candidates of the in-flight handshake towards `K`, or start
one (§7.9), and send message 1 to those endpoints now (the in-flight one, or the new one
to every candidate), which opens this node's NAT towards `K` and gives `K` a response path. If `K` is not a configured peer, drop silently: a
lighthouse cannot make a node talk to a key it does not list.

## 14. Relay procedures (v0.5)

### 14.1 Node side

A node keeps a permanent session with each configured relay (§9). To send an outer message
`m` of its session with `B` on path `relayed(R)` (§12.3, §12.4), the node sends
`relay_forward { to = B, payload = m }` as a non-keepalive `data` packet on its `current`
session with `R`; with no `current` session towards `R` that can send, `m` is not sent.
`len(m) ≤ MAX_RELAY_PAYLOAD` always holds: the largest outer message is a `data` packet of
a full-MTU IP packet (§17).

On `relay_forwarded { from = A, payload }` received from configured relay `R` on a direct
session (the outer datagram came from `R`'s address, not itself through a relay):

1. `A` MUST be a configured peer of the node (not a lighthouse or relay); otherwise drop
   silently.
2. Process `payload` as a datagram received on path `relayed(R)` through §5.6 and the
   rest of this document, with one more check: the party that `payload` authenticates as
   (the static key of a message 1, the owner of the `receiver_index` of a message 2 or a
   `data` packet) MUST be `A`, checked **before** any state of that party changes;
   otherwise drop silently. So a relay cannot make one peer's packet count as another's.
3. Inside `payload`, no relay message is accepted: §10.2 accepts `relay_forwarded` only
   from a relay on a direct session, and the payload's sender is a peer (no nested
   relaying). A dropped payload is counted as a drop of the content of `R`'s packet; the
   transport effects on the `A↔R` session stand (§10.1).

Counters (§12.6): the `relay_forwarded` packet counts for `R`; its payload counts as one
received datagram of `len(payload)` bytes for `A`. A relayed send counts as one sent
datagram for `B` and one for `R`.

### 14.2 Relay side

A relay is a party that lists node keys only (ADR 0014): it completes handshakes with them,
keeps their sessions, accepts `keepalive` and `relay_forward` (§10.2) and routes nothing
else. On `relay_forward { to = B, payload }` from key `A` on a direct session:

1. `B` MUST be in the relay's peer list and have a `current` session with the relay that
   can send; otherwise drop silently and count (`dropped_no_route`).
2. If a per-sender rate limit `M` (payload bytes per second) is configured: `A`'s bucket
   holds at most `M` tokens, refilled continuously at `M` per second, full when first
   used; `len(payload)` tokens are taken, or, if the bucket holds fewer, nothing is taken
   and the packet is dropped silently and counted (`dropped_rate_limited`). With no limit
   nothing is dropped here.
3. Send `relay_forwarded { from = A, payload }` as a `data` packet on the relay's
   `current` session with `B`, and count it for `A` (`forwarded_packets`,
   `forwarded_bytes` of payload).

The relay copies `payload` as opaque bytes: it never parses it (a payload that is not even
an outer message is forwarded, and only `B`'s §5.6 drops it). Its state per sender is the
four counters and the bucket, for listed keys only. It holds no key of any `A↔B` session by
construction: the relay's core never derives one, and `kekkai-relay` is built without the
tunnel (no `tun` feature of `kekkai-io`, checked by the `relay-has-no-tunnel` check). A
`relay_forward` to `B = A` is forwarded back to `A` like any other. The relay never answers
anything but its sessions' own handshake and keepalive traffic: `relay_forward` produces at
most one `relay_forwarded`, of the same payload size, towards a listed node (no
amplification, §16).

## 15. Per-peer inbound firewall (v0.3)

Applies to `ip_packet` bodies entering the node from the tunnel, after §11, and never to
outbound traffic. Outbound traffic only **records state**.

Rules per peer: `allow_inbound`, a list of `proto/port` entries where `proto` is `tcp` or
`udp` and `port` is a number or `*`; the entry `any` allows everything. **Default deny**;
ICMP and ICMPv6 are always allowed. A packet whose source is peer `P` passes if:

1. it is ICMP or ICMPv6; or
2. it matches an entry of `P`'s `allow_inbound`; or
3. it is a **reply to a flow this node initiated**, as defined below; or
4. it is a TCP segment that is not a flow opener (SYN set, ACK clear): such segments pass
   without a rule; a stray one reaches the kernel, which answers with a reset over the
   tunnel, harmless and documented.

**UDP flows**: an outbound UDP datagram records `(src addr, dst addr, src port, dst port)`
in the flow table with `expires = now + UDP_FLOW_TIMEOUT`; an outbound datagram matching an
existing entry refreshes it. An inbound UDP datagram whose reversed 4-tuple matches an
unexpired entry passes (rule 3). Inbound matches do **not** refresh.

**IP fragments**: only a first fragment (offset 0) carries the transport header and is
checked against the rules. A first fragment that does **not** contain the complete
transport header (for TCP: ports and flags, 14 bytes; for UDP: 8 bytes; for IPv6, the whole
extension header chain plus that transport header) is dropped and records nothing. An
accepted first fragment of a fragmented packet records `(src addr, dst addr, protocol,
identification)` with `expires = now + FRAGMENT_ENTRY_TIMEOUT` in the same table.
A non-initial fragment passes only if it matches an unexpired entry **and** its offset does
not overlap the transport header region (offset × 8 ≥ the transport header length above);
otherwise it is dropped. IPv6 uses the Fragment extension header's offset and
identification. These are the RFC 1858 and RFC 7112 cases.

**Table bound**: one table of at most `UDP_FLOWS_MAX` entries for UDP flows and fragments.
When full, the entry with the **oldest `expires`** is evicted so that a new outbound flow
always gets an entry; the eviction counter is reported. Expired entries are removed lazily
on lookup and on insertion.

## 16. Silence

A kekkai port is silent to anyone without a listed key (threat model §4.1). The complete
list of conditions under which a party **drops silently** (no datagram in reaction, no
ICMP error induced by the core, no state change other than a counter):

- §5.6: datagram too short, too long, unknown version, unknown or reserved type, wrong
  length for the type, bad `mac1`.
- §7.6: Noise failure in message 1, TLV parse error, unknown critical TLV, identity rejected
  (unlisted key), missing or stale timestamp.
- §7.7: unknown `receiver_index`, Noise failure in message 2, TLV parse error, unknown
  critical TLV.
- §8.2: unknown `receiver_index`, counter rejected by the window, AEAD failure.
- §10: unassigned inner type, malformed body, inner type not accepted from this sender or
  on this path (§10.2), nested relaying.
- §11: source address not belonging to the sending peer, non-unicast.
- §13 and §14: query for an unlisted key answers "unknown" to a **listed** querier only;
  a query over the querier's budget (§13.2); relay forwarding to an unlisted or absent
  destination, or over the sender's rate limit (§14.2); a `relay_forwarded` whose sender
  is not a configured peer or whose payload authenticates as another party (§14.1).

The §10 and §11 conditions (and §15) occur after a `data` packet was authenticated: "no
state change" there concerns the rejected content only; the transport effects of §8.2
steps 4 and 5 have already happened and stand.

Each condition increments a counter exposed through the control API; none of them logs
above `debug`, and none logs a key or payload. Rate limiting of these counters' log lines
is the IO layer's business.

Not covered by silence, by design: a listed peer learns that it is listed (its handshake
completes), and an observer of a handshake between two listed parties sees that a
handshake happened and the sizes of what followed (no padding, ADR 0009). An observer who
holds candidate public keys also recognizes the receiver of each handshake message through
`mac1` (§5.5).

## 17. Bounds

Everything the core allocates is bounded by configuration (ADR 0027):

| Object | Bound |
| --- | --- |
| Datagram accepted or produced | `MAX_DATAGRAM` = 1378 bytes |
| Tunnel packet accepted from the interface | `MTU` = 1280 bytes (configurable downwards); larger packets are dropped |
| `relay_forward` payload | `MAX_RELAY_PAYLOAD` = 1313 bytes |
| Handshake TLV payload | `MAX_DATAGRAM − 136` for message 1, `MAX_DATAGRAM − 92` for message 2 (and `MAX_RELAY_PAYLOAD − …` when relayed) |
| Sessions per peer | 3 slots (§8.1) |
| In-flight handshakes | 1 per peer |
| Staged packets | `MAX_STAGED_PACKETS` = 128 per peer |
| Replay window | 8192 bits per receiving session |
| `last_timestamp` table | one entry per listed key |
| Endpoints in a TLV | `MAX_ENDPOINTS` = 16; local endpoints sent: `MAX_LOCAL_ENDPOINTS` = 8 |
| Candidates per in-flight handshake | static endpoints + 1 last known + `MAX_ENDPOINTS` from each lighthouse reply or punch, deduplicated, at most 32; admission rule in §12.2 |
| Firewall table | `UDP_FLOWS_MAX` = 4096 entries (about 256 KB) |
| Lighthouse registrations | one per listed key |
| Lighthouse query budgets | one bucket per listed key that queried |
| Relay per-sender state | four counters and one bucket per listed key that sent |
| Relayed sessions | the relay holds at most the three slots of §8.1 per listed key, nothing per node pair |

MTU budget for a 1280-byte IP packet (ADR 0009):

| Layer | Bytes |
| --- | --- |
| IP packet | 1280 |
| `A↔B` `data`: header 16 + `inner_type` 1 + tag 16 | 1313 |
| Relayed: `inner_type` 1 + `from_pubkey` 32 inside `R↔B` `data`: header 16 + tag 16 | 1378 |
| UDP 8 + IPv6 40 (IPv4: 28) | 1426 (1406) |

No protocol-level fragmentation; TCP MSS is clamped on the interface by the IO layer.

## 18. Registries

### 18.1 Outer message types

| Type | Name | Status |
| --- | --- | --- |
| 0 | — | invalid |
| 1 | `handshake_init` | assigned |
| 2 | `handshake_resp` | assigned |
| 3 | `cookie_reply` | reserved, dropped in v0 |
| 4 | `data` | assigned |
| 5–255 | — | unassigned, dropped |

### 18.2 Inner message types

| Type | Name | Body |
| --- | --- | --- |
| 0 | — | invalid |
| 1 | `ip_packet` | one IP packet |
| 2 | `keepalive` | empty |
| 3 | `lighthouse_register` | lighthouse TLV list |
| 4 | `lighthouse_query` | lighthouse TLV list |
| 5 | `lighthouse_query_reply` | lighthouse TLV list |
| 6 | `lighthouse_punch` | lighthouse TLV list |
| 7 | `relay_forward` | `to_pubkey (32) \|\| payload` |
| 8 | `relay_forwarded` | `from_pubkey (32) \|\| payload` |
| 9–255 | — | unassigned, dropped |

### 18.3 Handshake TLV types

| Type | Name | Value | In |
| --- | --- | --- | --- |
| 1 | `timestamp` | TAI64N (12) | message 1, required in v0, non-critical |
| 2 | `certificate` | reserved for v1 | both messages, non-critical |
| 3–127 | — | unassigned | |
| 128–255 | — | unassigned critical types; none assigned in v0, so all are unknown critical (§6). `t \| 0x80` is not a variant of `t` | |

### 18.4 Lighthouse TLV types

| Type | Name | Value |
| --- | --- | --- |
| 1 | `pubkey` | 32 bytes |
| 2 | `endpoints` | 18 × n bytes, `n ≤ MAX_ENDPOINTS` |
| 3 | `last_seen` | `u32` seconds |
| 4 | `certificate` | reserved for v1, non-critical |
| 5–127 | — | unassigned |
| 128–255 | — | unassigned critical types; none assigned in v0, so all are unknown critical (§6). `t \| 0x80` is not a variant of `t` |

### 18.5 Wire versions

| Version | Change |
| --- | --- |
| 0 | invalid |
| 1 | this document |

A new wire version is a new line here and a new prologue value; nodes with different wire
versions ignore each other silently (ADR 0024).

## 19. Test vectors

JSON files under [`vectors/`](vectors/), byte strings as lowercase hex. **Exact integers**:
a field whose type can hold a value above 2^53 − 1 (every 64-bit counter: `replay.json`
counters, `handshake.json` `data_packets[].counter`) is a **decimal string in every entry**,
whatever the value, so that readers that store JSON numbers as doubles stay exact; a JSON
number is used only for fields bounded by 2^53 − 1 (indices, lengths, seconds, types). Each file carries a `description` naming the section it exercises.
They are loaded by the Rust test suite of `kekkai-core` (all of them) and by the Go CLI's
tests (`keygen.json`), both run by `nix flake check` (ADR 0020).

| File | Checks | Section |
| --- | --- | --- |
| `keygen.json` | private → public key, clamping, base64 (includes the RFC 7748 keys) | §4 |
| `tai64n.json` | timestamp encoding and alignment, the bytewise comparison rule | §7.4 |
| `tlv.json` | encoding, canonical form, unknown critical and non-critical, truncation | §6 |
| `noise_ikpsk2.json` | the published cacophony vector for `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, verbatim; the same file `snow`'s own suite replays | §7.1 |
| `handshake.json` | a complete kekkai handshake with fixed keys, indices and timestamp: both datagrams byte for byte, `mac1` keys and values, transport keys, the first data packets of both directions, and datagrams that must be rejected with the reason | §5, §7, §8.2 |
| `wire.json` | outer header accept and drop cases, endpoint encoding, every inner message encoding, the registries | §5.6, §10, §18 |
| `replay.json` | a counter sequence with the accept or reject outcome of each | §8.4 |

v0.5 adds no codec: `relay_forward` and `relay_forwarded` were frozen with the registries in
v0.1 and their encodings are in `wire.json` (`inner_messages`). The token bucket of §13.2
and §14.2 is checked by a property test (no window grants more than its burst plus its
refill), the relay procedures by unit tests and the deterministic simulation (ADR 0020).

**Generation.** Every file lists its inputs in full (keys, ephemerals, indices, timestamp,
plaintexts), so any implementation of this document reproduces it. The files were produced
by an independent reference implementation of this document written for that purpose
(Python over the `cryptography` package, kept out of the repository, ADR 0002), which was
first checked against `noise_ikpsk2.json` (messages, handshake hash and transport
messages all match) and against the RFC 7748 public keys; its output is a pure function of
the inputs listed in the files and was generated twice with identical results. From v0.1b
on, `kekkai-core`'s test suite is the generator of record: every test recomputes the outputs
of its file from the inputs listed there and fails unless the file reproduces byte for byte;
after a spec change, `KEKKAI_WRITE_VECTORS=1 cargo test -p kekkai-core` rewrites the files
from the Rust implementation and the diff is reviewed with the change (ADR 0003). The
published Noise vector is never regenerated.

Rejection vectors name a `reason`; implementations are free in how they report it, but the
packet MUST produce no output (§16).

**Independent reproduction.** Because the Rust suite is the generator of record, the glue
vectors cannot by themselves detect a wrong implementation after a regeneration; the only
permanent external anchor is `noise_ikpsk2.json`, which checks `snow` (or the kekkai
resolver, §8.5), not the glue. At review gate 1 (2026-10-21) each reviewer recorded what
it checked independently of the Rust code:

- **Fable** (first round, Python 3 without third-party modules): `mac1_key` and `mac1` of
  both messages (`hashlib.blake2s` with `digest_size = 16`; a truncated 32-byte keyed digest
  does not match), the handshake timestamp and every case and comparison of `tai64n.json`,
  and the four `data_packets` of `handshake.json` with a from-scratch RFC 8439
  ChaCha20-Poly1305 (self-tested against the RFC §2.8.2 tag) using the `0^32 ||
  LE64(counter)` nonce and empty associated data, which pins the nonce layout and the
  orientation of the two `Split()` outputs. All matched.
- **Codex**: the `mac1` derivations, including, in the second round, both receivers'
  `mac1` keys and tags recomputed from public keys with Python `hashlib.blake2s`; and the
  published Noise vector compared with the upstream copy. Codex read the TAI64N and
  transport code and ran the Rust suite, but did not reproduce `tai64n.json` or the
  transport packets with a second implementation.

So the TAI64N and transport-nonce glue rests on one independent reproduction. A durable
second implementation of `mac1` and of the transport nonce (for example in the Go CLI's
tests over `handshake.json`) would keep that check alive; it is future work, not a v0 task.

**Checks over existing bytes.** The **receiver recognition** check documents the accepted
property of §5.5 using only public fields of `handshake.json`: for `message_2.datagram`
and the candidates `{initiator.static_public, responder.static_public}`, compute
`BLAKE2s(key = BLAKE2s(MAC1_LABEL || candidate), out = 16, datagram[..len − 32])` and
compare it with `datagram[len − 32 .. len − 16]`. Exactly `initiator.static_public`
matches, and its key and tag equal `message_2.mac1_key` and `message_2.mac1`. The same
computation over `message_1.datagram` matches exactly `responder.static_public`
(`message_1.mac1_key`, `message_1.mac1`). The check reads no private key, ephemeral or
transport key and adds no field to the file.

**Cases required by review gate 1** (to be added with the code): `tlv.json` decode cases
against the production message 1 registry (`known_tlvs = [1]`): a timestamp as `0x01`
accepted; the same value as `0x81` rejected as unknown critical; `0x01` followed by `0x81`
rejected as unknown critical (§6). `handshake.json` `data_packets[].counter` as decimal
strings, with a format check that no vector file carries a JSON number above 2^53 − 1;
integers, datagrams and ciphertexts unchanged. The replay regression of §8.4 is a unit
test through the session's decrypt path, not a vector.
