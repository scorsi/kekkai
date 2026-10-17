# kekkai protocol specification

Wire version **1**. Status: v0 draft for review gate 1 (ADR 0021).

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
  wall clock is read for exactly one purpose, §7.4.
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
| `PROLOGUE` | `"kekkai" \|\| WIRE_VERSION` as one byte: `6b656b6b6169 01` | §7.1 |
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
| `DIRECT_PATH_TIMEOUT` | 3 s, configurable | §12.3 |
| `DIRECT_RETRY_INTERVAL` | 60 s, configurable | §12.3 |
| `LIGHTHOUSE_ENTRY_TIMEOUT` | 75 s (3 × `PERSISTENT_KEEPALIVE`) | §13 |
| `KEEPALIVE_FAILURES_BEFORE_REREGISTER` | 3 | §12.5 |
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

`reserved` is zero on send and ignored on receipt. `version` is `WIRE_VERSION`. Four types
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
  configuration). The initiator's static key travels encrypted in message 1; a passive
  observer learns neither identity, and an active probe learns nothing from a responder
  that never answers it.
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
   place (the retransmission timer applies).
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
live session**; the loser expires through the timers of §9 (it stops receiving traffic,
hence is never refreshed, and is rejected at `REJECT_AFTER_TIME`). There is no tie-break.

### 7.9 Initiation and retransmission

A party initiates a handshake towards a peer when §9 or §12 asks for one, unless a message
1 was sent to that peer less than `REKEY_TIMEOUT` ago. At most **one in-flight initiator
handshake per peer** exists; starting a new one replaces it. Every (re)transmission builds
a **fresh message 1** (new ephemeral, new timestamp, new `sender_index`, so that a late response to an earlier copy fails §7.7 step 1); the
message is sent to every candidate path of §12.2. If no valid response arrives within
`REKEY_TIMEOUT` plus a random jitter of at most `REKEY_TIMEOUT_JITTER`, the message is
rebuilt and resent; after `MAX_TIMER_HANDSHAKES` attempts (90 s) the handshake is
abandoned, the staged packets are dropped, and the peer's path becomes `none` with the
failure reason recorded (§12.6). The next IP packet towards the peer starts over.

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
| `next` | a responder-side session that has not yet received its first packet, or the initiator-side in-flight handshake state |

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
2. The counter MUST pass the replay window check (§8.4) in its **pre-check** form (not
   already seen and within the window) before decryption.
3. `AEAD` decrypt with the session's receiving key and `nonce(counter)`; failure drops
   silently and does not mark the counter.
4. Mark the counter in the window (§8.4). Update `last_received`. Apply the path and
   endpoint rules of §12.4. Record traffic for the timers (§9).
5. If the session was `next` and unconfirmed: it becomes `current` (`current` moves to
   `previous`, the old `previous` is discarded) and `confirmed = true`.
6. Process `inner` (§10).

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
- `check(counter)`:
  1. If `counter ≥ REJECT_AFTER_MESSAGES`: reject.
  2. If `counter > last`: clear the words between `last`'s word and `counter`'s word
     (at most all 128), then `last = counter`.
  3. Else if `last − counter ≥ COUNTER_WINDOW_SIZE`: reject (too old).
  4. If the bit of `counter` is set: reject (already seen). Otherwise accept.
- The bit is **set only after the AEAD succeeds** (§8.2 step 4); a forged packet with a
  fresh counter does not burn that counter. Implementations run steps 1 to 4 as a
  pre-check without setting, then set after decryption; the net effect on valid traffic is
  the algorithm above.

Properties: a counter is accepted at most once; any counter more than `COUNTER_WINDOW_SIZE`
behind the highest one is rejected; reordering within the window is tolerated.

Vectors: [`vectors/replay.json`](vectors/replay.json).

### 8.5 Session replacement and expiry

- A new confirmed session becomes `current`; the old `current` becomes `previous` and the
  old `previous` is discarded with its keys zeroized.
- A session is discarded when `now − created ≥ REJECT_AFTER_TIME`, or when its sending
  counter reaches `REJECT_AFTER_MESSAGES` (it then cannot send; it is still allowed to
  receive until it expires in time), or when a reload removes its peer from the list.
- Keys of discarded sessions are zeroized.
- A monotonic clock that jumps forward by more than `REJECT_AFTER_TIME` in one step (a long
  suspend) expires every session on the next tick; the core then re-handshakes on demand
  (§12.5) without waiting out any timer.

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
FIFO of `MAX_STAGED_PACKETS` per peer; a full queue drops the oldest. They are sent when a
session becomes `current` (§7.7 step 7) and dropped when the handshake is abandoned
(§7.9). Nothing else is ever queued in the core.

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
| Persistent keepalive | `PERSISTENT_KEEPALIVE` since the last packet sent on `current` | Send a keepalive; always on, towards every peer with a `current` session, every lighthouse and every relay (§12.5 also hooks here) |
| Lighthouse session | A node has no live session with a configured lighthouse or relay | Initiate towards its configured endpoint; retry under the retransmit rules; keep trying forever at `REKEY_TIMEOUT` pace after each abandonment (the session is permanent) |

Keepalives are authenticated `data` packets and **count as traffic** for `last_received`,
the window and the "new handshake" timer, but a received keepalive does not trigger the
passive keepalive (that would ping-pong). With both sides sending persistent keepalives a
session never idles out; it rekeys every `REKEY_AFTER_TIME` and expires only when the peer
is gone.

A **failed keepalive** towards a peer is a persistent-keepalive tick at which no
authenticated packet has been received from that peer since the previous keepalive was
sent to it. `KEEPALIVE_FAILURES_BEFORE_REREGISTER` consecutive failures towards a
lighthouse trigger §12.5. (A lighthouse always answers a `lighthouse_register` within
`KEEPALIVE_TIMEOUT` through the passive keepalive rule, since the register is a
non-keepalive packet.)

## 10. Inner protocol

### 10.1 Framing

The plaintext of every `data` packet is `inner_type (1) || body`. Inner types are
registered in §18.2. An unassigned inner type, or a body that does not parse for its type,
drops the packet silently after the counter was marked (the packet was authentic; only its
content is unusable).

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
| `lighthouse_register` (3) | — | `endpoints` (the sender's local endpoints, at most `MAX_LOCAL_ENDPOINTS`) | "Here I am"; the observed endpoint is the datagram's source |
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
updated only by directly received authenticated packets (§12.4).

### 12.2 Candidates

To reach a peer `B`, node `A` builds the candidate set: the static `endpoints` of `B` from
configuration (DNS names resolved by the IO layer at start and on keepalive failure), `B`'s
last known endpoint, and every endpoint received in a `lighthouse_query_reply` or a
`lighthouse_punch` for `B`, both families. Candidates are **not ranked**. Message 1 of the
in-flight handshake is sent to **all** candidates known at the time, and to any candidate
learnt later while the handshake is in flight. **The first completed handshake wins**; its
session becomes `current` and its path is kept until the session is lost.

The same message 1 reaching `B` by several candidates is accepted once: the copies carry
the same timestamp and fail §7.4. `B` answers the source of the first copy. Late responses
to `A` fail §7.7 step 1.

### 12.3 Relay fallback and direct retry (v0.5)

If `DIRECT_PATH_TIMEOUT` elapses after a rediscovery started (§12.5) without a completed
handshake, and `A` has a live session with a configured relay `R`, the in-flight message 1
and its retransmissions are **also** sent through `R` (§14.1). A handshake completing
through `R` yields a session with `path = relayed(R)`.

While a peer's `current` session is relayed, every `DIRECT_RETRY_INTERVAL` the node starts
a rediscovery towards that peer **without** the relay for its first `DIRECT_PATH_TIMEOUT`.
If a direct handshake completes, its session becomes `current` and traffic switches at
once. If only the relayed one completes, it simply replaces the previous relayed session.
Rekeys of a relayed session (§8.6) go through the same rediscovery procedure, so a
rekey is also a direct retry.

With no relay configured or no live relay session, the handshake keeps retrying directly
until abandoned.

### 12.4 Roaming

On every authenticated packet (a valid `data`, a fully accepted `handshake_init`, a valid
`handshake_resp`) received from a peer:

- received **directly**: the peer's endpoint becomes the datagram's source address and the
  session's path becomes `direct(source)` (WireGuard's rule);
- received **inside `relay_forwarded` from `R`**: the session's path becomes `relayed(R)`;
  the endpoint is **not** touched (the datagram's source was the relay's, inside the
  `A↔R` session).

Sending on a session follows its path: directly to the peer's endpoint, or wrapped for `R`.

### 12.5 Rediscovery triggers

A **rediscovery** of peer `B` is: send `lighthouse_query { B }` to every lighthouse with a
live session (§13.2), then run §12.2 (and §12.3 when applicable) with a fresh in-flight
handshake, keeping an in-flight one if it exists and merely widening its candidates. It is
triggered by any of:

1. an IP packet towards `B` while `B` has no live `current` session;
2. a message 1 towards `B` unanswered after its first `REKEY_TIMEOUT` (one retransmission
   has happened); this is what revives a session whose endpoint was a LAN address the node
   has left, or whose peer moved;
3. a change of the node's own local addresses (§13.1), detected at a persistent-keepalive
   tick: the node re-registers immediately and rediscovers **every peer with a live
   session**;
4. `KEEPALIVE_FAILURES_BEFORE_REREGISTER` consecutive failed keepalives towards a lighthouse
   (§9): the node re-handshakes with the lighthouse, re-registers and rediscovers every
   peer with a live session;
5. receipt of a `lighthouse_punch` for `B` (§13.3), which starts or widens a handshake
   towards the given endpoints even if a session with `B` exists.

v0 does not listen to OS network-change events.

### 12.6 Reporting

Per peer, the core keeps: `path` (§12.1), `endpoint`, the instant of the last completed
handshake, counters of packets and bytes in and out, the number of replay rejections, and
the **reason of the last direct-path failure**, one of: `no_candidates`, `timeout` (no
candidate answered within `DIRECT_PATH_TIMEOUT`), `abandoned` (§7.9), `lighthouse_unknown`
(the lighthouse did not know the peer). These feed `status --json` (ADR 0015).

## 13. Lighthouse procedures (v0.4)

### 13.1 Registration (node side)

A node keeps a **permanent session** with each configured lighthouse (§9, last row). At
every persistent-keepalive tick towards a lighthouse, instead of a bare keepalive, the node
sends `lighthouse_register` carrying its current local endpoints: `(address, listen_port)`
for every unicast address of the host's interfaces, excluding loopback, link-local and the
overlay addresses themselves, at most `MAX_LOCAL_ENDPOINTS` (the IO layer collects them;
the core only compares the list with the previous one for trigger 3 of §12.5). A node also
sends a `lighthouse_register` immediately after the lighthouse session completes.

### 13.2 Lighthouse state and answers

The lighthouse keeps `pubkey → { observed_endpoint, local_endpoints, refreshed }` for each
registered key; `observed_endpoint` is the UDP source of the authenticated
`lighthouse_register` datagram. An entry **expires** `LIGHTHOUSE_ENTRY_TIMEOUT` after
`refreshed`; expired entries answer as unknown. The lighthouse holds nothing on disk and
logs only aggregate counters.

On `lighthouse_query { K' }` from key `K` (source address `S`):

1. If `K'` is not in the lighthouse's peer list, or has no unexpired entry: reply
   `lighthouse_query_reply { pubkey = K' }` to `K` and stop.
2. Reply `lighthouse_query_reply { pubkey = K', endpoints = [observed, locals...],
   last_seen = now − refreshed }` to `K`.
3. If the lighthouse has a live session with `K'`, send `lighthouse_punch { pubkey = K,
   endpoints = [S, locals of K...] }` to `K'`, where the locals are those of `K`'s own
   registration if it has one.

Any authenticated node may query any listed key in v0 (ADR 0012). Queries from keys that
are not in the peer list never reach this step: they have no session.

### 13.3 Punch (node side)

On `lighthouse_punch { K, endpoints }` from a configured lighthouse: if `K` is a configured
peer, add `endpoints` to the candidates of the in-flight handshake towards `K`, or start
one (§7.9), and send message 1 to those endpoints now, which opens this node's NAT towards
`K` and gives `K` a response path. If `K` is not a configured peer, drop silently: a
lighthouse cannot make a node talk to a key it does not list.

## 14. Relay procedures (v0.5)

### 14.1 Node side

A node keeps a permanent session with each configured relay (§9). To send an outer message
`m` of its session with `B` on path `relayed(R)`, the node sends `relay_forward { to = B,
payload = m }` as a `data` packet on its `current` session with `R`.

On `relay_forwarded { from = A, payload }` received from configured relay `R` on a direct
session: process `payload` as a datagram received on path `relayed(R)` through §5.6 and the
rest of this document, with these restrictions: `payload` MUST NOT itself yield a
`relay_forward` or `relay_forwarded` (no nested relaying; drop), and `A` MUST be a
configured peer (otherwise drop; `payload` would fail `verify` anyway).

### 14.2 Relay side

On `relay_forward { to = B, payload }` from key `A` on a direct session:

1. `B` MUST be in the relay's peer list and have a live `current` session with the relay;
   otherwise drop silently and count.
2. If a per-sender rate limit is configured and `A` exceeds it, drop and count.
3. Send `relay_forwarded { from = A, payload }` on the relay's session with `B`.

The relay copies `payload` as opaque bytes. Its state per sender is: counters of packets
and bytes, and the rate-limit bucket. It holds no key of any `A↔B` session by
construction: the relay's core never derives one, and `kekkai-relay` depends on no tunnel
decryption path (checked in v0.5).

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
  relay forwarding to an unlisted or absent destination.

Each condition increments a counter exposed through the control API; none of them logs
above `debug`, and none logs a key or payload. Rate limiting of these counters' log lines
is the IO layer's business.

Not covered by silence, by design: a listed peer learns that it is listed (its handshake
completes), and an observer of a handshake between two listed parties sees that a
handshake happened and the sizes of what followed (no padding, ADR 0009).

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
| Candidates per in-flight handshake | static endpoints + 1 last known + `MAX_ENDPOINTS` from each lighthouse reply or punch, deduplicated, at most 32 |
| Firewall table | `UDP_FLOWS_MAX` = 4096 entries (about 256 KB) |
| Lighthouse registrations | one per listed key |

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
| 128–255 | critical variants of 0–127 | | |

### 18.4 Lighthouse TLV types

| Type | Name | Value |
| --- | --- | --- |
| 1 | `pubkey` | 32 bytes |
| 2 | `endpoints` | 18 × n bytes, `n ≤ MAX_ENDPOINTS` |
| 3 | `last_seen` | `u32` seconds |
| 4 | `certificate` | reserved for v1, non-critical |
| 5–127 | — | unassigned |
| 128–255 | critical variants of 0–127 | |

### 18.5 Wire versions

| Version | Change |
| --- | --- |
| 0 | invalid |
| 1 | this document |

A new wire version is a new line here and a new prologue value; nodes with different wire
versions ignore each other silently (ADR 0024).

## 19. Test vectors

JSON files under [`vectors/`](vectors/), byte strings as lowercase hex, integers above
2^53 as decimal strings. Each file carries a `description` naming the section it exercises.
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

**Generation.** Every file lists its inputs in full (keys, ephemerals, indices, timestamp,
plaintexts), so any implementation of this document reproduces it. The files were produced
by an independent reference implementation of this document written for that purpose
(Python over the `cryptography` package, kept out of the repository, ADR 0002), which was
first checked against `noise_ikpsk2.json` (messages, handshake hash and transport
messages all match) and against the RFC 7748 public keys; its output is a pure function of
the inputs listed in the files and was generated twice with identical results. From v0.1b
on, `kekkai-core`'s test suite is the generator of record: a spec change regenerates the
files from the Rust implementation and the diff is reviewed with the change (ADR 0003).
The published Noise vector is never regenerated.

Rejection vectors name a `reason`; implementations are free in how they report it, but the
packet MUST produce no output (§16).
