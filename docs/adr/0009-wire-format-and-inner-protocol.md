# ADR 0009 — Wire format and inner protocol

Status: Accepted — 2026-10-13

## Context

Node, lighthouse and relay exchange control messages in addition to tunnelled IP packets. The format must be versioned, parseable without a session for handshakes, and relay-friendly. Handshake messages carry session indices and no counter; data packets carry a counter and one index.

## Options considered

- Control messages in cleartext beside the transport: cheap to parse, but unauthenticated and visible; contradicts "silent to the unknown".
- Control messages inside the Noise transport, distinguished by an inner type byte.
- One fixed outer header for every message type: wrong for handshakes, which need the initiator's index echoed back and no counter.

## Decision

### Outer messages

All integers big endian. Every message starts with `type (1) | version (1) | reserved (2)`; `reserved` is zero on send and ignored on receipt. Layout per type, as in WireGuard:

```
handshake_init  (type 1):
  type | version | reserved | sender_index (4)
  | noise: ephemeral (32) | enc_static (32 + 16) | enc_payload (TLVs + 16)
  | mac1 (16) | mac2 (16)

handshake_resp  (type 2):
  type | version | reserved | sender_index (4) | receiver_index (4)
  | noise: ephemeral (32) | enc_payload (TLVs + 16)
  | mac1 (16) | mac2 (16)

cookie_reply    (type 3, reserved, not sent in v0):
  type | version | reserved | receiver_index (4) | nonce (24) | enc_cookie (16 + 16)

data            (type 4):
  type | version | reserved | receiver_index (4) | counter (8)
  | ciphertext: inner_type (1) | body | tag (16)
```

- `sender_index` is the random 32-bit index chosen by the sender of the handshake message for its receiving session; `receiver_index` echoes the peer's (0008). On `data`, the receiver index resolves the session; no trial decryption.
- `mac1` is keyed BLAKE2s with a **16-byte output** (`BLAKE2s-128`, truncated as in WireGuard): `mac1 = BLAKE2s(key = BLAKE2s("kekkai mac1" || receiver static public key), output = 16, input = all preceding bytes)`, where the **receiver** is the peer the message is sent to: the responder's static public key in `handshake_init`, the initiator's in `handshake_resp`. It lets a receiver drop, without any Diffie-Hellman, a message from someone who does not even know its public key, which is the cheapest form of "silent to the unknown" (0006). `mac2` is 16 zero bytes in v0 and not checked; it is the cookie MAC slot for the reserved `cookie_reply` mechanism (0007). Handshake messages are variable length because of the TLV payload; `mac1` covers everything before it.
- Handshake messages are parsed against `version`, which is also bound by the Noise prologue (0007). On `data` the version is redundant but kept for uniform parsing. A message of unknown type, unknown version, bad `mac1` or wrong length is **dropped silently**.
- **Wire version** starts at **1**; 0 is invalid. It changes only on an incompatible change of the format or of the inner protocol (0024).

### TLV encoding

Shared by handshake payloads and extensible inner messages: `type (1) | length (2) | value`, no alignment, no padding. The high bit of `type` marks a **critical** TLV, **set by the sender** when the message must not be processed by a receiver that does not understand that TLV: unknown non-critical TLVs are skipped, an unknown critical TLV rejects the whole message (silently for a handshake). **Canonical form is mandatory**: types in strictly increasing order, no duplicate; anything else is a parse error. Canonical form is what makes a signature over a TLV subset well-defined in v1 (0027). The v1 certificate TLV is **non-critical**: a v0 receiver skips it, and whether a certificate is required is the receiving side's identity trait's decision (0007), which is what keeps a v0 → v1 migration possible.

### Inner protocol

Everything that is not an IP packet travels **inside the transport**, prefixed by `inner_type`: `ip_packet`, `keepalive`, `lighthouse_register`, `lighthouse_query`, `lighthouse_query_reply`, `lighthouse_punch`, `relay_forward`, `relay_forwarded`. Bodies are TLV lists where extensibility is needed (lighthouse reply, 0027). `relay_forward` carries `to_pubkey (32) | payload`, `relay_forwarded` carries `from_pubkey (32) | payload`, where `payload` is a complete outer message of the A↔B session (0014). Inner types and TLV types are registered in the spec.

### MTU

The overlay interface MTU defaults to **1280** and is configurable **downwards only** (`node.mtu`, 0016), never above 1280 in v0; no protocol-level fragmentation; TCP MSS clamped on the interface. Budget for a 1280-byte IP packet:

| Layer | Bytes |
| --- | --- |
| IP packet | 1280 |
| A↔B `data`: header 16 + `inner_type` 1 + tag 16 | 1313 |
| Relayed: `inner_type` 1 + `from_pubkey` 32 inside R↔B `data`: header 16 + tag 16 | 1378 |
| UDP 8 + IPv6 40 (IPv4: 28) | **1426** (1406) |

Under 1454 (common PPPoE and MAP-E paths) and 1500. A tighter underlay is handled by lowering `node.mtu`.

### No padding, no obfuscation

Out of scope in v0; traffic analysis is not addressed (0006).

## Consequences

- Lighthouse and relay are authenticated by construction: they only ever see inner messages after a complete handshake.
- The relay forwards complete outer messages of the A↔B session as opaque payload; it never parses them beyond their length (0014).
- Parsers of the outer messages, TLV lists and inner messages are fuzz targets (0020).
- Adding `cookie_reply` later needs no format change: the `mac2` slot and the message type already exist.
