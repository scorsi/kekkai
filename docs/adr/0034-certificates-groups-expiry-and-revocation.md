# ADR 0034 — Certificates, groups, expiry and revocation (v1)

Status: Accepted — 2026-10-24

Opens v1. Supersedes the first bullet of 0027 ("Certificates, groups, expiry,
revocation") and amends 0004 (a second use of the wall clock), 0007 (the identity function
returns a peer, the initiator verifies message 2), 0011 (group rules), 0012 (admission by
certificate, query by address), 0016 (configuration), 0017 (the CA key), 0021 (review gate 3)
and 0028 (one new crate). Every amendment lands in the spec and the threat model first.

## Context

In v0 the configuration is the identity system: every party lists every other party's
public key and overlay addresses, and every node lists, per peer, what that peer may reach
(0011, 0016). The deployment generates those lists from one Nix attrset, so they are
consistent, but they cannot do the following:

- **Add a node without redeploying every peer.** A mini-PC joining today means a new peer
  entry, and an `allow_inbound` decision, on every node, the lighthouse and the relay: a
  reload on all hosts (0026) for one new one.
- **Express policy by role.** `allow_inbound` is per peer: "every admin machine may SSH
  here" is repeated per admin machine on every target, and grows with each node.
- **Expire.** A key in the list is valid until someone removes it.
- **Revoke quickly and selectively.** Revocation is removing the key and redeploying
  (threat model §4.4); acceptable for three hosts, not for a lost phone.
- **Admit the iOS app** (0027): a device that lags behind the hosts' configuration and
  that peers should not have to list one by one.

0027 fixed the constraints that keep this possible without a wire change: identity behind
a function (0007), canonical TLV payloads (0009), a non-critical `certificate` TLV reserved
in both handshake messages and in the lighthouse registry (spec §18.3, §18.4), and the
author's preference for a minimal home-grown format over X.509. hanko's v1 internal
identity (hanko ADR-0004, not scheduled) already rejected kekkai certificates as service
identities and relies on kekkai for node attestation; the two layers are separate by design.

Attacker classes addressed: compromised node (expiry, revocation, containment by group),
network attacker (a new parser reachable after the Noise read), compromised lighthouse
(it now distributes certificates), and a new one, compromise of the CA key.

## Options considered

**Format.**

- *X.509* (RFC 8410 for X25519 subject keys, groups in a private extension): standard
  tooling, but an ASN.1/DER parser reachable by anyone who knows a responder's public key,
  a size that crowds the 1313-byte relay bound, and no consumer that needs it (hanko
  issues its own X.509).
- *Nebula's protobuf certificate, CBOR/COSE, PASETO, JWT*: each brings a second encoding
  and its parser into `kekkai-core`.
- *Minimal TLV certificate*: the TLV codec of spec §6 (canonical form, critical bit),
  already fuzzed and reviewed at gate 1, plus a detached signature. No new parser.

**Signature algorithm.**

- *Ed25519*: reserved for this since 0003 and spec §2, 64-byte signatures, deterministic,
  same curve family as the `curve25519-dalek` already in the core; its pitfall is
  verification malleability, settled by specifying strict verification.
- *ECDSA P-256*: what the Secure Enclave and older YubiKeys hold, and what hanko uses;
  needs a good nonce source at signing and a second curve in the core.
- *ML-DSA or a hybrid*: signatures of 2.4 KB or more do not fit a relayed message 1, and
  0027 does not list post-quantum certificates.

**What a certificate binds.** Public key only (rules stay in configuration), or public key
plus name, overlay addresses, groups and validity (Nebula's set). Without addresses a node
cannot route to a peer it has never listed, and without groups rules cannot drop peer
names.

**CA key custody and signing.**

- *Online CA daemon* (hanko-ca's model) on the public entry point: automatic renewal,
  short lifetimes, but the forging key on the most exposed host, and an online service
  every node depends on.
- *Offline key on the operator's machine*, encrypted at rest to the operator only, used by
  `kekkai` CLI commands when a node is added or renewed.
- *Hardware key* (YubiKey PIV Ed25519, firmware 5.7 and later): non-exportable, but a
  PIV or PKCS#11 path in the CLI. Can come later without a format change.
- *Reuse hanko's CA*: hanko-ca reaches nodes over kekkai and attests them by overlay
  address, so kekkai's admission cannot depend on it; its key is P-256 and its output
  X.509. Sharing only conventions (names) costs nothing.

**Distribution.** `IK` needs the responder's static key before message 1 (0007).

- *Configuration only* (certificates in every peer's config): changes nothing about "add a
  node without redeploying every peer".
- *Handshake TLV*: each side presents its certificate; enough for the responder to admit
  an unknown initiator, not for an initiator to find an unknown responder.
- *Handshake TLV plus the lighthouse*: the lighthouse keeps the certificate each node
  presented and answers a query **by overlay address** with it; the querier verifies it
  itself, so the lighthouse's trust level does not grow (0007, 0012).

**Expiry and renewal.** Long lifetimes (a year, Nebula's default) with manual renewal and
a revocation list; short lifetimes (hours, days) as the revocation mechanism, which needs
the online CA above; medium (90 days) with manual renewal, toil for every host each
quarter.

**Revocation.**

- *Deny list in each party's configuration*: public keys and certificate fingerprints,
  applied by the existing reload (0026). Revoking still touches every host, but only on
  compromise or loss, which is rare, unlike adding a node.
- *Signed CRL distributed by the lighthouse*: no redeploy, but a new message, a version
  and freshness rule, and a lighthouse that can withhold it.
- *Short lifetimes only*: see above.
- *Online status check (OCSP-like)*: a live dependency for every handshake.

**Groups in the firewall (0011).** Receiver-side rules naming groups from the peer's
certificate (Nebula's model; the receiver keeps its policy); rules embedded in the
certificate (the CA decides what a node may reach everywhere, the wrong owner); a central
policy pushed by the lighthouse (a new trust role).

## Decision

### Certificate format

```
certificate = body || signature (64)
body        = TLV list, spec §6 rules: canonical order, critical bit
signature   = Ed25519(CA private key, "kekkai certificate v1" || body)
fingerprint = BLAKE2s-256(certificate)
```

| Type | Name | Value | Required |
| --- | --- | --- | --- |
| 1 | `name` | 1 to 63 bytes, `[a-z0-9-]`, no leading or trailing `-` | yes |
| 2 | `public_key` | the node's X25519 public key (32) | yes |
| 3 | `addresses` | `n × 16`, `1 ≤ n ≤ 4`, IPv6 or IPv4-mapped, each a `/128` or `/32` | yes |
| 4 | `groups` | `len (1) \|\| group`, at most 16, strictly increasing, same charset, 1 to 32 bytes | no |
| 5 | `not_before` | `u64` Unix seconds | yes |
| 6 | `not_after` | `u64` Unix seconds | yes |

- An unknown non-critical TLV is skipped (it is still signed); an unknown critical TLV
  rejects the certificate, so a later constraint can be added safely. The context string
  versions the signature; no version field.
- **`MAX_CERTIFICATE` = 960 bytes**, enforced by signer and parsers: a relayed message 1
  stays under `MAX_RELAY_PAYLOAD`, and a `lighthouse_query_reply` with `MAX_ENDPOINTS`
  endpoints and a certificate stays within one `data` packet (spec §17). A typical
  certificate is about 250 bytes.
- The CA is a bare Ed25519 public key, no CA certificate and no CA expiry; a party trusts
  **one or two** (rotation). Signatures are verified **strictly** (RFC 8032 with canonical
  `S`, canonical and non-small-order `A` and `R`: `ed25519-dalek`'s `verify_strict`), with
  edge-case vectors. Text form: base64, one line, as keys (spec §4).

### Verification (the identity function, 0007)

A party without a `[pki]` section behaves exactly as v0 and never parses the certificate
TLV. With `[pki]`, `verify(key, tlvs)` returns a peer record (name, addresses, groups,
`not_after`, source `static` or `certificate`) or reject:

1. Key or presented fingerprint in the deny list: reject (revocation beats static).
2. Key in the static list: the v0 entry, certificate ignored.
3. Otherwise a `certificate` TLV is required: parsed, size-bounded, signed by a trusted
   CA, `public_key` equal to the Noise static key, `not_before ≤ now < not_after` on the
   wall clock, every address inside the node's configured overlay prefixes.

The initiator now also verifies message 2's certificate (spec §7.7 step 3 changes); a
failure there is the existing "TLV failure after a Noise read" case. Every handshake
re-verifies, so expiry and revocation reach live sessions within `REJECT_AFTER_TIME`
(180 s), and a reload that adds to the deny list discards matching sessions at once, as a
removed peer is today (spec §4.1). Peers admitted by certificate live in a bounded table
(`pki.max_peers`, iOS memory, 0027), evicting the oldest one without a session; their
`last_timestamp` goes with them, so an evicted peer's message 1 replays once, the residual
v0 accepts after a restart.

### Distribution

- Both handshake messages carry the sender's certificate (type 2, non-critical). The
  responder admits an unlisted initiator from it and routes its addresses.
- Lighthouse and relay admit nodes by certificate the same way. The lighthouse stores the
  certificate from each node's message 1 with its registration; `lighthouse_query` takes
  either `pubkey` or a new non-critical `address` TLV (type 5, 16 bytes); the reply and
  `lighthouse_punch` carry the `certificate` TLV (type 4). The querier verifies it and
  checks that it binds the queried address.
- A node routes its whole overlay prefixes to the tunnel (`[pki] prefixes`); a packet for
  an unknown address inside them starts a query by address, staged as today (spec §8.7).
  Lighthouses and relays stay pinned by key in node configuration.
- An address claimed by a static entry goes to it; between two valid certificates, the
  later `not_before` wins.
- Wire version stays 1: every addition is a non-critical TLV in an existing registry, so
  a v1 node, a v0 node and a lagging iOS app interoperate (0024).

### Expiry, renewal and custody

- Default lifetime **one year**, `not_before` set one hour in the past by the signer to
  absorb clock skew. `status` shows the node's own `not_after`; a `certificate-expiring`
  warning is logged from 30 days before, and a metric carries the remaining seconds.
- **CA key offline**: an Ed25519 key encrypted to the operator's age identity only, never
  to a host key, decrypted into the CLI's stdin when signing. CLI: `kekkai ca keygen`,
  `kekkai cert sign` (from a public key, name, addresses, groups, lifetime),
  `kekkai cert show` (decodes and verifies offline). The deployment repository declares
  name, addresses and groups per node, a script signs or renews certificates that expire
  within 30 days, and the certificates (public) are committed there and deployed inline in
  the configuration. A node's private key is generated as in 0017; the iOS app generates
  its own and shows its public key for signing.
- The certificate, CA list and deny list reload with `SIGHUP` (spec §4.1): renewal and
  revocation are reloads, never restarts.

### Revocation

A `[pki] revoked` list of public keys and certificate fingerprints in every party's
configuration, nodes, lighthouse and relay alike (the lighthouse then neither admits nor
serves a revoked certificate). No CRL protocol in v1; lifetimes are the backstop for a
host the deny list has not reached.

### Groups in the firewall

Receiver-side rules, union of every match, default deny and ICMP unchanged (0011):

```toml
[[firewall.inbound]]
groups = ["admin"]          # any of these groups
names  = []                 # or certificate names
allow  = ["tcp/22"]
```

Rules apply to certificate peers; static peers keep their per-peer `allow_inbound`. The
allowed set is computed when a peer is admitted and again at reload. Lighthouse queries
stay open to any admitted node (accepted risk in threat model §5 unchanged).

### hanko

Independent, aligned: a certificate's `name` is the host name of the shared peer list,
the `<host>` of hanko's SPIFFE IDs; no shared key, format or service. Node attestation for
hanko-ca by overlay address becomes stronger, since a certificate now binds the address.

### Review gate 3 (0021)

New crypto and a new parser reachable after the Noise read by anyone who knows a
responder's public key: the certificate codec, strict Ed25519 verification, the identity
function and its precedence rules, message 2 verification, distribution through the
lighthouse, the bounded peer table, the amended threat model (CA compromise, lighthouse
learning names and groups). One gate at the end of v1.2, before any certificate is
accepted on the real network; until it passes, deployed hosts carry no `[pki]` section.

## Questions decided

The owner answered yes to all twelve on 2026-10-24.

1. **Format**: the TLV certificate above, signed over a context string, at most 960
   bytes? *Recommended: yes.*
2. **Algorithm**: Ed25519 with strict verification, adding `ed25519-dalek` to
   `kekkai-core` (amends 0028)? *Recommended: yes; P-256 only if the CA key must live in
   hardware without Ed25519 support.*
3. **Contents**: name, X25519 key, overlay addresses, groups, validity; no role, no
   issuer field, no CA certificate (bare CA keys, at most two)? *Recommended: yes.*
4. **CA custody**: offline, age-encrypted to the operator only, signing by the CLI on the
   operator's machine, no online CA? *Recommended: yes; a YubiKey PIV path later if
   wanted, without format change.*
5. **Lifetime**: one year by default, renewal by a deployment script from 30 days before
   expiry, warning and metric on the node? *Recommended: yes (90 days if you prefer expiry
   as a stronger backstop and accept quarterly renewals).*
6. **Revocation**: deny list of keys and fingerprints in configuration, applied by reload,
   no CRL protocol in v1? *Recommended: yes.*
7. **Distribution**: certificate in both handshake messages, lighthouse keeps it and
   answers queries by overlay address; lighthouses and relays stay pinned by key?
   *Recommended: yes.*
8. **Firewall**: receiver-side `[[firewall.inbound]]` rules by group or certificate name,
   per-peer `allow_inbound` kept for static peers? *Recommended: yes.*
9. **Lighthouse query policy**: still any admitted node may query any address in v1?
   *Recommended: yes; group-restricted queries only if a need appears.*
10. **hanko**: independent, names aligned, nothing shared? *Recommended: yes.*
11. **Review gate 3**: a single gate at the end of v1.2, no `[pki]` on deployed hosts
    before it? *Recommended: yes.*
12. **End state**: once gate 3 has passed, the deployment drops static peer lists and
    keeps only lighthouse and relay keys, the CA keys and the deny list? *Recommended:
    yes.*

## Milestones (copied into `docs/milestones.md`)

```
v1.0 certificates in the handshake → v1.1 discovery by certificate → v1.2 groups
→ v1.3 migration of the deployment
                                              ↑ review gate 3
```

- **v1.0 — Certificates in the handshake.** Spec (format, §4 identity function, §7.6 and
  §7.7, constants, registries) and `certificate.json` vectors including Ed25519 edge
  cases; codec, strict verification and peer table in the core; `[pki]` configuration
  with reload; `kekkai ca keygen`, `cert sign`, `cert show`; status and log additions;
  fuzz target for the codec. *Acceptance*: `nixosTest` `certificates`: C, listed nowhere,
  initiates to A and pings it; an expired certificate, one from another CA, one with a
  foreign key and a revoked one are refused silently; adding C to A's deny list and
  reloading cuts C at once; a v0-configured node (no `[pki]`) is byte-identical in
  behaviour (existing tests unchanged); simulation: expiry cuts a live session within
  `REJECT_AFTER_TIME`.
- **v1.1 — Discovery by certificate.** Lighthouse and relay admission by certificate,
  certificate storage, query by address, certificate in reply and punch; overlay prefixes
  routed to the tunnel. *Acceptance*: `nixosTest` `cert-discovery`: D joins with only its
  own configuration (no change on A, B, lighthouse or relay), A pings D's address and D
  pings A, behind the NATs of `nat-direct`; through the relay as in `nat-relayed`;
  simulation: a lighthouse returning a certificate of another CA, of another address or a
  revoked one gets no handshake.
- **v1.2 — Groups in the firewall.** `[[firewall.inbound]]` rules, computed at admission
  and reload. Review gate 3. *Acceptance*: `nixosTest` `firewall-groups`: a peer in
  `admin` reaches `tcp/22`, a peer outside it does not, a renewed certificate without the
  group loses access at the next handshake; gate 3 passed.
- **v1.3 — Migration of the deployment.** *Acceptance* (manual, recorded): every host on
  certificates with static peer lists removed; a new node added without touching any
  other host's configuration; a revocation applied by reload; a renewal applied by reload
  without restart.

*Excluded*: online CA, CRL protocol, hardware CA key, the iOS app itself, multi-lighthouse,
lighthouse query policy, anything else in 0027.

## Consequences

- Adding a node becomes: generate its key, sign its certificate, deploy that node (plus
  annai's zone, which is annai's plan). Revoking still touches every host.
- The CA key is the one secret whose loss forges any identity; its custody is the
  operator's, offline.
- The wall clock gains a second use (certificate validity, 0004): a host whose clock is
  far off refuses valid certificates or accepts expired ones until NTP corrects it.
- A compromised lighthouse learns names, groups and addresses in addition to keys; it
  still cannot forge or impersonate.
- The responder parses and verifies one certificate of at most 960 bytes for any sender
  that passes `mac1` and the Noise read: one Ed25519 verification beside the three X25519
  operations of today, within the accepted handshake-flood risk.
