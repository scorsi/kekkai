# kekkai — milestone plan

Technical milestones, no calendar. Each milestone has an **objective**, **deliverables**, **acceptance criteria** proven by `nix flake check` (unit, property, simulation, corpus replay, `nixosTest` on the `linux` runner) whenever possible, **dependencies**, and what is **excluded**. A milestone is closed when its criteria pass in CI; `nix flake check` never stays red between milestones. ADR references in parentheses.

Order of v0: local network first, then discovery, then relaying, then the real network.

```
v0.0 skeleton → v0.1 spec + core → v0.2 first tunnel (Linux) → v0.3 macOS + firewall
→ v0.4 lighthouse → v0.5 relay → v0.6 real network → v0.7 reload
                  ↑ review gate 1                    ↑ review gate 2
```

## External dependencies

| Dependency                                              | Blocks                                   |
| ------------------------------------------------------- | ---------------------------------------- |
| The `linux` Forgejo runner with KVM (nested virtualization in the CI VM, or the NixOS laptop) | `nixosTest`s in CI from v0.0; until then they run by hand |
| Public VPS with native IPv6 (provider not chosen)       | Real deployment of v0.4 and v0.5, not their `nixosTest`s |
| NixOS laptop                                            | Part of v0.6 (roaming scenarios)         |

Nothing external blocks v0.1.

---

## v0.0 — Skeleton: a green repository at the first commit

**Objective**: the monorepo exists, builds nothing useful, and every tool of the project already runs in CI.

**Deliverables**: flake (flake-parts, crane, treefmt, devShell), Cargo workspace with the three empty crates and three empty binaries, empty Go module with `go.work`, `proto/kekkai/control/v1/control.proto` with a `GetStatus` stub and `buf.yaml`, `nix/` with packages, `nixosModules.{node,lighthouse,relay}`, `darwinModules.node` (empty options), a trivial `nixosTest` that starts `kekkai-node --version`, `versions-identical` check, `.forgejo/workflows/check.yml`, `LICENSE` (Apache-2.0), `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `docs/adr/`, this plan. (0022, 0023, 0024, 0025)

**Acceptance criteria**

- `nix flake check` green on `aarch64-linux` (`linux` runner) and, for the non-VM checks, on `aarch64-darwin`.
- `nix build .#kekkai-node .#kekkai-lighthouse .#kekkai-relay .#kekkai` succeed; each binary prints the `VERSION` value with `--version`.
- `buf lint` and `buf generate` run; the generated Go and Rust code compiles.
- The trivial `nixosTest` passes on the `linux` runner.
- Forgejo repository with GitHub mirror in place.

**Dependencies**: the `linux` runner for the `nixosTest` criterion (otherwise run by hand and recorded).

**Excluded**: any protocol code.

---

## v0.1 — Specification and sans-IO core

**Objective**: the protocol exists as a document and as a deterministic state machine that two instances can run against each other without any network.

**Deliverables**

- `docs/threat-model.md` (0006) and `docs/spec/protocol.md` (0003): notation, suite, handshake (0007), sessions and timers (0008), wire format and inner protocol with type registries (0009), lighthouse messages (0012), NAT traversal procedure (0013), relay messages (0014), constants, firewall semantics (0011), test vectors under `docs/spec/vectors/`.
- `kekkai-core`: `Noise_IKpsk2` handshake through `snow` with zero psk, `mac1` pre-check, TAI64N anti-replay with reduced precision, two-clock surface (monotonic and wall), canonical TLV payloads with critical-bit handling, per-type outer message layouts, identity trait with the static-list implementation, sessions with receiver index, nonce counter, 8128 replay window, rekey and rejection timers, keepalives, outer header and inner message codecs, routing table (`/32`, `/128`), the sans-IO driver surface (input bytes and time in, output bytes and deadline out), `StaticKey` opaque type, peer list as a replaceable value. (0004, 0017)
- Lighthouse, relay and firewall logic in the core **may** land here if convenient, but are only accepted in v0.4, v0.5 and v0.3 respectively.
- Tests (0020): Noise vectors, keygen vectors (Rust side), wire vectors, proptest on codecs and replay window, deterministic simulation harness with loss, reordering, duplication, delay and clock drift, fuzz targets with an initial corpus for the outer header, TLV lists and inner messages.
- Review gate 1 (0021): spec, threat model, diff and vectors sent to the reviewers; findings resolved.

**Acceptance criteria**

- Two cores complete a handshake and exchange data in the simulation under 10 % loss, reordering and duplication, with a fixed seed; the test is reproducible.
- Replayed message 1 is rejected; a data packet outside the window is rejected; a counter reuse is impossible by construction (unit test on the session type).
- Rekey happens at 120 s and the old session is rejected at 180 s in the simulated clock; a session whose peer went silent expires and is recreated on demand.
- An unknown wire version, an unknown message type, a bad `mac1`, a malformed packet, a non-canonical TLV list and an unknown critical TLV produce no output (silence, 0006); an unknown non-critical TLV is ignored and the handshake completes.
- A wall clock stepped backwards makes the node's own initiations rejected until it catches up, while it still answers its peers; timers are unaffected by wall-clock steps (simulation).
- Simulation "long suspend then resume": the monotonic clock jumps forward by more than `REJECT_AFTER_TIME` in one step; on the next tick the core expires the stale sessions, re-handshakes and resumes traffic without waiting out the old timers.
- `cargo fuzz run <target>` for the parsers builds and the committed corpus replays green in `nix flake check`.
- Every ADR 0027 constraint on the core is checked: no tokio or socket dependency in `kekkai-core`, no generics or async in its public surface, bounded buffers with documented sizes.
- Review gate 1 passed (2026-10-21, ADR 0021 amendment of that date).

**Dependencies**: v0.0.

**Excluded**: any IO, TUN, CLI, Nix module behaviour, lighthouse and relay services.

---

## v0.2 — First tunnel: `kekkai-node` on Linux

**Objective**: two Linux nodes with static endpoints ping each other through the overlay, from a Nix-generated configuration.

**Deliverables**: `kekkai-io` (tokio UDP dual-stack socket, Linux TUN behind the `tun` feature, key loading from a file, MTU 1280 and MSS clamping), `kekkai-node` (config loading and `config check`, routing, `Type=notify`, control socket serving `GetStatus`), `kekkai-control`, the Go CLI with `keygen`, `pubkey` and `status --json`, Go-side keygen vectors, NixOS module `node` with hardening (0018), `/etc/kekkai/node.toml` at a stable path, group `kekkai` and socket permissions (0015, 0016). `nixosTest` `two-nodes`: two NixOS nodes on one network, static endpoints.

**Acceptance criteria**

- `nixosTest two-nodes`: both services reach `READY=1`; `ping` in both directions over IPv4 and IPv6 overlay addresses; `kekkai status --json` on each node shows the peer with `path = direct`, a recent handshake and non-zero counters; `kekkai-node config check` accepts the module's output and refuses a file containing an inline secret; the control socket is `0660 root:kekkai` and a user outside the group is refused.
- `nixosTest two-nodes` also checks silence: a packet from an unlisted key gets no reply (observed with `tcpdump` on the sender).
- The Go keygen vectors pass, identical to the Rust ones.
- `nix flake check` green on the `linux` runner.

**Dependencies**: v0.1.

**Excluded**: macOS, firewall, lighthouse, relay, roaming, reload.

---

## v0.3 — macOS node and per-peer firewall

**Objective**: a real tunnel between the Mac and the NixOS VM on its hypervisor bridge, with inbound filtering, so that kekkai serves daily on the local network.

**Deliverables**: `utun` support in `kekkai-io`, nix-darwin module `node` (LaunchDaemon as root, stderr to a launchd-managed file, control socket under `/var/run/kekkai/`, group creation), per-peer inbound firewall in the core (0011) with `allow_inbound` in the configuration and the module, firewall tests in the simulation, `nixosTest` `firewall`.

**Acceptance criteria**

- `nixosTest firewall`: peer A may reach `tcp/22` on B and nothing else; a connection to another port from A is dropped (timeout, no reset over the tunnel); ICMP always passes; a UDP request from B to A's allowed `udp/…` service gets its reply back (flow table); the rules survive a service restart.
- Simulation: TCP SYN filtered, non-SYN passed, UDP flow entries expire at 60 s; a full flow table evicts the oldest entry and the eviction counter appears in `status --json`; a non-initial IP fragment passes only after its accepted first fragment; a first fragment with a truncated transport header and a non-initial fragment overlapping the transport header are both dropped (property tests and fuzz corpus, RFC 1858 and RFC 7112 cases).
- CI `macos` job builds `kekkai-node` for `aarch64-darwin` and evaluates `darwinModules.node`.
- Manual, recorded in the milestone's closing note: the Mac and the VM ping each other over the overlay through the hypervisor NAT bridge with static endpoints; `status --json` shows `direct` on both; SSH from the Mac to the VM over the overlay works; the macOS service survives a reboot.

**Dependencies**: v0.2, review gate 1 (real use on a local network, 0021).

**Excluded**: lighthouse, relay, roaming, Network Extension, any macOS version without `utun` through a LaunchDaemon.

---

## v0.4 — Lighthouse: discovery, hole punching, basic roaming

**Objective**: two nodes behind two different NATs find each other through one lighthouse and establish a verified direct path.

**Deliverables**: `kekkai-lighthouse` (register, query, punch, expiry, static-user hardening (0018), `config check`, 0012), node-side discovery with candidates, parallel handshakes, first-wins, 3 s and 60 s constants, roaming on authenticated source change, re-registration after three failed keepalives (0013), `lighthouses = [ … ]` configuration accepting exactly one element, NixOS module `lighthouse`, `status --json` sections for lighthouse state, `path` and last direct-path failure reason, simulation scenarios with cone NAT and address rewriting, `nixosTest` `nat-direct` with two nftables router nodes (`masquerade`), `nixosTest` `roaming`.

**Acceptance criteria**

- `nixosTest nat-direct`: A and B, each behind its own cone NAT, with the lighthouse on a third network; neither knows the other's endpoint from configuration; after start, `status --json` on both shows `path = direct` and an endpoint that is the other's NAT address; `ping` works; the lighthouse's `status` lists both registrations; stopping the lighthouse does not break the established A↔B session.
- `nixosTest roaming`: A and B first connect through their LAN addresses on a shared network; A is moved to a different network behind a NAT; within 30 s both `status --json` show a new direct endpoint learnt through the lighthouse and `ping` resumes.
- Silence: a `lighthouse_query` from an unlisted key gets no reply.
- Simulation: with a cone NAT on both sides the direct path completes; with a symmetric NAT on both sides the node reports `path = none` with the failure reason after 3 s (relay comes in v0.5).
- Simulation, rediscovery triggers: a node whose session to a peer used a LAN endpoint moves to another network (local addresses change) and recovers a direct path through the lighthouse well before `REJECT_AFTER_TIME`; the same when only the peer moved (handshake unanswered after `REKEY_TIMEOUT` triggers the query); a relayed packet never changes the peer's endpoint.
- Two nodes on the same LAN as the lighthouse-registered local endpoints connect through their local addresses (asserted on the endpoint in `status`).
- Manual, once the public VPS exists: lighthouse deployed on it; the Mac and the VM discover each other through it with no static endpoints.

**Note (2026-10-21, owner decision)**: the manual criterion above is postponed until review gate 2 has passed (end of v0.5), since ADR 0021 allows Internet exposure only from gate 2 on. Until then v0.4 is validated by the simulation and the `nixosTest`s `nat-direct` and `roaming`; the manual run is recorded when it happens.

**Dependencies**: v0.3. The public VPS with native IPv6 for the manual criterion only.

**Excluded**: relay, multi-lighthouse union, symmetric-NAT tricks, OS network-change events, certificates in lighthouse replies.

---

## v0.5 — Relay

**Objective**: when no direct path exists, traffic flows through a relay that cannot read it, and the relay's blindness is proven.

**Deliverables**: `kekkai-relay` (`relay_forward` and `relay_forwarded`, per-sender counters, optional per-sender rate limit, static-user hardening (0018), `config check`, 0014), node-side relay fallback and periodic direct retry (0013), `relays = [ … ]` configuration accepting exactly one element, NixOS module `relay`, `status --json` relay sections and `path = relayed` with the relay's key, simulation scenarios, `nixosTest` `nat-relayed` with `masquerade fully-random` on both routers, `nixosTest` `relay-upgrade`. Review gate 2 (0021).

**Acceptance criteria**

- `nixosTest nat-relayed`: A and B behind symmetric NATs, lighthouse and relay on a third network; `status --json` on both shows `path = relayed` with the relay's public key within 10 s; `ping` works; a `tcpdump` capture on the relay host during a ping carrying a known 64-byte pattern does not contain the pattern; the relay's `status` shows per-sender counters growing.
- `nixosTest relay-upgrade`: starting relayed, the routers are switched to cone NAT; within 90 s both nodes show `path = direct`.
- Unit test: the relay's state type holds no session key of a node pair; `kekkai-relay` has no dependency on the tunnel decryption path (checked by a `cargo tree`-based check in `nix flake check`).
- Rate limit: with a limit configured, a flooding sender is capped and the counters show drops; with no limit nothing is dropped.
- Silence: a `relay_forward` from an unlisted key gets no reply.
- Review gate 2 passed (2026-10-22, ADR 0021 amendment of that date; authorizes Internet exposure).

**Note (2026-10-21)**: the per-sender rate limit is in payload bytes per second
(`[service] max_bytes_per_second`), and the lighthouse's query budget left open by the v0.4
review is decided with it (spec §13.2, §14.2, ADR 0031, proposed). The "no dependency on
the tunnel decryption path" criterion is checked by `relay-has-no-tunnel` (no `tun` feature,
no `kekkai-node` in the relay's `cargo tree`). What review gate 2 receives is listed in ADR
0021's amendment "review gate 2 brief".

**Dependencies**: v0.4.

**Excluded**: multi-relay, TCP/443, relay selection by RTT.

---

## v0.6 — Real network

**Objective**: kekkai runs on every host of the deployment, with the lighthouse and relay on the public entry point, and holds up to the manual scenarios.

**Deliverables**: v0.5 running on every host of the deployment with the lighthouse and relay on the public entry point; detached activation in the deployment repository's scripts (0026, option 2). Everything the deployment repository has to do around it (peer attrset, keys, entry point, replacing Tailscale) is its own plan, not part of this milestone. The `SIGHUP` reload moved to v0.7 (owner, 2026-10-22).

**Acceptance criteria**

- `status --json` shows the expected `path` for every pair: direct where the underlay allows it (same hypervisor bridge, native IPv6), relayed elsewhere.
- Manual scenarios passed and recorded: reboot of the public entry point, of the VM host and of the hypervisor host; laptop sleep and wake; Wi-Fi change and change of location; restart of `kekkai-node` during an SSH session with recovery under 10 s; a deployment over kekkai that upgrades the binary (detached activation, 0026).
- A breakage seen on the real network becomes a simulation or `nixosTest` case before it is fixed (0020).

**Dependencies**: v0.5 and review gate 2; the public VPS; the laptop for the roaming scenarios.

---

## v0.7 — Reload

**Objective**: a change of the configured lists applies without restarting the daemons, so the most frequent deployment over kekkai does not cut its own session.

**Deliverables**: `SIGHUP` reload of the configured lists in node, lighthouse and relay with `ExecReload`, `reloadTriggers` on the configuration file and `restartTriggers` on the binary and the restart-only settings (0026; spec §4.1: a node's lighthouse and relay lists reload too, every other section restarts); `nixosTest` `reload`. Status 2026-10-22: implemented (1ed92e7), review findings closed (29b4297), re-review and `nixosTest` reruns pending.

**Acceptance criteria**

- `nixosTest reload`: adding a peer in the configuration and reloading makes it reachable without restarting; removing one makes its handshakes refused; an unchanged peer's session keeps its receiver index across the reload; an invalid configuration changes nothing.
- Manual scenario passed and recorded: a deployment over kekkai that changes the peer list.

**Dependencies**: v0.6.

**Excluded**: everything in ADR 0027. After v0.7, the next ADR opens v1 (certificates and groups).

---

## Open questions

Decided and closed on 2026-10-13: Noise hash (BLAKE2s), TLV encoding and critical bit, TAI64N precision, concurrent initiations, UDP flow table bounds, ACME ownership (hanko issues, genkan loads files, annai serves the challenges).

Nothing blocks v0.1. Still open, with the milestone they block:

| Question | Blocks | Note |
| --- | --- | --- |
| Public VPS provider, native IPv6 required | Real deployment of v0.4 and v0.5 | Their `nixosTest`s do not depend on it |
| Nested virtualization in the CI VM, validated by `nix build nixpkgs#nixosTests.simple` | `nixosTest`s in CI from v0.0 | Fallback: run by hand until the laptop runner exists |
| Scheduled fuzz job | nothing | Manual fuzzing in v0 (0020) |
| Release method (branch, changelog) | nothing | Specified at the first tagged release |
| v1 certificate format (home-grown minimal preferred over X.509), lifetime, groups | nothing in v0 | Decided after v0.7 (0027) |

Note (owner, 2026-10-21): when two crossing handshakes complete, one direct and one relayed, each
side may keep a different path until the next handshake (at most about 60 s). Accepted until after
review gate 2; making the direct session always win needs a change to session promotion in
`peer.rs` (gate 1 scope) and is planned after gate 2.
