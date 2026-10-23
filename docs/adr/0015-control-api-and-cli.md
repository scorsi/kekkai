# ADR 0015 — Control API and CLI

Status: Accepted — 2026-10-13

Amended by [0033](0033-the-cli-in-rust.md) — 2026-10-24: the CLI is Rust (`apps/cli`), a tonic client generated at build time by `kekkai-control`; no Go client is generated or committed. `keygen` and `pubkey` use `kekkai-core`'s key code, so the shared keygen vectors are checked by the Rust suites (core and CLI) only.

## Context

The Go CLI needs to read the node's state; later it will drive reloads and more. The author already uses gRPC with buf conventions in another project.

## Options considered

- Line-delimited JSON over a Unix socket, no schema: least code for one command, every future command reinvents a contract.
- gRPC over a Unix socket with buf, reusing known conventions.

## Decision

- **gRPC over a Unix domain socket**, protos under `proto/kekkai/control/v1/`, package `kekkai.control.v1`, tooling and rules as in the author's kajiba project: `buf lint`, `buf generate`, `buf breaking` informational during v0; standard gRPC codes with `google.rpc.Status` details; `google.protobuf.Timestamp` and `Duration`. Rust server through tonic (`kekkai-control` crate, 0023), Go client generated and committed.
- v0 exposes a single `GetStatus` RPC. `kekkai status --json` prints its reply in protojson form.
- **Socket path and permissions are per platform**: Linux `/run/kekkai/control.sock`, macOS `/var/run/kekkai/control.sock`; owner `root:kekkai`, mode `0660`; the operator's user is added to the `kekkai` group by the module. Nothing is mutable in v0, but the permissions are set now so that a future mutating RPC needs no hardening afterwards.
- **`keygen` and `pubkey`** are fully local, without the daemon: `kekkai keygen` writes an X25519 private key (0017) to stdout or to a file in mode 0400; `kekkai pubkey` derives the public key. Encoding: standard base64, one line, as WireGuard does. Because these run in Go, the spec ships **shared test vectors** (private key → public key → base64) checked by both the Rust and Go test suites in `nix flake check`.
- **Status content**: node (public key, overlay addresses, binary version, wire version, uptime, listen port); per lighthouse and relay (session state `connected`/`handshaking`/`down`, last handshake, last keepalive received); per peer (public key, overlay addresses, `path` as in 0013, current endpoint, last handshake, bytes and packets in and out, replay rejections, reason of the last direct-path failure); firewall (UDP flow table size, maximum, evictions, 0011).

## Consequences

- The CLI contains no hand-written protocol types.
- `nixosTest`s assert on `status --json`, not on `ping` alone.

## Amendment — 2026-10-21: peer name in status

Owner decision: `PeerStatus` carries `name`, the name this node's own configuration gives the peer (0016), matched by public key; a local label, never sent over the overlay nor learned from peers.

## Implementation note — 2026-10-22: receiver index in status (v0.6)

`PeerStatus.receiver_index` (field 16, `optional uint32`, unset without a `current` session) is the local index of the peer's `current` session (spec §7.5); the reload test of 0026 compares it before and after a reload. Additive (0024), shown by `status --json` without CLI change. `PeerStatus.session_created` (field 17, v0.7) is when that session was created: the reload test proves with it that the index it compares belongs to a young confirmed session (`last_handshake` can be a newer session not yet confirmed); additive too.
