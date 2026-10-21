# ADR 0030 — Lighthouse status, logs and metrics

Status: Proposed — 2026-10-21

## Context

Milestone v0.4 asks that "the lighthouse's `status` lists both registrations", and the
observability contracts ask every house daemon for schema logs and a loopback `/metrics`.
ADR 0015 defines the control API for the node only, ADR 0012 and 0006 say the lighthouse
logs aggregate counters only, ADR 0019 names the node's `info` events, and ADR 0029 lists
which binary uses which crate. None of them says how the lighthouse is observed.

## Options considered

- Metrics only: a `kekkai_lighthouse_registrations` gauge proves a count, not which nodes
  are registered, and `status --json` is what the tests assert on (0015, 0020).
- A second protocol or file dump: more code than reusing the control API.
- The same `ControlService.GetStatus` served by the lighthouse on its own socket.

## Decision

- `kekkai-lighthouse` serves `GetStatus` on `/run/kekkai-lighthouse/control.sock`
  (systemd socket unit, `root:kekkai-lighthouse 0660`, the module's `operators` join the
  group). The reply fills `node` (its key, version, wire version, uptime, port) and
  `registrations` (name, key, observed and local endpoints, `last_seen`) and nothing else.
  `kekkai status --json --socket PATH` reads it. The node's reply gains `lighthouses`
  (state `connected`/`handshaking`/`down`, last handshake, last packet received), the
  section ADR 0015 announced.
- The registrations are readable on the host only, through the socket's permissions. The
  lighthouse's **logs** stay aggregate (0012): `ready`, `stopping`, `fatal`, never a node
  name, key or endpoint; its `/metrics` has no per-node label:
  `kekkai_build_info`, `kekkai_lighthouse_registrations`, `kekkai_lighthouse_registers_total`,
  `kekkai_lighthouse_queries_total{result="known|unknown"}`,
  `kekkai_lighthouse_punches_total`, `kekkai_dropped_packets_total{reason}`.
- Node `info` events added to ADR 0019's list: `direct-path-failed{peer,reason}` (spec
  §12.6 reason) and `lighthouse-session-change{lighthouse,from,to}` (the "lighthouse session
  state change" of ADR 0019; `lighthouse` is the configured endpoint as written, since the
  `[[lighthouses]]` entry has no name).
- `kekkai-lighthouse` uses exactly the crates `kekkai-node` uses minus the TUN feature
  (tokio, tonic, prost-types, tokio-stream, tracing, tracing-subscriber; ADR 0029's table
  gains it in the "Used by" column). No new crate. The schema log layer is the node's file,
  included by path.

## Consequences

- One CLI and one proto serve both daemons; the relay (v0.5) can follow the same pattern.
- Anyone in the `kekkai-lighthouse` group can read where every node is; on the public
  entry point that group should stay empty or hold the operator only.
