# ADR 0031 — Relay status, logs, metrics and rate limits

Status: Proposed — 2026-10-21

## Context

Milestone v0.5 asks that "the relay's `status` shows per-sender counters growing", that a
configured per-sender rate limit caps a flooding sender (ADR 0014: "a per-sender maximum
rate is configurable, disabled by default"), and that the node shows `path = relayed` with
the relay's key (ADR 0013, 0015). ADR 0030 settled how the lighthouse is observed and said
the relay "can follow the same pattern", without fixing its socket, status content,
metrics or log events. ADR 0014 leaves the unit of the rate limit open. The v0.4 review
(finding L7) left open whether the lighthouse needs a per-sender budget for queries and
punches, to be decided with the relay's rate limit before review gate 2.

## Options considered

- Relay status through metrics only: a sum proves no per-sender counter; the milestone
  asks for per-sender counters in `status`.
- Per-sender metrics labels on the relay: per-node labels are what ADR 0012 and 0030 keep
  off the infrastructure roles' metrics.
- Rate limit in packets per second: a flood of small packets and one of full-size packets
  would cost the relay very differently under the same limit. In bytes per second: what
  the relay's link actually spends.
- Lighthouse budget: keep L7 open for gate 2; a fixed per-sender rate; or a rate derived
  from the configuration that a node following the specification can never exceed.

## Decision

- **Relay status**: `kekkai-relay` serves `ControlService.GetStatus` on
  `/run/kekkai-relay/control.sock` (systemd socket unit, `root:kekkai-relay 0660`, the
  module's `operators` join the group), as ADR 0030 does for the lighthouse. The reply fills
  `node` (key, version, wire version, uptime, port) and `senders`: per listed key, its
  configured name, whether it has a live session, `forwarded_packets`, `forwarded_bytes`,
  `dropped_no_route`, `dropped_rate_limited`. **No endpoint**: the relay does not need to
  show where a node is. `kekkai status --json --socket PATH` reads it.
- **Node status**: `GetStatusResponse.relays` (state, last handshake, last packet received,
  the shape of `lighthouses`), the section ADR 0015 announced; `PeerStatus.path =
  PATH_RELAYED` with `relay_public_key`.
- **Logs**: the relay logs aggregate events only (ADR 0014): `ready{port,peers,
  rate_limited}`, `stopping`, `fatal`; never a node name, key or endpoint. The node gains
  the `info` event `relay-session-change{relay,from,to}` (the "relay session state change"
  of ADR 0019; `relay` is the configured endpoint as written), and `path-change` now uses
  `relayed` (ADR 0019).
- **Metrics**: the relay's `/metrics` has no per-node label: `kekkai_build_info`,
  `kekkai_relay_sessions`, `kekkai_relay_forwarded_packets_total`,
  `kekkai_relay_forwarded_bytes_total`, `kekkai_relay_refused_total{reason="no_route|
  rate_limited"}`, `kekkai_dropped_packets_total{reason}`. The node emits
  `kekkai_peer_path{peer,via}` for both `direct` and `relayed`: six series per peer instead
  of five (ADR 0019's 500-series budget then holds up to about 80 peers). kekkai-core's
  `DropReason` gains `rate_limited`. The lighthouse's `kekkai_lighthouse_queries_total`
  gains `result="limited"`.
- **Rate limit**: `[service] max_bytes_per_second` in the relay file (module option
  `maxBytesPerSecond`, default `null`: no limit): `relay_forward` **payload bytes** per
  second per sender, a token bucket with one second's worth as burst (spec §14.2). A refused
  packet is dropped silently and counted per sender.
- **Lighthouse query budget** (closes L7): per querier, `2 × L` queries as burst, refilled
  at `L` per `DIRECT_PATH_TIMEOUT`, `L` the number of listed keys; a query over budget gets
  no reply and no punch and is counted (spec §13.2). A node that follows §12.5 queries each
  peer at most once per rediscovery window, so it is never refused; a compromised node's
  punches are bounded by the configuration. Not configurable: no deployment needs another
  value, like the other timing constants of ADR 0013's amendment.
- **No tunnel in the relay**: "`kekkai-relay` depends on no tunnel decryption path" (ADR
  0014) is checked as: the relay is built without `kekkai-io`'s `tun` feature and without
  `kekkai-node` (`relay-has-no-tunnel`, a `cargo tree` check in `nix flake check`), its core
  role never parses a payload (unit test: an arbitrary payload is forwarded byte for byte),
  and its state holds per-sender counters and buckets only (simulation and unit tests).
  The relay necessarily links the session code of `kekkai-core` for its own sessions with
  the nodes.
- `kekkai-relay` uses exactly the crates `kekkai-lighthouse` uses (ADR 0029, 0030); the
  schema log layer is the node's file, included by path. No new crate.

## Consequences

- One CLI and one proto serve the three daemons.
- Anyone in the `kekkai-relay` group learns which nodes use the relay and how much; on the
  public entry point that group should stay empty or hold the operator only.
- A legitimate burst larger than the configured rate is dropped by the relay; the setting
  is per deployment and off by default.
