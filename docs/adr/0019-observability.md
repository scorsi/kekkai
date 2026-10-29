# ADR 0019 — Observability

Status: Accepted — 2026-10-13

## Context

Journald everywhere on Linux, launchd on macOS, no metrics collector yet. Debugging a mesh needs to know when paths change.

## Options considered

- Prometheus exporter from the start: nothing to scrape it.
- Structured logs plus counters exposed through the control API; metrics endpoint when a collector exists.

## Decision

- **Structured logs** through `tracing`, written to stderr: journald on Linux, a file managed by launchd on macOS. Level per target through `RUST_LOG` or `[log] level` (precedence in 0016). **Never a key or a payload in logs.**
- Events at `info`: handshake completed with a peer, path change (direct, relayed, none) with the reason, endpoint change, session expired, lighthouse or relay session state change.
- **No metrics exporter in v0.** Counters live in the core and are exposed by `status --json` (0015). A `/metrics` endpoint is added when a collector exists; counters are instrumented once, now.
- **Health**: `READY=1` through `Type=notify`; no HTTP health endpoint. Health is read through `status --json`.
- Lighthouse and relay log aggregate counters only (0006).

## Consequences

- Session losses on the real network are explained from these events alone.
- Debugging is `journalctl -u kekkai-node` plus `kekkai status --json`.

## Amendment — 2026-10-20: log schema, metrics endpoint, validators

A collector now exists (hikyaku pushing to nisshi and masu), so the "no metrics exporter in
v0" line is lifted and the log format is fixed.

- **Logs**: every line `kekkai-node` writes on stderr is one JSON object of nisshi's log
  schema v1: `v` (`1`), `ts` (UTC, RFC 3339, exactly 9 fractional digits, `Z`), `level`
  (`debug`, `info`, `warn`, `error`; `trace` events are written as `debug`), `event`
  (kebab-case), optional `msg`, `err` only on `warn` and `error`, then the event's own
  fields. Never a field the agent or the store adds (`node`, `service`, `stream`, `seq`,
  `source`, `recv_ts`, `_*`). This covers start-up and fatal errors (`fatal{err}`, also
  written by the panic hook), so the journal of the unit holds nothing else.
- The `info` events above are named `handshake-completed{peer,endpoint,initiator}`,
  `path-change{peer,from,to,reason}` (`from`/`to` among `direct`, `relayed`, `none`;
  `reason` kebab-case, e.g. `handshake-completed`, `session-expired`), `endpoint-change{peer,
  endpoint}`, plus `ready`, `stopping`, `endpoint-unresolved`. `peer` is the configured peer
  name. Never a key, a nonce or a payload, as before.
- The line is written by a hand-written `tracing` layer in `kekkai-node`: `tracing` stays
  the facade, the `Targets` filter of 0016 is unchanged, and no crate is added to 0029
  (`tracing-subscriber`'s JSON formatter would need `serde_json`).
- **No journald rate limit**: kekkai does not log per packet or per request (drops are
  `trace` and counted), so the `LogRateLimit*` defaults nisshi ADR 0009 sets for annai and
  genkan are not set by the kekkai modules.
- **Metrics**: `services.kekkai-node.metrics.listen` (`[metrics] listen`, default `null` = no
  listener) opens a loopback-only `GET /metrics` (the module's type and the daemon both refuse
  another address), hand-written Prometheus text 0.0.4 following masu's metric convention:
  `kekkai_build_info{version}`, `kekkai_peer_path{peer,via="direct"}` (`relayed` with the
  relay, v0.5), `kekkai_handshakes_total{peer,result="ok|timeout"}`,
  `kekkai_rx_bytes_total{peer}`, `kekkai_tx_bytes_total{peer}`,
  `kekkai_dropped_packets_total{reason}` with `reason` = kekkai-core's `DropReason` names.
  Five series per peer plus at most 24 others, within the 500-series budget up to about 95
  peers. The core's per-peer counters gain the completed handshakes per role and the
  abandoned ones; `status --json` (0015) is unchanged.
- **Validators in tests**: the `two-nodes` nixosTest pipes
  `journalctl _SYSTEMD_UNIT=kekkai-node.service -o cat` of each node into
  `nisshi validate --logs`, asserts that `handshake-completed` lines exist, runs
  `masu validate --metrics` on the endpoint and checks that `kekkai_handshakes_total` moved.
  nisshi and masu are test-only flake inputs; the package and the modules do not use them.
  Unit tests pin the line format (timestamp, escaping, reserved names) and the exposition.
- The darwin LaunchDaemon writes the same lines to its log file.

## Amendment — 2026-10-29: certificates (ADR 0034)

With `[pki]` only; a node without it exposes and logs exactly what it did before.

- **Log**: `certificate-expiring{not_after,remaining_seconds}` at `warn` (`not_after` UTC
  RFC 3339), from 30 days before the own certificate's `not_after` (spec §4.2): at start, after
  each reload and once a day, and still once it has expired (negative `remaining_seconds`).
  Refused handshakes stay silent on the wire and are not logged at `info` (drops are `trace`
  and counted), as before. The per-peer events (`handshake-completed`, `path-change`, …) still
  name configured peers only; certificate peers are seen through the status.
- **Metrics**: the gauge `kekkai_certificate_remaining_seconds` (negative once expired), and
  the certificate rejects of spec §18.7 as `kekkai_dropped_packets_total{reason}` with
  `reason` = `certificate_<reason>` (`certificate_expired`, `certificate_bad_signature`, …),
  kekkai-core's `DropReason` names as before: at most 34 drop series. Certificate peers get
  no per-peer series (`pki.max_peers` of them would exceed masu's 500-series budget); their
  traffic stays in the status.
- **Status** (0015): `node.certificate` (name, fingerprint, `not_before`, `not_after`,
  groups) and, for each peer admitted by certificate, `peers[].certificate`, the peer's
  `name` and `addresses` then being the certificate's.
