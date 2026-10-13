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
