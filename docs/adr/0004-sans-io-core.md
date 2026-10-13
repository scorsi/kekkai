# ADR 0004 — Sans-IO core

Status: Accepted — 2026-10-13

## Context

The same protocol must run under tokio on Linux and macOS, under `NEPacketTunnelProvider` on iOS, and inside deterministic tests that simulate loss, reordering and clock drift.

## Options considered

- Protocol logic written against tokio sockets directly: simple at first, impossible to test deterministically or to embed in a Network Extension.
- A sans-IO state machine with platform drivers around it.

## Decision

- `kekkai-core` is a **sans-IO state machine**. Its surface is: feed it incoming datagrams and tunnel packets with the current time, get back datagrams to send, tunnel packets to deliver, and the next deadline. It owns no socket, no thread, no timer, no file.
- The core takes **two clocks**: a monotonic instant for every timer and deadline (on Linux `CLOCK_BOOTTIME`, on macOS `mach_continuous_time`, so that time spent suspended counts and sessions expire correctly on wake), and the wall clock only to produce the TAI64N handshake timestamp (0007). Timers never depend on the wall clock.
- **Suspend**: the IO layer's sleeping primitives (`tokio::time::sleep`) stop during suspend on both Linux and macOS, so a deadline armed before a long sleep would fire late by the whole suspend duration. `kekkai-io` therefore **never sleeps more than about one second at a time**: it wakes, reads the suspend-aware clock above, hands the core the current instant and lets it process every deadline that has passed (expirations, rekeys, keepalives). The simulation (0020) includes a "long suspend then resume" scenario.
- The IO layer (`kekkai-io`) drives it: UDP and TUN through tokio on Linux and macOS, `packetFlow` on iOS later.
- The core treats transport as **abstract datagrams**: a TCP adapter later adds length framing outside the core (0027).
- The core exposes no generics and no async in its public surface, so it can be wrapped by UniFFI later (0027).
- The peer list is a replaceable value of the core, not a constant captured at construction, so that a reload (0016, 0026) is possible without rebuilding the state.

## Consequences

- Hole punching, relay fallback and roaming are first proven in simulated-network tests (0020) before any `nixosTest`.
- The core's memory use is bounded by configuration, a requirement of the iOS Network Extension (0027).
