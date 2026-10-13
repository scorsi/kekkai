# ADR 0002 — Languages

Status: Accepted — 2026-10-13

## Context

The protocol must run as a privileged daemon on Linux and macOS, later inside an iOS Network Extension, and be fuzzed and property-tested. The author already uses Rust for daemons, Go for CLIs, Nushell for scripts and Python only where NixOS tests impose it.

## Options considered

- Everything in Rust, including the CLI: one toolchain, but the author's CLI conventions and generated gRPC clients already exist in Go (kajiba).
- Everything in Go: no sans-IO core discipline, weaker property testing and fuzzing story for a cryptographic state machine, no embedding in a Network Extension without cgo pain.
- Zig or Nim for the core: not proven enough for cryptographic code the author must have reviewed.

## Decision

- **Rust** for everything that speaks the protocol: the sans-IO core (0004), the three daemons, the core embedded in iOS later, fuzzing and property tests. There is **exactly one implementation** of the protocol.
- **Go** for the `kekkai` CLI, a gRPC client generated from the protos (0015).
- **Nushell** for glue and development scripts.
- **Python** only inside `nixosTest` scripts, as the framework requires.
- **Swift** later, for the iOS app shell around the Rust core.
- **Nim** kept in reserve for a small tool with no stakes. **No Zig.**

## Consequences

- The Rust core has a C-compatible surface in mind from day one (0027) even though no binding exists in v0.
- The CLI never reimplements protocol logic; what it needs comes from the control API or from cryptographic operations whose test vectors are shared with Rust (0015).
