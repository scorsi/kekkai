# ADR 0029 — Dependencies of the IO layer, the control API and the daemons

Status: Accepted — 2026-10-18

Amended by [0033](0033-the-cli-in-rust.md) — 2026-10-24: the CLI is Rust; its dependencies are listed in 0033 and the Go paragraph below no longer applies.

## Context

ADR 0028 fixes the dependencies of `kekkai-core`. The first tunnel milestone (v0.2) adds
`kekkai-io`, the `kekkai-node` daemon, the control server and the CLI commands. The ADRs name
some of what they need (tokio in 0004, tonic and buf in 0015, `tracing` in 0019, a TOML file
read through a serde struct in 0016) but not the crates around them, and any extra
dependency is an ADR, not a `cargo add` (0002).

## Options considered

- The `tun` crate for the TUN device: its address configuration is IPv4-centred and it
  brings its own async wrappers; the Linux TUN setup is five ioctls.
- A netlink crate (`rtnetlink`, `neli`) for addresses and routes: a large dependency tree
  for two address assignments and `/32`, `/128` routes, which the legacy `SIOCSIFADDR` and
  `SIOCADDRT` ioctls do on both families.
- `sd-notify`, `clap`, `anyhow`, `thiserror`: each replaces a few lines.
- `tracing-subscriber` with `env-filter`: pulls `regex`; the `Targets` filter parses the
  same `target=level,level` syntax without it.

## Decision

Rust, direct dependencies outside `kekkai-core`:

| Crate | Used by | Why |
| --- | --- | --- |
| `tokio` (`rt`, `net`, `time`, `macros`, `signal`) | `kekkai-io`, `kekkai-node` | the runtime of ADR 0004 |
| `tonic`, `prost` | `kekkai-control`, `kekkai-node` | already in the workspace (0015) |
| `prost-types` | `kekkai-control`, `kekkai-node` | `google.protobuf.Timestamp` and `Duration` (0015) |
| `tokio-stream` (`net`) | `kekkai-node` | serves tonic on a Unix listener; already pulled by tonic |
| `tracing` | `kekkai-io`, `kekkai-node` | the logging facade of 0019 and 0027 |
| `tracing-subscriber` (`registry`, `std`, no `fmt`, no `env-filter`) | `kekkai-node` | `Targets` filter for `RUST_LOG` and `[log] level`, and the `Layer` trait of the hand-written schema layer (`apps/node/src/log.rs`, ADR 0019 amendment 2026-10-20) |
| `serde` (`derive`), `toml` | `kekkai-io` | the configuration of 0016 |
| `libc` | `kekkai-io` | TUN ioctls, `CLOCK_BOOTTIME` (0004); already pulled by tokio |

No other crate. `READY=1` (0018) and systemd socket activation are written against the
documented protocols with the standard library. Argument parsing stays hand-written (two
subcommands).

Go: no new module. `kekkai keygen` and `pubkey` use `crypto/ecdh` and `encoding/base64` from
the standard library; `status --json` uses `protojson` from `google.golang.org/protobuf`,
already required by the generated client.

## Consequences

- `unsafe` appears in `kekkai-io` only (ioctls, the clock, the inherited socket fd);
  `kekkai-core` keeps `#![forbid(unsafe_code)]`.
- The TUN code depends on the Linux ioctl ABI; macOS `utun` (v0.3) adds its own module.
- On macOS the `utun` interface's MTU, addresses and routes are configured by running
  `/sbin/ifconfig` and `/sbin/route` (as `wg-quick` does) rather than with routing-socket
  code, so no extra crate is needed.
- Adding a crate to these lists is a new ADR, as for the core.

## Amendment — 2026-10-20: `tracing-subscriber` without `fmt`

Since the log schema of ADR 0019 (amendment 2026-10-20), `kekkai-node` writes every stderr
line with a hand-written `tracing` layer. The `fmt` feature is no longer used, so the
dependency is `tracing-subscriber` with `registry` and `std` only: the registry, the
`Targets` filter and the `Layer` trait. No new crate.
