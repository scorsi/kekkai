# kekkai (結界, "the barrier")

A small authenticated overlay network: a Noise-based tunnel between nodes, with
lighthouses for discovery and relays for hard NAT. One Rust implementation of
the protocol, a Go CLI. See [`docs/adr/`](docs/adr/) for the design decisions
and [`docs/milestones.md`](docs/milestones.md) for the plan.

Status: **v0.0**, skeleton only, no protocol code yet.

## Layout

- `proto/` — the control API contract (`kekkai.control.v1`), buf.
- `crates/` — Rust libraries: `kekkai-core`, `kekkai-io`, `kekkai-control`.
- `apps/` — `node`, `lighthouse`, `relay` (Rust binaries) and `cli` (Go module).
- `nix/` — packages, NixOS and nix-darwin modules, tests, checks.
- `docs/` — ADRs, the milestone plan, the protocol specification (`docs/spec/`, with test
  vectors) and the threat model.

## Building

```sh
nix develop        # Rust, Go, buf, protoc plugins, cargo-fuzz, nushell
nix flake check    # unit, lint, format and module checks (nixosTest on Linux only)
nix build .#kekkai-node .#kekkai-lighthouse .#kekkai-relay .#kekkai
```

## License

Apache-2.0, see [`LICENSE`](LICENSE).
