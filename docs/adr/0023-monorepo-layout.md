# ADR 0023 — Monorepo layout

Status: Accepted — 2026-10-13

## Context

Three Rust daemons, a Go CLI, a gRPC contract, Nix modules, a spec and fuzz targets. The author's kajiba monorepo (its ADR 0018) is the template.

## Options considered

- One repository per component: four flakes, four CIs, a shared proto to publish.
- A single repository with one version.

## Decision

- **A single `kekkai` repository**:

  ```
  proto/kekkai/control/v1/      gRPC contract, buf (0015)
  crates/kekkai-core/           sans-IO protocol: Noise, sessions, routing, firewall, inner protocol, timers (0004)
  crates/kekkai-io/             tokio UDP driver, key loading; TUN (Linux, utun) behind the `tun` Cargo feature
  crates/kekkai-control/        tonic server code generated from the protos
  apps/node/ apps/lighthouse/ apps/relay/   Rust binaries
  apps/cli/                     Go module, generated client committed
  fuzz/                         cargo-fuzz targets and committed corpus (0020)
  nix/                          packages, nixosModules, darwinModules, tests, checks
  docs/adr/ docs/spec/ docs/threat-model.md docs/milestones.md
  flake.nix go.work VERSION LICENSE README.md CLAUDE.md CONTRIBUTING.md
  ```

- Crate names are fixed: `kekkai-core`, `kekkai-io`, `kekkai-control`. The network protocol lives in `kekkai-core`; `kekkai-control` is only the control API, hence the name. **No new top-level crate without an ADR.**
- `kekkai-core` depends on no async runtime and no socket type. `kekkai-io` enables `tun` only for the node, so lighthouse and relay do not link TUN code.
- Format with `nix fmt` (treefmt). Generated Go code is committed; generated Rust code is not.

## Consequences

- A cross-cutting change (spec, core, daemons, CLI) is one commit and one `nix flake check`.
- Nix builds stay separate derivations per component.
