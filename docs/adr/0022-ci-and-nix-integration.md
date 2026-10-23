# ADR 0022 — CI and Nix integration

Status: Accepted — 2026-10-13

Amended by [0033](0033-the-cli-in-rust.md) — 2026-10-24: the `kekkai` package is built by crane like the daemons; Go, the protoc Go plugins, `gofmt`, `buildGoModule`, the `go-test` and `buf-generate` checks are gone (`buf-lint` stays).

## Context

The deployment repository consumes the author's applications as pinned flake inputs and wraps them in its own feature modules. CI runs on self-hosted Forgejo runners: a Linux VM and a Mac.

## Options considered

- Export a flake-parts module like the author's base configuration: fits a configuration base, not an application.
- Export plain `nixosModules`, `darwinModules`, `packages` and an overlay; the deployment wraps them.

## Decision

- **Flake outputs**: `packages.{kekkai-node,kekkai-lighthouse,kekkai-relay,kekkai}`, `nixosModules.{node,lighthouse,relay}`, `darwinModules.node`, `overlays.default`, `devShells.default` (stable Rust, Go, buf, protoc plugins, cargo-fuzz, nushell), `checks`, `formatter` (treefmt: rustfmt, gofmt, nixfmt). flake-parts, crane for Rust, `buildGoModule` for the CLI, same base as kajiba.
- The modules are **agnostic of any deployment**: no DNS suffix, no host name, no address range. The deployment repository owns a single shared peer attrset and generates, for every host, its node configuration, annai's zone data (0010) and SSH aliases.
- **Workflow** `.forgejo/workflows/check.yml`: job `linux` on `runs-on: linux` running `nix fmt -- --ci`, `buf lint` and a `nix build -L` of every `checks.aarch64-linux` attribute, one nix process per check to bound evaluator memory (a single `nix flake check` evaluating all `nixosTest`s exceeds the runner's memory); job `macos` building the Darwin packages and evaluating `darwinModules.node`. No x86_64 job until an x86_64 runner exists.
- Hosted on Forgejo, mirrored to GitHub; inputs in the deployment point at Forgejo, GitHub is the recovery path, as for the author's other flakes.

## Consequences

- A `nix flake check` on macOS covers units, simulation and corpus replay; the `nixosTest`s need the `linux` runner, which provides KVM (0020).
- Adding a lighthouse or relay on a new host is a deployment change only.
