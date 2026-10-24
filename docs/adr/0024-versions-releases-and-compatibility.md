# ADR 0024 — Versions, releases and compatibility

Status: Accepted — 2026-10-13

Amended by [0033](0033-the-cli-in-rust.md) — 2026-10-24: there is no Go module any more; `versions-identical` requires the CLI and the three daemons to take the Cargo workspace version.

## Context

One repository, three daemons and a CLI deployed from a single commit by the deployment repository. The wire format evolves independently of the software version. An iOS app will later break the single-commit assumption.

## Options considered

- Independent versions per component: drift to manage, contrary to the monorepo.
- One software version plus a separate wire version.

## Decision

- **One semver `0.x` version** in `VERSION` at the repository root, carried by the Cargo workspace and the Go module, enforced identical by a `versions-identical` check in `nix flake check`. A release is a commit carrying the bump plus a **signed tag** `vX.Y.Z`. No linearity constraint; the release method is specified later.
- **Wire version** (0009): an integer in the outer header, starting at **1**, changed only on an incompatible change of the wire format or of the inner protocol. Nodes with different wire versions **ignore each other silently**.
- Control API: `buf breaking` informational during v0; from the first production version (once kekkai is in production), additive only or a new package version.
- **Compatibility rule in v0**: everything is deployed from one commit, so mixed versions exist only during deployment windows and the silent-ignore rule is enough.
- **Recorded for later**: the iOS app will always lag behind the hosts (a TestFlight build is never deployed in the same `switch`), so **overlapping wire versions** will be required then: a node must accept the current and the previous wire version for a transition period. The header's version byte and the prologue binding make this possible without a format change.

## Consequences

- A wire-format break once kekkai is in production is a visible, deliberate event (wire version bump, both versions supported for a while).
- The software version is what users see; the wire version is what the spec tracks.
