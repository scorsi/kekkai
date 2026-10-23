# kekkai — notes for AI assistants

Read [`docs/adr/`](docs/adr/) before making an architectural choice. [`docs/milestones.md`](docs/milestones.md)
is the plan: its acceptance criteria are the definition of done for a milestone.

## Conventions

- One version (`VERSION` at the repo root) across the Cargo workspace, the `kekkai` CLI
  included, enforced by the `versions-identical` check (0024).
- `proto/` is the only place `.proto` contracts live. After editing: `cd proto && buf lint`.
  Generated Rust is not committed (0023); a contract change needs a hand-written
  `status --json` fixture under `apps/cli/testdata/status/` (0033).
- Crate names are fixed (`kekkai-core`, `kekkai-io`, `kekkai-control`); no new top-level crate
  without an ADR (0023). `kekkai-core` has no async runtime and no socket type (0004).
- Format with `nix fmt` (treefmt).
- Public repository: no host names, domains, address ranges or keys of any deployment (0025).
- Code, comments, docs and commits in English.
