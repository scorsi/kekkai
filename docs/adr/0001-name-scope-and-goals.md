# ADR 0001 — Name, scope and goals

Status: Accepted — 2026-10-13

## Context

The author runs a small, fully declarative homelab (NixOS, nix-darwin, flakes, sops-nix) whose hosts move often, sit behind consumer routers the author cannot configure, share untrusted LANs, and will partly live behind CGNAT. Today the hosts are connected by Tailscale. The author wants a mesh overlay they own end to end: no closed coordination server, no subscription, everything declared in Nix, a deep learning exercise and a portfolio piece.

## Options considered

- Keep Tailscale, or self-host Headscale: solves the subscription, not the learning goal, and the client remains someone else's code.
- Deploy Nebula or plain WireGuard: proven, but configuration of discovery and relaying stays outside the author's control and the learning goal is not met.
- Build an overlay from proven cryptographic building blocks, with the author's own protocol and services.

## Decision

- Name: **kekkai** (結界, the protective barrier). One product, components named by suffix: `kekkai-node`, `kekkai-lighthouse`, `kekkai-relay`, `kekkai` (CLI).
- Goal: **replace Tailscale** for the author's hosts once a v0 is stable. Until then Tailscale stays installed; replacing it is a deployment plan, not an ADR.
- Design references: WireGuard, Tailscale and Nebula. None of them is deployed as part of kekkai; they are read, not reused.
- Scope of v0: authenticated encrypted tunnels between statically listed peers, discovery and hole punching through a lighthouse, relaying through a relay, Linux and macOS nodes, a read-only CLI. Everything else is explicitly later (0027).
- Technical milestones, no calendar (`docs/milestones.md`). The project advances in small steps alongside other projects.

## Consequences

- Every design choice is judged against "could it make the Tailscale replacement impossible" first and "is it the smallest thing that works" second.
- Nebula and WireGuard conventions are borrowed whenever they are well analysed (timers, replay window, cookie mechanism), so that reviewers can compare against known designs.
