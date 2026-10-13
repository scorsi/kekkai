# ADR 0025 — License and public documentation policy

Status: Accepted — 2026-10-13

## Context

A portfolio project, public from the first commit. The design is informed by the author's own hosts, some of which have accepted weaknesses.

## Options considered

- Private repository until v1: contradicts the portfolio goal.
- Public, with deployment specifics kept out.

## Decision

- **Apache-2.0** from the first commit, as for the author's other projects. Public on Forgejo with a GitHub mirror.
- Code, comments, protos, spec, ADRs, plan, README, CLAUDE.md and CONTRIBUTING **in English**.
- **The public documentation stays generic**: no host names, no address ranges, no public keys, no weaknesses specific to the author's deployment. The threat model speaks of "a host whose disk is not encrypted", never of a named machine. The concrete values (overlay prefixes, peers, ports, which host carries which role, the accepted key-at-rest risk on a given host) live in the author's private deployment repository.

## Consequences

- ADRs and the plan describe roles and constraints, and refer to "the public entry point" or "the hypervisor bridge" rather than hosts.
- Review material shared with external reviewers (0021) is public material by construction.
