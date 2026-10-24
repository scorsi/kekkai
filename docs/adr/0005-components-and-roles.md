# ADR 0005 — Components and roles

Status: Accepted — 2026-10-13

Amended by [0033](0033-the-cli-in-rust.md) — 2026-10-24: the `kekkai` CLI is a Rust binary of the workspace, no longer the Go CLI; its commands and its use of the control socket are unchanged.

## Context

Discovery and relaying need a reachable host on the public Internet. The author will start with one VPS and may add a second entry point on another continent later. Discovery and relaying must not be an open service.

## Options considered

- One binary with roles enabled by configuration: fewer artifacts, but the privileged node code (TUN, routing) would ship on hosts that only relay.
- Separate binaries per role, roles assigned by configuration, never by host.

## Decision

- Four deliverables:
  - `kekkai-node`: the node service (TUN, routing, per-peer firewall). Privileged.
  - `kekkai-lighthouse`: endpoint registration and lookup. Unprivileged.
  - `kekkai-relay`: forwards encrypted traffic it cannot read. Unprivileged.
  - `kekkai`: the Go CLI, unprivileged, talking to `kekkai-node` over the control socket (0015). v0 commands: `keygen`, `pubkey`, `status --json`.
- **Lighthouse and relay are roles**, never tied to a given host, so a second entry point can be added later. Nodes configure them as **lists** from the start; v0 supports exactly one element in each list (0012, 0014).
- Lighthouse and relay **authenticate peers with the same handshake as nodes** (0007) and speak to nodes through the inner protocol inside the Noise transport (0009). They never answer an unauthenticated packet.
- A host that carries the lighthouse and relay roles also runs a `kekkai-node`: three services, three identity keys. Otherwise that host would be the only one unreachable through the overlay once Tailscale is gone.
- Default UDP ports, all configurable: lighthouse **4800**, relay **4801**, node **4802**. No privileged port.

## Consequences

- Three daemons share `kekkai-core` and `kekkai-io`; TUN support is a Cargo feature only the node enables (0023).
- Multi-lighthouse and multi-relay union is a later milestone, but the configuration shape never changes.
