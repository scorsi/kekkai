# ADR 0018 — Platforms and service hardening

Status: Accepted — 2026-10-13

## Context

v0 must serve between a headless Mac (nix-darwin) and NixOS machines. The public entry point runs unprivileged services. Other platforms are later.

## Options considered

- Linux only in v0: simplest, but the author's Mac is the hub of the homelab and a real tunnel exists only once macOS works.
- macOS through a Network Extension: requires an Apple Developer account and a signed app for a headless daemon; `utun` from a LaunchDaemon needs neither.

## Decision

- **Platforms in v0**: Linux (systemd service, NixOS module) and macOS (LaunchDaemon, nix-darwin module, `utun`, no Network Extension). **Nothing else.** iOS and iPadOS come later as a SwiftUI app with a Packet Tunnel Provider, distributed through internal TestFlight or Ad Hoc only, never publicly (0027).
- **`kekkai-node` on Linux**: `User=kekkai`, `CapabilityBoundingSet=` and `AmbientCapabilities=CAP_NET_ADMIN`, `DeviceAllow=/dev/net/tun`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`, `Type=notify` with `READY=1` after TUN creation and socket bind. No `CAP_NET_BIND_SERVICE` (ports above 1024).
- **`kekkai-lighthouse` and `kekkai-relay`**: static users `kekkai-lighthouse` and `kekkai-relay`, empty capability set, same restrictions without TUN and netlink. **No `DynamicUser` anywhere**: sops-nix sets the owner of the key at activation, before any unit runs, so the user must exist then; named users are also simpler to inspect when debugging.
- **macOS**: the LaunchDaemon runs as root because `utun` requires it; documented risk. Control socket under `/var/run/kekkai/` (0015).
- **Future hardening, not implemented**: a persistent TUN interface created by systemd-networkd and owned by the `kekkai` user, addresses and routes declared by Nix, so that the daemon runs with no capability at all and a restart does not bring the interface down (0026).

## Consequences

- The TUN code is a Cargo feature of `kekkai-io` that only the node enables (0023).
- The macOS module is tested by evaluation in CI only; a `nixosTest` equivalent does not exist for Darwin.
