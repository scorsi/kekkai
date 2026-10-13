# ADR 0026 — Deploying over the overlay

Status: Accepted — 2026-10-13

## Context

Once kekkai is in production, hosts are deployed over SSH through kekkai. A `switch` that changes the peer list restarts `kekkai-node` in the middle of activation and cuts the deployment session. Today the author's deployment scripts run the activation in the foreground of the SSH session.

## Options considered

1. **`SIGHUP` reload** of the peer list: no restart on the most frequent change; a binary change still restarts.
2. **Detached activation** in the deployment scripts: `switch-to-configuration` started through `systemd-run` on the target, the SSH client only waits for the result. The activation finishes even if the session drops. Covers binary changes too.
3. **deploy-rs** with magic rollback: replaces the author's existing deploy scripts, a larger change in the deployment repository.

## Decision

- **Options 1 and 2 together**, delivered in the real-network milestone (v0.6). Option 3 only if 2 proves fragile.
- Reload: `ExecReload` sends `SIGHUP`; the daemon re-reads the configuration at its stable path (`/etc/kekkai/node.toml`) and applies a **diff of the peer list** to the core (0004, 0016) without touching existing sessions of unchanged peers. The module sets `reloadTriggers` on the configuration file and `restartTriggers` on the binary. Lighthouse and relay get the same reload for their peer lists.
- A restart still cuts traffic for one to two seconds; TCP survives, so a detached activation makes deployment safe even across a binary upgrade.
- **macOS** has neither `systemd-run` nor `reloadTriggers`, and a remote `darwin-rebuild switch` loses its SSH session when the LaunchDaemon restarts. Equivalents:
  - Reload: the configuration lives at a stable path (`/etc/kekkai/node.toml` through `environment.etc`) so that a peer change leaves the plist untouched and nix-darwin does not restart the daemon; an activation script then sends `launchctl kill HUP system/kekkai-node` when the file changed. A binary change changes the plist and restarts the daemon, as on Linux.
  - Detached activation: the switch runs inside a detached `tmux` session on the Mac (`tmux new -d -s switch '…switch…; echo $? > /tmp/switch.status'`), tmux being already installed on every host; the deploying side reconnects and reads the status. In practice the Mac is also deployed locally when the operator works on it, which needs nothing.
- Future hardening already noted in 0018: TUN owned by systemd-networkd, so that even a restart keeps the interface and routes up.

## Consequences

- The real-network milestone includes a deployment over kekkai that changes the peer list and one that upgrades the binary.
- Reload is the first mutating operation in the daemon's life; it needs its own `nixosTest` (peer added and reachable, peer removed and refused, unchanged peer's session untouched).
