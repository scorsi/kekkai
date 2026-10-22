# ADR 0026 — Deploying over the overlay

Status: Accepted — 2026-10-13

## Context

Once kekkai is in production, hosts are deployed over SSH through kekkai. A `switch` that changes the peer list restarts `kekkai-node` in the middle of activation and cuts the deployment session. Today the author's deployment scripts run the activation in the foreground of the SSH session.

## Options considered

1. **`SIGHUP` reload** of the peer list: no restart on the most frequent change; a binary change still restarts.
2. **Detached activation** in the deployment scripts: `switch-to-configuration` started through `systemd-run` on the target, the SSH client only waits for the result. The activation finishes even if the session drops. Covers binary changes too.
3. **deploy-rs** with magic rollback: replaces the author's existing deploy scripts, a larger change in the deployment repository.

## Decision

- **Options 1 and 2 together**, delivered in the real-network milestone (v0.6). Option 3 only if 2 proves fragile. (2026-10-22: option 1, the reload, moved to its own milestone v0.7; option 2 stays in v0.6.)
- Reload: `ExecReload` sends `SIGHUP`; the daemon re-reads the configuration at its stable path (`/etc/kekkai/node.toml`) and applies a **diff of the peer list** to the core (0004, 0016) without touching existing sessions of unchanged peers. The module sets `reloadTriggers` on the configuration file and `restartTriggers` on the binary. Lighthouse and relay get the same reload for their peer lists.
- A restart still cuts traffic for one to two seconds; TCP survives, so a detached activation makes deployment safe even across a binary upgrade.
- **macOS** has neither `systemd-run` nor `reloadTriggers`, and a remote `darwin-rebuild switch` loses its SSH session when the LaunchDaemon restarts. Equivalents:
  - Reload: the configuration lives at a stable path (`/etc/kekkai/node.toml` through `environment.etc`) so that a peer change leaves the plist untouched and nix-darwin does not restart the daemon; an activation script then sends `launchctl kill HUP system/kekkai-node` when the file changed. A binary change changes the plist and restarts the daemon, as on Linux.
  - Detached activation: the switch runs inside a detached `tmux` session on the Mac (`tmux new -d -s switch '…switch…; echo $? > /tmp/switch.status'`), tmux being already installed on every host; the deploying side reconnects and reads the status. In practice the Mac is also deployed locally when the operator works on it, which needs nothing.
- Future hardening already noted in 0018: TUN owned by systemd-networkd, so that even a restart keeps the interface and routes up.

## Consequences

- The real-network milestone includes a deployment over kekkai that changes the peer list and one that upgrades the binary.
- Reload is the first mutating operation in the daemon's life; it needs its own `nixosTest` (peer added and reachable, peer removed and refused, unchanged peer's session untouched).

## Implementation notes — 2026-10-22 (reload, v0.7)

- Semantics are specified in spec §4.1: the lists (node: peers, lighthouses, relays;
  lighthouse and relay: peers) reload as a diff by public key; every other section needs a
  restart and a reload only warns about it (`reload-restart-required`). Lighthouse and relay
  endpoints of a node reload in place like a peer's static endpoints, because the core
  already replaces static candidates without touching sessions (the DNS re-resolution of
  0016 does the same).
- This replaces the v0 line of 0016 ("a change restarts the service at switch") for the
  lists only. Modules: `reloadTriggers` is the generated file, `restartTriggers` the binary
  and a hash of the restart-only sections (`restartFingerprint`), so a file change that
  touches both restarts. `ExecReload` is `kill -HUP $MAINPID`; the daemon frames the reload
  with `RELOADING=1` / `READY=1`. The reload is asynchronous to `systemctl reload`: wait for
  the `reloaded` (or `reload-failed`) log event, not for the command.
- macOS: `postActivation` keeps two markers, `/var/db/kekkai-node.restart` (the hash of the
  restart-only sections) and `/var/db/kekkai-node.config` (the file). A changed hash runs
  `launchctl kickstart -k`; otherwise a changed file runs `launchctl kill SIGHUP` (launchctl
  takes the signal's full name). A binary change still changes the plist and restarts.
  A marker moves only after its launchctl action succeeded, and a failure stops the
  activation (nix-darwin runs it under `set -e`), so an interrupted or failed activation
  runs the action again next time instead of recording it. `.config` means "signalled",
  as `systemctl reload` does on Linux: a reload the daemon refuses shows as
  `reload-failed` in its log. The first activation, without markers, restarts the daemon
  launchd has just started (redundant, harmless). A deployment fragment ordered after
  this one (e.g. a secret installation that restarts the daemon and records its own
  marker after a successful kickstart) does not run when this one fails, and runs again
  with it at the next activation; when both a restart-only section and the secret change,
  the daemon restarts twice. `modules-eval` runs the fragment against a fake launchctl:
  missing markers, a refused action, an interruption between action and marker.
- The daemons install their `SIGHUP` handler first thing at start, before DNS resolution
  and interface creation and always before `READY=1` (spec §4.1); a `SIGHUP` during
  start-up is applied once ready.
- Routes (spec §4.1): additions then deletions as one transaction, undone in reverse on a
  refusal (the reload then fails); the daemon keeps the set the kernel holds, so a route
  an undo could not restore is reconciled at the next reload. A route deleted behind the
  daemon's back makes every reload that removes it fail until a restart.
- Log events (0019 schema): `reloaded{peers,added,removed,changed}` (`info`),
  `reload-failed{err}` (`error`), `reload-restart-required{sections}` (`warn`),
  `route-rollback-failed{route,err}` (`error`).
- Status (0015, additive per 0024): `PeerStatus.receiver_index` (16, optional), the local
  index of the `current` session; a reload that keeps the peer keeps it.
  `PeerStatus.session_created` (17) dates that session, for the reload test.
- `nixosTest` `reload` switches specialisations with `switch-to-configuration test`, so
  the module triggers are tested with the daemon.
