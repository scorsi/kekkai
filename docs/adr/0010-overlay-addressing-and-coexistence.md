# ADR 0010 — Overlay addressing and coexistence with Tailscale

Status: Accepted — 2026-10-13

## Context

Tailscale stays installed during v0 for remote access. Tailscale uses `100.64.0.0/10` and a ULA prefix of its own. Some tools are still IPv4-only; IPv6 addresses are painful without DNS.

## Options considered

- IPv6 ULA only: no collision possible, but unfriendly without DNS and some tools need IPv4.
- IPv4 only: simple, but collides with LANs eventually and forecloses nothing good.
- Dual stack: ULA as the primary identity, an IPv4 range for comfort.

## Decision

- **Dual stack.** Each node has one IPv6 `/128` inside a ULA `/48` generated per RFC 4193 by the operator, and one IPv4 `/32` inside a range reserved by the operator in `10.0.0.0/8`, chosen to avoid Tailscale's `100.64.0.0/10`, the hypervisor NAT ranges in use and common LAN ranges. The concrete prefixes are deployment values and live in the deployment repository, not here (0025).
- Addresses are **static**, declared per peer in the Nix-generated configuration. The node's routing table maps overlay address → peer public key, like WireGuard's AllowedIPs. Only `/32` and `/128` routes in v0.
- **No subnet routing, no exit node** in v0.
- **No DNS in kekkai**, in v0 or later. Names, zones and the resolver configuration of the hosts belong to annai, whose zone data is generated from the same shared peer list; the kekkai modules are agnostic of any suffix. The deployment may still generate `/etc/hosts` entries for node names as a bootstrap fallback when annai is down, and SSH aliases.
- **Underlay is dual stack from the first tunnel milestone**: the UDP socket is IPv6 with IPv4 mapped addresses, and endpoint candidates include both families (0013). Native IPv6 at the public entry point is required (a deployment constraint recorded in `docs/milestones.md`).

## Consequences

- No route or address conflict with Tailscale by construction while both run.
- Reaching a host's LAN from afar needs subnet routing (0027).
- Native IPv6 between two nodes gives a direct path without hole punching, only a firewall pinhole.
