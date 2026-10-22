# ADR 0032 — Keepalive on a change of local addresses

Status: Accepted — 2026-10-22

## Context

ADR 0013 makes roaming follow the source of authenticated packets (WireGuard's rule) and
acts on a change of the node's own local addresses only at the lighthouse register tick
(§12.5 rule 3, up to 25 s). On the real network (milestone v0.6, finding 4) a node that
changed network while it only received traffic was found again only when it next sent
something: its passive keepalive, up to `KEEPALIVE_TIMEOUT` (10 s) later; 1.4 s and 8.2 s
were observed. The simulation `a_receiving_node_that_changes_network_is_reached_within_a_round_trip`
reproduces it: 0.6 to 9.8 s depending on the phase of that keepalive.

## Options considered

- Re-register and rediscover every peer at once (rule 3 without waiting for the register
  tick): a lighthouse query and a handshake per peer for what one authenticated packet
  already fixes when the peer is reachable; changes rule 3, which the review gates passed.
- Listen to OS network-change events (netlink, `PF_ROUTE`): new IO code per platform, and
  ADR 0013 keeps OS events out of v0.
- Send one keepalive on every live session as soon as the local endpoints the IO layer
  already collects at every wake-up (§13.1) change.

## Decision

- When the set of local endpoints collected by the IO layer changes, the node sends at the
  next tick one keepalive on every `current` session that can send (peers, lighthouses,
  relays), so each moves its endpoint by §12.4 within one round trip. Existing message
  type, no wire change.
- The IO layer of the node collects its local endpoints at every wake-up whether a
  lighthouse is configured or not, and wakes up at least once a second on an absolute
  deadline that received traffic does not postpone (a fresh one-second sleep per received
  datagram or packet would starve the collection under steady inbound traffic). Even
  under saturated input: an overdue deadline is served before any input is read, and the
  loop yields to the runtime regularly. No OS event, no new dependency.
- Rule 3 of §12.5 (re-registration and rediscovery at the register tick) is unchanged.

## Consequences

- A peer reachable at its unchanged endpoint (a public node, a NAT that keeps its mapping)
  sends to the moved node again about one round trip after the change is seen, plus at
  most one IO wake-up (≤ 1 s).
- A peer reached through an address the node has left still waits for §12.5 rule 2 or 3.
- A keepalive sent while the new address has no route yet is lost; the next change of the
  collection, or the §12.5 triggers, recover.
- One extra keepalive per session per change, at most one per collection (two deadlines of
  the core within a second can make two collections): no measurable cost.
- A peer behind a NAT that filters by address and port is not reached by the keepalive
  when the node's own NAT gives its new address another public port: that peer's NAT
  drops it, and the triggers of §12.5 find the node (about 20 s in the `roaming` nixosTest
  before it was changed to keep the port). Only the lighthouse, the relays and peers with
  an unfiltered endpoint learn the new port from the keepalive.
