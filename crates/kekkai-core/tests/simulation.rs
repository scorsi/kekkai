//! Deterministic simulation (ADR 0020 tier 2): several `Node`s through an in-memory network
//! with seeded loss, duplication and delay (hence reordering), per-host clock drift,
//! wall-clock steps, suspend and NAT emulated by address rewriting (cone and symmetric). The network decisions derive from the seed and a per-link
//! datagram counter, so they do not depend on the core's own randomness (indices,
//! ephemerals, retransmit jitter), which still comes from the OS.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use kekkai_core::firewall::Rule;
use kekkai_core::inner::Endpoint;
use kekkai_core::keys::{PublicKey, StaticKey};
use kekkai_core::node::{LighthouseConfig, Node, Output, Path, PathFailure, PeerConfig};
use kekkai_core::tai64n::Tai64n;
use kekkai_core::wire::{self, DropReason};
use kekkai_core::{MTU, PERSISTENT_KEEPALIVE, REJECT_AFTER_TIME, REKEY_AFTER_TIME};
use wire::TYPE_HANDSHAKE_INIT;

const EPOCH: i64 = 1_767_225_600;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

/// splitmix64: every network decision is `mix(seed, link, n)` for the n-th datagram on a link.
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

#[derive(Clone, Copy)]
struct Link {
    loss_permille: u64,
    dup_permille: u64,
    delay_min: Duration,
    delay_max: Duration,
}

const PERFECT: Link = Link {
    loss_permille: 0,
    dup_permille: 0,
    delay_min: Duration::from_millis(10),
    delay_max: Duration::from_millis(10),
};

const LOSSY: Link = Link {
    loss_permille: 100,
    dup_permille: 50,
    delay_min: Duration::from_millis(5),
    delay_max: Duration::from_millis(80),
};

struct Host {
    node: Node,
    key: PublicKey,
    /// The host's own underlay socket address.
    addr: Endpoint,
    /// The NAT the host sits behind; hosts behind the same NAT share a LAN, hosts behind
    /// none are on the public network.
    nat: Option<usize>,
    /// Monotonic clock rate offset in parts per million (ADR 0004: timers follow this one).
    drift_ppm: i64,
    /// Wall clock minus monotonic clock, in seconds; stepped by the scenarios.
    wall_offset: i64,
    asleep_until: Option<Duration>,
    /// Sequence number of the next scripted packet this host sends.
    next_seq: u32,
    /// Tunnel packets delivered, as `(sim time, sending host, sequence number)`.
    received: Vec<(Duration, usize, u32)>,
    drops: Vec<(Duration, DropReason)>,
}

impl Host {
    fn mono(&self, sim: Duration) -> Duration {
        let n = sim.as_nanos() as i128;
        Duration::from_nanos((n + n * self.drift_ppm as i128 / 1_000_000) as u64)
    }

    /// The sim instant at which this host's clock has reached `mono` (rounded up).
    fn sim_of(&self, mono: Duration) -> Duration {
        let n = mono.as_nanos() as i128;
        Duration::from_nanos((n * 1_000_000 / (1_000_000 + self.drift_ppm as i128)) as u64 + 1)
    }

    fn wall(&self, sim: Duration) -> Tai64n {
        let mono = self.mono(sim);
        let unix = EPOCH + mono.as_secs() as i64 + self.wall_offset;
        Tai64n::from_unix(unix as u64, mono.subsec_nanos())
    }

    fn asleep(&self, sim: Duration) -> bool {
        self.asleep_until.is_some_and(|t| sim < t)
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Event {
    at: Duration,
    seq: u64,
    to: usize,
    /// The datagram's source as the receiver sees it (after NAT).
    source: Endpoint,
    /// The receiver's NAT and public port: its filtering applies on arrival.
    via: Option<Via>,
    datagram: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NatKind {
    /// Endpoint-independent mapping, address-and-port-dependent filtering (Linux
    /// `masquerade` with its port kept).
    Cone,
    /// A new public port per destination (`masquerade fully-random`).
    Symmetric,
}

struct Nat {
    public: Ipv4Addr,
    kind: NatKind,
    next_port: u16,
    /// `(inside, destination if symmetric)` → public port.
    out: HashMap<(Endpoint, Option<Endpoint>), u16>,
    /// Public port → inside endpoint and the remotes it sent to (conntrack filtering).
    back: HashMap<u16, (Endpoint, HashSet<Endpoint>)>,
    /// The router accepts unsolicited datagrams to itself (no input firewall, like the
    /// nixosTests' routers before): each one confirms a conntrack entry (see `translate`).
    holds: bool,
    /// `(public port, remote)` of such a datagram, until its conntrack entry expires (Linux:
    /// 30 s after the last one).
    held: HashMap<(u16, Endpoint), Duration>,
    /// `(inside, remote)` flows that found their port held: they got another one.
    moved: HashMap<(Endpoint, Endpoint), u16>,
}

impl Nat {
    /// Linux `masquerade` keeps a flow's mapped port, but a new flow towards a remote whose
    /// unanswered datagrams to that port left a conntrack entry gets another port: the
    /// remote's later datagrams to the first port never reach the inside host.
    /// shortcut: a moved flow keeps its port forever, enough while it carries traffic.
    fn translate(&mut self, inside: Endpoint, to: Endpoint, now: Duration) -> Endpoint {
        let key = (inside, (self.kind == NatKind::Symmetric).then_some(to));
        let next = &mut self.next_port;
        let mut port = *self.out.entry(key).or_insert_with(|| {
            *next += 1;
            *next
        });
        if let Some(p) = self.moved.get(&(inside, to)) {
            port = *p;
        } else if !self.back.get(&port).is_some_and(|(_, a)| a.contains(&to))
            && self.held.get(&(port, to)).is_some_and(|t| now < *t)
        {
            self.next_port += 1;
            port = self.next_port;
            self.moved.insert((inside, to), port);
        }
        let entry = self.back.entry(port).or_insert((inside, HashSet::new()));
        entry.1.insert(to);
        Endpoint::new(IpAddr::V4(self.public), port)
    }

    /// The inside endpoint a datagram from `from` to public `port` reaches, if filtering lets
    /// it; a dropped one holds `(port, from)` (see `translate`).
    fn admit(&mut self, port: u16, from: Endpoint, now: Duration) -> Option<Endpoint> {
        match self.back.get(&port) {
            Some((inside, allowed)) if allowed.contains(&from) => Some(*inside),
            _ => {
                if self.holds {
                    self.held.insert((port, from), now + secs(30));
                }
                None
            }
        }
    }
}

/// A NAT and the public port a datagram enters it by.
type Via = (usize, u16);

/// One emitted datagram: `(sim time, from, to, outer type)`.
type Emitted = (Duration, usize, usize, u8);

struct Sim {
    seed: u64,
    now: Duration,
    seq: u64,
    link: Link,
    hosts: Vec<Host>,
    nats: Vec<Nat>,
    queue: BinaryHeap<Reverse<Event>>,
    /// Links cut by a scenario: `(from, to)`.
    partitions: HashSet<(usize, usize)>,
    emitted: Vec<Emitted>,
    /// Every datagram handed to the network: `(sim time, from, destination, bytes)`.
    sent: Vec<(Duration, usize, Endpoint, Vec<u8>)>,
    /// The lighthouse's key, to restart it (`Sim::discovery`).
    lighthouse_key: Option<StaticKey>,
    /// The relay's key, to restart it (`Sim::add_relay`).
    relay_key: Option<StaticKey>,
    /// Datagrams sent per link, the `n` of `mix(seed, link, n)`.
    link_counts: Vec<u64>,
}

fn address(host: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, host as u8 + 1))
}

/// Underlay endpoint `a.b.c.d:port`.
fn ep(a: u8, b: u8, c: u8, d: u8, port: u16) -> Endpoint {
    Endpoint::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

/// Default public underlay endpoint of host `i`.
fn public_addr(host: usize) -> Endpoint {
    ep(192, 0, 2, host as u8 + 1, 4802)
}

/// An IPv4/UDP packet from `src` to `dst` whose payload is the sequence number.
fn ip_packet(src: IpAddr, dst: IpAddr, seq: u32) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src, dst) else {
        unreachable!("IPv4 overlay in this harness")
    };
    let mut p = vec![0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17, 0, 0];
    p.extend_from_slice(&s.octets());
    p.extend_from_slice(&d.octets());
    p.extend_from_slice(&[0x30, 0x39, 0x30, 0x39, 0, 12, 0, 0]);
    p.extend_from_slice(&seq.to_be_bytes());
    p
}

/// Sending host and sequence number of a harness packet.
fn origin_of(packet: &[u8]) -> (usize, u32) {
    let seq = u32::from_be_bytes(packet[28..32].try_into().expect("harness packet"));
    (usize::from(packet[15]) - 1, seq)
}

impl Sim {
    /// `n` hosts in a full mesh, host `i` at `10.0.0.(i+1)`.
    fn new(seed: u64, n: usize, link: Link) -> Self {
        let keys: Vec<StaticKey> = (0..n).map(|_| StaticKey::generate()).collect();
        let publics: Vec<PublicKey> = keys.iter().map(StaticKey::public).collect();
        let hosts = keys
            .into_iter()
            .enumerate()
            .map(|(i, key)| {
                let peers = (0..n)
                    .filter(|&j| j != i)
                    .map(|j| PeerConfig {
                        public_key: publics[j],
                        addresses: vec![address(j)],
                        allow_inbound: vec![Rule::Any],
                        endpoints: vec![public_addr(j)],
                    })
                    .collect();
                Host {
                    node: Node::new(key, peers),
                    key: publics[i],
                    addr: public_addr(i),
                    nat: None,
                    drift_ppm: 0,
                    wall_offset: 0,
                    asleep_until: None,
                    next_seq: 0,
                    received: Vec::new(),
                    drops: Vec::new(),
                }
            })
            .collect();
        Self {
            seed,
            now: Duration::ZERO,
            seq: 0,
            link,
            hosts,
            nats: Vec::new(),
            queue: BinaryHeap::new(),
            partitions: HashSet::new(),
            emitted: Vec::new(),
            sent: Vec::new(),
            lighthouse_key: None,
            relay_key: None,
            link_counts: vec![0; n * n],
        }
    }

    fn addr(&self, host: usize) -> Endpoint {
        self.hosts[host].addr
    }

    fn peer_config(&self, j: usize) -> PeerConfig {
        PeerConfig {
            public_key: self.hosts[j].key,
            addresses: vec![address(j)],
            allow_inbound: vec![Rule::Any],
            endpoints: vec![self.hosts[j].addr],
        }
    }

    /// `n` nodes that know no endpoint of each other and one public lighthouse (the last
    /// host, at `203.0.113.1:4800`) listing them all (§13).
    fn discovery(seed: u64, n: usize) -> Self {
        let mut sim = Sim::new(seed, n, PERFECT);
        let key = StaticKey::generate();
        let lighthouse = LighthouseConfig {
            public_key: key.public(),
            endpoints: vec![ep(203, 0, 113, 1, 4800)],
        };
        let keys: Vec<PublicKey> = sim.hosts.iter().map(|h| h.key).collect();
        for i in 0..n {
            let peers = (0..n)
                .filter(|&j| j != i)
                .map(|j| PeerConfig {
                    endpoints: Vec::new(),
                    ..sim.peer_config(j)
                })
                .collect();
            sim.hosts[i].node.set_peers(peers);
            sim.hosts[i].node.set_lighthouses(vec![lighthouse.clone()]);
            let addr = sim.hosts[i].addr;
            sim.hosts[i].node.set_local_endpoints(vec![addr]);
        }
        sim.hosts.push(Host {
            node: Node::lighthouse(key.clone(), keys),
            key: lighthouse.public_key,
            addr: lighthouse.endpoints[0],
            nat: None,
            drift_ppm: 0,
            wall_offset: 0,
            asleep_until: None,
            next_seq: 0,
            received: Vec::new(),
            drops: Vec::new(),
        });
        sim.link_counts = vec![0; (n + 1) * (n + 1)];
        sim.lighthouse_key = Some(key);
        sim
    }

    fn add_nat(&mut self, public: Ipv4Addr, kind: NatKind) -> usize {
        self.nats.push(Nat {
            public,
            kind,
            next_port: 40000,
            out: HashMap::new(),
            back: HashMap::new(),
            holds: false,
            held: HashMap::new(),
            moved: HashMap::new(),
        });
        self.nats.len() - 1
    }

    /// Moves `host` to `addr` behind `nat`; its node learns its new local endpoint (§13.1).
    fn place(&mut self, host: usize, addr: Endpoint, nat: Option<usize>) {
        let h = &mut self.hosts[host];
        h.addr = addr;
        h.nat = nat;
        h.node.set_local_endpoints(vec![addr]);
    }

    fn lighthouse(&self) -> usize {
        let key = self
            .lighthouse_key
            .as_ref()
            .expect("discovery sim")
            .public();
        self.hosts
            .iter()
            .position(|h| h.key == key)
            .expect("a host")
    }

    fn relay(&self) -> usize {
        let key = self.relay_key.as_ref().expect("relay sim").public();
        self.hosts
            .iter()
            .position(|h| h.key == key)
            .expect("a host")
    }

    /// Adds a public relay at `203.0.113.2:4801` listing the nodes `listed`, and configures
    /// it on every node (§14), with an optional per-sender limit in bytes per second.
    fn add_relay(&mut self, listed: &[usize], limit: Option<u64>) -> usize {
        let key = StaticKey::generate();
        let config = LighthouseConfig {
            public_key: key.public(),
            endpoints: vec![ep(203, 0, 113, 2, 4801)],
        };
        let lighthouse = self.lighthouse();
        for (i, h) in self.hosts.iter_mut().enumerate() {
            if i != lighthouse {
                h.node.set_relays(vec![config.clone()]);
            }
        }
        let keys = listed.iter().map(|&i| self.hosts[i].key).collect();
        self.hosts.push(Host {
            node: Node::relay(key.clone(), keys, limit),
            key: config.public_key,
            addr: config.endpoints[0],
            nat: None,
            drift_ppm: 0,
            wall_offset: 0,
            asleep_until: None,
            next_seq: 0,
            received: Vec::new(),
            drops: Vec::new(),
        });
        let n = self.hosts.len();
        self.link_counts = vec![0; n * n];
        self.relay_key = Some(key);
        n - 1
    }

    /// Where a datagram from `from` to `dst` lands, its source as seen there and the NAT and
    /// public port it enters by: hosts on the public network or on the same LAN reach each
    /// other's address; a NAT translates on the way out and filters on the way in, when the
    /// datagram arrives (`Sim::arrives`); no hairpinning.
    fn resolve(&mut self, from: usize, dst: Endpoint) -> Option<(usize, Endpoint, Option<Via>)> {
        let (src, lan, now) = (self.hosts[from].addr, self.hosts[from].nat, self.now);
        let outside = |nats: &mut Vec<Nat>| match lan {
            Some(n) => nats[n].translate(src, dst, now),
            None => src,
        };
        if let Some(j) = self.hosts.iter().position(|h| h.addr == dst) {
            if self.hosts[j].nat == lan {
                return Some((j, src, None));
            }
            if self.hosts[j].nat.is_some() {
                return None;
            }
            return Some((j, outside(&mut self.nats), None));
        }
        let n = self
            .nats
            .iter()
            .position(|n| Endpoint::new(IpAddr::V4(n.public), dst.port).address == dst.address)?;
        if lan == Some(n) {
            return None;
        }
        let source = outside(&mut self.nats);
        let Some((inside, _)) = self.nats[n].back.get(&dst.port) else {
            self.nats[n].admit(dst.port, source, now);
            return None;
        };
        let j = self
            .hosts
            .iter()
            .position(|h| h.addr == *inside && h.nat == Some(n))?;
        Some((j, source, Some((n, dst.port))))
    }

    /// Whether an event passes its receiver's NAT now, with the receiver still behind it.
    fn arrives(&mut self, e: &Event) -> bool {
        let Some((n, port)) = e.via else {
            return true;
        };
        let host = &self.hosts[e.to];
        let inside = self.nats[n].admit(port, e.source, self.now);
        inside == Some(host.addr) && host.nat == Some(n)
    }

    fn status(&self, host: usize, peer: usize) -> kekkai_core::node::PeerStatus {
        self.hosts[host]
            .node
            .status(&self.hosts[peer].key)
            .expect("configured")
    }

    /// Host `from` hands its next scripted tunnel packet towards host `to` to its node.
    fn send_ip(&mut self, from: usize, to: usize) -> Result<(), DropReason> {
        let seq = self.hosts[from].next_seq;
        self.hosts[from].next_seq += 1;
        let packet = ip_packet(address(from), address(to), seq);
        self.send_raw(from, &packet)
    }

    fn send_raw(&mut self, from: usize, packet: &[u8]) -> Result<(), DropReason> {
        let host = &mut self.hosts[from];
        let (mono, wall) = (host.mono(self.now), host.wall(self.now));
        match host.node.send_packet(mono, wall, packet) {
            Ok(out) => {
                self.emit(from, out);
                Ok(())
            }
            Err(reason) => {
                host.drops.push((self.now, reason));
                Err(reason)
            }
        }
    }

    /// Sends the datagrams of `out` through the network and delivers its tunnel packets.
    fn emit(&mut self, from: usize, out: Output) {
        for packet in out.packets {
            let (sender, seq) = origin_of(&packet);
            self.hosts[from].received.push((self.now, sender, seq));
        }
        for (dst, datagram) in out.datagrams {
            self.sent.push((self.now, from, dst, datagram.clone()));
            let Some((to, source, via)) = self.resolve(from, dst) else {
                self.emitted.push((self.now, from, usize::MAX, datagram[0]));
                continue;
            };
            self.emitted.push((self.now, from, to, datagram[0]));
            let n = self.hosts.len();
            let count = &mut self.link_counts[from * n + to];
            let roll = mix(self.seed ^ ((from * n + to) as u64) << 48 ^ *count);
            *count += 1;
            if self.partitions.contains(&(from, to)) || roll % 1000 < self.link.loss_permille {
                continue;
            }
            let copies = 1 + usize::from((roll >> 10) % 1000 < self.link.dup_permille);
            for copy in 0..copies as u64 {
                let span = (self.link.delay_max - self.link.delay_min).as_millis() as u64 + 1;
                let delay = self.link.delay_min + ms(mix(roll ^ copy) % span);
                self.seq += 1;
                self.queue.push(Reverse(Event {
                    at: self.now + delay,
                    seq: self.seq,
                    to,
                    source,
                    via,
                    datagram: datagram.clone(),
                }));
            }
        }
    }

    fn deliver(&mut self, to: usize, source: Endpoint, datagram: &[u8]) -> Result<(), DropReason> {
        let host = &mut self.hosts[to];
        let (mono, wall) = (host.mono(self.now), host.wall(self.now));
        match host.node.handle_datagram(mono, wall, source, datagram) {
            Ok(out) => {
                let dropped = out.dropped;
                if let Some(reason) = dropped {
                    host.drops.push((self.now, reason));
                }
                self.emit(to, out);
                dropped.map_or(Ok(()), Err)
            }
            Err(reason) => {
                host.drops.push((self.now, reason));
                Err(reason)
            }
        }
    }

    /// Advances to `end`, delivering datagrams and running every deadline on the way. Hosts
    /// are woken at least once a second (ADR 0004); an asleep host drops what reaches it.
    fn run_until(&mut self, end: Duration) {
        while self.now < end {
            let mut next = (self.now + secs(1)).min(end);
            if let Some(Reverse(e)) = self.queue.peek() {
                next = next.min(e.at.max(self.now));
            }
            for h in &self.hosts {
                // A sleeping host's deadlines wait for its wake-up.
                match h.asleep_until.filter(|t| self.now < *t) {
                    Some(wake) => next = next.min(wake),
                    None => {
                        if let Some(d) = h.node.next_deadline() {
                            next = next.min(h.sim_of(d).max(self.now));
                        }
                    }
                }
            }
            // Always advance: a deadline reached exactly is run below, at this instant.
            self.now = next.max(self.now + Duration::from_nanos(1));
            while self.queue.peek().is_some_and(|Reverse(e)| e.at <= self.now) {
                let Reverse(e) = self.queue.pop().expect("peeked");
                if !self.hosts[e.to].asleep(self.now) && self.arrives(&e) {
                    let _ = self.deliver(e.to, e.source, &e.datagram);
                }
            }
            for i in 0..self.hosts.len() {
                let host = &mut self.hosts[i];
                if host.asleep(self.now) {
                    continue;
                }
                let (mono, wall) = (host.mono(self.now), host.wall(self.now));
                if host.node.next_deadline().is_some_and(|d| d <= mono) {
                    let out = host.node.tick(mono, wall);
                    self.emit(i, out);
                }
            }
        }
    }

    fn sessions(&self, host: usize, peer: usize) -> usize {
        self.hosts[host]
            .node
            .status(&self.hosts[peer].key)
            .map_or(0, |s| s.sessions)
    }

    /// Sequence numbers `host` received from `peer` since `since`.
    fn received(&self, host: usize, peer: usize, since: Duration) -> Vec<u32> {
        self.hosts[host]
            .received
            .iter()
            .filter(|(t, p, _)| *t >= since && *p == peer)
            .map(|(_, _, s)| *s)
            .collect()
    }

    fn message_1s(&self, from: usize, to: usize) -> Vec<Duration> {
        self.emitted
            .iter()
            .filter(|(_, f, t, ty)| *f == from && *t == to && *ty == wire::TYPE_HANDSHAKE_INIT)
            .map(|(at, ..)| *at)
            .collect()
    }

    fn drops(&self, host: usize, reason: DropReason) -> Vec<Duration> {
        self.hosts[host]
            .drops
            .iter()
            .filter(|(_, r)| *r == reason)
            .map(|(t, _)| *t)
            .collect()
    }

    /// Scripted traffic: one packet per `period` from `from` to `to` until `end`.
    fn stream(&mut self, from: usize, to: usize, period: Duration, end: Duration) {
        while self.now < end {
            let _ = self.send_ip(from, to);
            let next = self.now + period;
            self.run_until(next.min(end));
        }
    }
}

/// Distinct sequence numbers: duplicates on the wire never reach the tunnel.
fn unique(seqs: &[u32]) -> usize {
    seqs.iter().collect::<HashSet<_>>().len()
}

#[test]
fn mesh_under_loss_reordering_and_duplication() {
    let mut sim = Sim::new(1, 3, LOSSY);
    sim.hosts[1].drift_ppm = 800;
    sim.hosts[2].drift_ppm = -800;
    let streams = [(0, 1), (1, 0), (0, 2), (2, 1)];
    let end = secs(30);
    let mut sent = 0;
    while sim.now < end {
        for (from, to) in streams {
            let _ = sim.send_ip(from, to);
        }
        sent += 1;
        sim.run_until((sim.now + ms(50)).min(end));
    }
    for (from, to) in streams {
        let got = sim.received(to, from, secs(0));
        assert_eq!(
            unique(&got),
            got.len(),
            "{from}->{to}: a duplicate reached the tunnel"
        );
        assert!(
            got.len() >= sent * 3 / 4,
            "{from}->{to}: {} of {sent} delivered under 10 % loss",
            got.len()
        );
        assert!(got.len() <= sent);
        assert!(!sim.message_1s(from, to).is_empty() || !sim.message_1s(to, from).is_empty());
    }
    // Duplicated datagrams were rejected by the window, never by the AEAD.
    assert!(!sim.drops(1, DropReason::CounterRejected).is_empty());
    assert!(sim.drops(1, DropReason::BadTag).is_empty());
}

#[test]
fn concurrent_initiations_both_complete() {
    let mut sim = Sim::new(2, 2, PERFECT);
    sim.send_ip(0, 1).unwrap();
    sim.send_ip(1, 0).unwrap();
    sim.run_until(secs(1));
    assert_eq!(sim.message_1s(0, 1).len(), 1);
    assert_eq!(sim.message_1s(1, 0).len(), 1);
    assert_eq!(sim.received(0, 1, secs(0)), [0]);
    assert_eq!(sim.received(1, 0, secs(0)), [0]);
    assert_eq!(
        (sim.sessions(0, 1), sim.sessions(1, 0)),
        (2, 2),
        "both handshakes completed, both sessions exist"
    );
    // Each side's most recently confirmed session is the one the other initiated (§7.8), so
    // each sends as a responder and receives as an initiator on its `previous`: neither
    // rekey rule of §8.6 applies, both sessions expire at REJECT_AFTER_TIME, the next packet
    // is staged and a fresh pair of concurrent handshakes follows. No packet is lost.
    let end = secs(200);
    while sim.now < end {
        sim.send_ip(0, 1).unwrap();
        sim.send_ip(1, 0).unwrap();
        sim.run_until((sim.now + secs(1)).min(end));
    }
    let sent = sim.hosts[0].next_seq as usize;
    assert_eq!(unique(&sim.received(0, 1, secs(0))), sent);
    assert_eq!(unique(&sim.received(1, 0, secs(0))), sent);
    let later: Vec<_> = sim
        .message_1s(0, 1)
        .into_iter()
        .chain(sim.message_1s(1, 0))
        .filter(|t| *t > secs(1))
        .collect();
    assert_eq!(later.len(), 2, "{later:?}");
    assert!(
        later
            .iter()
            .all(|t| *t >= REJECT_AFTER_TIME && *t < REJECT_AFTER_TIME + secs(2)),
        "{later:?}"
    );
    assert_eq!((sim.sessions(0, 1), sim.sessions(1, 0)), (2, 2));
}

#[test]
fn rekey_at_120_expiry_at_180_and_silent_peer() {
    let mut sim = Sim::new(3, 2, PERFECT);
    sim.hosts[1].drift_ppm = 1000;
    sim.stream(0, 1, secs(1), secs(119));
    assert_eq!(sim.message_1s(0, 1).len(), 1);
    assert_eq!((sim.sessions(0, 1), sim.sessions(1, 0)), (1, 1));
    sim.stream(0, 1, secs(1), secs(122));
    let rekey = sim.message_1s(0, 1);
    assert_eq!(rekey.len(), 2, "{rekey:?}");
    // The session was created when message 2 arrived, one RTT after 0: the first send at
    // which it is REKEY_AFTER_TIME old is the one at 121 s.
    assert_eq!(rekey[1], REKEY_AFTER_TIME + secs(1), "initiator rule");
    assert_eq!(
        (sim.sessions(0, 1), sim.sessions(1, 0)),
        (2, 2),
        "current and previous"
    );
    sim.stream(0, 1, secs(1), secs(179));
    assert_eq!((sim.sessions(0, 1), sim.sessions(1, 0)), (2, 2));
    sim.stream(0, 1, secs(1), secs(182));
    assert_eq!(
        (sim.sessions(0, 1), sim.sessions(1, 0)),
        (1, 1),
        "the session created at 0 is rejected at 180 s"
    );
    assert_eq!(
        unique(&sim.received(1, 0, secs(0))),
        182,
        "no packet lost across the rekey"
    );

    // Host 1 goes silent: the new-handshake timer, retransmissions, abandonment, expiry.
    sim.partitions.insert((1, 0));
    sim.partitions.insert((0, 1));
    let before = sim.message_1s(0, 1).len();
    sim.stream(0, 1, secs(1), secs(500));
    assert_eq!(sim.sessions(0, 1), 0, "expired while the peer was silent");
    assert!(
        sim.message_1s(0, 1).len() - before >= 18,
        "retransmitted up to abandonment"
    );
    let delivered_before = sim.hosts[1].received.len();
    sim.partitions.clear();
    sim.stream(0, 1, secs(1), secs(510));
    assert!(
        sim.hosts[1].received.len() > delivered_before,
        "recreated on demand and traffic resumed"
    );
    assert_eq!(sim.sessions(0, 1), 1);
}

#[test]
fn junk_and_replays_are_silent() {
    let mut sim = Sim::new(4, 2, PERFECT);
    sim.send_ip(0, 1).unwrap();
    sim.run_until(secs(1));
    let msg1 = {
        // A real message 1 towards host 1, captured by forcing a fresh handshake.
        let peer = sim.peer_config(1);
        sim.hosts[0].node.set_peers(vec![]);
        sim.hosts[0].node.set_peers(vec![peer]);
        sim.send_ip(0, 1).unwrap();
        sim.queue.pop().expect("message 1 queued").0.datagram
    };
    let emitted = sim.emitted.len();
    assert_eq!(msg1[0], wire::TYPE_HANDSHAKE_INIT);
    let mut version = msg1.clone();
    version[1] = 2;
    let mut unknown_type = msg1.clone();
    unknown_type[0] = 3;
    let mut bad_mac1 = msg1.clone();
    bad_mac1[msg1.len() - 20] ^= 1;
    let mut data_unknown_index = wire::data_header(0xdead_beef, 7).to_vec();
    data_unknown_index.extend_from_slice(&[0; 17]);
    let cases: [(&[u8], DropReason); 9] = [
        (&[], DropReason::BadLength),
        (&[4, 1, 0], DropReason::BadLength),
        (&[0u8; 1379], DropReason::BadLength),
        (&version, DropReason::UnknownVersion),
        (&unknown_type, DropReason::UnknownType),
        (&[200, 1, 0, 0, 1, 2, 3, 4], DropReason::UnknownType),
        (&msg1[..135], DropReason::BadLength),
        (&bad_mac1, DropReason::BadMac1),
        (&data_unknown_index, DropReason::UnknownIndex),
    ];
    for (datagram, reason) in cases {
        assert_eq!(sim.deliver(1, sim.addr(0), datagram), Err(reason));
    }
    assert_eq!(sim.emitted.len(), emitted, "no datagram in reaction");
    // The genuine copy still completes; its replay is silent (§7.4).
    assert!(sim.deliver(1, sim.addr(0), &msg1).is_ok());
    sim.run_until(secs(2));
    assert_eq!(sim.received(1, 0, secs(1)), [1]);
    assert_eq!(
        sim.deliver(1, sim.addr(0), &msg1),
        Err(DropReason::TimestampNotNewer)
    );
    // A replayed data packet is rejected by the window (§8.4), its payload delivered once.
    let emitted = sim.emitted.len();
    sim.send_ip(0, 1).unwrap();
    let data = sim.queue.pop().expect("data queued").0.datagram;
    assert_eq!(data[0], wire::TYPE_DATA);
    assert!(sim.deliver(1, sim.addr(0), &data).is_ok());
    assert_eq!(
        sim.deliver(1, sim.addr(0), &data),
        Err(DropReason::CounterRejected)
    );
    assert_eq!(sim.emitted.len(), emitted + 1, "only the original send");
    assert_eq!(sim.received(1, 0, secs(1)), [1, 2]);
    // §12.6 reporting: the replay is counted, junk from nobody is not.
    let status = sim.hosts[1].node.status(&sim.hosts[0].key).unwrap();
    assert!(status.current && status.last_handshake.is_some());
    assert_eq!(status.counters.replay_rejections, 1);
    assert!(status.counters.rx_packets >= 3 && status.counters.tx_packets >= 2);
    assert!(status.counters.rx_bytes > status.counters.rx_packets * 32);
}

#[test]
fn keepalives_rekey_an_idle_initiator_session() {
    let mut sim = Sim::new(8, 2, PERFECT);
    sim.send_ip(0, 1).unwrap();
    sim.run_until(secs(400));
    // Only persistent keepalives flow. The initiator rule of §8.6 applies to any send, so
    // host 0 rekeys at its first keepalive past REKEY_AFTER_TIME, every time; the responder
    // safety net never has to act.
    let m1 = sim.message_1s(0, 1);
    assert_eq!(m1.len(), 4, "{m1:?}");
    assert!(
        m1.windows(2).all(|w| {
            w[1] - w[0] >= REKEY_AFTER_TIME && w[1] - w[0] < REKEY_AFTER_TIME + PERSISTENT_KEEPALIVE
        }),
        "{m1:?}"
    );
    assert!(sim.message_1s(1, 0).is_empty());
    assert_eq!(sim.received(1, 0, secs(0)), [0]);
    assert!(sim.drops(0, DropReason::UnknownIndex).is_empty());
    assert!(sim.drops(1, DropReason::UnknownIndex).is_empty());
}

#[test]
fn routing_and_peer_list_reload() {
    let mut sim = Sim::new(5, 3, PERFECT);
    sim.stream(0, 1, secs(1), secs(2));
    assert_eq!(sim.received(1, 0, secs(0)), [0, 1]);
    let unroutable = ip_packet(address(0), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 0);
    assert_eq!(sim.send_raw(0, &unroutable), Err(DropReason::NoRoute));
    let multicast = ip_packet(address(0), IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 0);
    assert_eq!(sim.send_raw(0, &multicast), Err(DropReason::NotUnicast));
    let big = vec![0x45; MTU + 1];
    assert_eq!(sim.send_raw(0, &big), Err(DropReason::PacketTooLarge));
    assert_eq!(sim.send_raw(0, &[0x45, 0, 0]), Err(DropReason::NoRoute));
    // Cryptokey routing: host 2 cannot speak for host 0's address.
    let spoofed = ip_packet(address(0), address(1), 99);
    sim.send_raw(2, &spoofed).unwrap();
    sim.run_until(secs(3));
    assert_eq!(sim.drops(1, DropReason::SourceNotPeer).len(), 1);
    assert!(sim.received(1, 2, secs(0)).is_empty());

    // Host 1 drops host 0 from its list: sessions go, host 0 becomes a stranger.
    let keep = vec![sim.peer_config(2)];
    sim.hosts[1].node.set_peers(keep);
    assert!(sim.hosts[1].node.status(&sim.hosts[0].key).is_none());
    sim.send_ip(0, 1).unwrap();
    sim.run_until(secs(4));
    assert_eq!(sim.drops(1, DropReason::UnknownIndex).len(), 1);
    sim.stream(0, 1, secs(1), secs(30));
    assert!(!sim.drops(1, DropReason::IdentityRejected).is_empty());
    assert!(sim.received(1, 0, secs(3)).is_empty());
    // Listed again: the next handshake is answered and traffic resumes.
    let all = vec![sim.peer_config(0), sim.peer_config(2)];
    sim.hosts[1].node.set_peers(all);
    sim.stream(0, 1, secs(1), secs(45));
    assert!(!sim.received(1, 0, secs(30)).is_empty());
}

#[test]
fn wall_clock_stepped_backwards() {
    let mut sim = Sim::new(6, 2, PERFECT);
    sim.stream(0, 1, secs(1), secs(130));
    assert_eq!(sim.message_1s(0, 1).len(), 2, "initial and the 120 s rekey");
    // Host 0's wall clock steps back 200 s: its next timestamps are older than the one
    // host 1 accepted at 120 s, until its clock passes that value again (at 320 s).
    sim.hosts[0].wall_offset = -200;
    sim.stream(0, 1, secs(1), secs(400));
    let rejected = sim.drops(1, DropReason::TimestampNotNewer);
    assert!(rejected.len() >= 8, "{} rejections", rejected.len());
    assert!(rejected.iter().all(|t| *t >= secs(240) && *t < secs(290)));
    let attempts: Vec<_> = sim
        .message_1s(0, 1)
        .into_iter()
        .filter(|t| *t >= secs(240))
        .collect();
    assert!(
        attempts.windows(2).all(|w| w[1] - w[0] >= secs(5)),
        "retransmissions keep their monotonic cadence: {attempts:?}"
    );
    assert_eq!(
        attempts.len(),
        rejected.len(),
        "timers are unaffected by the wall-clock step"
    );
    let answered: Vec<_> = sim
        .emitted
        .iter()
        .filter(|(t, f, _, ty)| *f == 1 && *ty == wire::TYPE_HANDSHAKE_INIT && *t > secs(130))
        .map(|(t, ..)| *t)
        .collect();
    let answer = *answered
        .iter()
        .find(|t| **t >= secs(280) && **t < secs(300))
        .unwrap_or_else(|| panic!("host 1's responder rule initiated: {answered:?}"));
    // §8.2 step 5: confirming host 1's session ended host 0's rejected sequence (no further
    // message 1) and carried its staged packets, so nothing waited for its clock to catch up.
    assert!(attempts.iter().all(|t| *t < answer));
    assert_eq!(
        unique(&sim.received(1, 0, secs(0))),
        400,
        "traffic never stopped: host 0 still answers its peer's handshakes"
    );
    let status = sim.hosts[0].node.status(&sim.hosts[1].key).unwrap();
    assert_eq!(
        (status.handshake_in_flight, status.staged_packets),
        (false, 0)
    );
}

#[test]
fn long_suspend_then_resume() {
    let mut sim = Sim::new(7, 2, PERFECT);
    sim.stream(0, 1, secs(1), secs(50));
    sim.stream(1, 0, secs(1), secs(51));
    assert_eq!((sim.sessions(0, 1), sim.sessions(1, 0)), (1, 1));
    // Host 0 sleeps for 250 s: nothing reaches it, nothing runs, its monotonic clock keeps
    // counting (CLOCK_BOOTTIME), so the next tick sees a 250 s jump.
    sim.hosts[0].asleep_until = Some(secs(300));
    sim.stream(1, 0, secs(1), secs(299));
    assert_eq!(sim.sessions(1, 0), 0, "host 1 gave up on host 0");
    assert_eq!(
        sim.sessions(0, 1),
        1,
        "host 0 still holds its stale session while asleep"
    );
    sim.run_until(ms(300_001));
    assert_eq!(
        sim.sessions(0, 1),
        0,
        "the first tick after the wake-up expires the stale session"
    );
    let before = sim.hosts[1].received.len();
    sim.send_ip(0, 1).unwrap();
    sim.run_until(secs(301));
    assert_eq!(
        sim.hosts[1].received.len(),
        before + 1,
        "re-handshake on the first packet, no timer waited out"
    );
    sim.stream(0, 1, secs(1), secs(310));
    assert_eq!(sim.received(1, 0, secs(300)).len(), 10);
}

/// An IPv4 packet of `protocol` whose transport header is `header` and whose bytes 28..32
/// carry the sequence number (as [`ip_packet`] does, so [`origin_of`] reads it back).
fn transport_packet(src: usize, dst: usize, protocol: u8, header: &[u8], seq: u32) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (address(src), address(dst)) else {
        unreachable!("IPv4 overlay in this harness")
    };
    let mut t = header.to_vec();
    t.resize(t.len().max(12), 0);
    t[8..12].copy_from_slice(&seq.to_be_bytes());
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, protocol, 0, 0];
    p.extend_from_slice(&s.octets());
    p.extend_from_slice(&d.octets());
    p.extend_from_slice(&t);
    let len = p.len() as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p
}

/// A 20-byte TCP header towards `dport` with `flags` (0x02 SYN, 0x10 ACK).
fn tcp(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut t = vec![0; 20];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[12] = 0x50;
    t[13] = flags;
    t
}

fn udp(sport: u16, dport: u16) -> Vec<u8> {
    let mut t = vec![0; 8];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[4..6].copy_from_slice(&12u16.to_be_bytes());
    t
}

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

/// §15 in the simulation: host 1 lets host 0 reach `tcp/22` and nothing else, and host 2
/// nothing at all (default deny).
#[test]
fn firewall_rules_flows_and_eviction() {
    let mut sim = Sim::new(8, 3, PERFECT);
    let rules = |sim: &Sim, j: usize, allow: &[&str]| PeerConfig {
        allow_inbound: allow.iter().map(|r| r.parse().unwrap()).collect(),
        ..sim.peer_config(j)
    };
    let peers = vec![rules(&sim, 0, &["tcp/22"]), rules(&sim, 2, &[])];
    sim.hosts[1].node.set_peers(peers);
    let send = |sim: &mut Sim, from: usize, to: usize, protocol: u8, header: Vec<u8>| {
        let seq = sim.hosts[from].next_seq;
        sim.hosts[from].next_seq += 1;
        let packet = transport_packet(from, to, protocol, &header, seq);
        sim.send_raw(from, &packet).unwrap();
        let end = sim.now + secs(1);
        sim.run_until(end);
        sim.received(to, from, Duration::ZERO).contains(&seq)
    };
    let drops = |sim: &Sim, host: usize, peer: usize| {
        let status = sim.hosts[host].node.status(&sim.hosts[peer].key).unwrap();
        status.counters.firewall_drops
    };

    // TCP: the allowed opener passes, another port and another peer are dropped.
    assert!(
        send(&mut sim, 0, 1, 6, tcp(40000, 22, SYN)),
        "tcp/22 from host 0"
    );
    assert!(
        !send(&mut sim, 0, 1, 6, tcp(40000, 23, SYN)),
        "tcp/23 from host 0"
    );
    assert!(
        !send(&mut sim, 2, 1, 6, tcp(40000, 22, SYN)),
        "tcp/22 from host 2"
    );
    assert_eq!((drops(&sim, 1, 0), drops(&sim, 1, 2)), (1, 1));
    assert_eq!(sim.drops(1, DropReason::Firewall).len(), 2);
    // Non-openers pass without a rule (§15 rule 4), SYN+ACK included.
    assert!(send(&mut sim, 2, 1, 6, tcp(22, 40000, SYN | ACK)));
    assert!(send(&mut sim, 2, 1, 6, tcp(22, 40000, ACK)));
    // ICMP always passes, even from a peer with no rule.
    assert!(send(&mut sim, 2, 1, 1, vec![8, 0, 0, 0, 0, 0, 0, 0]));
    // Outbound traffic is never filtered: host 1 reaches anything on host 2 (any rule).
    assert!(send(&mut sim, 1, 2, 6, tcp(40000, 9999, SYN)));

    // UDP: a reply to a flow host 1 opened passes until UDP_FLOW_TIMEOUT, then is dropped.
    let opened = sim.now;
    assert!(send(&mut sim, 1, 2, 17, udp(5000, 53)));
    assert!(
        send(&mut sim, 2, 1, 17, udp(53, 5000)),
        "reply to an open flow"
    );
    assert!(
        !send(&mut sim, 2, 1, 17, udp(53, 5001)),
        "not the flow's port"
    );
    assert!(
        !send(&mut sim, 2, 1, 17, udp(54, 5000)),
        "not the flow's peer port"
    );
    // Inbound matches do not refresh the entry.
    sim.stream(2, 1, secs(10), opened + secs(59));
    assert!(
        send(&mut sim, 2, 1, 17, udp(53, 5000)),
        "still open just before 60 s"
    );
    sim.run_until(opened + secs(61));
    assert!(
        !send(&mut sim, 2, 1, 17, udp(53, 5000)),
        "expired after 60 s"
    );
    let status = sim.hosts[1].node.firewall_status();
    assert_eq!((status.max, status.evictions), (4096, 0));

    // A full table evicts the entry with the oldest expiry and counts it.
    sim.hosts[1].node.set_udp_flows_max(2);
    for port in [6000, 6001, 6002] {
        assert!(send(&mut sim, 1, 2, 17, udp(port, 53)));
    }
    let status = sim.hosts[1].node.firewall_status();
    assert_eq!((status.entries, status.max, status.evictions), (2, 2, 1));
    assert!(!send(&mut sim, 2, 1, 17, udp(53, 6000)), "evicted flow");
    assert!(send(&mut sim, 2, 1, 17, udp(53, 6001)));
    assert!(send(&mut sim, 2, 1, 17, udp(53, 6002)));
}

/// §8.2 end (F1): host 1's first data packet confirms host 0's responder session but carries
/// a spoofed inner source. Only that content is dropped: the confirmation and host 0's staged
/// packet (step 5) still go out, and the sender is still reported.
#[test]
fn rejected_inner_keeps_the_transport_effects() {
    let mut sim = Sim::new(9, 2, PERFECT);
    sim.send_ip(0, 1).unwrap();
    let spoofed = ip_packet(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), address(0), 7);
    sim.send_raw(1, &spoofed).unwrap();
    let pop = |sim: &mut Sim, to: usize| {
        let mut held = Vec::new();
        let found = loop {
            let event = sim.queue.pop().expect("queued").0;
            if event.to == to {
                break event.datagram;
            }
            held.push(event);
        };
        sim.queue.extend(held.into_iter().map(Reverse));
        found
    };
    let msg1_1 = pop(&mut sim, 0);
    let msg1_0 = pop(&mut sim, 1);
    sim.deliver(0, sim.addr(1), &msg1_1).unwrap();
    sim.deliver(1, sim.addr(0), &msg1_0).unwrap();
    let lost_msg2 = pop(&mut sim, 0);
    assert_eq!(lost_msg2[0], wire::TYPE_HANDSHAKE_RESP);
    let msg2_0 = pop(&mut sim, 1);
    sim.deliver(1, sim.addr(0), &msg2_0).unwrap();
    let data = pop(&mut sim, 0);
    assert_eq!(
        sim.deliver(0, sim.addr(1), &data),
        Err(DropReason::SourceNotPeer)
    );
    let status = sim.hosts[0].node.status(&sim.hosts[1].key).unwrap();
    assert!(status.current && !status.handshake_in_flight);
    assert_eq!(status.staged_packets, 0);
    assert_eq!(
        status.counters.rx_packets, 2,
        "message 1 and the data packet"
    );
    sim.run_until(secs(1));
    assert_eq!(
        sim.received(1, 0, secs(0)),
        [0],
        "the staged packet went out"
    );
    assert!(sim.received(0, 1, secs(0)).is_empty());
}

// v0.4: lighthouse, NAT traversal and roaming (§12, §13).

/// Hosts 0 and 1 behind their own NAT of `kind`; the lighthouse is public. Both nodes are
/// registered after the first second.
fn behind_nats(seed: u64, kind: NatKind) -> Sim {
    let mut sim = Sim::discovery(seed, 2);
    let a = sim.add_nat(Ipv4Addr::new(198, 51, 100, 1), kind);
    let b = sim.add_nat(Ipv4Addr::new(198, 51, 100, 2), kind);
    sim.place(0, ep(192, 168, 1, 2, 4802), Some(a));
    sim.place(1, ep(192, 168, 2, 2, 4802), Some(b));
    sim.run_until(secs(1));
    let lh = sim.lighthouse();
    assert_eq!(sim.hosts[lh].node.registrations(sim.now).len(), 2);
    sim
}

fn public_ip(sim: &Sim, nat: usize) -> IpAddr {
    IpAddr::V4(sim.nats[nat].public)
}

#[test]
fn cone_nats_on_both_sides_give_a_direct_path() {
    let mut sim = behind_nats(20, NatKind::Cone);
    sim.stream(0, 1, secs(1), secs(5));
    sim.stream(1, 0, secs(1), secs(6));
    assert!(!sim.received(1, 0, secs(0)).is_empty());
    assert!(!sim.received(0, 1, secs(0)).is_empty());
    for (host, peer, nat) in [(0, 1, 1), (1, 0, 0)] {
        let s = sim.status(host, peer);
        assert!(s.current, "{host} -> {peer}");
        let endpoint = s.endpoint.expect("learnt");
        assert_eq!(
            endpoint.display().ip(),
            public_ip(&sim, nat),
            "the other's NAT"
        );
        assert_eq!(s.last_direct_path_failure, None);
    }
    let lh = sim.lighthouse();
    let counters = sim.hosts[lh].node.lighthouse_counters();
    assert!(counters.queries_known >= 1 && counters.punches >= 1);
    // Stopping the lighthouse does not break the established session, rekeys included.
    sim.hosts[lh].asleep_until = Some(secs(100_000));
    let since = sim.now;
    sim.stream(0, 1, secs(1), since + secs(300));
    let late = sim.received(1, 0, since + secs(290));
    assert!(late.len() >= 9, "{late:?}");
    assert!(sim.status(0, 1).current);
}

#[test]
fn symmetric_nats_on_both_sides_report_none_after_3_s() {
    let mut sim = behind_nats(21, NatKind::Symmetric);
    let start = sim.now;
    sim.send_ip(0, 1).unwrap();
    sim.run_until(start + ms(2900));
    assert_eq!(sim.status(0, 1).last_direct_path_failure, None);
    sim.run_until(start + ms(3100));
    let s = sim.status(0, 1);
    assert!(!s.current, "path = none");
    assert_eq!(s.last_direct_path_failure, Some(PathFailure::Timeout));
    assert!(sim.received(1, 0, secs(0)).is_empty());
}

#[test]
fn same_lan_peers_connect_through_their_local_endpoints() {
    let mut sim = Sim::discovery(22, 2);
    let nat = sim.add_nat(Ipv4Addr::new(198, 51, 100, 1), NatKind::Cone);
    sim.place(0, ep(192, 168, 1, 2, 4802), Some(nat));
    sim.place(1, ep(192, 168, 1, 3, 4802), Some(nat));
    sim.run_until(secs(1));
    sim.stream(0, 1, secs(1), secs(5));
    assert!(!sim.received(1, 0, secs(0)).is_empty());
    assert_eq!(sim.status(0, 1).endpoint, Some(sim.addr(1)));
    assert_eq!(sim.status(1, 0).endpoint, Some(sim.addr(0)));
}

/// §12.5 rule 3: host 0 leaves the LAN it shared with host 1 for another network behind
/// another NAT; its local addresses change and it recovers through the lighthouse.
#[test]
fn a_node_that_moves_rediscovers_through_the_lighthouse() {
    let mut sim = Sim::discovery(23, 2);
    let home = sim.add_nat(Ipv4Addr::new(198, 51, 100, 1), NatKind::Cone);
    let away = sim.add_nat(Ipv4Addr::new(198, 51, 100, 2), NatKind::Cone);
    sim.place(0, ep(192, 168, 1, 2, 4802), Some(home));
    sim.place(1, ep(192, 168, 1, 3, 4802), Some(home));
    sim.run_until(secs(1));
    sim.stream(0, 1, secs(1), secs(40));
    assert_eq!(
        sim.status(0, 1).endpoint,
        Some(sim.addr(1)),
        "LAN path first"
    );
    let moved = sim.now;
    sim.place(0, ep(192, 168, 7, 2, 4802), Some(away));
    sim.stream(0, 1, secs(1), moved + secs(60));
    let back = sim.received(1, 0, moved);
    let first = sim.hosts[1]
        .received
        .iter()
        .find(|(t, p, _)| *t > moved && *p == 0)
        .map(|(t, ..)| *t - moved)
        .expect("traffic resumed");
    assert!(first < secs(30), "recovered after {first:?}");
    assert!(back.len() >= 20, "{back:?}");
    let to_b = sim.status(0, 1).endpoint.unwrap();
    assert_eq!(
        to_b.display().ip(),
        public_ip(&sim, home),
        "B's observed endpoint"
    );
    let to_a = sim.status(1, 0).endpoint.unwrap();
    assert_eq!(to_a.display().ip(), public_ip(&sim, away));
}

/// §12.5 rule 2: host 1 moves behind another NAT with the same local address, so only
/// host 0's unanswered handshake can trigger the query.
#[test]
fn a_peer_that_moves_is_found_after_an_unanswered_handshake() {
    let mut sim = behind_nats(24, NatKind::Cone);
    sim.stream(0, 1, secs(1), secs(10));
    assert!(sim.status(0, 1).current);
    let lh = sim.lighthouse();
    let queries = sim.hosts[lh].node.lighthouse_counters().queries_known;
    let elsewhere = sim.add_nat(Ipv4Addr::new(198, 51, 100, 3), NatKind::Cone);
    let moved = sim.now;
    let addr = sim.addr(1);
    sim.place(1, addr, Some(elsewhere));
    sim.stream(0, 1, secs(1), moved + secs(60));
    let first = sim.hosts[1]
        .received
        .iter()
        .find(|(t, p, _)| *t > moved && *p == 0)
        .map(|(t, ..)| *t - moved)
        .expect("traffic resumed");
    // Host 1 reached the lighthouse from its new network (a passive keepalive), so the
    // first query (rule 2, about 12 s) gets its new address and crosses with the punch
    // (§13.2); answered with the register's address, it took more than 15 s.
    assert!(first < secs(15), "recovered after {first:?}");
    assert!(sim.hosts[lh].node.lighthouse_counters().queries_known > queries);
    let to_b = sim.status(0, 1).endpoint.unwrap();
    assert_eq!(to_b.display().ip(), public_ip(&sim, elsewhere));
}

/// Silence (§13.2, §16): an unlisted key never gets an answer from the lighthouse, and a
/// listed but unregistered peer is reported as `lighthouse_unknown`.
#[test]
fn lighthouse_silence_and_unknown_peers() {
    let mut sim = Sim::discovery(25, 3);
    let lh = sim.lighthouse();
    let listed = vec![sim.hosts[0].key, sim.hosts[1].key];
    sim.hosts[lh].node.set_lighthouse_peers(listed);
    sim.run_until(secs(20));
    let answered = sim
        .emitted
        .iter()
        .filter(|(_, f, t, _)| *f == lh && *t == 2)
        .count();
    assert_eq!(answered, 0, "the stranger got no datagram");
    assert!(!sim.drops(lh, DropReason::IdentityRejected).is_empty());
    assert!(!sim.status(2, lh).current);
    // Host 1 is listed but asleep from now on: its registration expires after 75 s.
    sim.hosts[1].asleep_until = Some(secs(100_000));
    sim.run_until(secs(120));
    assert_eq!(sim.hosts[lh].node.registrations(sim.now).len(), 1);
    let start = sim.now;
    sim.send_ip(0, 1).unwrap();
    sim.run_until(start + secs(4));
    let s = sim.status(0, 1);
    assert_eq!(
        s.last_direct_path_failure,
        Some(PathFailure::LighthouseUnknown)
    );
}

/// ADR 0013 "symmetric NAT: nothing special", against address-and-port-dependent filtering:
/// only cone on both sides gives a direct path; otherwise `none` with `timeout` after 3 s.
#[test]
fn every_nat_combination_gives_direct_or_a_timeout() {
    use NatKind::{Cone, Symmetric};
    for (seed, (a, b)) in [
        (Cone, Cone),
        (Cone, Symmetric),
        (Symmetric, Cone),
        (Symmetric, Symmetric),
    ]
    .into_iter()
    .enumerate()
    {
        let mut sim = Sim::discovery(30 + seed as u64, 2);
        let na = sim.add_nat(Ipv4Addr::new(198, 51, 100, 1), a);
        let nb = sim.add_nat(Ipv4Addr::new(198, 51, 100, 2), b);
        sim.place(0, ep(192, 168, 1, 2, 4802), Some(na));
        sim.place(1, ep(192, 168, 2, 2, 4802), Some(nb));
        sim.run_until(secs(1));
        sim.stream(0, 1, ms(500), secs(5));
        let s = sim.status(0, 1);
        let direct = a == Cone && b == Cone;
        assert_eq!(s.current, direct, "seed {seed}");
        let failure = (!direct).then_some(PathFailure::Timeout);
        assert_eq!(s.last_direct_path_failure, failure, "seed {seed}");
    }
}

// Review of v0.4 (2026-10-21): candidate retention (L1), register timer (L2), discovery
// timing (L5) and candidate admission (L6).

/// Queries the lighthouse answered so far.
fn queries(sim: &Sim) -> u64 {
    let c = sim.hosts[sim.lighthouse()].node.lighthouse_counters();
    c.queries_known + c.queries_unknown
}

/// When the lighthouse last refreshed `host`'s registration.
fn refreshed(sim: &Sim, host: usize) -> Option<Duration> {
    let lh = sim.lighthouse();
    let key = sim.hosts[host].key;
    let entries = sim.hosts[lh].node.registrations(sim.now);
    entries
        .into_iter()
        .find(|(k, _)| *k == key)
        .map(|(_, r)| r.refreshed)
}

/// Message 1 copies `from` sent since `since`: `(sim time, destination, bytes)`.
fn message_1_copies(sim: &Sim, from: usize, since: Duration) -> Vec<(Duration, Endpoint, Vec<u8>)> {
    sim.sent
        .iter()
        .filter(|(t, f, _, d)| *t >= since && *f == from && d[0] == TYPE_HANDSHAKE_INIT)
        .map(|(t, _, to, d)| (*t, *to, d.clone()))
        .collect()
}

/// L1, §12.2: endpoints learnt from the lighthouse stay candidates after the 3 s window, so
/// once the direct path comes back a later retransmission completes the handshake and the
/// one staged packet goes out, with no further IP packet.
#[test]
fn learnt_candidates_outlive_the_discovery_window() {
    let mut sim = behind_nats(40, NatKind::Cone);
    sim.partitions.extend([(0, 1), (1, 0)]);
    let start = sim.now;
    sim.send_ip(0, 1).unwrap();
    sim.run_until(start + secs(12));
    assert!(!sim.status(0, 1).current);
    let late = sim.message_1s(0, 1);
    assert!(
        late.iter().any(|t| *t > start + secs(9)),
        "retransmissions still reach the learnt candidates: {late:?}"
    );
    sim.partitions.clear();
    sim.run_until(start + secs(25));
    assert!(sim.status(0, 1).current);
    assert_eq!(sim.received(1, 0, start), [0], "the staged packet");
}

/// How long host 0 takes to be found again after leaving the LAN it shares with host 1 for
/// another NAT, `phase` after one of its registers, with no tunnel traffic: only §12.5 rule
/// 3 (the register tick) can find host 1. With `query`, host 0 queries the lighthouse (for
/// host 2, which never registered) just before moving: the reply is followed by host 0's
/// passive keepalive 10 s later, which postponed the register before L2.
fn roam(seed: u64, phase: Duration, query: bool) -> Duration {
    let mut sim = Sim::discovery(seed, 3);
    sim.hosts[2].asleep_until = Some(secs(100_000));
    let home = sim.add_nat(Ipv4Addr::new(198, 51, 100, 1), NatKind::Cone);
    let away = sim.add_nat(Ipv4Addr::new(198, 51, 100, 2), NatKind::Cone);
    sim.place(0, ep(192, 168, 1, 2, 4802), Some(home));
    sim.place(1, ep(192, 168, 1, 3, 4802), Some(home));
    sim.run_until(secs(1));
    sim.send_ip(0, 1).unwrap();
    sim.run_until(secs(5));
    assert_eq!(sim.status(0, 1).endpoint, Some(sim.addr(1)), "LAN path");
    let last = refreshed(&sim, 0);
    while refreshed(&sim, 0) == last {
        let t = sim.now + ms(10);
        sim.run_until(t);
    }
    let t = sim.now + phase;
    sim.run_until(t);
    if query {
        let _ = sim.send_ip(0, 2);
        let t = sim.now + ms(100);
        sim.run_until(t);
    }
    let moved = sim.now;
    sim.place(0, ep(192, 168, 7, 2, 4802), Some(away));
    let (home_ip, away_ip) = (public_ip(&sim, home), public_ip(&sim, away));
    let found = |sim: &Sim| {
        let ip = |host, peer| sim.status(host, peer).endpoint.map(|e| e.display().ip());
        ip(0, 1) == Some(home_ip) && ip(1, 0) == Some(away_ip)
    };
    while !found(&sim) {
        assert!(
            sim.now < moved + secs(60),
            "not recovered: phase {phase:?} query {query} {:?} {:?}",
            sim.status(0, 1),
            sim.status(1, 0)
        );
        let t = sim.now + ms(100);
        sim.run_until(t);
    }
    sim.now - moved
}

/// L2, L5, milestone v0.4 "within 30 s": a node that moves at any phase of its register
/// cycle (every 500 ms of it), with or without a query and reply just before, is found again
/// within `PERSISTENT_KEEPALIVE` plus a round trip. The worst case is a move just after the
/// lighthouse answered a register: nothing is pending, the next register tick finds it.
/// (A move before that answer loses it, and the "new handshake" timer finds it at 15 s.)
#[test]
fn a_move_at_any_register_phase_recovers_within_30_s() {
    let mut worst = Duration::ZERO;
    for (i, phase) in (0..50).map(|k| k * 500).enumerate() {
        for query in [false, true] {
            let took = roam(50 + i as u64, ms(phase), query);
            assert!(took < secs(26), "phase {phase} ms, query {query}: {took:?}");
            worst = worst.max(took);
        }
    }
    assert!(worst > secs(24), "the worst case was exercised: {worst:?}");
}

/// L5, §9, §12.5 rule 4: when the lighthouse's answers stop, the third failed register
/// re-handshakes and rediscovers the live peers; once healed, the node registers again.
#[test]
fn three_failed_registers_reregister_and_rediscover() {
    let mut sim = behind_nats(41, NatKind::Cone);
    sim.stream(0, 1, secs(1), secs(5));
    assert!(sim.status(0, 1).current);
    let lh = sim.lighthouse();
    let before = queries(&sim);
    let c = sim.status(0, 1).counters;
    let handshakes = c.handshakes_initiated + c.handshakes_responded;
    sim.partitions.insert((lh, 0));
    let cut = sim.now;
    // The last answered register was at most 25 s before the cut: the third failed one
    // comes 65 to 100 s after it.
    sim.run_until(cut + secs(64));
    assert_eq!(queries(&sim), before, "fewer than three failed registers");
    sim.run_until(cut + secs(101));
    assert!(queries(&sim) > before, "rule 4 queried for host 1");
    let c = sim.status(0, 1).counters;
    assert!(c.handshakes_initiated + c.handshakes_responded > handshakes);
    sim.partitions.clear();
    let healed = sim.now;
    sim.run_until(healed + secs(6));
    let s = sim.status(0, lh);
    assert!(s.current && s.last_handshake.is_some_and(|t| t >= healed));
    assert!(refreshed(&sim, 0).is_some_and(|t| t >= healed));
}

/// L5: a restarted lighthouse has lost every registration and session; a node's next
/// register goes unanswered, its "new handshake" timer (§9) re-handshakes 15 s later and
/// the register that follows restores the entry: within 25 + 15 s and a round trip. The
/// nodes' own session never broke.
#[test]
fn nodes_register_again_after_a_lighthouse_restart() {
    let mut sim = behind_nats(42, NatKind::Cone);
    sim.stream(0, 1, secs(1), secs(10));
    let lh = sim.lighthouse();
    let keys = vec![sim.hosts[0].key, sim.hosts[1].key];
    let key = sim.lighthouse_key.clone().expect("discovery sim");
    sim.hosts[lh].node = Node::lighthouse(key, keys);
    let restarted = sim.now;
    sim.stream(0, 1, secs(1), restarted + secs(1));
    assert!(sim.hosts[lh].node.registrations(sim.now).is_empty());
    sim.stream(0, 1, secs(1), restarted + secs(41));
    assert_eq!(sim.hosts[lh].node.registrations(sim.now).len(), 2);
    assert!(sim.received(1, 0, restarted).len() >= 40);
}

/// L5, §12.5: triggers that fire while a rediscovery runs join it: one query per 3 s.
#[test]
fn a_running_discovery_sends_one_query() {
    let mut sim = behind_nats(43, NatKind::Symmetric);
    let before = queries(&sim);
    let start = sim.now;
    for i in 1..=5 {
        sim.send_ip(0, 1).unwrap();
        sim.run_until(start + ms(500 * i));
    }
    sim.run_until(start + ms(2900));
    assert_eq!(queries(&sim), before + 1);
    sim.run_until(start + ms(3100));
    sim.send_ip(0, 1).unwrap();
    sim.run_until(start + ms(3200));
    assert_eq!(queries(&sim), before + 2, "a new window");
}

/// L5, §12.2: an endpoint learnt while message 1 is in flight gets the same bytes, and the
/// retransmit deadline stays the first copy's.
#[test]
fn learnt_candidates_get_the_in_flight_message_1() {
    let mut sim = behind_nats(44, NatKind::Cone);
    let nowhere = ep(192, 0, 2, 200, 4802);
    let peers = vec![PeerConfig {
        endpoints: vec![nowhere],
        ..sim.peer_config(1)
    }];
    sim.hosts[0].node.set_peers(peers);
    sim.partitions.extend([(0, 1), (1, 0)]);
    let start = sim.now;
    sim.send_ip(0, 1).unwrap();
    sim.run_until(start + secs(12));
    let copies = message_1_copies(&sim, 0, start);
    let (first_at, first_to, first) = copies[0].clone();
    assert_eq!(first_to, nowhere);
    assert!(
        copies
            .iter()
            .any(|(t, to, d)| *d == first && *to != nowhere && *t > first_at),
        "the reply's endpoint got the in-flight message 1"
    );
    let (next_at, ..) = copies
        .iter()
        .find(|(.., d)| *d != first)
        .expect("retransmitted");
    let gap = *next_at - first_at;
    assert!(gap >= secs(5) && gap <= ms(5334), "{gap:?}");
}

/// L5, §12.6: `no_candidates` after 3 s, then `abandoned` after 18 attempts, and a later
/// success keeps the last failure.
#[test]
fn failure_reasons_survive_a_success() {
    let mut sim = Sim::new(45, 2, PERFECT);
    let peers = vec![PeerConfig {
        endpoints: Vec::new(),
        ..sim.peer_config(1)
    }];
    sim.hosts[0].node.set_peers(peers);
    sim.send_ip(0, 1).unwrap();
    sim.run_until(ms(3100));
    let failure = |sim: &Sim| sim.status(0, 1).last_direct_path_failure;
    assert_eq!(failure(&sim), Some(PathFailure::NoCandidates));
    sim.run_until(secs(100));
    assert_eq!(failure(&sim), Some(PathFailure::Abandoned));
    assert!(!sim.status(0, 1).handshake_in_flight);
    let peers = vec![sim.peer_config(1)];
    sim.hosts[0].node.set_peers(peers);
    sim.send_ip(0, 1).unwrap();
    sim.run_until(secs(102));
    assert!(sim.status(0, 1).current);
    assert_eq!(failure(&sim), Some(PathFailure::Abandoned));
}

/// L6, §12.2 admission: with 31 static candidates the lighthouse's endpoint is the 32nd and
/// gets message 1 at once and at every retransmission; with 32 it is never sent to.
#[test]
fn a_full_candidate_set_admits_no_learnt_endpoint() {
    for (statics, admitted) in [(31u8, true), (32, false)] {
        let mut sim = Sim::discovery(46, 2);
        sim.run_until(secs(1));
        // Registered, then silent: the lighthouse still answers with its endpoint.
        sim.hosts[1].asleep_until = Some(secs(100_000));
        let nowhere = (0..statics).map(|i| ep(192, 0, 2, 100 + i, 4802)).collect();
        let peers = vec![PeerConfig {
            endpoints: nowhere,
            ..sim.peer_config(1)
        }];
        sim.hosts[0].node.set_peers(peers);
        let start = sim.now;
        sim.send_ip(0, 1).unwrap();
        sim.run_until(start + secs(12));
        let to_b: Vec<Duration> = message_1_copies(&sim, 0, start)
            .into_iter()
            .filter(|(_, to, _)| *to == sim.addr(1))
            .map(|(t, ..)| t - start)
            .collect();
        if admitted {
            assert!(to_b.iter().any(|t| *t < secs(1)), "at once: {to_b:?}");
            assert!(
                to_b.iter().any(|t| *t >= secs(5)),
                "retransmitted: {to_b:?}"
            );
        } else {
            assert!(to_b.is_empty(), "{to_b:?}");
        }
    }
}

/// R2, §12.2, §13.1: a DNS refresh that replaces 31 statics by 32 keeps the admitted learnt
/// endpoint in the candidate set: the next retransmission still reaches it.
#[test]
fn a_dns_refresh_keeps_an_admitted_learnt_endpoint() {
    let mut sim = Sim::discovery(47, 2);
    sim.run_until(secs(1));
    sim.hosts[1].asleep_until = Some(secs(100_000));
    let statics = |base: u8, n: u8| (0..n).map(|i| ep(192, 0, 2, base + i, 4802)).collect();
    let peers = vec![PeerConfig {
        endpoints: statics(100, 31),
        ..sim.peer_config(1)
    }];
    sim.hosts[0].node.set_peers(peers);
    let start = sim.now;
    sim.send_ip(0, 1).unwrap();
    sim.run_until(start + secs(1));
    let to_b = |sim: &Sim, since| {
        message_1_copies(sim, 0, since)
            .into_iter()
            .filter(|(_, to, _)| *to == sim.addr(1))
            .count()
    };
    assert!(to_b(&sim, start) > 0, "admitted as the 32nd");
    let refreshed = vec![PeerConfig {
        endpoints: statics(140, 32),
        ..sim.peer_config(1)
    }];
    sim.hosts[0].node.set_peers(refreshed);
    sim.run_until(start + secs(6));
    assert!(sim.status(0, 1).handshake_in_flight, "same sequence");
    assert!(to_b(&sim, start + secs(1)) > 0, "retransmitted to it");
}

/// R1, §7.9, §12.5: host 0 and host 1 both initiate on their shared LAN 24 s after one of
/// host 0's registers, host 0 moves at 24.5 s and its register tick at 25 s finds the move;
/// the handshake that rediscovery asks for is refused by the 5 s pacing of the handshake
/// that just completed. It is deferred, not lost: with no tunnel traffic, both sides find
/// each other's new endpoint within 30 s of the move.
#[test]
fn a_move_just_after_a_handshake_recovers_within_30_s() {
    let mut worst = Duration::ZERO;
    for seed in 0..10 {
        let mut sim = Sim::discovery(60 + seed, 2);
        let home = sim.add_nat(Ipv4Addr::new(198, 51, 100, 1), NatKind::Cone);
        let away = sim.add_nat(Ipv4Addr::new(198, 51, 100, 2), NatKind::Cone);
        sim.place(0, ep(192, 168, 1, 2, 4802), Some(home));
        sim.place(1, ep(192, 168, 1, 3, 4802), Some(home));
        sim.run_until(secs(1));
        let last = refreshed(&sim, 0);
        while refreshed(&sim, 0) == last {
            let t = sim.now + ms(10);
            sim.run_until(t);
        }
        let register = sim.now;
        sim.run_until(register + secs(24));
        sim.send_ip(0, 1).unwrap();
        sim.send_ip(1, 0).unwrap();
        sim.run_until(register + ms(24_500));
        assert_eq!(sim.status(0, 1).endpoint, Some(sim.addr(1)), "LAN path");
        let lan = sim.status(0, 1).last_handshake;
        assert!(lan.is_some_and(|t| t >= register + secs(24)));
        let moved = sim.now;
        sim.place(0, ep(192, 168, 7, 2, 4802), Some(away));
        let (home_ip, away_ip) = (public_ip(&sim, home), public_ip(&sim, away));
        let found = |sim: &Sim| {
            let ip = |host, peer| sim.status(host, peer).endpoint.map(|e| e.display().ip());
            ip(0, 1) == Some(home_ip) && ip(1, 0) == Some(away_ip)
        };
        while !found(&sim) {
            assert!(
                sim.now < moved + secs(30),
                "seed {seed}: not recovered within 30 s {:?} {:?}",
                sim.status(0, 1),
                sim.status(1, 0)
            );
            let t = sim.now + ms(100);
            sim.run_until(t);
        }
        worst = worst.max(sim.now - moved);
    }
    // The register at 25 s found the move, the deferred handshake left at 29 s.
    assert!(worst > secs(4), "the deferral was exercised: {worst:?}");
}

/// The `roaming` nixosTest failure: host 0 moves just after a register and, before its next
/// one, reaches the lighthouse from its new network (a query, a passive keepalive), while
/// host 1, which sent to it just before the move, rediscovers it (§12.5 rule 2, at about
/// 20 s). The punch reaches host 0 at its new address and makes it send to host 1's NAT, so
/// the reply must give host 1 that address too (§13.2: the observed endpoint follows the
/// last authenticated datagram). With the register's address, host 0's datagrams reached
/// host 1's NAT before host 1 sent any to host 0's new address, held the port host 1's
/// mapping needed (Linux conntrack), and no handshake completed in the whole sequence.
#[test]
fn a_peer_rediscovering_a_moved_node_learns_its_current_endpoint() {
    for seed in 0..5 {
        let mut sim = Sim::discovery(70 + seed, 3);
        sim.hosts[2].asleep_until = Some(secs(100_000));
        let home = sim.add_nat(Ipv4Addr::new(198, 51, 100, 1), NatKind::Cone);
        let away = sim.add_nat(Ipv4Addr::new(198, 51, 100, 2), NatKind::Cone);
        sim.nats[home].holds = true;
        sim.nats[away].holds = true;
        sim.place(0, ep(192, 168, 1, 2, 4802), Some(home));
        sim.place(1, ep(192, 168, 1, 3, 4802), Some(home));
        sim.run_until(secs(1));
        sim.send_ip(0, 1).unwrap();
        sim.run_until(secs(5));
        assert_eq!(sim.status(0, 1).endpoint, Some(sim.addr(1)), "LAN path");
        let last = refreshed(&sim, 0);
        while refreshed(&sim, 0) == last {
            let t = sim.now + ms(10);
            sim.run_until(t);
        }
        // Host 0 queries for the unregistered host 2; host 1 sends without an answer.
        let _ = sim.send_ip(0, 2);
        sim.send_ip(1, 0).unwrap();
        let t = sim.now + ms(100);
        sim.run_until(t);
        let moved = sim.now;
        sim.place(0, ep(192, 168, 7, 2, 4802), Some(away));
        let (home_ip, away_ip) = (public_ip(&sim, home), public_ip(&sim, away));
        let found = |sim: &Sim| {
            let ip = |host, peer| sim.status(host, peer).endpoint.map(|e| e.display().ip());
            ip(0, 1) == Some(home_ip) && ip(1, 0) == Some(away_ip)
        };
        while !found(&sim) {
            assert!(
                sim.now < moved + secs(30),
                "seed {seed}: not recovered within 30 s {:?} {:?}",
                sim.status(0, 1),
                sim.status(1, 0)
            );
            let t = sim.now + ms(100);
            sim.run_until(t);
        }
        // Host 1's rediscovery found it, before host 0's register at 25 s.
        let took = sim.now - moved;
        assert!(took > secs(15) && took < secs(24), "seed {seed}: {took:?}");
    }
}

/// v0.6 finding 4: host 1 (public) streams to host 0 (behind a NAT), which sends nothing
/// back, then host 0 changes network. Its keepalive on the change of its local endpoints
/// (§12.4) gives host 1 the new endpoint at once, at every phase of host 0's passive
/// keepalive (10 s), which alone bounded the recovery before.
#[test]
fn a_receiving_node_that_changes_network_is_reached_within_a_round_trip() {
    let period = ms(200);
    for phase in 0..10 {
        let mut sim = Sim::discovery(90 + phase, 2);
        let home = sim.add_nat(Ipv4Addr::new(198, 51, 100, 1), NatKind::Cone);
        let away = sim.add_nat(Ipv4Addr::new(198, 51, 100, 2), NatKind::Cone);
        sim.place(0, ep(192, 168, 1, 2, 4802), Some(home));
        sim.run_until(secs(1));
        sim.stream(1, 0, period, secs(30 + phase));
        let ip = |sim: &Sim| sim.status(1, 0).endpoint.map(|e| e.display().ip());
        assert_eq!(ip(&sim), Some(public_ip(&sim, home)), "phase {phase} s");
        let moved = sim.now;
        sim.place(0, ep(192, 168, 7, 2, 4802), Some(away));
        sim.stream(1, 0, period, moved + secs(30));
        let first = sim.hosts[0]
            .received
            .iter()
            .find(|(t, p, _)| *t > moved && *p == 1)
            .map(|(t, ..)| *t - moved)
            .expect("traffic resumed");
        // Host 1's next packet after the keepalive arrived (10 ms each way).
        assert!(first < period + ms(50), "phase {phase} s: after {first:?}");
        assert_eq!(ip(&sim), Some(public_ip(&sim, away)), "phase {phase} s");
    }
}

// v0.5: relay (§12.3, §14).

/// Hosts 0 and 1 behind symmetric NATs, the lighthouse and a relay listing both on the
/// public network; every permanent session is up after two seconds.
fn behind_symmetric_nats_with_a_relay(seed: u64, limit: Option<u64>) -> Sim {
    let mut sim = behind_nats(seed, NatKind::Symmetric);
    let relay = sim.add_relay(&[0, 1], limit);
    sim.run_until(secs(2));
    for host in [0, 1] {
        assert!(sim.status(host, relay).current, "relay session of {host}");
    }
    sim
}

fn relay_key(sim: &Sim) -> PublicKey {
    sim.hosts[sim.relay()].key
}

/// Milestone v0.5, §12.3, §12.4: with symmetric NATs on both sides no direct handshake
/// completes; 3 s after the first packet the attempt goes through the relay as well and
/// both sides report `path = relayed` with the relay's key, the failure reason `timeout`,
/// and traffic in both directions. A relayed packet never changes the peer's endpoint.
#[test]
fn symmetric_nats_on_both_sides_go_through_the_relay() {
    let mut sim = behind_symmetric_nats_with_a_relay(50, None);
    let start = sim.now;
    sim.send_ip(0, 1).unwrap();
    sim.run_until(start + ms(2900));
    assert!(!sim.status(0, 1).current, "direct only for the first 3 s");
    sim.run_until(start + ms(3200));
    let relayed = Some(Path::Relayed(relay_key(&sim)));
    for (host, peer) in [(0, 1), (1, 0)] {
        let s = sim.status(host, peer);
        assert_eq!(s.path, relayed, "{host} -> {peer}");
        assert_eq!(s.endpoint, None, "a relayed packet never sets the endpoint");
    }
    assert_eq!(
        sim.received(1, 0, start),
        [0],
        "the staged packet went through"
    );
    assert_eq!(
        sim.status(0, 1).last_direct_path_failure,
        Some(PathFailure::Timeout)
    );
    sim.stream(0, 1, ms(500), start + secs(10));
    sim.stream(1, 0, ms(500), start + secs(15));
    assert!(sim.received(1, 0, start).len() >= 14);
    assert!(sim.received(0, 1, start).len() >= 9);
    for (host, peer) in [(0, 1), (1, 0)] {
        let s = sim.status(host, peer);
        assert_eq!(s.path, relayed);
        assert_eq!(s.endpoint, None, "{host} -> {peer}");
    }
    let r = sim.relay();
    let senders = sim.hosts[r].node.relay_senders();
    assert_eq!(senders.len(), 2);
    for (_, c) in &senders {
        assert!(c.forwarded_packets >= 9 && c.forwarded_bytes > 0, "{c:?}");
        assert_eq!((c.dropped_no_route, c.dropped_rate_limited), (0, 0));
    }
}

/// §14.2, ADR 0014: the relay holds sessions with the listed nodes only and nothing of the
/// A↔B session: its state is those sessions plus per-sender counters, and the A↔B
/// handshake and data reach the relay only as `relay_forward` payloads it never opens.
#[test]
fn the_relay_holds_nothing_of_the_session_it_carries() {
    let mut sim = behind_symmetric_nats_with_a_relay(51, None);
    let start = sim.now;
    sim.stream(0, 1, ms(500), start + secs(8));
    assert!(matches!(sim.status(0, 1).path, Some(Path::Relayed(_))));
    let r = sim.relay();
    // Every datagram the relay received or sent was on its own sessions with 0 and 1: the
    // A↔B messages never reached it as outer datagrams.
    for (_, from, to, ty) in &sim.emitted {
        if *to == r || *from == r {
            assert!(*from != r || *to <= 1, "relay talked to {to}");
            assert!(*to != r || *from <= 1, "{from} talked to the relay");
            let _ = ty;
        }
    }
    let relay = &sim.hosts[r].node;
    for host in [0, 1] {
        let s = relay.status(&sim.hosts[host].key).expect("listed");
        assert!(s.sessions >= 1 && s.sessions <= 3);
    }
    assert!(relay.status(&sim.hosts[sim.lighthouse()].key).is_none());
    // The relay's handshakes are its own: one completed per node, none for the pair.
    let handshakes: u64 = [0, 1]
        .iter()
        .map(|h| {
            let c = relay.status(&sim.hosts[*h].key).unwrap().counters;
            c.handshakes_initiated + c.handshakes_responded
        })
        .sum();
    assert_eq!(handshakes, 2, "only the relay's own sessions");
}

/// Milestone v0.5 (`relay-upgrade` in the simulation), §12.3: relayed first; the NATs turn
/// into cone NATs (conntrack flushed); a direct retry finds the direct path within 90 s
/// and traffic moves to it at once.
#[test]
fn relayed_peers_upgrade_to_direct_when_the_nats_allow_it() {
    let mut sim = behind_symmetric_nats_with_a_relay(52, None);
    let start = sim.now;
    sim.stream(0, 1, secs(1), start + secs(10));
    assert!(matches!(sim.status(0, 1).path, Some(Path::Relayed(_))));
    assert!(matches!(sim.status(1, 0).path, Some(Path::Relayed(_))));
    for nat in &mut sim.nats {
        nat.kind = NatKind::Cone;
        nat.out.clear();
        nat.back.clear();
    }
    let switched = sim.now;
    let mut direct_at = None;
    while sim.now < switched + secs(90) && direct_at.is_none() {
        let _ = sim.send_ip(0, 1);
        let _ = sim.send_ip(1, 0);
        let next = sim.now + secs(1);
        sim.run_until(next);
        let direct = |h, p| matches!(sim.status(h, p).path, Some(Path::Direct(_)));
        if direct(0, 1) && direct(1, 0) {
            direct_at = Some(sim.now - switched);
        }
    }
    let took = direct_at.expect("direct within 90 s");
    assert!(took > secs(1), "a retry, not luck: {took:?}");
    let to_b = sim.status(0, 1).endpoint.unwrap();
    assert_eq!(to_b.display().ip(), public_ip(&sim, 1));
    // Traffic now goes direct: the relay forwards nothing more.
    let r = sim.relay();
    let forwarded = |sim: &Sim| -> u64 {
        let senders = sim.hosts[r].node.relay_senders();
        senders.iter().map(|(_, c)| c.forwarded_packets).sum()
    };
    let before = forwarded(&sim);
    let now = sim.now;
    sim.stream(0, 1, secs(1), now + secs(5));
    assert_eq!(forwarded(&sim), before);
    assert!(sim.received(1, 0, now).len() >= 4);
}

/// §9 last row, §12.3: a restarted relay has lost every session; the nodes' relay sessions
/// come back through the "new handshake" timer and relayed traffic resumes, still relayed.
#[test]
fn relayed_traffic_resumes_after_a_relay_restart() {
    let mut sim = behind_symmetric_nats_with_a_relay(53, None);
    let start = sim.now;
    sim.stream(0, 1, secs(1), start + secs(10));
    let r = sim.relay();
    let keys = vec![sim.hosts[0].key, sim.hosts[1].key];
    let key = sim.relay_key.clone().expect("relay sim");
    sim.hosts[r].node = Node::relay(key, keys, None);
    let restarted = sim.now;
    sim.stream(0, 1, secs(1), restarted + secs(60));
    let first = sim.hosts[1]
        .received
        .iter()
        .find(|(t, p, _)| *t > restarted && *p == 0)
        .map(|(t, ..)| *t - restarted)
        .expect("traffic resumed");
    assert!(first < secs(30), "resumed after {first:?}");
    assert!(matches!(sim.status(0, 1).path, Some(Path::Relayed(_))));
    assert!(sim.received(1, 0, restarted + secs(30)).len() >= 25);
}

/// Milestone v0.5, §14.2: with a per-sender limit a flooding sender is capped and the
/// relay counts its drops; without a limit nothing is dropped.
#[test]
fn the_relay_rate_limit_caps_a_flooding_sender() {
    // Data packets of the harness carry 65 bytes of A↔B payload: 200 per second is
    // 13 000 bytes per second.
    let limit = 6_500;
    for (seed, limit) in [(54, Some(limit)), (55, None)] {
        let mut sim = behind_symmetric_nats_with_a_relay(seed, limit);
        let start = sim.now;
        sim.send_ip(0, 1).unwrap();
        sim.run_until(start + secs(4));
        assert!(matches!(sim.status(0, 1).path, Some(Path::Relayed(_))));
        let flood = sim.now;
        sim.stream(0, 1, ms(5), flood + secs(10));
        sim.run_until(flood + secs(11));
        let got = sim.received(1, 0, flood).len();
        let r = sim.relay();
        let senders = sim.hosts[r].node.relay_senders();
        let a = senders
            .iter()
            .find(|(k, _)| *k == sim.hosts[0].key)
            .unwrap()
            .1;
        match limit {
            Some(limit) => {
                assert!(a.dropped_rate_limited > 500, "{a:?}");
                // At most one second's burst plus ten seconds' worth.
                let cap = 11 * limit as usize / 65 + 1;
                assert!(got <= cap && got >= cap / 2, "{got} delivered, cap {cap}");
            }
            None => {
                assert_eq!(a.dropped_rate_limited, 0);
                assert_eq!(got, 2000, "nothing dropped");
            }
        }
    }
}

/// Silence (§14.2, §16): a key the relay does not list never gets a datagram from it, so it
/// can send no `relay_forward`; a listed node forwarding to a key the relay does not list
/// is dropped and counted, nothing goes out.
#[test]
fn relay_silence_and_unlisted_destinations() {
    let mut sim = Sim::discovery(56, 3);
    for (host, last) in [(0, 1), (1, 2), (2, 3)] {
        let nat = sim.add_nat(Ipv4Addr::new(198, 51, 100, last), NatKind::Symmetric);
        sim.place(host, ep(192, 168, last, 2, 4802), Some(nat));
    }
    let r = sim.add_relay(&[0, 1], None);
    sim.run_until(secs(20));
    let answered = sim
        .emitted
        .iter()
        .filter(|(_, f, t, _)| *f == r && *t == 2)
        .count();
    assert_eq!(answered, 0, "the unlisted host got no datagram");
    assert!(!sim.drops(r, DropReason::IdentityRejected).is_empty());
    assert!(!sim.status(2, r).current);
    // Host 0 lists host 2 as a peer; the relay does not.
    let start = sim.now;
    sim.send_ip(0, 2).unwrap();
    sim.run_until(start + secs(10));
    assert!(!sim.status(0, 2).current);
    let a = sim.hosts[r].node.relay_senders()[0..2]
        .iter()
        .find(|(k, _)| *k == sim.hosts[0].key)
        .unwrap()
        .1;
    assert!(a.dropped_no_route >= 1, "{a:?}");
    assert_eq!(a.forwarded_packets, 0);
    let to_2 = sim
        .emitted
        .iter()
        .filter(|(t, f, to, _)| *t >= start && *f == r && *to == 2)
        .count();
    assert_eq!(to_2, 0);
}
