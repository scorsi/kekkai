//! Deterministic simulation (ADR 0020 tier 2): several `Node`s through an in-memory network
//! with seeded loss, duplication and delay (hence reordering), per-host clock drift,
//! wall-clock steps and suspend. The network decisions derive from the seed and a per-link
//! datagram counter, so they do not depend on the core's own randomness (indices,
//! ephemerals, retransmit jitter), which still comes from the OS.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use kekkai_core::firewall::Rule;
use kekkai_core::keys::{PublicKey, StaticKey};
use kekkai_core::node::{Node, Output, PeerConfig};
use kekkai_core::tai64n::Tai64n;
use kekkai_core::wire::{self, DropReason};
use kekkai_core::{MTU, PERSISTENT_KEEPALIVE, REJECT_AFTER_TIME, REKEY_AFTER_TIME};

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
    datagram: Vec<u8>,
}

/// One emitted datagram: `(sim time, from, to, outer type)`.
type Emitted = (Duration, usize, usize, u8);

struct Sim {
    seed: u64,
    now: Duration,
    seq: u64,
    link: Link,
    hosts: Vec<Host>,
    queue: BinaryHeap<Reverse<Event>>,
    /// Links cut by a scenario: `(from, to)`.
    partitions: HashSet<(usize, usize)>,
    emitted: Vec<Emitted>,
    /// Datagrams sent per link, the `n` of `mix(seed, link, n)`.
    link_counts: Vec<u64>,
}

fn address(host: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, host as u8 + 1))
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
                    })
                    .collect();
                Host {
                    node: Node::new(key, peers),
                    key: publics[i],
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
            queue: BinaryHeap::new(),
            partitions: HashSet::new(),
            emitted: Vec::new(),
            link_counts: vec![0; n * n],
        }
    }

    fn host_of(&self, key: &PublicKey) -> usize {
        self.hosts
            .iter()
            .position(|h| h.key == *key)
            .expect("datagrams go to configured peers")
    }

    fn peer_config(&self, j: usize) -> PeerConfig {
        PeerConfig {
            public_key: self.hosts[j].key,
            addresses: vec![address(j)],
            allow_inbound: vec![Rule::Any],
        }
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
        for (key, datagram) in out.datagrams {
            let to = self.host_of(&key);
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
                    datagram: datagram.clone(),
                }));
            }
        }
    }

    fn deliver(&mut self, to: usize, datagram: &[u8]) -> Result<(), DropReason> {
        let host = &mut self.hosts[to];
        let (mono, wall) = (host.mono(self.now), host.wall(self.now));
        match host.node.handle_datagram(mono, wall, datagram) {
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
                if !self.hosts[e.to].asleep(self.now) {
                    let _ = self.deliver(e.to, &e.datagram);
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
        assert_eq!(sim.deliver(1, datagram), Err(reason));
    }
    assert_eq!(sim.emitted.len(), emitted, "no datagram in reaction");
    // The genuine copy still completes; its replay is silent (§7.4).
    assert!(sim.deliver(1, &msg1).is_ok());
    sim.run_until(secs(2));
    assert_eq!(sim.received(1, 0, secs(1)), [1]);
    assert_eq!(sim.deliver(1, &msg1), Err(DropReason::TimestampNotNewer));
    // A replayed data packet is rejected by the window (§8.4), its payload delivered once.
    let emitted = sim.emitted.len();
    sim.send_ip(0, 1).unwrap();
    let data = sim.queue.pop().expect("data queued").0.datagram;
    assert_eq!(data[0], wire::TYPE_DATA);
    assert!(sim.deliver(1, &data).is_ok());
    assert_eq!(sim.deliver(1, &data), Err(DropReason::CounterRejected));
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
    sim.deliver(0, &msg1_1).unwrap();
    sim.deliver(1, &msg1_0).unwrap();
    let lost_msg2 = pop(&mut sim, 0);
    assert_eq!(lost_msg2[0], wire::TYPE_HANDSHAKE_RESP);
    let msg2_0 = pop(&mut sim, 1);
    sim.deliver(1, &msg2_0).unwrap();
    let data = pop(&mut sim, 0);
    assert_eq!(sim.deliver(0, &data), Err(DropReason::SourceNotPeer));
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
