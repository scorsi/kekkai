//! The party-level driver (ADR 0004): datagrams, tunnel packets and the two clocks in;
//! datagrams, tunnel packets and the next deadline out. It owns the peer map (a replaceable
//! value), the index table (§7.5), the routing table (§11) and the identity list (§4).
//!
//! Paths and endpoints are §12 (v0.4): until then every outgoing datagram names the peer it
//! is for and the IO layer maps a peer to its configured endpoint.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::MTU;
use crate::handshake::{self, Identity};
use crate::inner::Inner;
use crate::keys::{PublicKey, StaticKey};
use crate::mac1::Mac1Key;
use crate::peer::{Counters, Ctx, IndexTable, Peer};
use crate::tai64n::Tai64n;
use crate::tlv::Tlv;
use crate::wire::{self, DropReason, Outer};

/// One `[[peers]]` entry: the static key and the overlay addresses (`/32` and `/128` only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerConfig {
    pub public_key: PublicKey,
    pub addresses: Vec<IpAddr>,
}

/// What one call produced: datagrams to send, each for the peer that owns the session, and
/// IP packets to deliver to the tunnel interface.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub datagrams: Vec<(PublicKey, Vec<u8>)>,
    pub packets: Vec<Vec<u8>>,
    /// The peer that sent the handled datagram, once authenticated (§12.4): the IO layer
    /// records the datagram's source as that peer's endpoint.
    pub from: Option<PublicKey>,
}

/// Per-peer counters for the control API and the tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerStatus {
    /// Live sessions in the three slots (§8.1).
    pub sessions: usize,
    /// A message 1 is awaiting its answer (§7.9).
    pub handshake_in_flight: bool,
    pub staged_packets: usize,
    /// A `current` session exists (§12.1: the peer's path is that session's, else `none`).
    pub current: bool,
    pub last_handshake: Option<Duration>,
    pub counters: Counters,
}

/// One party. `Node` is the whole public surface the IO layer drives.
pub struct Node {
    key: StaticKey,
    public_key: PublicKey,
    mac1: Mac1Key,
    indices: IndexTable,
    peers: HashMap<PublicKey, Peer>,
    routes: HashMap<IpAddr, PublicKey>,
}

/// v0 identity (§4): the key is in the peer list.
struct Listed<'a>(&'a HashMap<PublicKey, Peer>);

impl Identity for Listed<'_> {
    fn verify(&self, static_public: &PublicKey, _tlvs: &[Tlv<'_>]) -> bool {
        self.0.contains_key(static_public)
    }
}

impl Node {
    pub fn new(key: StaticKey, peers: Vec<PeerConfig>) -> Self {
        let public_key = key.public();
        let mut node = Self {
            mac1: Mac1Key::for_receiver(&public_key),
            key,
            public_key,
            indices: IndexTable::new(),
            peers: HashMap::new(),
            routes: HashMap::new(),
        };
        node.set_peers(peers);
        node
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Replaces the peer list (ADR 0004, 0016): a removed peer loses its sessions (§8.5),
    /// a kept one keeps them, the routing table is rebuilt.
    pub fn set_peers(&mut self, peers: Vec<PeerConfig>) {
        self.routes.clear();
        for config in &peers {
            for address in &config.addresses {
                self.routes.insert(*address, config.public_key);
            }
        }
        for (key, peer) in &mut self.peers {
            if !peers.iter().any(|c| c.public_key == *key) {
                peer.forget(&mut self.indices);
            }
        }
        self.peers
            .retain(|key, _| peers.iter().any(|c| c.public_key == *key));
        for config in peers {
            self.peers
                .entry(config.public_key)
                .or_insert_with(|| Peer::new(config.public_key));
        }
    }

    pub fn status(&self, peer: &PublicKey) -> Option<PeerStatus> {
        self.peers.get(peer).map(|p| PeerStatus {
            sessions: p.sessions().count(),
            handshake_in_flight: p.has_in_flight_handshake(),
            staged_packets: p.staged_packets(),
            current: p.current().is_some(),
            last_handshake: p.last_handshake,
            counters: p.counters,
        })
    }

    /// §11 outbound: a packet from the tunnel interface, routed by destination.
    pub fn send_packet(
        &mut self,
        now: Duration,
        wall: Tai64n,
        packet: &[u8],
    ) -> Result<Output, DropReason> {
        if packet.len() > MTU {
            return Err(DropReason::PacketTooLarge);
        }
        let (_, destination) = ip_addresses(packet).ok_or(DropReason::NoRoute)?;
        if !is_unicast(destination) {
            return Err(DropReason::NotUnicast);
        }
        let key = *self.routes.get(&destination).ok_or(DropReason::NoRoute)?;
        let peer = self.peers.get_mut(&key).expect("routes point at peers");
        let mut ctx = Ctx {
            now,
            wall,
            local: &self.key,
            indices: &mut self.indices,
        };
        let output = Output {
            datagrams: peer
                .send_ip(&mut ctx, packet)
                .into_iter()
                .map(|d| (key, d))
                .collect(),
            ..Output::default()
        };
        self.count_tx(&output);
        Ok(output)
    }

    /// §5.6, then §7.6, §7.7 or §8.2 and §10, §11 inbound. `Err` is the silent drop of §16.
    pub fn handle_datagram(
        &mut self,
        now: Duration,
        wall: Tai64n,
        datagram: &[u8],
    ) -> Result<Output, DropReason> {
        let output = self.receive(now, wall, datagram)?;
        if let Some(peer) = output.from.and_then(|k| self.peers.get_mut(&k)) {
            peer.counters.rx_packets += 1;
            peer.counters.rx_bytes += datagram.len() as u64;
        }
        self.count_tx(&output);
        Ok(output)
    }

    fn receive(
        &mut self,
        now: Duration,
        wall: Tai64n,
        datagram: &[u8],
    ) -> Result<Output, DropReason> {
        let mut ctx = Ctx {
            now,
            wall,
            local: &self.key,
            indices: &mut self.indices,
        };
        let mut output = Output::default();
        match wire::parse(datagram)? {
            Outer::HandshakeInit(init) => {
                init.verify_mac1(&self.mac1)?;
                let pending = handshake::read_init(&self.key, &init, &Listed(&self.peers))?;
                let key = pending.initiator_static;
                let peer = self.peers.get_mut(&key).expect("verify checked the list");
                output.from = Some(key);
                output
                    .datagrams
                    .push((key, peer.accept_init(&mut ctx, pending)?));
            }
            Outer::HandshakeResp(resp) => {
                resp.verify_mac1(&self.mac1)?;
                let key = *ctx
                    .indices
                    .owner(resp.receiver_index)
                    .ok_or(DropReason::UnknownIndex)?;
                let peer = self.peers.get_mut(&key).expect("indices point at peers");
                output.from = Some(key);
                output.datagrams.extend(
                    peer.handle_resp(&mut ctx, &resp)?
                        .into_iter()
                        .map(|d| (key, d)),
                );
            }
            Outer::Data(data) => {
                let key = *ctx
                    .indices
                    .owner(data.receiver_index)
                    .ok_or(DropReason::UnknownIndex)?;
                let peer = self.peers.get_mut(&key).expect("indices point at peers");
                let (plaintext, datagrams) = match peer.handle_data(&mut ctx, &data) {
                    Err(DropReason::CounterRejected) => {
                        peer.counters.replay_rejections += 1;
                        return Err(DropReason::CounterRejected);
                    }
                    result => result?,
                };
                output.from = Some(key);
                output
                    .datagrams
                    .extend(datagrams.into_iter().map(|d| (key, d)));
                // §10.2 for a node: ip_packet from peers, keepalive from any session.
                match Inner::decode(&plaintext)? {
                    Inner::IpPacket(packet) => {
                        let (source, destination) =
                            ip_addresses(packet).ok_or(DropReason::InnerMalformed)?;
                        if !is_unicast(destination) {
                            return Err(DropReason::NotUnicast);
                        }
                        if self.routes.get(&source) != Some(&key) {
                            return Err(DropReason::SourceNotPeer);
                        }
                        output.packets.push(packet.to_vec());
                    }
                    Inner::Keepalive => {}
                    _ => return Err(DropReason::NotAccepted),
                }
            }
        }
        Ok(output)
    }

    /// Runs every deadline that has passed (§9).
    pub fn tick(&mut self, now: Duration, wall: Tai64n) -> Output {
        let mut ctx = Ctx {
            now,
            wall,
            local: &self.key,
            indices: &mut self.indices,
        };
        let mut output = Output::default();
        for (key, peer) in &mut self.peers {
            output
                .datagrams
                .extend(peer.tick(&mut ctx).into_iter().map(|d| (*key, d)));
        }
        self.count_tx(&output);
        output
    }

    fn count_tx(&mut self, output: &Output) {
        for (key, datagram) in &output.datagrams {
            if let Some(peer) = self.peers.get_mut(key) {
                peer.counters.tx_packets += 1;
                peer.counters.tx_bytes += datagram.len() as u64;
            }
        }
    }

    /// The earliest pending deadline over every peer (§9).
    pub fn next_deadline(&self) -> Option<Duration> {
        self.peers.values().filter_map(Peer::next_deadline).min()
    }

    #[cfg(test)]
    pub(crate) fn index_count(&self) -> usize {
        self.indices.len()
    }
}

/// Source and destination of an IPv4 or IPv6 packet; `None` when the header is truncated.
fn ip_addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    let addr = |at: usize, n: usize| packet.get(at..at + n);
    match packet.first().map(|b| b >> 4) {
        Some(4) => {
            let (s, d) = (addr(12, 4)?, addr(16, 4)?);
            let v4 = |b: &[u8]| IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
            Some((v4(s), v4(d)))
        }
        Some(6) => {
            let (s, d) = (addr(8, 16)?, addr(24, 16)?);
            let v6 = |b: &[u8]| Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b).ok()?)));
            Some((v6(s)?, v6(d)?))
        }
        _ => None,
    }
}

/// §11: multicast and broadcast destinations are dropped on both sides.
fn is_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => !v4.is_multicast() && !v4.is_broadcast(),
        IpAddr::V6(v6) => !v6.is_multicast(),
    }
}
