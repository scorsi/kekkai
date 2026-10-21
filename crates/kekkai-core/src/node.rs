//! The party-level driver (ADR 0004): datagrams, tunnel packets and the two clocks in;
//! datagrams, tunnel packets and the next deadline out. It owns the peer map (a replaceable
//! value), the index table (§7.5), the routing table (§11), the identity list (§4) and, per
//! peer, the endpoint and candidates of §12. A party is a node, or a lighthouse
//! ([`Node::lighthouse`], §13.2).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::firewall::{Firewall, FirewallStatus, Rule};
use crate::handshake::{self, Identity};
use crate::inner::{Endpoint, Inner};
use crate::keys::{PublicKey, StaticKey};
use crate::lighthouse::{LighthouseCounters, Registration, Registry};
use crate::mac1::Mac1Key;
use crate::peer::{Counters, Ctx, IndexTable, Peer};
use crate::tai64n::Tai64n;
use crate::tlv::Tlv;
use crate::wire::{self, DropReason, Outer};
use crate::{
    DIRECT_PATH_TIMEOUT, KEEPALIVE_FAILURES_BEFORE_REREGISTER, MAX_CANDIDATES, MAX_LOCAL_ENDPOINTS,
    MTU, REKEY_TIMEOUT,
};

/// One `[[peers]]` entry: the static key, the overlay addresses (`/32` and `/128` only),
/// what the peer may reach on this node (§15; empty: ICMP and replies only) and its static
/// endpoints, resolved by the IO layer (§12.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerConfig {
    pub public_key: PublicKey,
    pub addresses: Vec<IpAddr>,
    pub allow_inbound: Vec<Rule>,
    pub endpoints: Vec<Endpoint>,
}

/// One `[[lighthouses]]` entry (§13.1): the node keeps a permanent session with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LighthouseConfig {
    pub public_key: PublicKey,
    pub endpoint: Endpoint,
}

/// What one call produced: datagrams to send, each with its destination, and IP packets to
/// deliver to the tunnel interface.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub datagrams: Vec<(Endpoint, Vec<u8>)>,
    pub packets: Vec<Vec<u8>>,
    /// The party that sent the handled datagram, once authenticated (§12.4).
    pub from: Option<PublicKey>,
    /// An authenticated `data` packet whose inner content was rejected (§10, §11, §15): only
    /// that content is dropped, the transport effects above stand (§8.2). Count it as a drop.
    pub dropped: Option<DropReason>,
}

/// Reason of the last direct-path failure (§12.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathFailure {
    NoCandidates,
    Timeout,
    Abandoned,
    LighthouseUnknown,
}

impl PathFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            PathFailure::NoCandidates => "no_candidates",
            PathFailure::Timeout => "timeout",
            PathFailure::Abandoned => "abandoned",
            PathFailure::LighthouseUnknown => "lighthouse_unknown",
        }
    }
}

/// Per-peer state for the control API and the tests (§12.6), lighthouses included.
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
    /// Last authenticated packet received from the peer (§12.4).
    pub last_received: Option<Duration>,
    /// Where direct traffic goes (§12.1), learnt from authenticated packets only.
    pub endpoint: Option<Endpoint>,
    pub last_direct_path_failure: Option<PathFailure>,
    pub counters: Counters,
}

/// §12 state of one configured party, beside its [`Peer`].
#[derive(Default)]
struct Link {
    lighthouse: bool,
    statics: Vec<Endpoint>,
    endpoint: Option<Endpoint>,
    /// Endpoints from lighthouse answers and punches, kept until a handshake completes or
    /// the attempt sequence is abandoned (§12.2).
    learnt: Vec<Endpoint>,
    /// The last message 1 sent, resent to candidates learnt while it is in flight (§12.2).
    message_1: Option<Vec<u8>>,
    /// Start of the running rediscovery (§12.5), until `DIRECT_PATH_TIMEOUT` or completion.
    discovery: Option<Duration>,
    /// A lighthouse answered "unknown" during the running rediscovery.
    unknown: bool,
    failure: Option<PathFailure>,
    last_received: Option<Duration>,
    // Towards a lighthouse (§9, §13.1).
    received_since_register: bool,
    failed_keepalives: u32,
    /// Local endpoints of the last register sent; `None` before the first one.
    registered: Option<Vec<Endpoint>>,
    /// A handshake completed: register as soon as `current` can send.
    register_due: bool,
}

impl Link {
    /// §12.2: statics, the last known endpoint, the learnt ones; deduplicated, bounded (§17).
    fn candidates(&self) -> Vec<Endpoint> {
        let mut all: Vec<Endpoint> = Vec::new();
        for e in self
            .statics
            .iter()
            .chain(&self.endpoint)
            .chain(&self.learnt)
        {
            if !all.contains(e) && all.len() < MAX_CANDIDATES {
                all.push(*e);
            }
        }
        all
    }

    fn end_discovery(&mut self) {
        self.discovery = None;
        self.learnt.clear();
        self.unknown = false;
    }
}

/// A datagram waiting for its destination: `None` routes it by the peer's state (§12.2).
type Send = (PublicKey, Option<Endpoint>, Vec<u8>);

/// One party. `Node` is the whole public surface the IO layer drives.
pub struct Node {
    key: StaticKey,
    public_key: PublicKey,
    mac1: Mac1Key,
    indices: IndexTable,
    peers: HashMap<PublicKey, Peer>,
    links: HashMap<PublicKey, Link>,
    routes: HashMap<IpAddr, PublicKey>,
    rules: HashMap<PublicKey, Vec<Rule>>,
    firewall: Firewall,
    /// This node's local endpoints, as the IO layer last collected them (§13.1).
    locals: Vec<Endpoint>,
    /// `Some` for a lighthouse (§13.2).
    registry: Option<Registry>,
}

/// v0 identity (§4): the key is in the peer list.
struct Listed<'a>(&'a HashMap<PublicKey, Peer>);

impl Identity for Listed<'_> {
    fn verify(&self, static_public: &PublicKey, _tlvs: &[Tlv<'_>]) -> bool {
        self.0.contains_key(static_public)
    }
}

/// Builds the `Ctx` of a call from the party's fields, leaving the others borrowable.
macro_rules! ctx {
    ($self:ident, $now:expr, $wall:expr) => {
        Ctx {
            now: $now,
            wall: $wall,
            local: &$self.key,
            indices: &mut $self.indices,
        }
    };
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
            links: HashMap::new(),
            routes: HashMap::new(),
            rules: HashMap::new(),
            firewall: Firewall::default(),
            locals: Vec::new(),
            registry: None,
        };
        node.set_peers(peers);
        node
    }

    /// A lighthouse (§13.2): handshakes with the listed keys, answers their registers and
    /// queries, routes no IP packet.
    pub fn lighthouse(key: StaticKey, peers: Vec<PublicKey>) -> Self {
        let mut node = Self::new(key, Vec::new());
        node.registry = Some(Registry::default());
        node.set_lighthouse_peers(peers);
        node
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Sets the bound of the firewall table (`firewall.udp_flows_max`, §15); empties it.
    pub fn set_udp_flows_max(&mut self, max: usize) {
        self.firewall = Firewall::new(max);
    }

    pub fn firewall_status(&self) -> FirewallStatus {
        self.firewall.status()
    }

    /// Replaces the peer list (ADR 0004, 0016): a removed peer loses its sessions (§8.5),
    /// a kept one keeps them, the routing table and the firewall rules are rebuilt.
    pub fn set_peers(&mut self, peers: Vec<PeerConfig>) {
        self.routes.clear();
        self.rules.clear();
        for config in &peers {
            for address in &config.addresses {
                self.routes.insert(*address, config.public_key);
            }
            self.rules
                .insert(config.public_key, config.allow_inbound.clone());
        }
        let keep: Vec<PublicKey> = peers.iter().map(|c| c.public_key).collect();
        self.retain(false, &keep);
        for config in peers {
            self.insert(config.public_key, false, config.endpoints);
        }
    }

    /// Replaces the lighthouse list (§13.1; v0 configures at most one).
    pub fn set_lighthouses(&mut self, lighthouses: Vec<LighthouseConfig>) {
        let keep: Vec<PublicKey> = lighthouses.iter().map(|l| l.public_key).collect();
        self.retain(true, &keep);
        for l in lighthouses {
            self.insert(l.public_key, true, vec![l.endpoint]);
        }
    }

    /// A lighthouse's peer list: keys only (ADR 0012).
    pub fn set_lighthouse_peers(&mut self, peers: Vec<PublicKey>) {
        self.set_peers(
            peers
                .into_iter()
                .map(|public_key| PeerConfig {
                    public_key,
                    ..PeerConfig::default()
                })
                .collect(),
        );
    }

    fn retain(&mut self, lighthouse: bool, keep: &[PublicKey]) {
        let gone: Vec<PublicKey> = self
            .links
            .iter()
            .filter(|(k, l)| l.lighthouse == lighthouse && !keep.contains(k))
            .map(|(k, _)| *k)
            .collect();
        for key in gone {
            if let Some(mut peer) = self.peers.remove(&key) {
                peer.forget(&mut self.indices);
            }
            self.links.remove(&key);
        }
    }

    fn insert(&mut self, key: PublicKey, lighthouse: bool, statics: Vec<Endpoint>) {
        self.peers.entry(key).or_insert_with(|| Peer::new(key));
        let link = self.links.entry(key).or_default();
        link.lighthouse = lighthouse;
        link.statics = statics;
    }

    /// This host's local endpoints (§13.1), collected by the IO layer: compared at the next
    /// lighthouse keepalive tick (§12.5 rule 3) and sent in `lighthouse_register`.
    pub fn set_local_endpoints(&mut self, mut endpoints: Vec<Endpoint>) {
        endpoints.sort();
        endpoints.dedup();
        endpoints.truncate(MAX_LOCAL_ENDPOINTS);
        self.locals = endpoints;
    }

    pub fn status(&self, peer: &PublicKey) -> Option<PeerStatus> {
        let (p, link) = (self.peers.get(peer)?, self.links.get(peer)?);
        Some(PeerStatus {
            sessions: p.sessions().count(),
            handshake_in_flight: p.has_in_flight_handshake(),
            staged_packets: p.staged_packets(),
            current: p.current().is_some(),
            last_handshake: p.last_handshake,
            last_received: link.last_received,
            endpoint: link.endpoint,
            last_direct_path_failure: link.failure,
            counters: p.counters,
        })
    }

    /// The lighthouse's unexpired registrations, by key (empty for a node).
    pub fn registrations(&self, now: Duration) -> Vec<(PublicKey, Registration)> {
        self.registry
            .as_ref()
            .map_or_else(Vec::new, |r| r.entries(now))
    }

    pub fn lighthouse_counters(&self) -> LighthouseCounters {
        self.registry
            .as_ref()
            .map_or_else(LighthouseCounters::default, |r| r.counters)
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
        self.firewall.outbound(now, packet);
        let peer = self.peers.get_mut(&key).expect("routes point at peers");
        // §12.5 rule 1, before send_ip initiates.
        let rediscover = !peer.can_send(now);
        let mut sends: Vec<Send> = peer
            .send_ip(&mut ctx!(self, now, wall), packet)
            .into_iter()
            .map(|d| (key, None, d))
            .collect();
        if rediscover {
            self.rediscover(now, wall, key, false, &mut sends);
        }
        Ok(Output {
            datagrams: self.route(sends),
            ..Output::default()
        })
    }

    /// §5.6, then §7.6, §7.7 or §8.2 and §10, §11 inbound. `from` is the datagram's UDP
    /// source (§12.4). `Err` is the silent drop of §16; a rejected inner content is
    /// `Output::dropped`, with the transport effects kept.
    pub fn handle_datagram(
        &mut self,
        now: Duration,
        wall: Tai64n,
        from: Endpoint,
        datagram: &[u8],
    ) -> Result<Output, DropReason> {
        let mut sends = Vec::new();
        let mut output = self.receive(now, wall, from, datagram, &mut sends)?;
        if let Some(key) = output.from {
            let peer = self
                .peers
                .get_mut(&key)
                .expect("authenticated parties are listed");
            peer.counters.rx_packets += 1;
            peer.counters.rx_bytes += datagram.len() as u64;
            let link = self.links.get_mut(&key).expect("links follow peers");
            if link.register_due && peer.can_send(now) {
                self.register(now, wall, key, &mut sends);
            }
        }
        output.datagrams = self.route(sends);
        Ok(output)
    }

    fn receive(
        &mut self,
        now: Duration,
        wall: Tai64n,
        from: Endpoint,
        datagram: &[u8],
        sends: &mut Vec<Send>,
    ) -> Result<Output, DropReason> {
        let mut output = Output::default();
        let mut ctx = ctx!(self, now, wall);
        let (key, plaintext, before) = match wire::parse(datagram)? {
            Outer::HandshakeInit(init) => {
                init.verify_mac1(&self.mac1)?;
                let pending = handshake::read_init(&self.key, &init, &Listed(&self.peers))?;
                let key = pending.initiator_static;
                let peer = self.peers.get_mut(&key).expect("verify checked the list");
                let before = peer.last_handshake;
                sends.push((key, None, peer.accept_init(&mut ctx, pending)?));
                (key, None, before)
            }
            Outer::HandshakeResp(resp) => {
                resp.verify_mac1(&self.mac1)?;
                let key = *ctx
                    .indices
                    .owner(resp.receiver_index)
                    .ok_or(DropReason::UnknownIndex)?;
                let peer = self.peers.get_mut(&key).expect("indices point at peers");
                let before = peer.last_handshake;
                let out = peer.handle_resp(&mut ctx, &resp)?;
                sends.extend(out.into_iter().map(|d| (key, None, d)));
                (key, None, before)
            }
            Outer::Data(data) => {
                let key = *ctx
                    .indices
                    .owner(data.receiver_index)
                    .ok_or(DropReason::UnknownIndex)?;
                let peer = self.peers.get_mut(&key).expect("indices point at peers");
                let before = peer.last_handshake;
                let (plaintext, out) = match peer.handle_data(&mut ctx, &data) {
                    Err(DropReason::CounterRejected) => {
                        peer.counters.replay_rejections += 1;
                        return Err(DropReason::CounterRejected);
                    }
                    result => result?,
                };
                sends.extend(out.into_iter().map(|d| (key, None, d)));
                (key, Some(plaintext), before)
            }
        };
        output.from = Some(key);
        // §12.4: an authenticated packet received directly moves the endpoint.
        let link = self.links.get_mut(&key).expect("links follow peers");
        link.endpoint = Some(from);
        link.last_received = Some(now);
        link.received_since_register = true;
        if self.peers[&key].last_handshake != before {
            link.end_discovery();
            link.register_due = link.lighthouse;
        }
        let Some(plaintext) = plaintext else {
            return Ok(output);
        };
        match self.accept_inner(now, wall, key, from, &plaintext, sends) {
            Ok(packet) => output.packets.extend(packet),
            Err(reason) => output.dropped = Some(reason),
        }
        Ok(output)
    }

    /// §10.2: what this role accepts from `key`, and its processing.
    fn accept_inner(
        &mut self,
        now: Duration,
        wall: Tai64n,
        key: PublicKey,
        from: Endpoint,
        plaintext: &[u8],
        sends: &mut Vec<Send>,
    ) -> Result<Option<Vec<u8>>, DropReason> {
        let lighthouse_role = self.registry.is_some();
        let from_lighthouse = self.links[&key].lighthouse;
        match Inner::decode(plaintext)? {
            Inner::Keepalive => Ok(None),
            Inner::IpPacket(packet) if !lighthouse_role && !from_lighthouse => {
                match ip_addresses(packet) {
                    None => Err(DropReason::InnerMalformed),
                    Some((_, destination)) if !is_unicast(destination) => {
                        Err(DropReason::NotUnicast)
                    }
                    Some((source, _)) if self.routes.get(&source) != Some(&key) => {
                        Err(DropReason::SourceNotPeer)
                    }
                    Some(_) if !self.firewall.inbound(now, &self.rules[&key], packet) => {
                        let peer = self.peers.get_mut(&key).expect("routes point at peers");
                        peer.counters.firewall_drops += 1;
                        Err(DropReason::Firewall)
                    }
                    Some(_) => Ok(Some(packet.to_vec())),
                }
            }
            Inner::LighthouseRegister { endpoints } if lighthouse_role => {
                let registry = self.registry.as_mut().expect("lighthouse role");
                registry.register(key, from, endpoints, now);
                Ok(None)
            }
            Inner::LighthouseQuery { pubkey } if lighthouse_role => {
                self.answer_query(now, wall, key, from, pubkey, sends);
                Ok(None)
            }
            Inner::LighthouseQueryReply {
                pubkey, endpoints, ..
            } if from_lighthouse => self.learn(now, wall, pubkey, &endpoints, false, sends),
            Inner::LighthousePunch { pubkey, endpoints } if from_lighthouse => {
                self.learn(now, wall, pubkey, &endpoints, true, sends)
            }
            _ => Err(DropReason::NotAccepted),
        }
    }

    /// §13.2 steps 1 to 3, as the lighthouse.
    fn answer_query(
        &mut self,
        now: Duration,
        wall: Tai64n,
        querier: PublicKey,
        source: Endpoint,
        target: PublicKey,
        sends: &mut Vec<Send>,
    ) {
        let registry = self.registry.as_mut().expect("lighthouse role");
        let entry = registry
            .lookup(&target, now)
            .filter(|_| self.peers.contains_key(&target))
            .cloned();
        let reply = match &entry {
            None => {
                registry.counters.queries_unknown += 1;
                Inner::LighthouseQueryReply {
                    pubkey: target,
                    endpoints: Vec::new(),
                    last_seen: None,
                }
            }
            Some(e) => {
                registry.counters.queries_known += 1;
                let age = now.saturating_sub(e.refreshed).as_secs();
                Inner::LighthouseQueryReply {
                    pubkey: target,
                    endpoints: e.endpoints(),
                    last_seen: Some(u32::try_from(age).unwrap_or(u32::MAX)),
                }
            }
        };
        let mut punch_to = vec![source];
        if let Some(own) = registry.lookup(&querier, now) {
            punch_to.extend(own.locals.iter().filter(|e| **e != source));
        }
        let mut ctx = ctx!(self, now, wall);
        let peer = self.peers.get_mut(&querier).expect("authenticated");
        let out = peer.send_inner(&mut ctx, &reply.encode());
        sends.extend(out.into_iter().map(|d| (querier, None, d)));
        if entry.is_none() || target == querier {
            return;
        }
        let peer = self.peers.get_mut(&target).expect("listed");
        let punch = Inner::LighthousePunch {
            pubkey: querier,
            endpoints: punch_to,
        };
        let out = peer.send_inner(&mut ctx, &punch.encode());
        if !out.is_empty() {
            let registry = self.registry.as_mut().expect("lighthouse role");
            registry.counters.punches += 1;
        }
        sends.extend(out.into_iter().map(|d| (target, None, d)));
    }

    /// §12.2 and §13.3 on a node: endpoints for `target` from a lighthouse answer or punch.
    fn learn(
        &mut self,
        now: Duration,
        wall: Tai64n,
        target: PublicKey,
        endpoints: &[Endpoint],
        punch: bool,
        sends: &mut Vec<Send>,
    ) -> Result<Option<Vec<u8>>, DropReason> {
        // A lighthouse cannot make a node talk to a key it does not list (§13.3).
        let link = self
            .links
            .get_mut(&target)
            .filter(|l| !l.lighthouse)
            .ok_or(DropReason::NotAccepted)?;
        if endpoints.is_empty() {
            link.unknown = true;
            return Ok(None);
        }
        let known = link.candidates();
        let new: Vec<Endpoint> = endpoints
            .iter()
            .filter(|e| !known.contains(e))
            .copied()
            .collect();
        link.learnt.extend(&new);
        let excess = link.learnt.len().saturating_sub(MAX_CANDIDATES);
        link.learnt.drain(..excess);
        if punch && link.discovery.is_none() {
            link.discovery = Some(now);
        }
        let peer = self.peers.get_mut(&target).expect("links follow peers");
        if peer.has_in_flight_handshake() {
            // §13.3: send now to the punch's endpoints, which opens this node's NAT.
            let to = if punch { endpoints.to_vec() } else { new };
            if let Some(m1) = &link.message_1 {
                sends.extend(to.into_iter().map(|e| (target, Some(e), m1.clone())));
            }
        } else if punch || !peer.can_send(now) {
            let out = peer.start_handshake(&mut ctx!(self, now, wall));
            sends.extend(out.map(|d| (target, None, d)));
        }
        Ok(None)
    }

    /// §12.5: queries every lighthouse with a live session (once per rediscovery) and, when
    /// `handshake`, starts an attempt sequence towards the candidates.
    fn rediscover(
        &mut self,
        now: Duration,
        wall: Tai64n,
        target: PublicKey,
        handshake: bool,
        sends: &mut Vec<Send>,
    ) {
        let link = self.links.get_mut(&target).expect("links follow peers");
        if link.discovery.is_none() {
            link.discovery = Some(now);
            link.unknown = false;
            let query = Inner::LighthouseQuery { pubkey: target }.encode();
            let lighthouses: Vec<PublicKey> = self
                .links
                .iter()
                .filter(|(_, l)| l.lighthouse)
                .map(|(k, _)| *k)
                .collect();
            for lh in lighthouses {
                let peer = self.peers.get_mut(&lh).expect("links follow peers");
                let out = peer.send_inner(&mut ctx!(self, now, wall), &query);
                sends.extend(out.into_iter().map(|d| (lh, None, d)));
            }
        }
        if handshake {
            let peer = self.peers.get_mut(&target).expect("links follow peers");
            let out = peer.start_handshake(&mut ctx!(self, now, wall));
            sends.extend(out.map(|d| (target, None, d)));
        }
    }

    /// §13.1: `lighthouse_register` with the current local endpoints, on `current`.
    fn register(&mut self, now: Duration, wall: Tai64n, lh: PublicKey, sends: &mut Vec<Send>) {
        let inner = Inner::LighthouseRegister {
            endpoints: self.locals.clone(),
        }
        .encode();
        let peer = self.peers.get_mut(&lh).expect("links follow peers");
        let out = peer.send_inner(&mut ctx!(self, now, wall), &inner);
        if !out.is_empty() {
            let link = self.links.get_mut(&lh).expect("links follow peers");
            link.register_due = false;
            link.received_since_register = false;
            link.registered = Some(self.locals.clone());
        }
        sends.extend(out.into_iter().map(|d| (lh, None, d)));
    }

    /// Runs every deadline that has passed (§9, §12.5, §13).
    pub fn tick(&mut self, now: Duration, wall: Tai64n) -> Output {
        let mut sends = Vec::new();
        let mut rediscover_all = false;
        let keys: Vec<PublicKey> = self.peers.keys().copied().collect();
        for key in &keys {
            let key = *key;
            let peer = self.peers.get_mut(&key).expect("listed");
            let link = self.links.get_mut(&key).expect("links follow peers");
            if link.lighthouse {
                // §9 last row: the lighthouse session is permanent.
                if !peer.can_send(now) && !peer.has_in_flight_handshake() {
                    let out = peer.start_handshake(&mut ctx!(self, now, wall));
                    sends.extend(out.map(|d| (key, None, d)));
                }
                let peer = self.peers.get_mut(&key).expect("listed");
                if peer.persistent_keepalive_at().is_some_and(|t| t <= now) {
                    // §13.1: a register instead of the keepalive; §9 failed keepalives.
                    let link = self.links.get_mut(&key).expect("links follow peers");
                    if link.received_since_register {
                        link.failed_keepalives = 0;
                    } else {
                        link.failed_keepalives += 1;
                    }
                    let moved = link.registered.as_ref().is_some_and(|r| *r != self.locals);
                    let failed = link.failed_keepalives >= KEEPALIVE_FAILURES_BEFORE_REREGISTER;
                    self.register(now, wall, key, &mut sends);
                    if failed {
                        // §12.5 rule 4: re-handshake, re-register on completion, rediscover.
                        let link = self.links.get_mut(&key).expect("links follow peers");
                        link.failed_keepalives = 0;
                        let peer = self.peers.get_mut(&key).expect("listed");
                        let out = peer.start_handshake(&mut ctx!(self, now, wall));
                        sends.extend(out.map(|d| (key, None, d)));
                    }
                    rediscover_all |= moved || failed;
                }
            }
            let peer = self.peers.get_mut(&key).expect("listed");
            let (attempts, timeouts) =
                (peer.in_flight_attempts(), peer.counters.handshake_timeouts);
            let out = peer.tick(&mut ctx!(self, now, wall));
            sends.extend(out.into_iter().map(|d| (key, None, d)));
            let peer = &self.peers[&key];
            let link = self.links.get_mut(&key).expect("links follow peers");
            if peer.counters.handshake_timeouts != timeouts {
                link.end_discovery();
                link.failure = Some(PathFailure::Abandoned);
            }
            let first_timeout = attempts == Some(1) && peer.in_flight_attempts() == Some(2);
            if first_timeout && !link.lighthouse {
                // §12.5 rule 2.
                self.rediscover(now, wall, key, false, &mut sends);
            }
            let link = self.links.get_mut(&key).expect("links follow peers");
            if link
                .discovery
                .is_some_and(|start| now >= start + DIRECT_PATH_TIMEOUT)
            {
                link.failure = Some(if link.unknown && link.learnt.is_empty() {
                    PathFailure::LighthouseUnknown
                } else if link.candidates().is_empty() {
                    PathFailure::NoCandidates
                } else {
                    PathFailure::Timeout
                });
                link.end_discovery();
            }
        }
        if rediscover_all {
            // §12.5 rules 3 and 4: every peer with a live session.
            for key in keys {
                let live = self.peers[&key].can_send(now);
                if live && !self.links[&key].lighthouse {
                    self.rediscover(now, wall, key, true, &mut sends);
                }
            }
        }
        if let Some(registry) = &mut self.registry {
            let peers = &self.peers;
            registry.expire(now, |k| peers.contains_key(k));
        }
        Output {
            datagrams: self.route(sends),
            ..Output::default()
        }
    }

    /// §12.2: message 1 goes to every candidate, everything else to the endpoint. Counts
    /// what leaves (§12.6).
    fn route(&mut self, sends: Vec<Send>) -> Vec<(Endpoint, Vec<u8>)> {
        let mut out = Vec::with_capacity(sends.len());
        for (key, to, datagram) in sends {
            let (Some(link), Some(peer)) = (self.links.get_mut(&key), self.peers.get_mut(&key))
            else {
                continue;
            };
            let targets = match to {
                Some(e) => vec![e],
                None if datagram.first() == Some(&wire::TYPE_HANDSHAKE_INIT) => {
                    link.message_1 = Some(datagram.clone());
                    link.candidates()
                }
                None => link.endpoint.into_iter().collect(),
            };
            for e in targets {
                peer.counters.tx_packets += 1;
                peer.counters.tx_bytes += datagram.len() as u64;
                out.push((e, datagram.clone()));
            }
        }
        out
    }

    /// The earliest pending deadline over every peer (§9, §12.5, §13).
    pub fn next_deadline(&self) -> Option<Duration> {
        let mut next = self.peers.values().filter_map(Peer::next_deadline).min();
        for (key, link) in &self.links {
            let peer = &self.peers[key];
            let discovery = link.discovery.map(|s| s + DIRECT_PATH_TIMEOUT);
            let retry =
                (link.lighthouse && peer.current().is_none() && !peer.has_in_flight_handshake())
                    .then(|| {
                        peer.last_init_sent()
                            .map_or(Duration::ZERO, |t| t + REKEY_TIMEOUT)
                    });
            next = [next, discovery, retry].into_iter().flatten().min();
        }
        next
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
