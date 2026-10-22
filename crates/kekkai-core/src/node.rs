//! The party-level driver (ADR 0004): datagrams, tunnel packets and the two clocks in;
//! datagrams, tunnel packets and the next deadline out. It owns the peer map (a replaceable
//! value), the index table (§7.5), the routing table (§11), the identity list (§4) and, per
//! peer, the endpoint, candidates and session paths of §12. A party is a node, a lighthouse
//! ([`Node::lighthouse`], §13.2) or a relay ([`Node::relay`], §14.2).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::firewall::{Firewall, FirewallStatus, Rule};
use crate::handshake::{self, Identity};
use crate::inner::{Endpoint, Inner};
use crate::keys::{PublicKey, StaticKey};
use crate::lighthouse::{LighthouseCounters, Registration, Registry};
use crate::mac1::Mac1Key;
use crate::peer::{Counters, Ctx, IndexTable, Peer};
use crate::relay::{Forwarder, SenderCounters};
use crate::tai64n::Tai64n;
use crate::tlv::Tlv;
use crate::wire::{self, DropReason, Outer};
use crate::{
    DIRECT_PATH_TIMEOUT, DIRECT_RETRY_INTERVAL, KEEPALIVE_FAILURES_BEFORE_REREGISTER,
    MAX_CANDIDATES, MAX_LOCAL_ENDPOINTS, MTU, PERSISTENT_KEEPALIVE, REKEY_TIMEOUT,
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

/// One `[[lighthouses]]` entry (§13.1): the node keeps a permanent session with it. Every
/// address its endpoint resolved to is a candidate; none while it is unresolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LighthouseConfig {
    pub public_key: PublicKey,
    pub endpoints: Vec<Endpoint>,
}

/// One `[[relays]]` entry (§14.1): the same shape, a permanent session too.
pub type RelayConfig = LighthouseConfig;

/// How a datagram reached or leaves this party (§12.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    /// To or from the peer's endpoint.
    Direct(Endpoint),
    /// Inside `relay_forward` to or `relay_forwarded` from this relay.
    Relayed(PublicKey),
}

/// What a configured party is to this node (§10.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Role {
    #[default]
    Peer,
    Lighthouse,
    Relay,
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
    /// The `current` session's path (§12.1); `None` without one.
    pub path: Option<Path>,
    pub last_handshake: Option<Duration>,
    /// Last authenticated packet received from the peer (§12.4).
    pub last_received: Option<Duration>,
    /// Where direct traffic goes (§12.1), learnt from authenticated packets only.
    pub endpoint: Option<Endpoint>,
    pub last_direct_path_failure: Option<PathFailure>,
    pub counters: Counters,
    /// The `current` session's local index (§7.5): what the peer puts in `receiver_index`.
    /// Kept across a reload that keeps the peer (§4).
    pub current_index: Option<u32>,
}

/// §12 state of one configured party, beside its [`Peer`].
#[derive(Default)]
struct Link {
    role: Role,
    statics: Vec<Endpoint>,
    endpoint: Option<Endpoint>,
    /// Local indices of the sessions whose last authenticated packet came through a relay
    /// (§12.4); the others are direct.
    relayed: HashMap<u32, PublicKey>,
    /// The attempt sequence also goes through a relay (§12.3), until it ends.
    via_relay: bool,
    /// Next direct retry while `current` is relayed (§12.3).
    retry_at: Option<Duration>,
    /// Admitted endpoints from lighthouse answers and punches, kept until a handshake
    /// completes or the attempt sequence is abandoned (§12.2).
    learnt: Vec<Endpoint>,
    /// The last message 1 sent, resent to candidates learnt while it is in flight (§12.2).
    message_1: Option<Vec<u8>>,
    /// Start of the running rediscovery (§12.5), until `DIRECT_PATH_TIMEOUT` or completion.
    discovery: Option<Duration>,
    /// A lighthouse answered "unknown" during the running rediscovery.
    unknown: bool,
    /// When a rediscovery or punch handshake refused by the §7.9 pacing may start.
    deferred: Option<Duration>,
    failure: Option<PathFailure>,
    last_received: Option<Duration>,
    // Towards a lighthouse (§9, §13.1).
    /// The register timer; armed by the first register.
    register_at: Option<Duration>,
    received_since_register: bool,
    failed_keepalives: u32,
    /// Local endpoints of the last register sent; `None` before the first one.
    registered: Option<Vec<Endpoint>>,
    /// A handshake completed: register as soon as `current` can send.
    register_due: bool,
}

impl Link {
    /// §12.2: statics, the last known endpoint, the learnt ones; deduplicated, bounded (§17).
    /// The admitted learnt ones keep their room when the statics are replaced.
    fn candidates(&self) -> Vec<Endpoint> {
        let room = MAX_CANDIDATES.saturating_sub(self.learnt.len());
        let mut all: Vec<Endpoint> = Vec::new();
        for e in self.statics.iter().chain(&self.endpoint) {
            if !all.contains(e) && all.len() < room {
                all.push(*e);
            }
        }
        for e in &self.learnt {
            if !all.contains(e) {
                all.push(*e);
            }
        }
        all
    }

    /// §12.2 admission: appends the endpoints of `endpoints` that are new while the set has
    /// room, and returns the candidate set.
    fn admit(&mut self, endpoints: &[Endpoint]) -> Vec<Endpoint> {
        let mut all = self.candidates();
        for e in endpoints {
            if !all.contains(e) && all.len() < MAX_CANDIDATES {
                all.push(*e);
                self.learnt.push(*e);
            }
        }
        all
    }

    /// End of the rediscovery window (§12.5); the learnt candidates stay (§12.2).
    fn end_discovery(&mut self) {
        self.discovery = None;
        self.unknown = false;
    }

    /// A handshake completed or the attempt sequence was abandoned (§7.9, §12.2).
    fn end_attempts(&mut self) {
        self.end_discovery();
        self.learnt.clear();
        self.deferred = None;
        self.via_relay = false;
    }

    /// §12.1: the path of `peer`'s `current` session, `None` without one.
    fn path(&self, peer: &Peer) -> Option<Path> {
        let current = peer.current()?;
        match self.relayed.get(&current.local_index) {
            Some(relay) => Some(Path::Relayed(*relay)),
            None => self.endpoint.map(Path::Direct),
        }
    }
}

/// A datagram waiting for its destination: `None` routes it by the peer's state (§12.2).
type Send = (PublicKey, Option<Path>, Vec<u8>);

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
    /// `Some` for a relay (§14.2).
    forwarder: Option<Forwarder>,
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
            forwarder: None,
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

    /// A relay (§14.2): handshakes with the listed keys and forwards their `relay_forward`s
    /// to each other, at most `limit` payload bytes per second per sender when set.
    pub fn relay(key: StaticKey, peers: Vec<PublicKey>, limit: Option<u64>) -> Self {
        let mut node = Self::new(key, Vec::new());
        node.forwarder = Some(Forwarder::new(limit));
        node.set_lighthouse_peers(peers);
        node
    }

    /// A lighthouse or a relay: answers its listed keys, routes no IP packet (§10.2).
    fn serves(&self) -> bool {
        self.registry.is_some() || self.forwarder.is_some()
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

    /// Replaces the peer list (ADR 0004, 0016, spec §4.1): a removed peer loses its sessions
    /// (§8.5), a kept one keeps them, the routing table and the firewall rules are rebuilt,
    /// and the firewall entries of an address that left the table or changed peer go (§15).
    pub fn set_peers(&mut self, peers: Vec<PeerConfig>) {
        let old = std::mem::take(&mut self.routes);
        self.rules.clear();
        for config in &peers {
            for address in &config.addresses {
                self.routes.insert(*address, config.public_key);
            }
            self.rules
                .insert(config.public_key, config.allow_inbound.clone());
        }
        let routes = &self.routes;
        self.firewall.forget(|ip| old.get(ip) != routes.get(ip));
        // §4.1: a kept peer that lost an address may hold staged packets for it.
        for (ip, key) in &old {
            if routes.get(ip) != Some(key) {
                if let Some(peer) = self.peers.get_mut(key) {
                    peer.drop_staged();
                }
            }
        }
        let keep: Vec<PublicKey> = peers.iter().map(|c| c.public_key).collect();
        self.retain(Role::Peer, &keep);
        for config in peers {
            self.insert(config.public_key, Role::Peer, config.endpoints);
        }
    }

    /// Replaces the lighthouse list (§13.1; v0 configures at most one).
    pub fn set_lighthouses(&mut self, lighthouses: Vec<LighthouseConfig>) {
        self.set_services(Role::Lighthouse, lighthouses);
    }

    /// Replaces the relay list (§14.1; v0 configures at most one).
    pub fn set_relays(&mut self, relays: Vec<RelayConfig>) {
        self.set_services(Role::Relay, relays);
    }

    fn set_services(&mut self, role: Role, configs: Vec<LighthouseConfig>) {
        let keep: Vec<PublicKey> = configs.iter().map(|l| l.public_key).collect();
        self.retain(role, &keep);
        for l in configs {
            self.insert(l.public_key, role, l.endpoints);
        }
    }

    /// A lighthouse's or relay's peer list: keys only (ADR 0012, 0014).
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

    fn retain(&mut self, role: Role, keep: &[PublicKey]) {
        let gone: Vec<PublicKey> = self
            .links
            .iter()
            .filter(|(k, l)| l.role == role && !keep.contains(k))
            .map(|(k, _)| *k)
            .collect();
        for key in gone {
            self.remove(&key);
        }
    }

    /// §4.1: the party's sessions, indices, handshake, staged packets and §12 state go
    /// (keys erased, §8.5), and so do its registration or relay sender state (§13.2, §14.2).
    fn remove(&mut self, key: &PublicKey) {
        if let Some(mut peer) = self.peers.remove(key) {
            peer.forget(&mut self.indices);
        }
        let was_relay = self
            .links
            .remove(key)
            .is_some_and(|l| l.role == Role::Relay);
        if was_relay {
            // §4.1: a session relayed by this key loses its path; the direct retry of §12.3
            // starts at the next tick instead of `DIRECT_RETRY_INTERVAL` later.
            for (k, link) in &mut self.links {
                let orphaned = (self.peers.get(k).and_then(Peer::current))
                    .is_some_and(|s| link.relayed.get(&s.local_index) == Some(key));
                if orphaned {
                    link.retry_at = Some(Duration::ZERO);
                }
            }
        }
        if let Some(registry) = &mut self.registry {
            registry.forget(key);
        }
        if let Some(forwarder) = &mut self.forwarder {
            forwarder.senders.remove(key);
        }
    }

    fn insert(&mut self, key: PublicKey, role: Role, statics: Vec<Endpoint>) {
        // §4.1: a key that changes role (peer, lighthouse, relay) starts afresh.
        if self.links.get(&key).is_some_and(|l| l.role != role) {
            self.remove(&key);
        }
        self.peers.entry(key).or_insert_with(|| Peer::new(key));
        let link = self.links.entry(key).or_default();
        link.role = role;
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
            path: link.path(p),
            last_handshake: p.last_handshake,
            last_received: link.last_received,
            endpoint: link.endpoint,
            last_direct_path_failure: link.failure,
            counters: p.counters,
            current_index: p.current().map(|s| s.local_index),
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

    /// The relay's per-sender counters, by key, listed keys only (empty for a node).
    pub fn relay_senders(&self) -> Vec<(PublicKey, SenderCounters)> {
        let Some(f) = &self.forwarder else {
            return Vec::new();
        };
        let mut all: Vec<_> = self
            .peers
            .keys()
            .map(|k| (*k, f.senders.get(k).map(|s| s.0).unwrap_or_default()))
            .collect();
        all.sort_by_key(|e| e.0);
        all
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
        // §12.5 rule 1, before send_ip stages and initiates (§8.7).
        let rediscover = !peer.can_send(now);
        let mut sends: Vec<Send> = peer
            .send_ip(&mut ctx!(self, now, wall), packet)
            .into_iter()
            .map(|d| (key, None, d))
            .collect();
        if rediscover {
            // §7.9: a handshake send_ip could not start under the pacing is deferred.
            self.rediscover(now, wall, key, true, &mut sends);
        }
        Ok(Output {
            datagrams: self.route(now, wall, sends),
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
        let mut output = self.receive(now, wall, Path::Direct(from), None, datagram, &mut sends)?;
        if let Some(key) = output.from {
            let peer = self
                .peers
                .get_mut(&key)
                .expect("authenticated parties are listed");
            peer.counters.rx_packets += 1;
            peer.counters.rx_bytes += datagram.len() as u64;
            let link = self.links.get_mut(&key).expect("links follow peers");
            // §13.1 after a handshake with the lighthouse, which may be how a move shows.
            if link.register_due && peer.can_send(now) && self.register(now, wall, key, &mut sends)
            {
                self.rediscover_live(now, wall, &mut sends);
            }
        }
        output.datagrams = self.route(now, wall, sends);
        Ok(output)
    }

    /// §5.6 onwards for a datagram that arrived on `via`. `claimed` is the sender named by a
    /// `relay_forwarded` (§14.1): the datagram must authenticate as that peer, checked before
    /// any state changes.
    fn receive(
        &mut self,
        now: Duration,
        wall: Tai64n,
        via: Path,
        claimed: Option<PublicKey>,
        datagram: &[u8],
        sends: &mut Vec<Send>,
    ) -> Result<Output, DropReason> {
        let mut output = Output::default();
        let mut ctx = ctx!(self, now, wall);
        let claim = |key: PublicKey| match claimed {
            Some(c) if c != key => Err(DropReason::NotAccepted),
            _ => Ok(()),
        };
        // `completed`: the attempt sequence ends (§7.9): its own response, or a confirmed
        // responder session (§8.2 step 5); accepting a message 1 alone does not end it.
        let (key, index, plaintext, before, completed) = match wire::parse(datagram)? {
            Outer::HandshakeInit(init) => {
                init.verify_mac1(&self.mac1)?;
                let pending = handshake::read_init(&self.key, &init, &Listed(&self.peers))?;
                let key = pending.initiator_static;
                claim(key)?;
                let peer = self.peers.get_mut(&key).expect("verify checked the list");
                let before = peer.last_handshake;
                let response = peer.accept_init(&mut ctx, pending)?;
                // §5.2: the responder's sender index is its new session's local index.
                let index = u32::from_be_bytes(response[4..8].try_into().expect("message 2"));
                // §12.2: message 2 goes back the way the accepted copy came.
                sends.push((key, Some(via), response));
                (key, index, None, before, false)
            }
            Outer::HandshakeResp(resp) => {
                resp.verify_mac1(&self.mac1)?;
                let key = *ctx
                    .indices
                    .owner(resp.receiver_index)
                    .ok_or(DropReason::UnknownIndex)?;
                claim(key)?;
                let peer = self.peers.get_mut(&key).expect("indices point at peers");
                let before = peer.last_handshake;
                let out = peer.handle_resp(&mut ctx, &resp)?;
                sends.extend(out.into_iter().map(|d| (key, None, d)));
                (key, resp.receiver_index, None, before, true)
            }
            Outer::Data(data) => {
                let key = *ctx
                    .indices
                    .owner(data.receiver_index)
                    .ok_or(DropReason::UnknownIndex)?;
                claim(key)?;
                let peer = self.peers.get_mut(&key).expect("indices point at peers");
                let before = peer.last_handshake;
                let current = peer.current().map(|s| s.local_index);
                let (plaintext, out) = match peer.handle_data(&mut ctx, &data) {
                    Err(DropReason::CounterRejected) => {
                        peer.counters.replay_rejections += 1;
                        return Err(DropReason::CounterRejected);
                    }
                    result => result?,
                };
                sends.extend(out.into_iter().map(|d| (key, None, d)));
                // Only step 5 replaces `current`; expiry can only empty it.
                let confirmed = peer
                    .current()
                    .is_some_and(|s| Some(s.local_index) != current);
                (key, data.receiver_index, Some(plaintext), before, confirmed)
            }
        };
        output.from = Some(key);
        // §12.4: the session's path follows its authenticated packets; `sends` are routed
        // after this, so what the handling produced follows the new path.
        let link = self.links.get_mut(&key).expect("links follow peers");
        match via {
            Path::Direct(_) => link.relayed.remove(&index),
            Path::Relayed(relay) => link.relayed.insert(index, relay),
        };
        let live: Vec<u32> = self.peers[&key].sessions().map(|s| s.local_index).collect();
        link.relayed.retain(|i, _| live.contains(i));
        if let Path::Direct(from) = via {
            // §12.4: an authenticated packet received directly moves the endpoint; one that
            // came through a relay never does.
            link.endpoint = Some(from);
            if let Some(registry) = &mut self.registry {
                registry.observe(&key, from);
            }
        }
        link.last_received = Some(now);
        link.received_since_register = true;
        if completed {
            link.end_attempts();
        }
        if self.peers[&key].last_handshake != before {
            link.register_due = link.role == Role::Lighthouse;
        }
        let Some(plaintext) = plaintext else {
            return Ok(output);
        };
        match self.accept_inner(now, wall, key, via, &plaintext, sends) {
            Ok(packets) => output.packets.extend(packets),
            Err(reason) => output.dropped = Some(reason),
        }
        Ok(output)
    }

    /// §10.2: what this role accepts from `key` on `via`, and its processing. Returns the IP
    /// packets to deliver.
    fn accept_inner(
        &mut self,
        now: Duration,
        wall: Tai64n,
        key: PublicKey,
        via: Path,
        plaintext: &[u8],
        sends: &mut Vec<Send>,
    ) -> Result<Vec<Vec<u8>>, DropReason> {
        let lighthouse_role = self.registry.is_some();
        let role = self.links[&key].role;
        let direct = match via {
            Path::Direct(from) => Some(from),
            Path::Relayed(_) => None,
        };
        match Inner::decode(plaintext)? {
            Inner::Keepalive => Ok(Vec::new()),
            Inner::IpPacket(packet) if !self.serves() && role == Role::Peer => {
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
                    Some(_) => Ok(vec![packet.to_vec()]),
                }
            }
            Inner::LighthouseRegister { endpoints } if lighthouse_role && direct.is_some() => {
                // §13.1: invalid entries are removed silently, the register stands.
                let endpoints = endpoints
                    .into_iter()
                    .filter(|e| sendable(e, &self.locals))
                    .collect();
                let registry = self.registry.as_mut().expect("lighthouse role");
                let from = direct.expect("checked");
                registry.register(key, from, endpoints, now);
                Ok(Vec::new())
            }
            Inner::LighthouseQuery { pubkey } if lighthouse_role && direct.is_some() => {
                let from = direct.expect("checked");
                self.answer_query(now, wall, key, from, pubkey, sends)?;
                Ok(Vec::new())
            }
            Inner::LighthouseQueryReply {
                pubkey, endpoints, ..
            } if role == Role::Lighthouse => {
                self.learn(now, wall, pubkey, &endpoints, false, sends)?;
                Ok(Vec::new())
            }
            Inner::LighthousePunch { pubkey, endpoints } if role == Role::Lighthouse => {
                self.learn(now, wall, pubkey, &endpoints, true, sends)?;
                Ok(Vec::new())
            }
            Inner::RelayForward { to, payload } if self.forwarder.is_some() && direct.is_some() => {
                self.forward(now, wall, key, to, payload, sends)?;
                Ok(Vec::new())
            }
            Inner::RelayForwarded { from, payload }
                if role == Role::Relay && direct.is_some() && !self.serves() =>
            {
                // §14.1: a configured peer only, no nested relaying (the payload is processed
                // on path relayed(R), where no relay message is accepted).
                if self.links.get(&from).is_none_or(|l| l.role != Role::Peer) {
                    return Err(DropReason::NotAccepted);
                }
                let nested =
                    self.receive(now, wall, Path::Relayed(key), Some(from), payload, sends)?;
                let peer = self.peers.get_mut(&from).expect("links follow peers");
                peer.counters.rx_packets += 1;
                peer.counters.rx_bytes += payload.len() as u64;
                match nested.dropped {
                    Some(reason) => Err(reason),
                    None => Ok(nested.packets),
                }
            }
            _ => Err(DropReason::NotAccepted),
        }
    }

    /// §14.2 steps 1 to 3, as the relay: `relay_forwarded { from = sender }` towards `to`.
    fn forward(
        &mut self,
        now: Duration,
        wall: Tai64n,
        sender: PublicKey,
        to: PublicKey,
        payload: &[u8],
        sends: &mut Vec<Send>,
    ) -> Result<(), DropReason> {
        let forwarder = self.forwarder.as_mut().expect("relay role");
        if !self.peers.get(&to).is_some_and(|p| p.can_send(now)) {
            forwarder.counters(sender).dropped_no_route += 1;
            return Err(DropReason::NoRoute);
        }
        if !forwarder.admit(sender, now, payload.len()) {
            return Err(DropReason::RateLimited);
        }
        let counters = forwarder.counters(sender);
        counters.forwarded_packets += 1;
        counters.forwarded_bytes += payload.len() as u64;
        let inner = Inner::RelayForwarded {
            from: sender,
            payload,
        }
        .encode();
        let peer = self.peers.get_mut(&to).expect("checked above");
        let out = peer.send_inner(&mut ctx!(self, now, wall), &inner);
        sends.extend(out.into_iter().map(|d| (to, None, d)));
        Ok(())
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
    ) -> Result<(), DropReason> {
        let registry = self.registry.as_mut().expect("lighthouse role");
        if !registry.budget(querier, now, self.peers.len()) {
            return Err(DropReason::RateLimited);
        }
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
            return Ok(());
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
        Ok(())
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
    ) -> Result<(), DropReason> {
        let unknown = endpoints.is_empty();
        // §12.2 validity: dropped before admission; an answer with endpoints is not "unknown".
        let endpoints: Vec<Endpoint> = endpoints
            .iter()
            .filter(|e| sendable(e, &self.locals))
            .copied()
            .collect();
        // A lighthouse cannot make a node talk to a key it does not list (§13.3).
        let link = self
            .links
            .get_mut(&target)
            .filter(|l| l.role == Role::Peer)
            .ok_or(DropReason::NotAccepted)?;
        if unknown {
            link.unknown = true;
            return Ok(());
        }
        let before = link.candidates();
        let all = link.admit(&endpoints);
        // §12.2: only admitted endpoints are sent to, now as on every retransmission.
        let to: Vec<Endpoint> = endpoints
            .iter()
            .filter(|e| all.contains(e) && (punch || !before.contains(e)))
            .copied()
            .collect();
        if punch && link.discovery.is_none() {
            link.discovery = Some(now);
            link.unknown = false;
        }
        let peer = self.peers.get_mut(&target).expect("links follow peers");
        if peer.has_in_flight_handshake() {
            // §13.3: send now to the punch's endpoints, which opens this node's NAT.
            if let Some(m1) = &link.message_1 {
                let to = to
                    .into_iter()
                    .map(|e| (target, Some(Path::Direct(e)), m1.clone()));
                sends.extend(to);
            }
        } else if punch || !peer.can_send(now) {
            self.initiate(now, wall, target, sends);
        }
        Ok(())
    }

    /// §7.9 for a rediscovery or a punch: starts an attempt sequence, or defers one that
    /// the `REKEY_TIMEOUT` pacing refuses to the end of that pacing.
    fn initiate(&mut self, now: Duration, wall: Tai64n, key: PublicKey, sends: &mut Vec<Send>) {
        let peer = self.peers.get_mut(&key).expect("links follow peers");
        let out = peer.start_handshake(&mut ctx!(self, now, wall));
        let link = self.links.get_mut(&key).expect("links follow peers");
        link.deferred = match out {
            None if !peer.has_in_flight_handshake() => {
                peer.last_init_sent().map(|t| t + REKEY_TIMEOUT)
            }
            _ => None,
        };
        sends.extend(out.map(|d| (key, None, d)));
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
                .filter(|(_, l)| l.role == Role::Lighthouse)
                .map(|(k, _)| *k)
                .collect();
            for lh in lighthouses {
                let peer = self.peers.get_mut(&lh).expect("links follow peers");
                let out = peer.send_inner(&mut ctx!(self, now, wall), &query);
                sends.extend(out.into_iter().map(|d| (lh, None, d)));
            }
        }
        if handshake {
            self.initiate(now, wall, target, sends);
        }
    }

    /// §12.5 rules 3 and 4: every peer with a live session.
    fn rediscover_live(&mut self, now: Duration, wall: Tai64n, sends: &mut Vec<Send>) {
        let keys: Vec<PublicKey> = self.peers.keys().copied().collect();
        for key in keys {
            if self.peers[&key].can_send(now) && self.links[&key].role == Role::Peer {
                self.rediscover(now, wall, key, true, sends);
            }
        }
    }

    /// §13.1: `lighthouse_register` with the current local endpoints, on `current`. Returns
    /// whether they differ from the previous register's (§12.5 rule 3).
    fn register(
        &mut self,
        now: Duration,
        wall: Tai64n,
        lh: PublicKey,
        sends: &mut Vec<Send>,
    ) -> bool {
        let inner = Inner::LighthouseRegister {
            endpoints: self.locals.clone(),
        }
        .encode();
        let peer = self.peers.get_mut(&lh).expect("links follow peers");
        let out = peer.send_inner(&mut ctx!(self, now, wall), &inner);
        let mut moved = false;
        if !out.is_empty() {
            let link = self.links.get_mut(&lh).expect("links follow peers");
            link.register_at = Some(now + PERSISTENT_KEEPALIVE);
            link.register_due = false;
            link.received_since_register = false;
            moved = link.registered.as_ref().is_some_and(|r| *r != self.locals);
            link.registered = Some(self.locals.clone());
        }
        sends.extend(out.into_iter().map(|d| (lh, None, d)));
        moved
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
            if link.role != Role::Peer {
                // §9 last row: the lighthouse and relay sessions are permanent.
                if !peer.can_send(now) && !peer.has_in_flight_handshake() {
                    let out = peer.start_handshake(&mut ctx!(self, now, wall));
                    sends.extend(out.map(|d| (key, None, d)));
                }
            }
            if self.links[&key].role == Role::Lighthouse {
                let current = self.peers[&key].current().is_some();
                let link = self.links.get_mut(&key).expect("links follow peers");
                if current && link.register_at.is_some_and(|t| t <= now) {
                    // §9 register tick: failed registers, local endpoints, then the register.
                    link.register_at = Some(now + PERSISTENT_KEEPALIVE);
                    if link.received_since_register {
                        link.failed_keepalives = 0;
                    } else {
                        link.failed_keepalives += 1;
                    }
                    link.received_since_register = false;
                    let failed = link.failed_keepalives >= KEEPALIVE_FAILURES_BEFORE_REREGISTER;
                    let moved = self.register(now, wall, key, &mut sends);
                    if failed {
                        // §12.5 rule 4: re-handshake, re-register on completion, rediscover.
                        let link = self.links.get_mut(&key).expect("links follow peers");
                        link.failed_keepalives = 0;
                        self.initiate(now, wall, key, &mut sends);
                    }
                    rediscover_all |= moved || failed;
                }
            }
            if self.links[&key].deferred.is_some_and(|t| t <= now) {
                self.initiate(now, wall, key, &mut sends);
            }
            let peer = self.peers.get_mut(&key).expect("listed");
            let (attempts, timeouts) =
                (peer.in_flight_attempts(), peer.counters.handshake_timeouts);
            let out = peer.tick(&mut ctx!(self, now, wall));
            sends.extend(out.into_iter().map(|d| (key, None, d)));
            let peer = &self.peers[&key];
            let link = self.links.get_mut(&key).expect("links follow peers");
            if peer.counters.handshake_timeouts != timeouts {
                link.end_attempts();
                link.failure = Some(PathFailure::Abandoned);
            }
            let first_timeout = attempts == Some(1) && peer.in_flight_attempts() == Some(2);
            if first_timeout && link.role == Role::Peer {
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
                // §12.3: the sequence goes through the relay too, the in-flight message 1 now;
                // a fresh one queued by this tick goes through it in `route`, the cached one
                // is obsolete then.
                let fresh = sends.iter().any(|(k, to, d)| {
                    *k == key && to.is_none() && d.first() == Some(&wire::TYPE_HANDSHAKE_INIT)
                });
                if let Some(relay) = self.live_relay(now) {
                    let link = self.links.get_mut(&key).expect("links follow peers");
                    link.via_relay = true;
                    let m1 = link.message_1.clone();
                    if self.peers[&key].has_in_flight_handshake() && !fresh {
                        sends.extend(m1.map(|m1| (key, Some(Path::Relayed(relay)), m1)));
                    }
                }
            }
            // The fallback belongs to the sequence: it ends with it (completion ends it in
            // `receive`), and whenever nothing is in flight or deferred.
            let link = self.links.get_mut(&key).expect("links follow peers");
            if !self.peers[&key].has_in_flight_handshake() && link.deferred.is_none() {
                link.via_relay = false;
            }
            // §12.3 direct retry, every `DIRECT_RETRY_INTERVAL` while `current` is relayed.
            let link = &self.links[&key];
            let relayed = matches!(link.path(&self.peers[&key]), Some(Path::Relayed(_)));
            let retry = match (relayed, link.retry_at) {
                (false, _) => None,
                (true, None) => Some(now + DIRECT_RETRY_INTERVAL),
                (true, Some(t)) if t <= now => {
                    self.rediscover(now, wall, key, true, &mut sends);
                    Some(now + DIRECT_RETRY_INTERVAL)
                }
                (true, t) => t,
            };
            self.links.get_mut(&key).expect("listed").retry_at = retry;
        }
        if rediscover_all {
            self.rediscover_live(now, wall, &mut sends);
        }
        if let Some(registry) = &mut self.registry {
            let peers = &self.peers;
            registry.expire(now, |k| peers.contains_key(k));
        }
        if let Some(forwarder) = &mut self.forwarder {
            forwarder.senders.retain(|k, _| self.peers.contains_key(k));
        }
        Output {
            datagrams: self.route(now, wall, sends),
            ..Output::default()
        }
    }

    /// A configured relay `current` can send to (§12.3); the smallest key if several.
    fn live_relay(&self, now: Duration) -> Option<PublicKey> {
        self.links
            .iter()
            .filter(|(k, l)| l.role == Role::Relay && self.peers[*k].can_send(now))
            .map(|(k, _)| *k)
            .min()
    }

    /// §12.2, §12.3: message 1 goes to every candidate, and through the relay once the
    /// sequence falls back to it; everything else follows the `current` session's path
    /// (§12.4), wrapped in `relay_forward` when relayed. Counts what leaves (§12.6).
    fn route(&mut self, now: Duration, wall: Tai64n, sends: Vec<Send>) -> Vec<(Endpoint, Vec<u8>)> {
        let relay = self.live_relay(now);
        let mut queue = VecDeque::from(sends);
        let mut out = Vec::with_capacity(queue.len());
        while let Some((key, to, datagram)) = queue.pop_front() {
            let (Some(link), Some(peer)) = (self.links.get_mut(&key), self.peers.get_mut(&key))
            else {
                continue;
            };
            let paths: Vec<Path> = match to {
                Some(path) => vec![path],
                None if datagram.first() == Some(&wire::TYPE_HANDSHAKE_INIT) => {
                    link.message_1 = Some(datagram.clone());
                    let direct = link.candidates().into_iter().map(Path::Direct);
                    let relayed = relay.filter(|_| link.via_relay).map(Path::Relayed);
                    direct.chain(relayed).collect()
                }
                None => link
                    .path(peer)
                    .or(link.endpoint.map(Path::Direct))
                    .into_iter()
                    .collect(),
            };
            for path in paths {
                let peer = self.peers.get_mut(&key).expect("checked above");
                peer.counters.tx_packets += 1;
                peer.counters.tx_bytes += datagram.len() as u64;
                match path {
                    Path::Direct(e) => out.push((e, datagram.clone())),
                    Path::Relayed(r) => {
                        // §4.1: only a configured relay relays; a path through a key that
                        // left the relay list is unavailable, never direct.
                        if self.links.get(&r).is_none_or(|l| l.role != Role::Relay) {
                            continue;
                        }
                        let Some(relay) = self.peers.get_mut(&r) else {
                            continue;
                        };
                        let forward = Inner::RelayForward {
                            to: key,
                            payload: &datagram,
                        };
                        let wrapped =
                            relay.send_inner(&mut ctx!(self, now, wall), &forward.encode());
                        queue.extend(wrapped.into_iter().map(|d| (r, None, d)));
                    }
                }
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
            let retry = (link.role != Role::Peer
                && peer.current().is_none()
                && !peer.has_in_flight_handshake())
            .then(|| {
                peer.last_init_sent()
                    .map_or(Duration::ZERO, |t| t + REKEY_TIMEOUT)
            });
            let register = link.register_at.filter(|_| peer.current().is_some());
            next = [
                next,
                discovery,
                retry,
                register,
                link.deferred,
                link.retry_at,
            ]
            .into_iter()
            .flatten()
            .min();
        }
        next
    }

    #[cfg(test)]
    pub(crate) fn index_count(&self) -> usize {
        self.indices.len()
    }

    /// Keys holding a lighthouse query budget and keys holding relay sender state, sorted:
    /// what [`Node::relay_senders`] cannot show (it lists the configured keys).
    #[cfg(test)]
    pub(crate) fn per_key_state(&self) -> (Vec<PublicKey>, Vec<PublicKey>) {
        let sorted = |mut v: Vec<PublicKey>| {
            v.sort();
            v
        };
        let budgets = (self.registry.as_ref()).map_or_else(Vec::new, |r| r.budget_keys());
        let senders = (self.forwarder.as_ref())
            .map_or_else(Vec::new, |f| f.senders.keys().copied().collect());
        (sorted(budgets), sorted(senders))
    }

    /// Seals `inner` on `key`'s `current` session and routes it: a misbehaving party.
    #[cfg(test)]
    pub(crate) fn send_inner_to(
        &mut self,
        now: Duration,
        wall: Tai64n,
        key: PublicKey,
        inner: &[u8],
    ) -> Vec<(Endpoint, Vec<u8>)> {
        let peer = self.peers.get_mut(&key).expect("configured");
        let out = peer.send_inner(&mut ctx!(self, now, wall), inner);
        let sends = out.into_iter().map(|d| (key, None, d)).collect();
        self.route(now, wall, sends)
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

/// §12.2 validity: an endpoint a datagram may go to, and not one of `own`.
fn sendable(endpoint: &Endpoint, own: &[Endpoint]) -> bool {
    let address = endpoint.address.to_canonical();
    endpoint.port != 0
        && !address.is_unspecified()
        && is_unicast(address)
        && !own.contains(endpoint)
}

/// §11: multicast and broadcast destinations are dropped on both sides.
fn is_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => !v4.is_multicast() && !v4.is_broadcast(),
        IpAddr::V6(v6) => !v6.is_multicast(),
    }
}
