//! Per-peer inbound firewall (§15, ADR 0011): default deny for `ip_packet` bodies entering
//! from the tunnel, ICMP always allowed, per-peer `allow_inbound` rules, and one bounded
//! table of outbound UDP flows and accepted first fragments so that replies and the rest of
//! a fragmented packet pass. Outbound traffic is never filtered, it only records state.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

/// §15: lifetime of an outbound UDP flow entry.
pub const UDP_FLOW_TIMEOUT: Duration = Duration::from_secs(60);
/// §15: lifetime of an accepted first fragment's entry.
pub const FRAGMENT_ENTRY_TIMEOUT: Duration = Duration::from_secs(30);
/// §15, §17: default bound of the table (`firewall.udp_flows_max`).
pub const UDP_FLOWS_MAX: usize = 4096;

const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMPV6: u8 = 58;
/// Ports and flags (§15): the TCP header bytes a first fragment must carry.
const TCP_HEADER: usize = 14;
const UDP_HEADER: usize = 8;

/// One `allow_inbound` entry: `tcp/22`, `udp/53`, `tcp/*` or `any`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    Any,
    /// Protocol number (TCP or UDP) and destination port, `None` for `*`.
    Port(u8, Option<u16>),
}

impl FromStr for Rule {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let bad = || format!("rule `{text}`: expected `any`, `tcp/PORT`, `udp/PORT` or `PROTO/*`");
        if text == "any" {
            return Ok(Rule::Any);
        }
        let (proto, port) = text.split_once('/').ok_or_else(bad)?;
        let proto = match proto {
            "tcp" => TCP,
            "udp" => UDP,
            _ => return Err(bad()),
        };
        let port = match port {
            "*" => None,
            p => Some(p.parse().ok().filter(|p| *p != 0).ok_or_else(bad)?),
        };
        Ok(Rule::Port(proto, port))
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rule::Any => f.write_str("any"),
            Rule::Port(proto, port) => {
                f.write_str(if *proto == TCP { "tcp/" } else { "udp/" })?;
                match port {
                    Some(p) => write!(f, "{p}"),
                    None => f.write_str("*"),
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Key {
    /// An outbound UDP flow, in outbound orientation.
    Flow(IpAddr, IpAddr, u16, u16),
    /// An accepted inbound first fragment: source, destination, protocol, identification.
    Fragment(IpAddr, IpAddr, u8, u32),
}

/// The firewall table's counters, for the control API (ADR 0015).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FirewallStatus {
    pub entries: usize,
    pub max: usize,
    pub evictions: u64,
}

/// The bounded table of §15. Each entry maps to its expiry and, for fragments, the length
/// of the header region a non-initial fragment must not overlap.
pub struct Firewall {
    entries: HashMap<Key, (Duration, usize)>,
    by_expiry: BTreeSet<(Duration, Key)>,
    max: usize,
    evictions: u64,
}

/// Where a packet sits in a fragmented datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fragment {
    None,
    First(u32),
    /// Identification and offset in bytes.
    Later(u32, usize),
}

/// The fields §15 looks at. `transport` is what the packet holds from the transport header
/// on; `header` is the length, from the start of the fragmentable part, of the region a
/// non-initial fragment must not overlap.
#[derive(Debug)]
struct Parsed<'a> {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    fragment: Fragment,
    /// The protocol a fragment entry is keyed by: IPv4's protocol field, or the next header
    /// of IPv6's Fragment header (the same in every fragment of a datagram).
    fragment_protocol: u8,
    transport: &'a [u8],
    header: usize,
}

impl<'a> Parsed<'a> {
    /// `None` for a packet §15 drops whatever the rules: truncated IP header or extension
    /// chain, or a first (or only) fragment without its complete transport header.
    fn new(packet: &'a [u8]) -> Option<Self> {
        let mut parsed = match packet.first()? >> 4 {
            4 => Self::v4(packet)?,
            6 => Self::v6(packet)?,
            _ => return None,
        };
        let needed = match parsed.protocol {
            TCP => TCP_HEADER,
            UDP => UDP_HEADER,
            _ => 0,
        };
        parsed.header += needed;
        if !matches!(parsed.fragment, Fragment::Later(..)) && parsed.transport.len() < needed {
            return None;
        }
        Some(parsed)
    }

    fn v4(p: &'a [u8]) -> Option<Self> {
        let ihl = usize::from(p[0] & 0x0f) * 4;
        if ihl < 20 || p.len() < ihl {
            return None;
        }
        let id = u32::from(u16::from_be_bytes([p[4], p[5]]));
        let flags = u16::from_be_bytes([p[6], p[7]]);
        let offset = usize::from(flags & 0x1fff) * 8;
        let fragment = match (offset, flags & 0x2000 != 0) {
            (0, false) => Fragment::None,
            (0, true) => Fragment::First(id),
            (o, _) => Fragment::Later(id, o),
        };
        let addr = |at: usize| IpAddr::V4(Ipv4Addr::new(p[at], p[at + 1], p[at + 2], p[at + 3]));
        Some(Self {
            source: addr(12),
            destination: addr(16),
            protocol: p[9],
            fragment,
            fragment_protocol: p[9],
            transport: &p[ihl..],
            header: 0,
        })
    }

    /// Walks the extension header chain (RFC 8200 §4) up to the upper-layer header; in a
    /// non-initial fragment, up to the Fragment header (the rest is fragment data).
    fn v6(p: &'a [u8]) -> Option<Self> {
        let header = p.get(..40)?;
        let addr = |at: usize| {
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&header[at..at + 16]).expect("16 bytes"),
            ))
        };
        let (mut next, mut at) = (header[6], 40);
        let mut fragment = Fragment::None;
        // Start of the fragmentable part, once a Fragment header was seen.
        let mut fragmentable = None;
        let mut fragment_protocol = 0;
        loop {
            let length = match next {
                // Hop-by-hop, routing, destination options.
                0 | 43 | 60 => (usize::from(*p.get(at + 1)?) + 1) * 8,
                // Authentication header.
                51 => (usize::from(*p.get(at + 1)?) + 2) * 4,
                44 => {
                    let f = p.get(at..at + 8)?;
                    if fragmentable.is_some() {
                        return None; // two Fragment headers
                    }
                    let field = u16::from_be_bytes([f[2], f[3]]);
                    let id = u32::from_be_bytes([f[4], f[5], f[6], f[7]]);
                    let offset = usize::from(field & 0xfff8);
                    fragmentable = Some(at + 8);
                    fragment_protocol = f[0];
                    if offset > 0 {
                        fragment = Fragment::Later(id, offset);
                        next = f[0];
                        at += 8;
                        break;
                    }
                    if field & 1 != 0 {
                        fragment = Fragment::First(id);
                    }
                    8
                }
                _ => break,
            };
            next = *p.get(at)?;
            at += length;
            if at > p.len() {
                return None;
            }
        }
        Some(Self {
            source: addr(8),
            destination: addr(24),
            protocol: next,
            fragment,
            fragment_protocol,
            transport: &p[at..],
            header: fragmentable.map_or(0, |f| at - f),
        })
    }

    fn ports(&self) -> (u16, u16) {
        let t = self.transport;
        (
            u16::from_be_bytes([t[0], t[1]]),
            u16::from_be_bytes([t[2], t[3]]),
        )
    }
}

impl Default for Firewall {
    fn default() -> Self {
        Self::new(UDP_FLOWS_MAX)
    }
}

impl Firewall {
    /// `max` is clamped to at least one entry.
    pub fn new(max: usize) -> Self {
        Self {
            entries: HashMap::new(),
            by_expiry: BTreeSet::new(),
            max: max.max(1),
            evictions: 0,
        }
    }

    pub fn status(&self) -> FirewallStatus {
        FirewallStatus {
            entries: self.entries.len(),
            max: self.max,
            evictions: self.evictions,
        }
    }

    /// §15 outbound: records (or refreshes) a UDP flow; never refuses a packet.
    pub fn outbound(&mut self, now: Duration, packet: &[u8]) {
        let Some(p) = Parsed::new(packet) else {
            return;
        };
        if p.protocol == UDP && !matches!(p.fragment, Fragment::Later(..)) {
            let (sport, dport) = p.ports();
            let key = Key::Flow(p.source, p.destination, sport, dport);
            self.insert(now, key, now + UDP_FLOW_TIMEOUT, 0);
        }
    }

    /// §15 inbound: whether a packet from a peer with these rules passes. The caller has
    /// already checked that the source belongs to that peer (§11).
    pub fn inbound(&mut self, now: Duration, rules: &[Rule], packet: &[u8]) -> bool {
        let Some(p) = Parsed::new(packet) else {
            return false;
        };
        if let Fragment::Later(id, offset) = p.fragment {
            let key = Key::Fragment(p.source, p.destination, p.fragment_protocol, id);
            return self.live(now, &key).is_some_and(|header| offset >= header);
        }
        let allowed = match p.protocol {
            ICMP | ICMPV6 => true,
            TCP => {
                let flags = p.transport[13];
                // Rule 4: only flow openers (SYN without ACK) are checked.
                flags & 0x12 != 0x02 || matches(rules, &p)
            }
            UDP => {
                let (sport, dport) = p.ports();
                let reply = Key::Flow(p.destination, p.source, dport, sport);
                matches(rules, &p) || self.live(now, &reply).is_some()
            }
            _ => rules.contains(&Rule::Any),
        };
        if let (true, Fragment::First(id)) = (allowed, p.fragment) {
            let key = Key::Fragment(p.source, p.destination, p.fragment_protocol, id);
            self.insert(now, key, now + FRAGMENT_ENTRY_TIMEOUT, p.header);
        }
        allowed
    }

    /// The entry's header length if it exists and has not expired; an expired one is removed.
    fn live(&mut self, now: Duration, key: &Key) -> Option<usize> {
        let (expires, header) = *self.entries.get(key)?;
        if expires > now {
            return Some(header);
        }
        self.entries.remove(key);
        self.by_expiry.remove(&(expires, *key));
        None
    }

    fn insert(&mut self, now: Duration, key: Key, expires: Duration, header: usize) {
        while let Some(&(at, old)) = self.by_expiry.first() {
            if at > now {
                break;
            }
            self.by_expiry.pop_first();
            self.entries.remove(&old);
        }
        if let Some((old, _)) = self.entries.remove(&key) {
            self.by_expiry.remove(&(old, key));
        } else if self.entries.len() >= self.max {
            // Full: the oldest `expires` goes, so the new flow always gets an entry.
            let (_, oldest) = self.by_expiry.pop_first().expect("max ≥ 1");
            self.entries.remove(&oldest);
            self.evictions += 1;
        }
        self.entries.insert(key, (expires, header));
        self.by_expiry.insert((expires, key));
    }
}

fn matches(rules: &[Rule], p: &Parsed<'_>) -> bool {
    let (_, dport) = p.ports();
    rules.iter().any(|rule| match *rule {
        Rule::Any => true,
        Rule::Port(proto, port) => proto == p.protocol && port.is_none_or(|q| q == dport),
    })
}
