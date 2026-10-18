//! §15 firewall: rules, fragments (RFC 1858 and RFC 7112 cases), table bound. The flows
//! through real nodes are in `tests/simulation.rs`.

use std::time::Duration;

use proptest::prelude::*;

use crate::firewall::{FRAGMENT_ENTRY_TIMEOUT, Firewall, Rule};

const T0: Duration = Duration::from_secs(1);

/// IPv4 10.0.0.2 → 10.0.0.1 with identification 7, the MF flag, an offset in 8-byte units
/// and `body` after the 20-byte header.
fn v4(protocol: u8, more: bool, offset: u16, body: &[u8]) -> Vec<u8> {
    let flags = offset | if more { 0x2000 } else { 0 };
    let mut p = vec![0x45, 0, 0, 0, 0, 7];
    p.extend_from_slice(&flags.to_be_bytes());
    p.extend_from_slice(&[64, protocol, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1]);
    p.extend_from_slice(body);
    let len = p.len() as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p
}

/// IPv6 fd00::2 → fd00::1 with `next` as the first next header and `rest` after the header.
fn v6(next: u8, rest: &[u8]) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend_from_slice(&(rest.len() as u16).to_be_bytes());
    p.extend_from_slice(&[next, 64]);
    p.extend_from_slice(&"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
    p.extend_from_slice(&"fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
    p.extend_from_slice(rest);
    p
}

/// An IPv6 Fragment header: next header, offset in 8-byte units, M flag, identification 9.
fn frag6(next: u8, offset: u16, more: bool) -> Vec<u8> {
    let field = (offset << 3) | u16::from(more);
    let mut h = vec![next, 0];
    h.extend_from_slice(&field.to_be_bytes());
    h.extend_from_slice(&9u32.to_be_bytes());
    h
}

/// An 8-byte destination options header (padding only) followed by `next`.
fn dest_opts(next: u8) -> Vec<u8> {
    vec![next, 0, 1, 4, 0, 0, 0, 0]
}

fn tcp(dport: u16, flags: u8) -> Vec<u8> {
    let mut t = vec![0; 20];
    t[0..2].copy_from_slice(&40000u16.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[12] = 0x50;
    t[13] = flags;
    t
}

fn rules(text: &[&str]) -> Vec<Rule> {
    text.iter().map(|r| r.parse().unwrap()).collect()
}

#[test]
fn rule_text() {
    for text in ["any", "tcp/22", "udp/53", "tcp/*", "udp/*", "tcp/65535"] {
        assert_eq!(text.parse::<Rule>().unwrap().to_string(), text);
    }
    for bad in [
        "",
        "tcp",
        "tcp/",
        "tcp/0",
        "tcp/65536",
        "icmp/1",
        "TCP/22",
        "tcp/2-3",
    ] {
        assert!(bad.parse::<Rule>().is_err(), "{bad}");
    }
}

#[test]
fn rules_and_default_deny() {
    let mut fw = Firewall::default();
    let ssh = rules(&["tcp/22"]);
    assert!(fw.inbound(T0, &ssh, &v4(6, false, 0, &tcp(22, 0x02))));
    assert!(!fw.inbound(T0, &ssh, &v4(6, false, 0, &tcp(23, 0x02))));
    assert!(!fw.inbound(T0, &[], &v4(6, false, 0, &tcp(22, 0x02))));
    assert!(fw.inbound(T0, &rules(&["tcp/*"]), &v4(6, false, 0, &tcp(23, 0x02))));
    assert!(!fw.inbound(T0, &rules(&["udp/*"]), &v4(6, false, 0, &tcp(23, 0x02))));
    // Other protocols: only `any`.
    assert!(!fw.inbound(T0, &ssh, &v4(47, false, 0, &[0; 8])));
    assert!(fw.inbound(T0, &rules(&["any"]), &v4(47, false, 0, &[0; 8])));
    // ICMP and ICMPv6 always.
    assert!(fw.inbound(T0, &[], &v4(1, false, 0, &[8, 0, 0, 0])));
    assert!(fw.inbound(T0, &[], &v6(58, &[128, 0, 0, 0])));
    // IPv6 TCP behind an extension header is still matched on its port.
    let mut rest = dest_opts(6);
    rest.extend(tcp(22, 0x02));
    assert!(fw.inbound(T0, &ssh, &v6(60, &rest)));
    rest[8 + 3] = 23;
    assert!(!fw.inbound(T0, &ssh, &v6(60, &rest)));
    // Truncated headers never pass.
    assert!(!fw.inbound(T0, &rules(&["any"]), &v4(6, false, 0, &tcp(22, 0x02)[..13])));
    assert!(!fw.inbound(T0, &rules(&["any"]), &v6(60, &[6, 0])));
    assert!(!fw.inbound(T0, &rules(&["any"]), &[0x45, 0, 0]));
}

#[test]
fn rfc1858_tiny_and_overlapping_fragments() {
    let ssh = rules(&["tcp/22"]);
    let mut fw = Firewall::default();
    // Tiny fragment: the first fragment holds 8 TCP bytes, not the flags. Dropped, and it
    // records nothing, so the rest of the datagram is dropped too.
    assert!(!fw.inbound(T0, &ssh, &v4(6, true, 0, &tcp(22, 0x02)[..8])));
    assert_eq!(fw.status().entries, 0);
    assert!(!fw.inbound(T0, &ssh, &v4(6, false, 1, &[0; 16])));
    // A non-initial fragment without an accepted first fragment is dropped.
    assert!(!fw.inbound(T0, &ssh, &v4(6, false, 3, &[0; 16])));
    // An accepted first fragment opens the rest, except an overlap of the TCP header.
    assert!(fw.inbound(T0, &ssh, &v4(6, true, 0, &tcp(22, 0x02))));
    assert_eq!(fw.status().entries, 1);
    assert!(
        !fw.inbound(T0, &ssh, &v4(6, true, 1, &[0; 16])),
        "offset 8 < 14"
    );
    assert!(fw.inbound(T0, &ssh, &v4(6, false, 2, &[0; 16])));
    // The entry lives FRAGMENT_ENTRY_TIMEOUT.
    let late = T0 + FRAGMENT_ENTRY_TIMEOUT;
    assert!(!fw.inbound(late, &ssh, &v4(6, false, 3, &[0; 16])));
    // A refused first fragment opens nothing.
    let mut fw = Firewall::default();
    assert!(!fw.inbound(T0, &ssh, &v4(6, true, 0, &tcp(23, 0x02))));
    assert!(!fw.inbound(T0, &ssh, &v4(6, false, 2, &[0; 16])));
}

#[test]
fn rfc7112_ipv6_fragments() {
    let ssh = rules(&["tcp/22"]);
    let mut fw = Firewall::default();
    // The first fragment ends inside the extension chain: no transport header, dropped.
    let mut first = frag6(60, 0, true);
    first.extend(dest_opts(6));
    assert!(!fw.inbound(T0, &ssh, &v6(44, &first)));
    // Complete chain and TCP header: accepted, and the header region is 8 + 14 bytes.
    first.extend(tcp(22, 0x02));
    assert!(fw.inbound(T0, &ssh, &v6(44, &first)));
    let later = |offset| {
        let mut f = frag6(60, offset, false);
        f.extend([0; 16]);
        v6(44, &f)
    };
    assert!(!fw.inbound(T0, &ssh, &later(2)), "offset 16 < 22 overlaps");
    assert!(fw.inbound(T0, &ssh, &later(3)));
    // Two Fragment headers are malformed.
    let mut double = frag6(44, 0, true);
    double.extend(frag6(6, 0, true));
    double.extend(tcp(22, 0x02));
    assert!(!fw.inbound(T0, &rules(&["any"]), &v6(44, &double)));
}

proptest! {
    /// No input panics the parser, whatever the rules.
    #[test]
    fn arbitrary_packets(packet in prop::collection::vec(any::<u8>(), 0..120), v in 0u8..3) {
        let mut fw = Firewall::new(4);
        let mut packet = packet;
        if let Some(b) = packet.first_mut() {
            *b = (*b & 0x0f) | [0x40, 0x60, *b & 0xf0][usize::from(v)];
        }
        fw.outbound(T0, &packet);
        fw.inbound(T0, &rules(&["any"]), &packet);
        fw.inbound(T0, &[], &packet);
        prop_assert!(fw.status().entries <= 4);
    }

    /// A non-initial TCP fragment passes iff an accepted, complete first fragment preceded
    /// it and it does not overlap the TCP header (offset × 8 ≥ 14).
    #[test]
    fn tcp_fragment_rule(first_len in 0usize..=20, offset in 1u16..0x1fff, allowed: bool) {
        let mut fw = Firewall::default();
        let r = if allowed { rules(&["tcp/22"]) } else { vec![] };
        let first = fw.inbound(T0, &r, &v4(6, true, 0, &tcp(22, 0x02)[..first_len]));
        prop_assert_eq!(first, allowed && first_len >= 14);
        let later = fw.inbound(T0, &r, &v4(6, false, offset, &[0; 8]));
        prop_assert_eq!(later, first && offset * 8 >= 14);
    }

    /// The table never exceeds its bound; each flow past it evicts exactly one entry.
    #[test]
    fn bounded_table(max in 1usize..16, flows in 0u16..64) {
        let mut fw = Firewall::new(max);
        for port in 0..flows {
            let mut udp = vec![0; 8];
            udp[0..2].copy_from_slice(&(1000 + port).to_be_bytes());
            udp[2..4].copy_from_slice(&53u16.to_be_bytes());
            fw.outbound(T0 + Duration::from_millis(u64::from(port)), &v4(17, false, 0, &udp));
            prop_assert!(fw.status().entries <= max);
        }
        let expected = usize::from(flows).saturating_sub(max) as u64;
        prop_assert_eq!(fw.status().evictions, expected);
    }
}
