//! TCP MSS clamping on the overlay interface (ADR 0009, spec §17): a SYN crossing the tunnel
//! never announces a segment larger than the overlay MTU allows.

/// Lowers the MSS option of a TCP SYN to `mtu − 40` (IPv4) or `mtu − 60` (IPv6) and fixes the
/// checksum incrementally (RFC 1624). Anything else is left untouched.
/// shortcut: IPv6 packets with extension headers before TCP are not clamped; upgrade if
/// subnet routing (ADR 0027) ever forwards such traffic.
pub fn clamp(packet: &mut [u8], mtu: u16) {
    let (tcp_at, max) = match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let fragment_offset = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff;
            if packet[9] != 6 || fragment_offset != 0 {
                return;
            }
            (usize::from(packet[0] & 0x0f) * 4, mtu.saturating_sub(40))
        }
        Some(6) if packet.len() >= 40 && packet[6] == 6 => (40, mtu.saturating_sub(60)),
        _ => return,
    };
    let Some(tcp) = packet.get_mut(tcp_at..) else {
        return;
    };
    if tcp.len() < 20 || tcp[13] & 0x02 == 0 {
        return;
    }
    let options_end = (usize::from(tcp[12] >> 4) * 4).min(tcp.len());
    let mut i = 20;
    while i < options_end {
        match tcp[i] {
            0 => return,
            1 => i += 1,
            kind => {
                let Some(&len) = tcp.get(i + 1) else { return };
                let len = usize::from(len);
                if len < 2 || i + len > options_end {
                    return;
                }
                if kind == 2 && len == 4 {
                    let old = u16::from_be_bytes([tcp[i + 2], tcp[i + 3]]);
                    if old > max {
                        tcp[i + 2..i + 4].copy_from_slice(&max.to_be_bytes());
                        let sum = u16::from_be_bytes([tcp[16], tcp[17]]);
                        tcp[16..18].copy_from_slice(&adjust(sum, old, max).to_be_bytes());
                    }
                    return;
                }
                i += len;
            }
        }
    }
}

/// RFC 1624 eqn. 3: `HC' = ~(~HC + ~m + m')`.
fn adjust(checksum: u16, old: u16, new: u16) -> u16 {
    let mut sum = u32::from(!checksum) + u32::from(!old) + u32::from(new);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::clamp;

    fn fold(mut sum: u32) -> u16 {
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn words(b: &[u8]) -> u32 {
        b.chunks(2)
            .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
            .sum()
    }

    /// TCP checksum over the IPv4 pseudo header.
    fn tcp4_checksum(p: &[u8]) -> u16 {
        let tcp = &p[20..];
        fold(words(&p[12..20]) + 6 + tcp.len() as u32 + words(tcp))
    }

    fn syn4(mss: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![
            0x45, 0, 0, 44, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let mut tcp = vec![
            0x30, 0x39, 0, 22, 0, 0, 0, 1, 0, 0, 0, 0, 0x60, flags, 0xff, 0xff,
        ];
        tcp.extend_from_slice(&[0, 0, 0, 0, 2, 4]);
        tcp.extend_from_slice(&mss.to_be_bytes());
        p.extend_from_slice(&tcp);
        let sum = tcp4_checksum(&p);
        p[36..38].copy_from_slice(&sum.to_be_bytes());
        p
    }

    #[test]
    fn clamps_syn_and_keeps_checksum_valid() {
        let mut p = syn4(1460, 0x02);
        clamp(&mut p, 1280);
        assert_eq!(&p[42..44], &1240u16.to_be_bytes());
        assert_eq!(tcp4_checksum(&p), 0, "checksum still verifies");
    }

    #[test]
    fn leaves_the_rest_alone() {
        for (mss, flags) in [(1200, 0x02), (1460, 0x10)] {
            let mut p = syn4(mss, flags);
            let before = p.clone();
            clamp(&mut p, 1280);
            assert_eq!(p, before, "mss {mss} flags {flags:#x}");
        }
        for mut junk in [vec![], vec![0x45; 3], vec![0x60; 50], vec![0x4f; 21]] {
            clamp(&mut junk, 1280);
        }
    }

    #[test]
    fn clamps_ipv6_syn() {
        let mut p = vec![0x60, 0, 0, 0, 0, 24, 6, 64];
        p.extend_from_slice(&[0; 32]);
        p.extend_from_slice(&[
            0x30, 0x39, 0, 22, 0, 0, 0, 1, 0, 0, 0, 0, 0x60, 0x02, 0xff, 0xff,
        ]);
        p.extend_from_slice(&[0x12, 0x34, 0, 0, 2, 4, 0x05, 0xa0]);
        clamp(&mut p, 1280);
        assert_eq!(&p[62..64], &1220u16.to_be_bytes());
        // 0x1234 adjusted by (1440 -> 1220).
        let expected = super::adjust(0x1234, 1440, 1220);
        assert_eq!(&p[56..58], &expected.to_be_bytes());
    }
}
