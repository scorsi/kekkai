//! The host's local endpoints for `lighthouse_register` (spec §13.1): every unicast address
//! of the interfaces that are up, except loopback, link-local and the overlay addresses,
//! paired with the listen port. `getifaddrs(3)` through `libc` (ADR 0029).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use kekkai_core::MAX_LOCAL_ENDPOINTS;
use kekkai_core::inner::Endpoint;

/// The addresses of the interfaces that are up, loopback interfaces excluded.
pub fn addresses() -> io::Result<Vec<IpAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list freed below by freeifaddrs.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: a non-null entry of the list getifaddrs returned, alive until freeifaddrs.
        let ifa = unsafe { &*cursor };
        cursor = ifa.ifa_next;
        let flags = ifa.ifa_flags as libc::c_int;
        if ifa.ifa_addr.is_null() || flags & libc::IFF_UP == 0 || flags & libc::IFF_LOOPBACK != 0 {
            continue;
        }
        // SAFETY: ifa_addr points at a sockaddr whose family tells its real type.
        let address = unsafe {
            match i32::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
                }
                libc::AF_INET6 => {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr))
                }
                _ => continue,
            }
        };
        out.push(address);
    }
    // SAFETY: the list returned by getifaddrs, freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// §13.1: what the node registers, sorted, at most `MAX_LOCAL_ENDPOINTS`.
pub fn local_endpoints(listen_port: u16, overlay: &[IpAddr]) -> io::Result<Vec<Endpoint>> {
    let mut found: Vec<Endpoint> = addresses()?
        .into_iter()
        .filter(|a| registrable(*a) && !overlay.contains(a))
        .map(|a| Endpoint::new(a, listen_port))
        .collect();
    found.sort();
    found.dedup();
    found.truncate(MAX_LOCAL_ENDPOINTS);
    Ok(found)
}

fn registrable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => !(v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()),
        IpAddr::V6(v6) => {
            let link_local = v6.segments()[0] & 0xffc0 == 0xfe80;
            !(v6.is_loopback() || link_local || v6.is_unspecified() || v6.is_multicast())
                && v6.to_ipv4_mapped().is_none()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters() {
        let keep = ["192.0.2.1", "2001:db8::1", "10.1.2.3", "fd00::5"];
        let drop = [
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "0.0.0.0",
            "::",
        ];
        for a in keep {
            assert!(registrable(a.parse().unwrap()), "{a}");
        }
        for a in drop {
            assert!(!registrable(a.parse().unwrap()), "{a}");
        }
        // The host this test runs on has a list, possibly empty; the overlay is excluded.
        let all = addresses().unwrap();
        let overlay: Vec<IpAddr> = all.iter().copied().take(1).collect();
        let found = local_endpoints(4802, &overlay).unwrap();
        assert!(found.len() <= MAX_LOCAL_ENDPOINTS);
        assert!(found.iter().all(|e| e.port == 4802));
        assert!(
            overlay
                .iter()
                .all(|o| !found.contains(&Endpoint::new(*o, 4802)))
        );
    }
}
