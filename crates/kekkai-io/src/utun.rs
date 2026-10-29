//! The macOS `utun` device (`tun` feature, ADR 0018): a kernel control socket connected to
//! `com.apple.net.utun_control`, no Network Extension. The kernel picks the first free
//! `utunN` name; the daemon logs it. Every packet carries a 4-byte address family header in
//! network order, added and removed here. Needs root (the LaunchDaemon runs as root, 0018).
//!
//! MTU, addresses and routes are set with `/sbin/ifconfig` and `/sbin/route`, as
//! `wg-quick` does on macOS: the routing-socket message format is undocumented and the
//! commands are part of the base system. The interface and its routes disappear with the
//! descriptor when the daemon exits.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::Route;

const CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

pub struct Utun {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// The 4-byte header of a utun packet: the address family of the packet's version nibble.
fn family_header(packet: &[u8]) -> io::Result<[u8; 4]> {
    let family = match packet.first().map(|b| b >> 4) {
        Some(4) => libc::AF_INET,
        Some(6) => libc::AF_INET6,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not an IP packet",
            ));
        }
    };
    Ok((family as u32).to_be_bytes())
}

/// The commands that configure `name` (spec §11, §4.4).
fn commands(name: &str, mtu: u16, addresses: &[IpAddr], routes: &[Route]) -> Vec<Vec<String>> {
    let mut all = vec![vec![
        "/sbin/ifconfig".into(),
        name.into(),
        "mtu".into(),
        mtu.to_string(),
        "up".into(),
    ]];
    for address in addresses {
        let a = address.to_string();
        all.push(match address {
            // A point-to-point interface: the local address is also the destination.
            IpAddr::V4(_) => vec![
                "/sbin/ifconfig".into(),
                name.into(),
                "inet".into(),
                a.clone(),
                a,
                "netmask".into(),
                "255.255.255.255".into(),
                "alias".into(),
            ],
            IpAddr::V6(_) => vec![
                "/sbin/ifconfig".into(),
                name.into(),
                "inet6".into(),
                a,
                "prefixlen".into(),
                "128".into(),
                "alias".into(),
            ],
        });
    }
    all.extend(routes.iter().map(|r| route_command(name, *r, true)));
    all
}

/// `/sbin/route add` (`add`) or `delete` of `route` towards `name`.
fn route_command(name: &str, route: Route, add: bool) -> Vec<String> {
    let family = if route.address.is_ipv4() {
        "-inet"
    } else {
        "-inet6"
    };
    vec![
        "/sbin/route".into(),
        "-q".into(),
        "-n".into(),
        if add { "add" } else { "delete" }.into(),
        family.into(),
        route.to_string(),
        "-interface".into(),
        name.into(),
    ]
}

/// Adds (`add`) or deletes `route` towards `name` (spec §11, §4.4): at start and when a
/// reload changes the peers' addresses or the `[pki]` prefixes (§4.1).
pub fn set_route(name: &str, route: Route, add: bool) -> io::Result<()> {
    run(&route_command(name, route, add))
}

fn run(command: &[String]) -> io::Result<()> {
    let out = Command::new(&command[0]).args(&command[1..]).output()?;
    if out.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{}: {}",
        command.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

impl Utun {
    /// Creates a `utunN` interface, sets its MTU, brings it up, assigns `addresses` (each a
    /// `/32` or `/128`) and adds every entry of `routes` towards it.
    pub fn create(mtu: u16, addresses: &[IpAddr], routes: &[Route]) -> io::Result<Self> {
        // SAFETY: plain syscall; the returned descriptor is owned from here on.
        let raw = check(unsafe {
            libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL)
        })?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: ctl_info is plain old data; all zeros is a valid value.
        let mut info: libc::ctl_info = unsafe { zeroed() };
        for (dst, src) in info.ctl_name.iter_mut().zip(CONTROL_NAME) {
            *dst = *src as libc::c_char;
        }
        // SAFETY: CTLIOCGINFO takes a ctl_info.
        check(unsafe { libc::ioctl(raw, libc::CTLIOCGINFO, &mut info as *mut libc::ctl_info) })?;
        let address = libc::sockaddr_ctl {
            sc_len: size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            // 0: the kernel picks the first free unit.
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        // SAFETY: address is a valid sockaddr_ctl of the given length.
        check(unsafe {
            libc::connect(
                raw,
                (&address as *const libc::sockaddr_ctl).cast(),
                size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        })?;
        let mut name = [0u8; libc::IFNAMSIZ];
        let mut len = name.len() as libc::socklen_t;
        // SAFETY: name is valid for writes of len bytes.
        check(unsafe {
            libc::getsockopt(
                raw,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut len,
            )
        })?;
        let name = std::ffi::CStr::from_bytes_until_nul(&name)
            .map_err(|_| io::Error::other("utun name not terminated"))?
            .to_string_lossy()
            .into_owned();
        // SAFETY: plain fcntl calls on the owned descriptor.
        let flags = check(unsafe { libc::fcntl(raw, libc::F_GETFL) })?;
        check(unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
        check(unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) })?;
        for command in commands(&name, mtu, addresses, routes) {
            run(&command)?;
        }
        // SAFETY: the descriptor is owned here and never replaced or closed behind tokio.
        let fd = unsafe {
            AsyncFd::register_with_interest(fd, Interest::READABLE | Interest::WRITABLE)
        }?;
        Ok(Self { fd, name })
    }

    /// The `utunN` name the kernel assigned.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl crate::Tunnel for Utun {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut header = [0u8; 4];
        loop {
            let mut guard = self.fd.readable().await?;
            let fd = guard.get_inner().as_raw_fd();
            let iov = [
                libc::iovec {
                    iov_base: header.as_mut_ptr().cast(),
                    iov_len: header.len(),
                },
                libc::iovec {
                    iov_base: buf.as_mut_ptr().cast(),
                    iov_len: buf.len(),
                },
            ];
            // SAFETY: both buffers are valid for writes of their lengths.
            match guard.try_io(|_| check(unsafe { libc::readv(fd, iov.as_ptr(), 2) as _ })) {
                Ok(n) => return n.map(|n| (n as usize).saturating_sub(header.len())),
                Err(_would_block) => continue,
            }
        }
    }

    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        let header = family_header(packet)?;
        loop {
            let mut guard = self.fd.writable().await?;
            let fd = guard.get_inner().as_raw_fd();
            let iov = [
                libc::iovec {
                    iov_base: header.as_ptr() as *mut _,
                    iov_len: header.len(),
                },
                libc::iovec {
                    iov_base: packet.as_ptr() as *mut _,
                    iov_len: packet.len(),
                },
            ];
            // SAFETY: both buffers are valid for reads of their lengths.
            match guard.try_io(|_| check(unsafe { libc::writev(fd, iov.as_ptr(), 2) as _ })) {
                Ok(n) => return n.map(drop),
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_headers() {
        assert_eq!(family_header(&[0x45, 0]).unwrap(), [0, 0, 0, 2]);
        assert_eq!(family_header(&[0x60, 0]).unwrap(), [0, 0, 0, 30]);
        assert!(family_header(&[0x10]).is_err() && family_header(&[]).is_err());
    }

    #[test]
    fn configuration_commands() {
        let addresses = ["10.0.0.1".parse().unwrap(), "fd00::1".parse().unwrap()];
        let routes = [
            Route::host("10.0.0.2".parse().unwrap()),
            Route::host("fd00::2".parse().unwrap()),
            Route {
                address: "10.1.0.0".parse().unwrap(),
                length: 16,
            },
        ];
        let lines: Vec<String> = commands("utun7", 1280, &addresses, &routes)
            .iter()
            .map(|c| c.join(" "))
            .collect();
        assert_eq!(
            lines,
            [
                "/sbin/ifconfig utun7 mtu 1280 up",
                "/sbin/ifconfig utun7 inet 10.0.0.1 10.0.0.1 netmask 255.255.255.255 alias",
                "/sbin/ifconfig utun7 inet6 fd00::1 prefixlen 128 alias",
                "/sbin/route -q -n add -inet 10.0.0.2/32 -interface utun7",
                "/sbin/route -q -n add -inet6 fd00::2/128 -interface utun7",
                "/sbin/route -q -n add -inet 10.1.0.0/16 -interface utun7",
            ]
        );
        let fd00 = Route::host("fd00::2".parse().unwrap());
        let delete = route_command("utun7", fd00, false).join(" ");
        assert_eq!(
            delete,
            "/sbin/route -q -n delete -inet6 fd00::2/128 -interface utun7"
        );
    }
}
