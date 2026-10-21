//! The underlay socket: one IPv6 UDP socket with IPv4-mapped addresses (ADR 0010), so one
//! socket serves both families whatever `net.ipv6.bindv6only` says.

use std::io;
use std::mem::size_of;
use std::os::fd::FromRawFd;

/// Binds `[::]:port` with `IPV6_V6ONLY` off.
pub fn bind(port: u16) -> io::Result<tokio::net::UdpSocket> {
    let check = |ret: libc::c_int| {
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    };
    // SAFETY: plain syscall; the descriptor is owned by the std socket right away.
    let fd = check(unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) })?;
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    let off: libc::c_int = 0;
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        // SAFETY: plain old data; all zeros is `::`.
        ..unsafe { std::mem::zeroed() }
    };
    // SAFETY: valid option value and address of the stated sizes.
    unsafe {
        check(libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&off as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        ))?;
        check(libc::bind(
            fd,
            (&addr as *const libc::sockaddr_in6).cast(),
            size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        ))?;
    }
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket)
}
