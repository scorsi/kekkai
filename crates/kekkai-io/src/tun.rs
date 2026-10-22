//! The Linux TUN device (`tun` feature, ADR 0005, 0018, 0023): created with `TUNSETIFF`, its
//! MTU, addresses and host routes set with the classic `SIOC*` ioctls on both families
//! (ADR 0029). Needs `CAP_NET_ADMIN` and `/dev/net/tun`, nothing else.

use std::ffi::CString;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// One TUN interface in `IFF_TUN | IFF_NO_PI` mode: every read and write is one IP packet.
pub struct Tun {
    fd: AsyncFd<OwnedFd>,
}

/// `struct rtentry` of `<linux/route.h>` (not exported by libc for glibc targets).
#[repr(C)]
struct RtEntry {
    rt_pad1: libc::c_ulong,
    rt_dst: libc::sockaddr,
    rt_gateway: libc::sockaddr,
    rt_genmask: libc::sockaddr,
    rt_flags: libc::c_ushort,
    rt_pad2: libc::c_short,
    rt_pad3: libc::c_ulong,
    rt_pad4: *mut libc::c_void,
    rt_metric: libc::c_short,
    rt_dev: *mut libc::c_char,
    rt_mtu: libc::c_ulong,
    rt_window: libc::c_ulong,
    rt_irtt: libc::c_ushort,
}

/// `struct in6_rtmsg` of `<linux/ipv6_route.h>` (libc keeps its fields private).
#[repr(C)]
struct In6RtMsg {
    rtmsg_dst: libc::in6_addr,
    rtmsg_src: libc::in6_addr,
    rtmsg_gateway: libc::in6_addr,
    rtmsg_type: u32,
    rtmsg_dst_len: u16,
    rtmsg_src_len: u16,
    rtmsg_metric: u32,
    rtmsg_info: libc::c_ulong,
    rtmsg_flags: u32,
    rtmsg_ifindex: libc::c_int,
}

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn socket(family: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the returned descriptor is owned from here on.
    let fd = check(unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn ioctl<T>(fd: RawFd, request: libc::c_ulong, arg: &mut T) -> io::Result<()> {
    // SAFETY: every caller passes the structure the kernel expects for `request`.
    check(unsafe { libc::ioctl(fd, request as _, arg as *mut T) }).map(drop)
}

fn ifreq(name: &str) -> io::Result<libc::ifreq> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad interface name",
        ));
    }
    // SAFETY: ifreq is plain old data; all zeros is a valid value.
    let mut req: libc::ifreq = unsafe { zeroed() };
    for (dst, src) in req.ifr_name.iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char;
    }
    Ok(req)
}

fn sockaddr_v4(ip: Ipv4Addr) -> libc::sockaddr {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: sockaddr_in and sockaddr have the same size on Linux.
    unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sin) }
}

fn in6(ip: Ipv6Addr) -> libc::in6_addr {
    libc::in6_addr {
        s6_addr: ip.octets(),
    }
}

/// Adds (`add`) or deletes the host route of `route` towards `name` (spec §11): at start and
/// when a reload changes the peers' addresses (§4.1).
pub fn set_route(name: &str, route: IpAddr, add: bool) -> io::Result<()> {
    match route {
        IpAddr::V4(ip) => {
            // SIOCADDRT copies IFNAMSIZ − 1 bytes from rt_dev: give it a full-size buffer.
            let mut devname = ifreq(name)?.ifr_name;
            // SAFETY: plain old data; all zeros is a valid value.
            let mut rt: RtEntry = unsafe { zeroed() };
            rt.rt_dst = sockaddr_v4(ip);
            rt.rt_genmask = sockaddr_v4(Ipv4Addr::BROADCAST);
            rt.rt_flags = libc::RTF_UP | libc::RTF_HOST;
            rt.rt_dev = devname.as_mut_ptr();
            let request = if add {
                libc::SIOCADDRT
            } else {
                libc::SIOCDELRT
            };
            ioctl(socket(libc::AF_INET)?.as_raw_fd(), request, &mut rt)
        }
        IpAddr::V6(ip) => {
            let cname = CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
            // SAFETY: cname is a valid C string.
            let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
            if index == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: plain old data; all zeros is a valid value.
            let mut rt: In6RtMsg = unsafe { zeroed() };
            rt.rtmsg_dst = in6(ip);
            rt.rtmsg_dst_len = 128;
            rt.rtmsg_flags = u32::from(libc::RTF_UP);
            rt.rtmsg_ifindex = index as libc::c_int;
            let request = if add {
                libc::SIOCADDRT
            } else {
                libc::SIOCDELRT
            };
            ioctl(socket(libc::AF_INET6)?.as_raw_fd(), request, &mut rt)
        }
    }
}

impl Tun {
    /// Creates `name`, sets its MTU, brings it up, assigns `addresses` (each a `/32` or
    /// `/128`) and adds one host route per entry of `routes` towards it (spec §11).
    pub fn create(
        name: &str,
        mtu: u16,
        addresses: &[IpAddr],
        routes: &[IpAddr],
    ) -> io::Result<Self> {
        let path = CString::new("/dev/net/tun").expect("no NUL");
        // SAFETY: plain syscall; the returned descriptor is owned from here on.
        let raw = check(unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        })?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut req = ifreq(name)?;
        req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        ioctl(fd.as_raw_fd(), libc::TUNSETIFF as libc::c_ulong, &mut req)?;

        let inet = socket(libc::AF_INET)?;
        let mut req = ifreq(name)?;
        req.ifr_ifru.ifru_mtu = libc::c_int::from(mtu);
        ioctl(inet.as_raw_fd(), libc::SIOCSIFMTU, &mut req)?;
        let mut req = ifreq(name)?;
        ioctl(inet.as_raw_fd(), libc::SIOCGIFFLAGS, &mut req)?;
        // SAFETY: SIOCGIFFLAGS filled the flags member.
        unsafe { req.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short };
        ioctl(inet.as_raw_fd(), libc::SIOCSIFFLAGS, &mut req)?;

        let cname = CString::new(name).expect("checked by ifreq");
        // SAFETY: cname is a valid C string.
        let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        let inet6 = || socket(libc::AF_INET6);
        for address in addresses {
            match address {
                IpAddr::V4(ip) => {
                    let mut req = ifreq(name)?;
                    req.ifr_ifru.ifru_addr = sockaddr_v4(*ip);
                    ioctl(inet.as_raw_fd(), libc::SIOCSIFADDR, &mut req)?;
                    let mut req = ifreq(name)?;
                    req.ifr_ifru.ifru_netmask = sockaddr_v4(Ipv4Addr::BROADCAST);
                    ioctl(inet.as_raw_fd(), libc::SIOCSIFNETMASK, &mut req)?;
                }
                IpAddr::V6(ip) => {
                    let mut req = libc::in6_ifreq {
                        ifr6_addr: in6(*ip),
                        ifr6_prefixlen: 128,
                        ifr6_ifindex: index as libc::c_int,
                    };
                    ioctl(inet6()?.as_raw_fd(), libc::SIOCSIFADDR, &mut req)?;
                }
            }
        }
        for route in routes {
            set_route(name, *route, true)?;
        }
        const _: () = assert!(size_of::<libc::sockaddr_in>() == size_of::<libc::sockaddr>());
        // SAFETY: the TUN descriptor is owned here and never replaced or closed behind tokio.
        let fd = unsafe {
            AsyncFd::register_with_interest(fd, Interest::READABLE | Interest::WRITABLE)
        }?;
        Ok(Self { fd })
    }
}

impl crate::Tunnel for Tun {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            let fd = guard.get_inner().as_raw_fd();
            // SAFETY: buf is valid for writes of its length.
            match guard.try_io(|_| {
                check(unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) as _ })
            }) {
                Ok(n) => return n.map(|n| n as usize),
                Err(_would_block) => continue,
            }
        }
    }

    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            let fd = guard.get_inner().as_raw_fd();
            // SAFETY: packet is valid for reads of its length.
            match guard.try_io(|_| {
                check(unsafe { libc::write(fd, packet.as_ptr().cast(), packet.len()) as _ })
            }) {
                Ok(n) => return n.map(drop),
                Err(_would_block) => continue,
            }
        }
    }
}
