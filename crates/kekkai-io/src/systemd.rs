//! The two systemd protocols the node speaks, on the standard library (ADR 0029): `READY=1`
//! for `Type=notify` (ADR 0018, 0019) and the control socket inherited from a `.socket` unit,
//! which systemd creates `root:kekkai 0660` before the unprivileged daemon starts (ADR 0015).

use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::net::{UnixDatagram, UnixListener};
use std::path::Path;

/// Sends `READY=1` to `$NOTIFY_SOCKET`; does nothing outside systemd.
pub fn notify_ready() -> io::Result<()> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket = UnixDatagram::unbound()?;
    let bytes = path.as_encoded_bytes();
    #[cfg(target_os = "linux")]
    if let Some(name) = bytes.strip_prefix(b"@") {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
        return socket.send_to_addr(b"READY=1", &addr).map(drop);
    }
    let _ = bytes;
    socket.send_to(b"READY=1", &path).map(drop)
}

/// The listening socket passed by systemd (`LISTEN_FDS`, first descriptor 3) or, outside
/// socket activation, a socket bound at `path` by the daemon itself.
pub fn control_listener(path: &Path) -> io::Result<tokio::net::UnixListener> {
    let ours = std::env::var("LISTEN_PID").ok() == Some(std::process::id().to_string());
    let count: u32 = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    let listener = if ours && count >= 1 {
        // SAFETY: systemd passed descriptor 3 to this process, and nothing else owns it.
        unsafe { UnixListener::from_raw_fd(3) }
    } else {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let _ = std::fs::remove_file(path);
        UnixListener::bind(path)?
    };
    listener.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(listener)
}
