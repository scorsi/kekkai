//! The two systemd protocols the node speaks, on the standard library (ADR 0029): `READY=1`
//! for `Type=notify` (ADR 0018, 0019), `RELOADING=1` around a reload (ADR 0026), and the control socket inherited from a `.socket` unit,
//! which systemd creates `root:kekkai 0660` before the unprivileged daemon starts (ADR 0015).

use std::ffi::CString;
use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixDatagram, UnixListener};
use std::path::Path;

/// Sends `READY=1` to `$NOTIFY_SOCKET`; does nothing outside systemd.
pub fn notify_ready() -> io::Result<()> {
    notify("READY=1")
}

/// Sends `state` (`READY=1`, `RELOADING=1`) to `$NOTIFY_SOCKET`; does nothing outside systemd.
pub fn notify(state: &str) -> io::Result<()> {
    let state = state.as_bytes();
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket = UnixDatagram::unbound()?;
    let bytes = path.as_encoded_bytes();
    #[cfg(target_os = "linux")]
    if let Some(name) = bytes.strip_prefix(b"@") {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
        return socket.send_to_addr(state, &addr).map(drop);
    }
    let _ = bytes;
    socket.send_to(state, &path).map(drop)
}

/// The listening socket passed by systemd (`LISTEN_FDS`, first descriptor 3) or, outside
/// socket activation (macOS, a manual run), a socket bound at `path` by the daemon itself,
/// mode 0660 and owned by `group` when that group exists (ADR 0015).
pub fn control_listener(path: &Path, group: &str) -> io::Result<tokio::net::UnixListener> {
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
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        if let Some(gid) = group_id(group) {
            std::os::unix::fs::chown(path, None, Some(gid))?;
        }
        listener
    };
    listener.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(listener)
}

fn group_id(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    // SAFETY: name is a valid C string; the result is read before any other getgr* call.
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    // SAFETY: a non-null result points at a valid group entry.
    (!group.is_null()).then(|| unsafe { (*group).gr_gid })
}
