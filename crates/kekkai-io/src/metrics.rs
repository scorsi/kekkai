//! `GET /metrics` on a loopback listener (ADR 0019, amended 2026-10-20): the HTTP side and
//! the text helpers shared by the daemons, each daemon renders its own families. A plain
//! thread with blocking IO: one local scraper, no HTTP crate (ADR 0029).

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

use crate::State;

/// Serves forever; a failed connection only loses that scrape.
pub fn serve(listener: TcpListener, state: &Mutex<State>, render: fn(&State) -> String) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if let Err(e) = answer(stream, state, render) {
            tracing::debug!(event = "metrics-scrape-failed", error = %e);
        }
    }
}

fn answer(
    mut stream: TcpStream,
    state: &Mutex<State>,
    render: fn(&State) -> String,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = [0u8; 4096];
    let mut n = 0;
    while n < buf.len() && !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf[n..])? {
            0 => break,
            r => n += r,
        }
    }
    let (status, body) = if buf[..n].starts_with(b"GET /metrics ") {
        let body = render(&state.lock().expect("no panic while holding the state"));
        ("200 OK", body)
    } else {
        ("404 Not Found", String::new())
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// `# HELP` and `# TYPE` lines of a family.
pub fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

/// A label value: `\`, `"` and newline escaped (a configured name may hold them).
pub fn label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// `kekkai_dropped_packets_total{reason}`, omitted until a drop happens.
pub fn drops(out: &mut String, state: &State) {
    if state.drops.is_empty() {
        return;
    }
    family(
        out,
        "kekkai_dropped_packets_total",
        "counter",
        "Datagrams and tunnel packets dropped, by kekkai-core DropReason.",
    );
    for (reason, n) in &state.drops {
        let _ = writeln!(
            out,
            "kekkai_dropped_packets_total{{reason=\"{reason}\"}} {n}"
        );
    }
}
