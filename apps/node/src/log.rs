//! Log lines in nisshi's log schema v1 (ADR 0019, amended 2026-10-20): one JSON object per
//! line on stderr, `v`, `ts`, `level`, `event`, `msg`, `err` first, then the event's fields.
//! Hand-written, as `tracing-subscriber`'s JSON formatter would need `serde_json` (ADR 0029).

use std::fmt::{self, Write as _};
use std::io::Write as _;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Written by the agent or the store, never by a service (log schema "Reserved"), plus the
/// envelope names this module writes itself.
const RESERVED: &[&str] = &[
    "node", "service", "stream", "seq", "source", "recv_ts", "v", "ts", "level", "msg",
];

/// Writes every `tracing` event as one schema line. An event names itself with an `event`
/// field (kebab-case); the format string, if any, becomes `msg`.
pub struct JsonLayer;

impl<S: Subscriber> Layer<S> for JsonLayer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        write(&format(event, &ts_now()));
    }
}

fn format(event: &Event<'_>, ts: &str) -> String {
    let mut line = Line::default();
    event.record(&mut line);
    let level = match *event.metadata().level() {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        _ => "debug", // the schema has no trace
    };
    line.render(ts, level)
}

/// The last line of a daemon that stops on an error (start-up, configuration, IO, panic).
pub fn fatal(err: &str) {
    let line = Line {
        event: Some("fatal".into()),
        err: Some(err.into()),
        ..Line::default()
    };
    write(&line.render(&ts_now(), "error"));
}

fn write(line: &str) {
    // A closed stderr must not kill the daemon.
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

#[derive(Default)]
struct Line {
    event: Option<String>,
    msg: Option<String>,
    err: Option<String>,
    /// `,"name":value` for each other field, in call order.
    fields: String,
}

impl Line {
    fn render(&self, ts: &str, level: &str) -> String {
        let mut out = format!(r#"{{"v":1,"ts":"{ts}","level":"{level}","event":"#);
        // A `tracing` event without a name (a dependency's) still yields a valid line.
        quote(&mut out, self.event.as_deref().unwrap_or("log"));
        if let Some(msg) = &self.msg {
            out.push_str(r#","msg":"#);
            quote(&mut out, msg);
        }
        if let Some(err) = &self.err {
            // The schema allows `err` only on warn and error.
            out.push_str(if matches!(level, "warn" | "error") {
                r#","err":"#
            } else {
                r#","error":"#
            });
            quote(&mut out, err);
        }
        out.push_str(&self.fields);
        out.push('}');
        out
    }

    fn raw(&mut self, field: &Field, value: &str) {
        self.key(field);
        self.fields.push_str(value);
    }

    fn key(&mut self, field: &Field) {
        let name = field.name();
        self.fields.push(',');
        if RESERVED.contains(&name) || name.starts_with('_') {
            quote(&mut self.fields, &format!("field-{name}"));
        } else {
            quote(&mut self.fields, name);
        }
        self.fields.push(':');
    }
}

impl Visit for Line {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "event" => self.event = Some(value.into()),
            "message" => self.msg = Some(value.into()),
            "err" => self.err = Some(value.into()),
            _ => {
                self.key(field);
                quote(&mut self.fields, value);
            }
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // `%x` fields and the format string arrive here; Debug of a Display wrapper is Display.
        self.record_str(field, &format!("{value:?}"));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.raw(field, if value { "true" } else { "false" });
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.raw(field, &value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.raw(field, &value.to_string());
    }
}

/// A JSON string literal: quotes, backslashes and control characters escaped.
fn quote(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn ts_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    ts_from(d.as_secs() as i64, d.subsec_nanos())
}

/// UTC, RFC 3339 with exactly 9 fractional digits; civil_from_days (Howard Hinnant), the
/// reference code of nisshi's log schema.
fn ts_from(secs: i64, nanos: u32) -> String {
    let (days, sod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{nanos:09}Z",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::prelude::*;

    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(ts_from(0, 0), "1970-01-01T00:00:00.000000000Z");
        // The log schema's example instant.
        assert_eq!(
            ts_from(1_792_397_643, 512_004_117),
            "2026-10-19T08:14:03.512004117Z"
        );
        assert_eq!(ts_from(951_782_400, 1), "2000-02-29T00:00:00.000000001Z");
        assert_eq!(ts_from(-1, 999_999_999), "1969-12-31T23:59:59.999999999Z");
        assert_eq!(ts_now().len(), 30);
    }

    #[test]
    fn escaping() {
        let mut out = String::new();
        quote(&mut out, "a\"b\\c\nd\u{1}é");
        assert_eq!(out, r#""a\"b\\c\nd\u0001é""#);
    }

    /// Lines produced through `tracing` with the layer installed.
    fn capture(emit: impl FnOnce()) -> Vec<String> {
        let lines = Arc::new(Mutex::new(Vec::new()));
        struct Capture(Arc<Mutex<Vec<String>>>);
        impl<S: Subscriber> Layer<S> for Capture {
            fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
                self.0.lock().unwrap().push(format(event, &ts_from(0, 0)));
            }
        }
        let subscriber = tracing_subscriber::registry().with(Capture(lines.clone()));
        tracing::subscriber::with_default(subscriber, emit);
        let lines = lines.lock().unwrap().clone();
        lines
    }

    #[test]
    fn schema_lines() {
        let lines = capture(|| {
            tracing::info!(
                event = "handshake-completed",
                peer = %"node-\"b\"",
                endpoint = Some(tracing::field::display("192.0.2.20:4802")),
                initiator = true
            );
            tracing::warn!(event = "endpoint-unresolved", peer = "b", err = %"no\nhost");
            tracing::info!(
                event = "x",
                err = "only on warn",
                node = "a",
                _hidden = 1u64
            );
            tracing::trace!(count = -3i64, "free text");
        });
        let ts = r#""ts":"1970-01-01T00:00:00.000000000Z""#;
        assert_eq!(
            lines,
            [
                format!(
                    r#"{{"v":1,{ts},"level":"info","event":"handshake-completed","peer":"node-\"b\"","endpoint":"192.0.2.20:4802","initiator":true}}"#
                ),
                format!(
                    r#"{{"v":1,{ts},"level":"warn","event":"endpoint-unresolved","err":"no\nhost","peer":"b"}}"#
                ),
                format!(
                    r#"{{"v":1,{ts},"level":"info","event":"x","error":"only on warn","field-node":"a","field-_hidden":1}}"#
                ),
                format!(
                    r#"{{"v":1,{ts},"level":"debug","event":"log","msg":"free text","count":-3}}"#
                ),
            ]
        );
    }
}
