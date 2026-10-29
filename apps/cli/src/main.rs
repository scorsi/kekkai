//! kekkai — the CLI (ADR 0015, 0033): `keygen` and `pubkey` run locally with kekkai-core's key
//! code, `status` is a thin gRPC client of a daemon's control socket. Same commands, messages
//! and exit codes as the Go CLI it replaced, except that `--json` is optional (the only format).
//! `ca keygen`, `ca pubkey`, `cert sign` and `cert show` (ADR 0034) run offline with kekkai-core's
//! certificate code; the CA private key only ever passes through pipes, to and from `age`.

use std::error::Error;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use kekkai_control::v1::control_service_client::ControlServiceClient;
use kekkai_control::v1::{GetStatusRequest, GetStatusResponse};
use kekkai_core::cert::{self, CaKey, Fields, Pki, Prefix, Reject};
use kekkai_core::keys::{StaticKey, public_key_from_text, public_key_to_text};
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions};
use serde_json::ser::{PrettyFormatter, Serializer};
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};

const USAGE: &str = "usage:
  kekkai keygen [FILE]   write a new private key to stdout, or to FILE in mode 0400
  kekkai pubkey          read a private key on stdin, print its public key
  kekkai status [--json] [--socket PATH]
                         print the node's status (protojson); --socket reads another
                         daemon's control socket, e.g. /run/kekkai-lighthouse/control.sock
  kekkai ca keygen       write a new CA private key to stdout (pipe it to age -e), its
                         public key to stderr
  kekkai ca pubkey       read a CA private key on stdin (from age -d), print its public
                         key
  kekkai cert sign --key PUBKEY --name NAME --address ADDR... [--group GROUP]...
                   [--days DAYS]
                         read the CA private key on stdin (from age -d), print a
                         certificate valid DAYS days (default 365), back-dated an hour
  kekkai cert show --ca CAKEY...
                         read a certificate on stdin, print its fields (dates in UTC,
                         RFC 3339), fingerprint and deny-list entries, and verify it
                         against CAKEY now
  kekkai --version";

/// The node's control socket (ADR 0015).
const CONTROL_SOCKET: &str = if cfg!(target_os = "macos") {
    "/var/run/kekkai/control.sock"
} else {
    "/run/kekkai/control.sock"
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args.iter().map(String::as_str).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kekkai: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[&str]) -> Result<(), String> {
    match args {
        [] => Err(format!("missing command\n{USAGE}")),
        ["--version", ..] => out(concat!(env!("CARGO_PKG_VERSION"), "\n")),
        ["keygen"] => keygen(None),
        ["keygen", file] => keygen(Some(file)),
        ["pubkey"] => pubkey(),
        ["ca", "keygen"] => ca_keygen(),
        ["ca", "pubkey"] => {
            let seed = ca_key(&read_stdin()?)?;
            out(&(public_key_to_text(&cert::ca_public(&seed)) + "\n"))
        }
        ["cert", "sign", options @ ..] => {
            let seed = read_stdin()?;
            out(&cert_sign(options, &seed, unix_now())?)
        }
        ["cert", "show", options @ ..] => {
            let (text, verdict) = cert_show(options, &read_stdin()?, unix_now())?;
            out(&text)?;
            verdict.map_err(|r| format!("certificate {}", r.as_str()))
        }
        ["status"] | ["status", "--json"] => status(CONTROL_SOCKET),
        ["status", "--socket", socket] | ["status", "--json", "--socket", socket] => status(socket),
        [command, ..] => Err(format!("unknown command {command:?}\n{USAGE}")),
    }
}

/// Writes to stdout. A closed reader (`kekkai status | head`) ends the command quietly, as
/// SIGPIPE did for the Go CLI, instead of the panic of `print!`; still a failure, so that
/// `keygen | …` never reports a key nobody received.
fn out(text: &str) -> Result<(), String> {
    match std::io::stdout().write_all(text.as_bytes()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(1),
        result => result.map_err(|e| lower(&e)),
    }
}

/// Go's wording for system errors ("permission denied"), which the nixosTests match.
fn lower(e: &dyn Error) -> String {
    let text = e.to_string();
    text.split(" (os error")
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

fn keygen(file: Option<&str>) -> Result<(), String> {
    let line = StaticKey::generate().to_text() + "\n";
    let Some(path) = file else {
        return out(&line);
    };
    // create_new: never overwrite an existing key.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)
        .map_err(|e| format!("open {path}: {}", lower(&e)))?
        .write_all(line.as_bytes())
        .map_err(|e| format!("write {path}: {}", lower(&e)))
}

fn pubkey() -> Result<(), String> {
    let mut text = String::new();
    std::io::stdin()
        .take(4096)
        .read_to_string(&mut text)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::InvalidData => "not a base64 32-byte key".to_string(),
            _ => lower(&e),
        })?;
    let key = StaticKey::from_file_text(text).ok_or("not a base64 32-byte key")?;
    out(&(public_key_to_text(&key.public()) + "\n"))
}

/// At most 4096 bytes of stdin, as `pubkey` reads.
fn read_stdin() -> Result<String, String> {
    let mut text = String::new();
    std::io::stdin()
        .take(4096)
        .read_to_string(&mut text)
        .map_err(|e| lower(&e))?;
    Ok(text)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

/// A new CA key: the 32-byte RFC 8032 seed (spec §4.2) in the key text form on stdout, never in
/// a file, so that it reaches the disk only encrypted (`kekkai ca keygen | age -e ...`). The
/// public key, for `[pki] ca_keys`, goes to stderr.
fn ca_keygen() -> Result<(), String> {
    let seed = ca_seed()?;
    out(&(public_key_to_text(&seed) + "\n"))?;
    eprintln!(
        "CA public key: {}",
        public_key_to_text(&cert::ca_public(&seed))
    );
    Ok(())
}

fn ca_seed() -> Result<[u8; 32], String> {
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|e| format!("/dev/urandom: {}", lower(&e)))?;
    Ok(seed)
}

/// The CA private key read on stdin: the seed in the key text form.
fn ca_key(text: &str) -> Result<[u8; 32], String> {
    Ok(public_key_from_text(text).ok_or("stdin: not a base64 32-byte CA key")?)
}

/// `cert sign`: the certificate's text form and a newline. The signer's rules are the core's
/// (spec §4.2); `not_before` is `now` minus an hour, `not_after` `now` plus the lifetime.
fn cert_sign(options: &[&str], seed: &str, now: u64) -> Result<String, String> {
    let (mut key, mut name, mut addresses, mut groups, mut days) =
        (None, None, Vec::new(), Vec::new(), 365u64);
    for pair in options.chunks(2) {
        let [option, value] = pair else {
            return Err(format!("missing value after {}\n{USAGE}", pair[0]));
        };
        match *option {
            "--key" => {
                key = Some(public_key_from_text(value).ok_or("--key: not a base64 32-byte key")?)
            }
            "--name" => name = Some(value.to_string()),
            "--address" => addresses.push(
                value
                    .parse::<IpAddr>()
                    .map_err(|_| format!("--address: not an IP address: {value}"))?,
            ),
            "--group" => groups.push(value.to_string()),
            "--days" => {
                days = value
                    .parse()
                    .ok()
                    .filter(|d| *d > 0)
                    .ok_or("--days: a whole number of days, at least 1")?
            }
            _ => return Err(format!("unknown option {option:?}\n{USAGE}")),
        }
    }
    let seed = ca_key(seed)?;
    let fields = Fields {
        public_key: key.ok_or("--key is required")?,
        name: name.ok_or("--name is required")?,
        addresses,
        groups,
        not_before: now.saturating_sub(3600),
        not_after: days
            .checked_mul(86_400)
            .and_then(|l| now.checked_add(l))
            .filter(|t| *t <= RFC3339_MAX)
            .ok_or("--days: not_after beyond 9999-12-31T23:59:59Z")?,
    };
    Ok(cert::to_text(&cert::sign(&seed, &fields)?) + "\n")
}

/// 9999-12-31T23:59:59Z, the last second RFC 3339 can write (spec §4.2 signer).
const RFC3339_MAX: u64 = 253_402_300_799;

/// Unix seconds as UTC RFC 3339 (protojson's form, as `status` prints times); a later value
/// (another signer's) as the raw seconds, marked.
fn rfc3339(secs: u64) -> String {
    if secs > RFC3339_MAX {
        return format!("{secs} (Unix seconds, out of RFC 3339 range)");
    }
    let seconds = i64::try_from(secs).expect("below RFC3339_MAX");
    prost_reflect::prost_types::Timestamp { seconds, nanos: 0 }.to_string()
}

/// `cert show`: the fields, the fingerprint, the two deny-list entries (spec §4.3 step 1) and
/// the verdict of §4.3 steps 4 to 8 against the given CA keys at `now`. A certificate that
/// fails verification is still printed, so that an expired one shows its `not_after`.
fn cert_show(
    options: &[&str],
    text: &str,
    now: u64,
) -> Result<(String, Result<(), Reject>), String> {
    let mut ca_keys = Vec::new();
    for pair in options.chunks(2) {
        match pair {
            ["--ca", value] => ca_keys.push(
                CaKey::from_text(value)
                    .map_err(|_| format!("--ca: not a valid CA key: {value}"))?,
            ),
            _ => return Err(format!("usage: kekkai cert show --ca CAKEY...\n{USAGE}")),
        }
    }
    if !(1..=kekkai_core::MAX_CA_KEYS).contains(&ca_keys.len()) {
        return Err("cert show: one or two --ca keys".into());
    }
    let certificate = cert::from_text(text).ok_or("stdin: not a base64 certificate")?;
    let body = (certificate.len() > 64 && certificate.len() <= kekkai_core::MAX_CERTIFICATE)
        .then(|| &certificate[..certificate.len() - 64])
        .ok_or("certificate bad_length")?;
    let fields = cert::parse_body(body).ok_or("certificate malformed")?;
    let fingerprint = cert::fingerprint(&certificate);
    let list = |items: Vec<String>| {
        if items.is_empty() {
            "-".into()
        } else {
            items.join(" ")
        }
    };
    let printed = format!(
        "name: {}\npublic_key: {}\naddresses: {}\ngroups: {}\nnot_before: {}\nnot_after: {}\n\
         fingerprint: {}\ndeny_key: key:{}\ndeny_cert: cert:{}\n",
        fields.name,
        public_key_to_text(&fields.public_key),
        list(fields.addresses.iter().map(IpAddr::to_string).collect()),
        list(fields.groups.clone()),
        rfc3339(fields.not_before),
        rfc3339(fields.not_after),
        public_key_to_text(&fingerprint),
        public_key_to_text(&fields.public_key),
        public_key_to_text(&fingerprint),
    );
    // Every address is inside `0.0.0.0/0` or `::/0`: prefixes are the verifying party's.
    let pki = Pki {
        ca_keys,
        certificate: Vec::new(),
        revoked: Vec::new(),
        prefixes: vec![
            Prefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).expect("0.0.0.0/0"),
            Prefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).expect("::/0"),
        ],
        max_peers: 1,
    };
    let verdict = pki
        .check(&certificate, &fields.public_key, Some(now))
        .map(drop);
    Ok((printed, verdict))
}

fn status(socket: &str) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| lower(&e))?;
    let reply = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(5), get_status(socket.to_string())).await
        })
        .map_err(|_| "context deadline exceeded".to_string())??;
    out(&format_status(&reply)?)
}

async fn get_status(socket: String) -> Result<GetStatusResponse, String> {
    let path = socket.clone();
    // The URI is required by tonic and unused: the connector dials the Unix socket.
    let channel = Endpoint::from_static("http://[::]:0")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .map_err(|e| {
            let mut cause: &dyn Error = &e;
            while let Some(source) = cause.source() {
                cause = source;
            }
            format!("dial unix {socket}: {}", lower(cause))
        })?;
    let reply = ControlServiceClient::new(channel)
        .get_status(GetStatusRequest {})
        .await
        .map_err(|status| status.to_string())?;
    Ok(reply.into_inner())
}

/// What `status --json` prints: protojson with the proto field names, two-space indent and
/// a final newline, byte for byte the Go CLI's `formatStatus` it replaced (checked by the tests
/// below).
fn format_status(reply: &GetStatusResponse) -> Result<String, String> {
    let pool =
        DescriptorPool::decode(kekkai_control::FILE_DESCRIPTOR_SET).map_err(|e| e.to_string())?;
    let descriptor = pool
        .get_message_by_name("kekkai.control.v1.GetStatusResponse")
        .ok_or("GetStatusResponse missing from the descriptor set")?;
    let message = DynamicMessage::decode(descriptor, reply.encode_to_vec().as_slice())
        .map_err(|e| e.to_string())?;
    let mut out = Serializer::with_formatter(Vec::new(), PrettyFormatter::with_indent(b"  "));
    message
        .serialize_with_options(
            &mut out,
            &SerializeOptions::new().use_proto_field_name(true),
        )
        .map_err(|e| e.to_string())?;
    let mut text = String::from_utf8(out.into_inner()).map_err(|e| e.to_string())?;
    text.push('\n');
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kekkai_control::v1::control_service_server::{ControlService, ControlServiceServer};

    const GOLDENS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/status");

    /// ADR 0033: on the committed replies (`*.binpb`), the output is the committed `*.json`, byte
    /// for byte. The first goldens were printed by the removed Go CLI; they are frozen, and a new
    /// fixture is written by hand and reviewed against protojson's JSON mapping, never generated
    /// by this code.
    #[test]
    fn status_matches_the_goldens() {
        let mut goldens = String::new();
        let mut count = 0;
        for entry in std::fs::read_dir(GOLDENS).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "binpb") {
                continue;
            }
            let wire = std::fs::read(&path).unwrap();
            let want = std::fs::read_to_string(path.with_extension("json")).unwrap();
            let reply = GetStatusResponse::decode(wire.as_slice()).unwrap();
            assert_eq!(format_status(&reply).unwrap(), want, "{}", path.display());
            goldens += &want;
            count += 1;
        }
        assert!(count >= 6, "goldens missing in {GOLDENS}");
        // Every field and enum value of the contract appears in a golden, so a proto change
        // without a new fixture fails here.
        let pool = DescriptorPool::decode(kekkai_control::FILE_DESCRIPTOR_SET).unwrap();
        for message in pool
            .all_messages()
            .filter(|m| m.package_name() == "kekkai.control.v1")
        {
            for field in message.fields() {
                let key = format!("\"{}\": ", field.name());
                assert!(
                    goldens.contains(&key),
                    "no golden shows {}",
                    field.full_name()
                );
            }
        }
        for e in pool
            .all_enums()
            .filter(|e| e.package_name() == "kekkai.control.v1")
        {
            for value in e.values().filter(|v| v.number() != 0) {
                let text = format!("\"{}\"", value.name());
                assert!(goldens.contains(&text), "no golden shows {}", value.name());
            }
        }
    }

    struct Fixed;

    #[tonic::async_trait]
    impl ControlService for Fixed {
        async fn get_status(
            &self,
            _: tonic::Request<GetStatusRequest>,
        ) -> Result<tonic::Response<GetStatusResponse>, tonic::Status> {
            let wire = std::fs::read(format!("{GOLDENS}/relay.binpb")).unwrap();
            Ok(tonic::Response::new(
                GetStatusResponse::decode(wire.as_slice()).unwrap(),
            ))
        }
    }

    /// The client half: a reply served on a Unix socket comes back intact.
    #[test]
    fn status_reads_a_unix_socket() {
        let socket = std::env::temp_dir().join(format!("kekkai-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let reply = runtime.block_on(async {
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            tokio::spawn(
                tonic::transport::Server::builder()
                    .add_service(ControlServiceServer::new(Fixed))
                    .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener)),
            );
            get_status(socket.to_str().unwrap().to_string()).await
        });
        std::fs::remove_file(&socket).unwrap();
        let want = std::fs::read_to_string(format!("{GOLDENS}/relay.json")).unwrap();
        assert_eq!(format_status(&reply.unwrap()).unwrap(), want);
        for args in [
            &["status", "--json", "--socket", "/nonexistent/kekkai.sock"][..],
            &["status", "--socket", "/nonexistent/kekkai.sock"],
        ] {
            assert_eq!(
                run(args).unwrap_err(),
                "dial unix /nonexistent/kekkai.sock: no such file or directory"
            );
        }
    }

    #[test]
    fn bad_arguments_are_refused() {
        for args in [
            &[][..],
            &["status", "--socket"],
            &["status", "--socket", "x", "--json"],
            &["pubkey", "x"],
            &["keygen", "a", "b"],
        ] {
            assert!(run(args).is_err(), "{args:?}");
        }
        assert!(
            run(&["nope"])
                .unwrap_err()
                .starts_with("unknown command \"nope\"\nusage:")
        );
    }

    #[test]
    fn keygen_writes_a_new_file_in_mode_0400_and_never_overwrites() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("kekkai-keygen-{}", std::process::id()));
        let path = path.to_str().unwrap();
        let _ = std::fs::remove_file(path);
        keygen(Some(path)).unwrap();
        let meta = std::fs::metadata(path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o400);
        let text = std::fs::read_to_string(path).unwrap();
        let key = StaticKey::from_text(&text).unwrap();
        assert!(text.ends_with('\n') && key.to_text() == key.clamped().to_text());
        assert!(keygen(Some(path)).unwrap_err().contains("file exists"));
        std::fs::remove_file(path).unwrap();
    }

    const NOW: u64 = 1_800_000_000;

    fn ca() -> (String, String) {
        let seed = [7u8; 32];
        (
            public_key_to_text(&seed) + "\n",
            public_key_to_text(&cert::ca_public(&seed)),
        )
    }

    fn sign_args<'a>(key: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
        let mut args = vec!["--key", key, "--name", "host-1", "--address", "10.0.0.1"];
        args.extend(extra);
        args
    }

    /// keygen -> sign -> show -> the core's identity function (ADR 0034).
    #[test]
    fn a_signed_certificate_shows_and_verifies() {
        assert!(run(&["ca", "keygen", "x"]).is_err());
        let seeds = [ca_seed().unwrap(), ca_seed().unwrap()];
        assert_ne!(seeds[0], seeds[1]);
        let (seed, ca_public) = ca_of(seeds[0]);
        let seed = seed + "\n";
        // `ca pubkey`: what `ca keygen` printed on stderr.
        assert_eq!(
            public_key_to_text(&cert::ca_public(&ca_key(&seed).unwrap())),
            ca_public
        );
        assert!(ca_key("not a key").is_err());
        let node = StaticKey::generate().public();
        let node_text = public_key_to_text(&node);
        let extra = ["--address", "fd00::1", "--group", "b", "--group", "a"];
        let text = cert_sign(&sign_args(&node_text, &extra), &seed, NOW).unwrap();
        assert!(text.ends_with('\n') && !text.trim_end().contains('\n'));
        let certificate = cert::from_text(&text).unwrap();
        let fingerprint = public_key_to_text(&cert::fingerprint(&certificate));
        let (shown, verdict) = cert_show(&["--ca", &ca_public], &text, NOW).unwrap();
        assert_eq!(verdict, Ok(()));
        let year = NOW + 365 * 86_400;
        assert_eq!(
            shown,
            format!(
                "name: host-1\npublic_key: {node_text}\naddresses: 10.0.0.1 fd00::1\n\
                 groups: a b\nnot_before: 2027-01-15T07:00:00Z\nnot_after: 2028-01-15T08:00:00Z\n\
                 fingerprint: {fingerprint}\n\
                 deny_key: key:{node_text}\ndeny_cert: cert:{fingerprint}\n"
            )
        );
        let pki = Pki {
            ca_keys: vec![CaKey::from_text(&ca_public).unwrap()],
            certificate: Vec::new(),
            revoked: Vec::new(),
            prefixes: vec![
                Prefix::new("10.0.0.0".parse().unwrap(), 8).unwrap(),
                Prefix::new("fd00::".parse().unwrap(), 8).unwrap(),
            ],
            max_peers: 1,
        };
        let verified = pki.verify(&node, Some(&certificate), false, NOW).unwrap();
        assert_eq!(verified.record.unwrap().fields.not_after, year);
        // The deny-list forms are what `[pki] revoked` accepts and they revoke it.
        for entry in [format!("key:{node_text}"), format!("cert:{fingerprint}")] {
            let revoked = Pki {
                revoked: vec![entry.parse().unwrap()],
                ..pki.clone()
            };
            assert_eq!(
                revoked
                    .verify(&node, Some(&certificate), false, NOW)
                    .unwrap_err(),
                Reject::Revoked
            );
        }
        // Lifetime, then the show verdicts: expired, another CA, not a certificate.
        let short = cert_sign(&sign_args(&node_text, &["--days", "2"]), &seed, NOW).unwrap();
        let (shown, verdict) = cert_show(&["--ca", &ca_public], &short, NOW + 2 * 86_400).unwrap();
        assert!(
            shown.contains("not_after: 2027-01-17T08:00:00Z\n"),
            "{shown}"
        );
        assert_eq!(verdict, Err(Reject::Expired));
        let (_, other) = ca_of([9; 32]);
        assert_eq!(
            cert_show(&["--ca", &other], &text, NOW).unwrap().1,
            Err(Reject::BadSignature)
        );
        assert!(cert_show(&["--ca", &ca_public], "not base64!", NOW).is_err());
        assert!(cert_show(&[], &text, NOW).is_err());
        let oversize = cert::to_text(&[0; kekkai_core::MAX_CERTIFICATE + 1]);
        assert_eq!(
            cert_show(&["--ca", &ca_public], &oversize, NOW).unwrap_err(),
            "certificate bad_length"
        );
        assert!(cert_show(&["--ca", "AAAA"], &text, NOW).is_err());
        // Beyond year 9999: `cert sign` refuses it, `cert show` prints the raw seconds.
        let err = cert_sign(&sign_args(&node_text, &["--days", "3000000"]), &seed, NOW);
        assert_eq!(
            err.unwrap_err(),
            "--days: not_after beyond 9999-12-31T23:59:59Z"
        );
        assert_eq!(rfc3339(RFC3339_MAX), "9999-12-31T23:59:59Z");
        assert_eq!(
            rfc3339(RFC3339_MAX + 1),
            "253402300800 (Unix seconds, out of RFC 3339 range)"
        );
        let mut fields = cert::parse_body(&certificate[..certificate.len() - 64]).unwrap();
        fields.not_after = u64::MAX;
        let huge = cert::to_text(&cert::sign(&ca_key(&seed).unwrap(), &fields).unwrap());
        let (shown, verdict) = cert_show(&["--ca", &ca_public], &huge, NOW).unwrap();
        assert!(
            shown.contains(
                "not_after: 18446744073709551615 (Unix seconds, out of RFC 3339 range)\n"
            ),
            "{shown}"
        );
        assert_eq!(verdict, Ok(()));
    }

    fn ca_of(seed: [u8; 32]) -> (String, String) {
        (
            public_key_to_text(&seed),
            public_key_to_text(&cert::ca_public(&seed)),
        )
    }

    /// A failed `age -d` (wrong passphrase or identity) leaves stdin empty or partial; the
    /// signer refuses it, and every field the signer's rules refuse (spec §4.2).
    #[test]
    fn cert_sign_refuses_a_bad_ca_key_and_bad_fields() {
        let (seed, _) = ca();
        let key = public_key_to_text(&StaticKey::generate().public());
        for bad_seed in ["", "age: error: no identity matched\n", &seed[..20]] {
            assert_eq!(
                cert_sign(&sign_args(&key, &[]), bad_seed, NOW).unwrap_err(),
                "stdin: not a base64 32-byte CA key"
            );
        }
        let five: Vec<String> = (1..=5).map(|i| format!("10.0.0.{}", i + 1)).collect();
        let mut too_many = vec![];
        for a in &five {
            too_many.extend(["--address", a.as_str()]);
        }
        let groups: Vec<String> = (0..17).map(|i| format!("g{i}")).collect();
        let mut too_many_groups = vec![];
        for g in &groups {
            too_many_groups.extend(["--group", g.as_str()]);
        }
        let refused = [
            vec!["--days", "0"],
            vec!["--days", "-1"],
            vec!["--days", "999999999999999"],
            vec!["--name", "-bad"],
            too_many,
            too_many_groups,
            vec!["--group", "UPPER"],
            vec!["--address", "10.0.0.1"],
            vec!["--key"],
            vec!["--color", "red"],
        ];
        for extra in refused {
            assert!(
                cert_sign(&sign_args(&key, &extra), &seed, NOW).is_err(),
                "{extra:?}"
            );
        }
        assert!(cert_sign(&["--name", "x", "--address", "10.0.0.1"], &seed, NOW).is_err());
        // The largest certificate the signer's rules allow stays within MAX_CERTIFICATE, and
        // an inverted window is refused by the same core signer `cert sign` calls.
        let mut largest = Fields {
            name: "n".repeat(63),
            public_key: [1; 32],
            addresses: (1..=4u16)
                .map(|i| IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, i)))
                .collect(),
            groups: (0..16).map(|i| format!("{i:0>32}")).collect(),
            not_before: NOW,
            not_after: NOW + 1,
        };
        let seed = public_key_from_text(&seed).unwrap();
        assert!(cert::sign(&seed, &largest).unwrap().len() <= kekkai_core::MAX_CERTIFICATE);
        largest.not_after = NOW;
        assert_eq!(
            cert::sign(&seed, &largest).unwrap_err(),
            "not_before must be before not_after"
        );
    }

    /// The shared vectors (ADR 0015), through the core functions `pubkey` calls.
    #[test]
    fn pubkey_passes_the_shared_vectors() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/spec/vectors/keygen.json"
        ))
        .unwrap();
        let vectors: serde_json::Value = serde_json::from_str(&raw).unwrap();
        for k in vectors["keys"].as_array().unwrap() {
            let private = k["private_key_base64"].as_str().unwrap();
            let key = StaticKey::from_file_text(format!("{private}\n")).unwrap();
            assert_eq!(public_key_to_text(&key.public()), k["public_key_base64"]);
        }
    }
}
