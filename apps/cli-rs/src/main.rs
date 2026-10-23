//! kekkai — the CLI (ADR 0015, 0033): `keygen` and `pubkey` run locally with kekkai-core's key
//! code, `status --json` is a thin gRPC client of a daemon's control socket. Same commands,
//! messages and exit codes as the Go CLI it replaces (apps/cli).

use std::error::Error;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use kekkai_control::v1::control_service_client::ControlServiceClient;
use kekkai_control::v1::{GetStatusRequest, GetStatusResponse};
use kekkai_core::keys::{StaticKey, public_key_to_text};
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions};
use serde_json::ser::{PrettyFormatter, Serializer};
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};

const USAGE: &str = "usage:
  kekkai keygen [FILE]   write a new private key to stdout, or to FILE in mode 0400
  kekkai pubkey          read a private key on stdin, print its public key
  kekkai status --json [--socket PATH]
                         print the node's status (protojson); --socket reads another
                         daemon's control socket, e.g. /run/kekkai-lighthouse/control.sock
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
        ["--version", ..] => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        ["keygen"] => keygen(None),
        ["keygen", file] => keygen(Some(file)),
        ["pubkey"] => pubkey(),
        ["status", "--json"] => status(CONTROL_SOCKET),
        ["status", "--json", "--socket", socket] => status(socket),
        [command, ..] => Err(format!("unknown command {command:?}\n{USAGE}")),
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
        return std::io::stdout()
            .write_all(line.as_bytes())
            .map_err(|e| lower(&e));
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
    println!("{}", public_key_to_text(&key.public()));
    Ok(())
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
    print!("{}", format_status(&reply)?);
    Ok(())
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
/// a final newline, byte for byte the Go CLI's `formatStatus` (checked by the tests below).
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

    /// ADR 0033: on the replies the Go CLI's status_test.go encodes, the output is the Go
    /// CLI's, byte for byte.
    #[test]
    fn status_matches_the_go_goldens() {
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
        let socket = std::env::temp_dir().join(format!("kekkai-cli-{}.sock", std::process::id()));
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
        let missing = run(&["status", "--json", "--socket", "/nonexistent/kekkai.sock"]);
        assert_eq!(
            missing.unwrap_err(),
            "dial unix /nonexistent/kekkai.sock: no such file or directory"
        );
    }

    #[test]
    fn arguments_follow_the_go_cli() {
        for args in [
            &[][..],
            &["status"],
            &["status", "--socket", "x"],
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
