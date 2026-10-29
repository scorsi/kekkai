//! The test vectors of `docs/spec/vectors/` (§19). Every file is loaded, every output in it is
//! recomputed from the inputs it lists, and the file must reproduce byte for byte. This suite
//! is the generator of record: `KEKKAI_WRITE_VECTORS=1 cargo test` rewrites the files (except
//! the published Noise vector) and the diff is reviewed with the spec change.

use std::net::IpAddr;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::cert;
use crate::handshake::{self, Initiator, SessionKeys};
use crate::inner::{Endpoint, Inner};
use crate::keys::{PublicKey, StaticKey, public_key_from_text, public_key_to_text};
use crate::mac1::Mac1Key;
use crate::session::{ReplayWindow, Role, Session};
use crate::tai64n::Tai64n;
use crate::tlv::{self, Tlv};
use crate::wire::{self, DropReason, Outer};
use crate::{
    COUNTER_WINDOW_SIZE, PROLOGUE, PSK, REJECT_AFTER_MESSAGES, TAI64N_NSEC_ALIGN, WIRE_VERSION,
    inner,
};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/spec/vectors/");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    unhex(s)
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("expected {N} bytes, got {}", v.len()))
}

fn load<T: DeserializeOwned>(file: &str) -> (String, T) {
    let path = format!("{DIR}{file}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
    (text, value)
}

/// Loads `file`, recomputes its outputs with `regenerate`, and checks (or writes) the file.
fn vector<T: Serialize + DeserializeOwned>(file: &str, regenerate: impl FnOnce(T) -> T) {
    let (text, loaded) = load::<T>(file);
    let mut produced = serde_json::to_string_pretty(&regenerate(loaded)).expect("serializable");
    produced.push('\n');
    if std::env::var_os("KEKKAI_WRITE_VECTORS").is_some() {
        std::fs::write(format!("{DIR}{file}"), produced).expect("write vector");
        return;
    }
    if produced != text {
        let line = produced
            .lines()
            .zip(text.lines())
            .position(|(a, b)| a != b)
            .map_or(0, |i| i + 1);
        let got = produced
            .lines()
            .nth(line.saturating_sub(1))
            .unwrap_or("<end>");
        let want = text.lines().nth(line.saturating_sub(1)).unwrap_or("<end>");
        panic!(
            "{file} does not reproduce at line {line}:\n  file:      {want}\n  computed:  {got}\n\
             If the spec changed, regenerate with KEKKAI_WRITE_VECTORS=1 and review the diff."
        );
    }
}

/// §19: a 64-bit counter is a decimal string in the files, exact in any JSON reader.
mod decimal {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// §19: no vector file carries a JSON number a double cannot hold exactly.
#[test]
fn no_json_number_above_2_pow_53() {
    const MAX: u64 = (1 << 53) - 1;
    fn walk(file: &str, v: &serde_json::Value) {
        match v {
            serde_json::Value::Number(n) => assert!(
                n.as_u64().is_some_and(|n| n <= MAX)
                    || n.as_i64().is_some_and(|n| n.unsigned_abs() <= MAX),
                "{file}: JSON number {n} is not exact as a double; write it as a decimal string"
            ),
            serde_json::Value::Array(a) => a.iter().for_each(|v| walk(file, v)),
            serde_json::Value::Object(o) => o.values().for_each(|v| walk(file, v)),
            _ => {}
        }
    }
    let mut files = 0;
    for entry in std::fs::read_dir(DIR).expect("vector directory") {
        let path = entry.expect("entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("UTF-8 name");
        if name.ends_with(".json") {
            walk(name, &load::<serde_json::Value>(name).1);
            files += 1;
        }
    }
    assert_eq!(files, 8, "every vector file is checked");
}

// --- keygen.json (§4) ---

#[derive(Serialize, Deserialize)]
struct Keygen {
    description: String,
    keys: Vec<KeygenKey>,
    clamping: Clamping,
}

#[derive(Serialize, Deserialize)]
struct KeygenKey {
    name: String,
    private_key: String,
    private_key_clamped: String,
    public_key: String,
    private_key_base64: String,
    public_key_base64: String,
}

#[derive(Serialize, Deserialize)]
struct Clamping {
    name: String,
    note: String,
    random_bytes: String,
    private_key: String,
    public_key: String,
    public_key_of_unclamped_input: String,
}

#[test]
fn keygen() {
    vector("keygen.json", |mut v: Keygen| {
        for k in &mut v.keys {
            let sk = StaticKey::from_bytes(arr(&k.private_key));
            let pk = sk.public();
            k.private_key_clamped = hex(sk.clamped().as_bytes());
            k.public_key = hex(&pk);
            k.private_key_base64 = sk.to_text();
            k.public_key_base64 = public_key_to_text(&pk);
            assert_eq!(
                sk.clamped().public(),
                pk,
                "{}: clamping changes the public key",
                k.name
            );
            assert_eq!(
                StaticKey::from_text(&k.private_key_base64)
                    .unwrap()
                    .as_bytes(),
                sk.as_bytes()
            );
            assert_eq!(public_key_from_text(&k.public_key_base64), Some(pk));
        }
        let c = &mut v.clamping;
        let raw = StaticKey::from_bytes(arr(&c.random_bytes));
        let sk = raw.clamped();
        c.private_key = hex(sk.as_bytes());
        c.public_key = hex(&sk.public());
        c.public_key_of_unclamped_input = hex(&raw.public());
        v
    });
    let generated = StaticKey::generate();
    assert_eq!(
        generated.clamped().as_bytes(),
        generated.as_bytes(),
        "keygen writes clamped keys"
    );
    assert!(StaticKey::from_text("not a key").is_none());
}

// --- tai64n.json (§7.4) ---

#[derive(Serialize, Deserialize)]
struct Tai64nFile {
    description: String,
    nanosecond_alignment: u32,
    cases: Vec<Tai64nCase>,
    comparisons: Vec<Tai64nComparison>,
}

#[derive(Serialize, Deserialize)]
struct Tai64nCase {
    name: String,
    unix_seconds: u64,
    nanoseconds: u32,
    tai64n: String,
}

#[derive(Serialize, Deserialize)]
struct Tai64nComparison {
    last_accepted: String,
    received: String,
    accept: bool,
}

#[test]
fn tai64n() {
    vector("tai64n.json", |mut v: Tai64nFile| {
        v.nanosecond_alignment = TAI64N_NSEC_ALIGN;
        for c in &mut v.cases {
            c.tai64n = hex(&Tai64n::from_unix(c.unix_seconds, c.nanoseconds).0);
        }
        for c in &mut v.comparisons {
            c.accept = Tai64n(arr(&c.received)).is_newer_than(&Tai64n(arr(&c.last_accepted)));
        }
        v
    });
}

// --- tlv.json (§6) ---

#[derive(Serialize, Deserialize)]
struct TlvFile {
    description: String,
    critical_bit: u8,
    encode: Vec<TlvEncode>,
    decode: Vec<TlvDecode>,
    message_1_v0_known_tlvs: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct TlvEncode {
    name: String,
    tlvs: Vec<TlvJson>,
    bytes: String,
}

#[derive(Serialize, Deserialize)]
struct TlvJson {
    #[serde(rename = "type")]
    ty: u8,
    value: String,
}

#[derive(Serialize, Deserialize)]
struct TlvDecode {
    name: String,
    bytes: String,
    result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    known_tlvs: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[test]
fn tlv() {
    vector("tlv.json", |mut v: TlvFile| {
        v.critical_bit = tlv::CRITICAL;
        v.message_1_v0_known_tlvs = handshake::MESSAGE_1_KNOWN_TLVS.to_vec();
        for e in &mut v.encode {
            let values: Vec<Vec<u8>> = e.tlvs.iter().map(|t| unhex(&t.value)).collect();
            let tlvs: Vec<Tlv<'_>> = e
                .tlvs
                .iter()
                .zip(&values)
                .map(|(t, value)| Tlv { ty: t.ty, value })
                .collect();
            let mut bytes = Vec::new();
            tlv::encode(&tlvs, &mut bytes);
            e.bytes = hex(&bytes);
            assert_eq!(
                tlv::decode(&bytes, &[1, 5, 7, 129]).unwrap(),
                tlvs,
                "{}: round trip",
                e.name
            );
        }
        for d in &mut v.decode {
            let known = d.known_tlvs.clone().unwrap_or_default();
            match tlv::decode(&unhex(&d.bytes), &known) {
                Ok(tlvs) => {
                    assert!(
                        tlvs.iter().all(|t| known.contains(&t.ty)),
                        "{}: only known TLVs come back",
                        d.name
                    );
                    d.result = "ok".into();
                    d.error = None;
                }
                Err(e) => {
                    d.result = "error".into();
                    d.error = Some(e.as_str().into());
                }
            }
        }
        v
    });
}

// --- wire.json (§5.6, §10, §18) ---

#[derive(Serialize, Deserialize)]
struct WireFile {
    description: String,
    wire_version: u8,
    outer_types: OuterTypes,
    inner_types: InnerTypes,
    lighthouse_tlv_types: LighthouseTlvTypes,
    handshake_tlv_types: HandshakeTlvTypes,
    endpoints: Vec<EndpointCase>,
    outer_headers: Vec<OuterHeaderCase>,
    inner_messages: Vec<InnerMessageCase>,
}

#[derive(Serialize, Deserialize)]
struct OuterTypes {
    handshake_init: u8,
    handshake_resp: u8,
    cookie_reply: u8,
    data: u8,
}

#[derive(Serialize, Deserialize)]
struct InnerTypes {
    ip_packet: u8,
    keepalive: u8,
    lighthouse_register: u8,
    lighthouse_query: u8,
    lighthouse_query_reply: u8,
    lighthouse_punch: u8,
    relay_forward: u8,
    relay_forwarded: u8,
}

#[derive(Serialize, Deserialize)]
struct LighthouseTlvTypes {
    pubkey: u8,
    endpoints: u8,
    last_seen: u8,
}

#[derive(Serialize, Deserialize)]
struct HandshakeTlvTypes {
    timestamp: u8,
}

#[derive(Serialize, Deserialize)]
struct EndpointCase {
    address: String,
    port: u16,
    bytes: String,
}

#[derive(Serialize, Deserialize)]
struct OuterHeaderCase {
    name: String,
    bytes: String,
    result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fields: Option<DataFields>,
}

#[derive(Serialize, Deserialize)]
struct DataFields {
    #[serde(rename = "type")]
    ty: u8,
    version: u8,
    receiver_index: u32,
    #[serde(with = "decimal")]
    counter: u64,
}

#[derive(Serialize, Deserialize)]
struct InnerMessageCase {
    name: String,
    inner_type: u8,
    body: String,
    plaintext: String,
}

#[test]
fn wire() {
    vector("wire.json", |mut v: WireFile| {
        v.wire_version = WIRE_VERSION;
        v.outer_types = OuterTypes {
            handshake_init: wire::TYPE_HANDSHAKE_INIT,
            handshake_resp: wire::TYPE_HANDSHAKE_RESP,
            cookie_reply: wire::TYPE_COOKIE_REPLY,
            data: wire::TYPE_DATA,
        };
        v.inner_types = InnerTypes {
            ip_packet: inner::IP_PACKET,
            keepalive: inner::KEEPALIVE,
            lighthouse_register: inner::LIGHTHOUSE_REGISTER,
            lighthouse_query: inner::LIGHTHOUSE_QUERY,
            lighthouse_query_reply: inner::LIGHTHOUSE_QUERY_REPLY,
            lighthouse_punch: inner::LIGHTHOUSE_PUNCH,
            relay_forward: inner::RELAY_FORWARD,
            relay_forwarded: inner::RELAY_FORWARDED,
        };
        v.lighthouse_tlv_types = LighthouseTlvTypes {
            pubkey: inner::TLV_PUBKEY,
            endpoints: inner::TLV_ENDPOINTS,
            last_seen: inner::TLV_LAST_SEEN,
        };
        v.handshake_tlv_types = HandshakeTlvTypes {
            timestamp: handshake::TLV_TIMESTAMP,
        };
        for e in &mut v.endpoints {
            let address: IpAddr = e.address.parse().expect("address");
            e.bytes = hex(&Endpoint::new(address, e.port).encode());
        }
        for h in &mut v.outer_headers {
            match wire::parse(&unhex(&h.bytes)) {
                Ok(Outer::Data(d)) => {
                    h.result = "ok".into();
                    h.reason = None;
                    h.fields = Some(DataFields {
                        ty: wire::TYPE_DATA,
                        version: WIRE_VERSION,
                        receiver_index: d.receiver_index,
                        counter: d.counter,
                    });
                }
                Ok(_) => panic!("{}: the vectors only hold data headers", h.name),
                Err(reason) => {
                    h.result = "drop".into();
                    h.reason = Some(reason.as_str().into());
                    h.fields = None;
                }
            }
        }
        for m in &mut v.inner_messages {
            let mut plaintext = vec![m.inner_type];
            plaintext.extend(unhex(&m.body));
            let decoded = Inner::decode(&plaintext).unwrap_or_else(|e| panic!("{}: {e:?}", m.name));
            assert_eq!(decoded.inner_type(), m.inner_type, "{}", m.name);
            assert_eq!(decoded.encode(), plaintext, "{}: round trip", m.name);
            m.plaintext = hex(&plaintext);
        }
        v
    });
    assert_eq!(Inner::decode(&[9]), Err(DropReason::InnerUnknownType));
    assert_eq!(
        Inner::decode(&[inner::IP_PACKET, 0x50]),
        Err(DropReason::InnerMalformed)
    );
    assert_eq!(
        Inner::decode(&[inner::LIGHTHOUSE_QUERY]),
        Err(DropReason::InnerMalformed),
        "pubkey is required"
    );
    assert_eq!(
        Inner::decode(&[inner::RELAY_FORWARD; 36]),
        Err(DropReason::InnerMalformed),
        "payload shorter than 4"
    );
}

// --- replay.json (§8.4) ---

#[derive(Serialize, Deserialize)]
struct ReplayFile {
    description: String,
    counter_window_size: u64,
    reject_after_messages: String,
    sequence: Vec<ReplayStep>,
}

#[derive(Serialize, Deserialize)]
struct ReplayStep {
    counter: String,
    accept: bool,
}

#[test]
fn replay() {
    vector("replay.json", |mut v: ReplayFile| {
        v.counter_window_size = COUNTER_WINDOW_SIZE;
        v.reject_after_messages = REJECT_AFTER_MESSAGES.to_string();
        let mut window = ReplayWindow::new();
        for step in &mut v.sequence {
            let counter: u64 = step.counter.parse().expect("counter");
            step.accept = window.check(counter);
            if step.accept {
                window.mark(counter);
            }
        }
        v
    });
}

// --- noise_ikpsk2.json (§7.1): the published vector, checked with snow, never regenerated ---

#[derive(Deserialize)]
struct NoiseVector {
    init_prologue: String,
    init_psks: Vec<String>,
    init_static: String,
    init_ephemeral: String,
    init_remote_static: String,
    resp_prologue: String,
    resp_psks: Vec<String>,
    resp_static: String,
    resp_ephemeral: String,
    handshake_hash: String,
    messages: Vec<NoiseMessage>,
}

#[derive(Deserialize)]
struct NoiseMessage {
    payload: String,
    ciphertext: String,
}

#[test]
fn noise_ikpsk2() {
    let (_, v) = load::<NoiseVector>("noise_ikpsk2.json");
    // Through kekkai's resolver: this vector is its correctness check (§8.5).
    let builder = || {
        let params = crate::NOISE_PATTERN.parse().unwrap();
        snow::Builder::with_resolver(params, Box::new(crate::resolver::Resolver))
    };
    let (init_prologue, resp_prologue) = (unhex(&v.init_prologue), unhex(&v.resp_prologue));
    let (init_psk, resp_psk): ([u8; 32], [u8; 32]) = (arr(&v.init_psks[0]), arr(&v.resp_psks[0]));
    let (init_static, resp_static) = (unhex(&v.init_static), unhex(&v.resp_static));
    let (init_ephemeral, resp_ephemeral) = (unhex(&v.init_ephemeral), unhex(&v.resp_ephemeral));
    let remote_static = unhex(&v.init_remote_static);
    let mut initiator = builder()
        .prologue(&init_prologue)
        .unwrap()
        .psk(2, &init_psk)
        .unwrap()
        .local_private_key(&init_static)
        .unwrap()
        .remote_public_key(&remote_static)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&init_ephemeral)
        .build_initiator()
        .unwrap();
    let mut responder = builder()
        .prologue(&resp_prologue)
        .unwrap()
        .psk(2, &resp_psk)
        .unwrap()
        .local_private_key(&resp_static)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&resp_ephemeral)
        .build_responder()
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let mut out = vec![0u8; 1024];
    for (i, m) in v.messages.iter().take(2).enumerate() {
        let (writer, reader) = if i % 2 == 0 {
            (&mut initiator, &mut responder)
        } else {
            (&mut responder, &mut initiator)
        };
        let n = writer.write_message(&unhex(&m.payload), &mut buf).unwrap();
        assert_eq!(hex(&buf[..n]), m.ciphertext, "handshake message {i}");
        let n = reader.read_message(&buf[..n], &mut out).unwrap();
        assert_eq!(hex(&out[..n]), m.payload);
    }
    assert_eq!(hex(initiator.get_handshake_hash()), v.handshake_hash);
    assert_eq!(hex(responder.get_handshake_hash()), v.handshake_hash);
    let mut initiator = initiator.into_transport_mode().unwrap();
    let mut responder = responder.into_transport_mode().unwrap();
    for (i, m) in v.messages.iter().enumerate().skip(2) {
        let (writer, reader) = if i % 2 == 0 {
            (&mut initiator, &mut responder)
        } else {
            (&mut responder, &mut initiator)
        };
        let n = writer.write_message(&unhex(&m.payload), &mut buf).unwrap();
        assert_eq!(hex(&buf[..n]), m.ciphertext, "transport message {i}");
        let n = reader.read_message(&buf[..n], &mut out).unwrap();
        assert_eq!(hex(&out[..n]), m.payload);
    }
}

// --- handshake.json (§5, §7, §8.2) ---

#[derive(Serialize, Deserialize)]
struct HandshakeFile {
    description: String,
    noise_protocol: String,
    wire_version: u8,
    prologue: String,
    psk: String,
    initiator: Party,
    responder: Party,
    timestamp: Timestamp,
    message_1: Message,
    message_2: Message,
    handshake_hash: String,
    transport_keys: TransportKeys,
    data_packets: Vec<DataPacket>,
    rejected: Vec<Rejected>,
}

#[derive(Serialize, Deserialize)]
struct Party {
    static_private: String,
    static_public: String,
    ephemeral_private: String,
    ephemeral_public: String,
    sender_index: u32,
}

#[derive(Serialize, Deserialize)]
struct Timestamp {
    unix_seconds: u64,
    nanoseconds: u32,
    tai64n: String,
}

#[derive(Serialize, Deserialize)]
struct Message {
    payload_tlvs: String,
    noise_message: String,
    mac1_key: String,
    mac1: String,
    datagram: String,
}

#[derive(Serialize, Deserialize)]
struct TransportKeys {
    initiator_to_responder: String,
    responder_to_initiator: String,
}

#[derive(Serialize, Deserialize)]
struct DataPacket {
    name: String,
    direction: String,
    #[serde(with = "decimal")]
    counter: u64,
    inner_type: u8,
    body: String,
    receiver_index: u32,
    datagram: String,
}

#[derive(Serialize, Deserialize)]
struct Rejected {
    name: String,
    datagram: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    after: Option<String>,
    reason: String,
}

/// The responder's receive path for one datagram (§5.6, then §7.6 or §8.2), as a party
/// would run it; used to compute the `reason` of each rejected vector.
fn responder_receive(
    datagram: &[u8],
    responder: &StaticKey,
    initiator_static: &PublicKey,
    last_timestamp: &Tai64n,
    session: &mut Session,
) -> Result<(), DropReason> {
    match wire::parse(datagram)? {
        Outer::HandshakeInit(init) => {
            init.verify_mac1(&Mac1Key::for_receiver(&responder.public()))?;
            let pending = handshake::read_init(responder, &init, &vec![*initiator_static])?;
            if !pending.timestamp.is_newer_than(last_timestamp) {
                return Err(DropReason::TimestampNotNewer);
            }
            Ok(())
        }
        Outer::HandshakeResp(_) => panic!("a responder does not receive message 2 here"),
        Outer::Data(data) => {
            assert_eq!(data.receiver_index, session.local_index);
            session
                .open(Duration::ZERO, data.counter, data.ciphertext)
                .map(drop)
        }
    }
}

#[test]
fn handshake() {
    vector("handshake.json", |mut v: HandshakeFile| {
        v.noise_protocol = crate::NOISE_PATTERN.into();
        v.wire_version = WIRE_VERSION;
        v.prologue = hex(PROLOGUE);
        v.psk = hex(&PSK);
        let init_key = StaticKey::from_bytes(arr(&v.initiator.static_private));
        let resp_key = StaticKey::from_bytes(arr(&v.responder.static_private));
        let (init_pub, resp_pub) = (init_key.public(), resp_key.public());
        v.initiator.static_public = hex(&init_pub);
        v.responder.static_public = hex(&resp_pub);
        let init_eph: [u8; 32] = arr(&v.initiator.ephemeral_private);
        let resp_eph: [u8; 32] = arr(&v.responder.ephemeral_private);
        v.initiator.ephemeral_public = hex(&StaticKey::from_bytes(init_eph).public());
        v.responder.ephemeral_public = hex(&StaticKey::from_bytes(resp_eph).public());
        let timestamp = Tai64n::from_unix(v.timestamp.unix_seconds, v.timestamp.nanoseconds);
        v.timestamp.tai64n = hex(&timestamp.0);
        let (init_index, resp_index) = (v.initiator.sender_index, v.responder.sender_index);

        // Message 1.
        let (mut initiator, datagram_1) =
            Initiator::with_ephemeral(&init_key, &resp_pub, init_index, timestamp, Some(&init_eph));
        let mut payload = Vec::new();
        tlv::encode(
            &[Tlv {
                ty: handshake::TLV_TIMESTAMP,
                value: &timestamp.0,
            }],
            &mut payload,
        );
        let mac1_key = Mac1Key::for_receiver(&resp_pub);
        v.message_1 = describe_message(&datagram_1, 8, &payload, &mac1_key);
        assert_eq!(datagram_1.len(), 151);

        // Message 2, through the responder's own path.
        let Outer::HandshakeInit(init) = wire::parse(&datagram_1).unwrap() else {
            panic!("message 1")
        };
        init.verify_mac1(&mac1_key).unwrap();
        let pending =
            handshake::read_init_with(&resp_key, &init, &vec![init_pub], Some(&resp_eph)).unwrap();
        assert_eq!(pending.initiator_static, init_pub);
        assert_eq!(pending.timestamp, timestamp);
        assert_eq!(pending.remote_index, init_index);
        let (datagram_2, resp_keys) = pending.respond(resp_index, None);
        let mac1_key_2 = Mac1Key::for_receiver(&init_pub);
        v.message_2 = describe_message(&datagram_2, 12, &[], &mac1_key_2);
        assert_eq!(datagram_2.len(), 92);

        // The initiator completes.
        let Outer::HandshakeResp(resp) = wire::parse(&datagram_2).unwrap() else {
            panic!("message 2")
        };
        resp.verify_mac1(&mac1_key_2).unwrap();
        assert_eq!(resp.receiver_index, init_index);
        let (init_keys, _) = initiator.finish(&resp, &vec![resp_pub]).unwrap();
        assert_eq!(init_keys.handshake_hash, resp_keys.handshake_hash);
        assert_eq!(init_keys.send, resp_keys.recv);
        assert_eq!(init_keys.recv, resp_keys.send);
        v.handshake_hash = hex(&init_keys.handshake_hash);
        v.transport_keys = TransportKeys {
            initiator_to_responder: hex(&init_keys.send),
            responder_to_initiator: hex(&init_keys.recv),
        };

        // Data packets, each sealed by its sender and opened by its receiver.
        let i2r = SessionKeys {
            send: init_keys.send,
            recv: init_keys.recv,
            handshake_hash: init_keys.handshake_hash,
        };
        let r2i = SessionKeys {
            send: resp_keys.send,
            recv: resp_keys.recv,
            handshake_hash: resp_keys.handshake_hash,
        };
        let mut init_session = Session::new(
            i2r,
            Role::Initiator,
            init_index,
            resp_index,
            Duration::ZERO,
            true,
        );
        let mut resp_session = Session::new(
            r2i,
            Role::Responder,
            resp_index,
            init_index,
            Duration::ZERO,
            false,
        );
        for p in &mut v.data_packets {
            let (sender, receiver) = match p.direction.as_str() {
                "initiator_to_responder" => (&mut init_session, &mut resp_session),
                "responder_to_initiator" => (&mut resp_session, &mut init_session),
                other => panic!("direction {other}"),
            };
            let mut plaintext = vec![p.inner_type];
            plaintext.extend(unhex(&p.body));
            sender.sending_counter = p.counter;
            let datagram = sender.seal(Duration::ZERO, &plaintext).unwrap();
            let Outer::Data(data) = wire::parse(&datagram).unwrap() else {
                panic!("data")
            };
            assert_eq!(data.counter, p.counter);
            assert_eq!(
                receiver
                    .open(Duration::ZERO, data.counter, data.ciphertext)
                    .unwrap(),
                plaintext,
                "{}",
                p.name
            );
            p.receiver_index = receiver.local_index;
            p.datagram = hex(&datagram);
        }
        assert_eq!(
            init_session.seal(Duration::ZERO, &[inner::KEEPALIVE]),
            None,
            "counter exhausted after REJECT − 1"
        );

        // Rejected datagrams: a fresh responder session for each, the timestamp table as `after` says.
        for r in &mut v.rejected {
            let last = if r.after.as_deref() == Some("message_1 accepted") {
                timestamp
            } else {
                Tai64n::default()
            };
            let keys = SessionKeys {
                send: resp_keys.send,
                recv: resp_keys.recv,
                handshake_hash: resp_keys.handshake_hash,
            };
            let mut session = Session::new(
                keys,
                Role::Responder,
                resp_index,
                init_index,
                Duration::ZERO,
                false,
            );
            let outcome = responder_receive(
                &unhex(&r.datagram),
                &resp_key,
                &init_pub,
                &last,
                &mut session,
            );
            r.reason = outcome.expect_err(&r.name).as_str().into();
        }
        v
    });
}

/// §19 receiver recognition (C2, accepted property of §5.5): from public fields only, an
/// observer holding candidate keys learns the receiver of each handshake message.
#[test]
fn receiver_recognition_from_public_keys() {
    use blake2::digest::Mac;
    use blake2::digest::consts::U16;
    use blake2::{Blake2s256, Blake2sMac, Digest};
    let (_, v) = load::<HandshakeFile>("handshake.json");
    let candidates = [&v.initiator.static_public, &v.responder.static_public];
    let recognized = |m: &Message| -> Vec<(String, String)> {
        let dg = unhex(&m.datagram);
        let covered = dg.len() - 32;
        candidates
            .iter()
            .filter_map(|c| {
                let key = Blake2s256::new()
                    .chain_update(crate::MAC1_LABEL)
                    .chain_update(unhex(c))
                    .finalize();
                let mut mac = <Blake2sMac<U16> as Mac>::new_from_slice(&key).unwrap();
                mac.update(&dg[..covered]);
                let tag = mac.finalize().into_bytes();
                (tag[..] == dg[covered..covered + 16]).then(|| (hex(&key), hex(&tag)))
            })
            .collect()
    };
    assert_eq!(
        recognized(&v.message_2),
        [(v.message_2.mac1_key.clone(), v.message_2.mac1.clone())],
        "message 2: exactly the initiator"
    );
    assert_eq!(
        recognized(&v.message_1),
        [(v.message_1.mac1_key.clone(), v.message_1.mac1.clone())],
        "message 1: exactly the responder"
    );
}

/// Splits a handshake datagram into the vector's fields and checks `mac1` against the key.
fn describe_message(
    datagram: &[u8],
    noise_start: usize,
    payload: &[u8],
    mac1_key: &Mac1Key,
) -> Message {
    let covered = datagram.len() - 32;
    assert_eq!(
        mac1_key.compute(&datagram[..covered]),
        datagram[covered..covered + 16]
    );
    assert_eq!(&datagram[covered + 16..], [0u8; 16], "mac2 is zero");
    Message {
        payload_tlvs: hex(payload),
        noise_message: hex(&datagram[noise_start..covered]),
        mac1_key: hex(mac1_key.as_bytes()),
        mac1: hex(&datagram[covered..covered + 16]),
        datagram: hex(datagram),
    }
}

// --- certificate.json (§4.2, §4.3) ---

#[derive(Serialize, Deserialize)]
struct CertificateFile {
    description: String,
    context: String,
    max_certificate: usize,
    cas: Vec<CaVector>,
    sign: Vec<SignCase>,
    verify: VerifySection,
    ca_keys: Vec<CaKeyCase>,
    revoked_entries: Vec<RevokedCase>,
}

#[derive(Serialize, Deserialize)]
struct CaVector {
    name: String,
    seed: String,
    public: String,
}

#[derive(Serialize, Deserialize)]
struct SignCase {
    name: String,
    ca: String,
    fields: SignFields,
    body: String,
    signature: String,
    certificate: String,
    text: String,
    fingerprint: String,
}

#[derive(Serialize, Deserialize)]
struct SignFields {
    name: String,
    public_key: String,
    addresses: Vec<String>,
    groups: Vec<String>,
    #[serde(with = "decimal")]
    not_before: u64,
    #[serde(with = "decimal")]
    not_after: u64,
    extra: Vec<ExtraTlv>,
}

#[derive(Serialize, Deserialize)]
struct ExtraTlv {
    #[serde(rename = "type")]
    ty: u8,
    value: String,
}

#[derive(Serialize, Deserialize)]
struct VerifySection {
    trusted: Vec<String>,
    prefixes: Vec<PrefixVector>,
    #[serde(rename = "static")]
    statics: Vec<String>,
    revoked: Vec<String>,
    cases: Vec<VerifyCase>,
}

#[derive(Serialize, Deserialize)]
struct PrefixVector {
    address: String,
    length: u8,
}

#[derive(Serialize, Deserialize)]
struct VerifyCase {
    name: String,
    note: String,
    static_public: String,
    #[serde(with = "decimal")]
    now: u64,
    certificate: Option<String>,
    result: String,
    peer: Option<PeerRecord>,
}

#[derive(Serialize, Deserialize)]
struct PeerRecord {
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CaKeyCase {
    name: String,
    note: String,
    public: String,
    result: String,
}

#[derive(Serialize, Deserialize)]
struct RevokedCase {
    name: String,
    entry: String,
    result: String,
}

fn result_name<T>(r: &Result<T, cert::Reject>) -> String {
    r.as_ref().map_or_else(|e| e.as_str(), |_| "ok").to_owned()
}

#[test]
fn certificate() {
    vector("certificate.json", |mut v: CertificateFile| {
        v.context = hex(crate::CERTIFICATE_CONTEXT);
        v.max_certificate = crate::MAX_CERTIFICATE;
        for ca in &mut v.cas {
            ca.public = hex(&cert::ca_public(&arr(&ca.seed)));
        }
        for case in &mut v.sign {
            let seed: [u8; 32] = arr(&v.cas.iter().find(|c| c.name == case.ca).unwrap().seed);
            let f = &case.fields;
            let fields = cert::Fields {
                name: f.name.clone(),
                public_key: arr(&f.public_key),
                addresses: f.addresses.iter().map(|a| cert::address(arr(a))).collect(),
                groups: f.groups.clone(),
                not_before: f.not_before,
                not_after: f.not_after,
            };
            let mut body = cert::encode_body(&fields);
            let extra: Vec<Vec<u8>> = f.extra.iter().map(|e| unhex(&e.value)).collect();
            let extra: Vec<Tlv> = (f.extra.iter().zip(&extra))
                .map(|(e, value)| Tlv { ty: e.ty, value })
                .collect();
            tlv::encode(&extra, &mut body);
            let certificate = cert::sign_body(&seed, &body);
            if extra.is_empty() {
                assert_eq!(
                    cert::sign(&seed, &fields).as_ref(),
                    Ok(&certificate),
                    "{}",
                    case.name
                );
            }
            assert_eq!(
                cert::parse_body(&body).as_ref(),
                Some(&fields),
                "{}",
                case.name
            );
            case.body = hex(&body);
            case.signature = hex(&certificate[body.len()..]);
            case.certificate = hex(&certificate);
            case.text = cert::to_text(&certificate);
            case.fingerprint = hex(&cert::fingerprint(&certificate));
            assert_eq!(cert::from_text(&case.text), Some(certificate));
        }
        let s = &v.verify;
        let pki = cert::Pki {
            ca_keys: (s.trusted.iter())
                .map(|k| cert::CaKey::from_bytes(&unhex(k)).unwrap())
                .collect(),
            certificate: Vec::new(),
            revoked: s.revoked.iter().map(|e| e.parse().unwrap()).collect(),
            prefixes: (s.prefixes.iter())
                // A prefix in `::ffff:0:0/96` is the IPv4 prefix it maps, as an address (§4.2).
                .map(|p| match cert::address(arr(&p.address)) {
                    a @ IpAddr::V4(_) => cert::Prefix::new(a, p.length.checked_sub(96)?),
                    a => cert::Prefix::new(a, p.length),
                })
                .collect::<Option<_>>()
                .unwrap(),
            max_peers: crate::MAX_CERTIFICATE_PEERS,
        };
        let statics: Vec<PublicKey> = s.statics.iter().map(|k| arr(k)).collect();
        for case in &mut v.verify.cases {
            let key: PublicKey = arr(&case.static_public);
            let certificate = case.certificate.as_deref().map(unhex);
            let verdict = pki.verify(
                &key,
                certificate.as_deref(),
                statics.contains(&key),
                case.now,
            );
            case.result = result_name(&verdict);
            case.peer = verdict.ok().map(|v| match v.record {
                None => PeerRecord {
                    source: "static".into(),
                    name: None,
                    addresses: None,
                    groups: None,
                    not_after: None,
                    fingerprint: None,
                },
                Some(r) => PeerRecord {
                    source: "certificate".into(),
                    name: Some(r.fields.name.clone()),
                    addresses: Some(
                        r.fields
                            .addresses
                            .iter()
                            .map(|a| hex(&cert::octets(*a)))
                            .collect(),
                    ),
                    groups: Some(r.fields.groups.clone()),
                    not_after: Some(r.fields.not_after.to_string()),
                    fingerprint: Some(hex(&r.fingerprint)),
                },
            });
        }
        for case in &mut v.ca_keys {
            case.result = result_name(&cert::CaKey::from_bytes(&unhex(&case.public)));
        }
        for case in &mut v.revoked_entries {
            case.result = result_name(&case.entry.parse::<cert::Revoked>());
        }
        v
    });
}
