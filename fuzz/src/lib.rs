//! Fuzz targets on the parsers (ADR 0020): each function is one target, run by libFuzzer
//! from `fuzz_targets/` and replayed over `corpus/<target>/` by `cargo test`.

use kekkai_core::inner::Inner;
use kekkai_core::{tlv, wire};

/// §5.6 steps 1 to 4 on arbitrary bytes.
pub fn outer_header(data: &[u8]) {
    let _ = wire::parse(data);
}

/// §6 on arbitrary bytes: with every type known, a list that parses re-encodes to itself.
pub fn tlv_list(data: &[u8]) {
    let all: Vec<u8> = (0..=255).collect();
    if let Ok(tlvs) = tlv::decode(data, &all) {
        let mut again = Vec::with_capacity(data.len());
        tlv::encode(&tlvs, &mut again);
        assert_eq!(again, data, "canonical lists round-trip");
    }
    let _ = tlv::decode(data, &[1, 2, 3]);
}

/// §10 on arbitrary bytes: a message that decodes survives an encode/decode round trip.
pub fn inner_message(data: &[u8]) {
    if let Ok(inner) = Inner::decode(data) {
        assert_eq!(Inner::decode(&inner.encode()), Ok(inner));
    }
}

/// ADR 0016 on arbitrary bytes: the node file parser and validator never panic.
pub fn node_config(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = kekkai_io::config::NodeConfig::parse(text);
    }
}

/// ADR 0016 on arbitrary bytes: the lighthouse file parser and validator never panic.
pub fn lighthouse_config(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = kekkai_io::config::LighthouseConfig::parse(text);
    }
}

/// ADR 0016, 0031 on arbitrary bytes: the relay file parser and validator never panic.
pub fn relay_config(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = kekkai_io::config::RelayConfig::parse(text);
    }
}

/// §15 on arbitrary IP packets: recording and filtering never panic and the table stays
/// within its bound.
pub fn firewall(data: &[u8]) {
    use kekkai_core::firewall::{Firewall, Rule};
    let mut fw = Firewall::new(2);
    let now = std::time::Duration::from_secs(1);
    fw.outbound(now, data);
    fw.inbound(now, &[], data);
    fw.inbound(now, &[Rule::Any], data);
    assert!(fw.status().entries <= 2);
}

/// §4.2, §4.3 on arbitrary bytes: a body that parses re-encodes to one that parses to the
/// same fields; the identity function and the configuration parsers never panic.
pub fn certificate(data: &[u8]) {
    use kekkai_core::cert::{self, CaKey, Pki, Revoked};
    if let Some(fields) = cert::parse_body(data) {
        assert_eq!(cert::parse_body(&cert::encode_body(&fields)), Some(fields));
    }
    let ca = CaKey::from_bytes(data.get(..32).unwrap_or(data));
    let pki = Pki {
        ca_keys: ca.into_iter().collect(),
        certificate: Vec::new(),
        revoked: Vec::new(),
        prefixes: Vec::new(),
        max_peers: 1,
    };
    let _ = pki.verify(&[0; 32], Some(data), false, 0);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = text.parse::<Revoked>();
        let _ = CaKey::from_text(text);
    }
}

/// `nix flake check` replays the committed corpus deterministically (ADR 0020).
#[cfg(test)]
mod replay {
    fn replay(target: &str, run: fn(&[u8])) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(target);
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        assert!(!entries.is_empty(), "empty corpus for {target}");
        for path in entries {
            run(&std::fs::read(&path).unwrap());
        }
    }

    #[test]
    fn outer_header() {
        replay("outer_header", super::outer_header);
    }

    #[test]
    fn tlv_list() {
        replay("tlv_list", super::tlv_list);
    }

    #[test]
    fn node_config() {
        replay("node_config", super::node_config);
    }

    #[test]
    fn lighthouse_config() {
        replay("lighthouse_config", super::lighthouse_config);
    }

    #[test]
    fn relay_config() {
        replay("relay_config", super::relay_config);
    }

    #[test]
    fn firewall() {
        replay("firewall", super::firewall);
    }

    #[test]
    fn certificate() {
        replay("certificate", super::certificate);
    }

    #[test]
    fn inner_message() {
        replay("inner_message", super::inner_message);
    }
}
