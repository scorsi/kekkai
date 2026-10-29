//! The control API server (ADR 0015): `GetStatus` over the Unix socket.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use kekkai_control::v1::control_service_server::{ControlService, ControlServiceServer};
use kekkai_control::v1::{
    Certificate, DirectPathFailure, FirewallStatus, GetStatusRequest, GetStatusResponse,
    LighthouseStatus, NodeStatus, Path, PeerStatus, RelayStatus, SessionState,
};
use kekkai_core::cert::Record;
use kekkai_core::keys::{PublicKey, public_key_to_text};
use kekkai_core::node::{self, PathFailure};
use kekkai_io::config::NodeConfig;
use kekkai_io::{State, clock};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

pub struct Control {
    state: Option<Arc<Mutex<State>>>,
    started: Duration,
    node: NodeStatus,
}

impl Control {
    pub fn new(config: &NodeConfig, public_key: PublicKey, started: Duration) -> Self {
        Self {
            state: None,
            started,
            node: NodeStatus {
                public_key: public_key_to_text(&public_key),
                addresses: config.node.addresses.clone(),
                version: env!("CARGO_PKG_VERSION").into(),
                wire_version: kekkai_core::WIRE_VERSION.into(),
                listen_port: config.node.listen_port.into(),
                ..NodeStatus::default()
            },
        }
    }

    pub async fn serve(
        mut self,
        state: Arc<Mutex<State>>,
        listener: tokio::net::UnixListener,
    ) -> Result<(), tonic::transport::Error> {
        self.state = Some(state);
        tonic::transport::Server::builder()
            .add_service(ControlServiceServer::new(self))
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await
    }

    fn status(&self) -> GetStatusResponse {
        let now = clock::monotonic();
        let wall = SystemTime::now();
        let state = self.state.as_ref().expect("set by serve");
        let state = state.lock().expect("no panic while holding the state");
        let mut node = self.node.clone();
        node.uptime = prost_types::Duration::try_from(now.saturating_sub(self.started)).ok();
        node.certificate = state.node.own_certificate().as_ref().map(certificate);
        let at = |t: Duration| -> prost_types::Timestamp { (wall - now.saturating_sub(t)).into() };
        // Configured peers, then certificate peers (spec §4.4), as name, addresses and
        // `allow_inbound` as written.
        let configured = (state.peers.iter())
            .map(|(key, info)| (key, info.name.clone(), info.addresses.clone(), None));
        let admitted = state.node.certificate_peers().map(|(key, record)| {
            let f = &record.fields;
            let addresses = (f.addresses.iter())
                .map(|a| format!("{a}/{}", if a.is_ipv4() { 32 } else { 128 }))
                .collect();
            (key, f.name.clone(), addresses, Some(record))
        });
        // By name: the order of the module's file (an attribute set), whatever reloads did.
        let mut listed: Vec<_> = configured.chain(admitted).collect();
        listed.sort_by(|a, b| a.1.cmp(&b.1));
        let peers = listed
            .into_iter()
            .filter_map(|(key, name, addresses, record)| {
                let status = state.node.status(key)?;
                let info = state.peers.get(key);
                Some(PeerStatus {
                    public_key: public_key_to_text(key),
                    // Same source as the metrics `peer` label (ADR 0019).
                    name,
                    addresses,
                    certificate: record.map(certificate),
                    // §12.1: the current session's path.
                    path: match status.path {
                        Some(node::Path::Direct(_)) => Path::Direct,
                        Some(node::Path::Relayed(_)) => Path::Relayed,
                        None => Path::None,
                    }
                    .into(),
                    relay_public_key: match status.path {
                        Some(node::Path::Relayed(r)) => public_key_to_text(&r),
                        _ => String::new(),
                    },
                    endpoint: status
                        .endpoint
                        .map(|e| e.display().to_string())
                        .unwrap_or_default(),
                    last_handshake: status.last_handshake.map(at),
                    last_direct_path_failure: status
                        .last_direct_path_failure
                        .map_or(DirectPathFailure::Unspecified, failure)
                        .into(),
                    rx_bytes: status.counters.rx_bytes,
                    tx_bytes: status.counters.tx_bytes,
                    rx_packets: status.counters.rx_packets,
                    tx_packets: status.counters.tx_packets,
                    replay_rejections: status.counters.replay_rejections,
                    allow_inbound: info.map(|i| i.allow_inbound.clone()).unwrap_or_default(),
                    firewall_drops: status.counters.firewall_drops,
                    receiver_index: status.current_index,
                    session_created: status.current_created.map(at),
                })
            })
            .collect();
        // Lighthouses and relays share the status shape (ADR 0015, 0030).
        let service = |(key, endpoint): &(PublicKey, String)| {
            let status = state.node.status(key)?;
            let session = match kekkai_io::session_state(&status) {
                "connected" => SessionState::Connected,
                "handshaking" => SessionState::Handshaking,
                _ => SessionState::Down,
            };
            Some(LighthouseStatus {
                public_key: public_key_to_text(key),
                endpoint: endpoint.clone(),
                state: session.into(),
                last_handshake: status.last_handshake.map(at),
                last_received: status.last_received.map(at),
            })
        };
        let lighthouses = state.lighthouses.iter().filter_map(service).collect();
        let relays = (state.relays.iter().filter_map(service))
            .map(|l| RelayStatus {
                public_key: l.public_key,
                endpoint: l.endpoint,
                state: l.state,
                last_handshake: l.last_handshake,
                last_received: l.last_received,
            })
            .collect();
        let firewall = state.node.firewall_status();
        GetStatusResponse {
            node: Some(node),
            peers,
            firewall: Some(FirewallStatus {
                udp_flows: firewall.entries as u64,
                udp_flows_max: firewall.max as u64,
                evictions: firewall.evictions,
            }),
            lighthouses,
            relays,
            ..GetStatusResponse::default()
        }
    }
}

fn certificate(record: &Record) -> Certificate {
    // protojson's Timestamp ends at 9999-12-31T23:59:59Z; a signed u64 may lie beyond.
    let time = |secs: u64| prost_types::Timestamp {
        seconds: secs.min(253_402_300_799) as i64,
        nanos: 0,
    };
    let f = &record.fields;
    Certificate {
        name: f.name.clone(),
        fingerprint: public_key_to_text(&record.fingerprint),
        not_before: Some(time(f.not_before)),
        not_after: Some(time(f.not_after)),
        groups: f.groups.clone(),
    }
}

fn failure(f: PathFailure) -> DirectPathFailure {
    match f {
        PathFailure::NoCandidates => DirectPathFailure::NoCandidates,
        PathFailure::Timeout => DirectPathFailure::Timeout,
        PathFailure::Abandoned => DirectPathFailure::Abandoned,
        PathFailure::LighthouseUnknown => DirectPathFailure::LighthouseUnknown,
    }
}

#[tonic::async_trait]
impl ControlService for Control {
    async fn get_status(
        &self,
        _: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        Ok(Response::new(self.status()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use kekkai_core::keys::StaticKey;
    use kekkai_core::node::{Node, PeerConfig};
    use kekkai_io::PeerInfo;

    use super::*;

    /// ADR 0034: the own certificate in `status`, and the gauge of its remaining seconds.
    #[test]
    fn status_and_metrics_show_the_own_certificate() {
        use kekkai_core::cert::{self, CaKey, Fields, Pki, Prefix};
        use kekkai_core::tai64n::Tai64n;

        let config =
            NodeConfig::parse("[node]\nprivate_key_file = \"/k\"\naddresses = [\"10.0.0.1/32\"]\n")
                .unwrap();
        let key = StaticKey::from_bytes([1; 32]).clamped();
        let seed = [7; 32];
        let mut fields = Fields {
            name: "host-1".into(),
            public_key: key.public(),
            addresses: vec!["10.0.0.1".parse().unwrap()],
            groups: vec!["admin".into()],
            not_before: 1_800_000_000,
            not_after: u64::MAX,
        };
        let pki = |certificate| Pki {
            ca_keys: vec![CaKey::from_bytes(&cert::ca_public(&seed)).unwrap()],
            certificate,
            revoked: Vec::new(),
            prefixes: vec![Prefix::new("10.0.0.0".parse().unwrap(), 8).unwrap()],
            max_peers: 1,
        };
        let certificate = cert::sign(&seed, &fields).unwrap();
        let mut node = Node::new(key, Vec::new());
        let mut control = Control::new(&config, *node.public_key(), clock::monotonic());
        node.set_pki(Tai64n::from_unix(0, 0), pki(certificate.clone()));
        let state = Arc::new(Mutex::new(State::new(node, HashMap::new())));
        control.state = Some(state.clone());
        let at = |seconds| Some(prost_types::Timestamp { seconds, nanos: 0 });
        assert_eq!(
            control.status().node.unwrap().certificate,
            Some(Certificate {
                name: "host-1".into(),
                fingerprint: public_key_to_text(&cert::fingerprint(&certificate)),
                not_before: at(1_800_000_000),
                // Clamped to protojson's last instant.
                not_after: at(253_402_300_799),
                groups: vec!["admin".into()],
            })
        );
        let own = state.lock().unwrap().node.own_certificate().unwrap();
        assert_eq!(crate::metrics::remaining(&own, 10), i64::MAX - 10);
        // Expired: negative, and the gauge says so.
        (fields.not_before, fields.not_after) = (0, 1_000);
        let expired = cert::sign(&seed, &fields).unwrap();
        (state.lock().unwrap().node).set_pki(Tai64n::from_unix(0, 0), pki(expired));
        let own = state.lock().unwrap().node.own_certificate().unwrap();
        assert_eq!(crate::metrics::remaining(&own, 1_500), -500);
        let text = crate::metrics::render(&state.lock().unwrap());
        assert!(text.contains("# TYPE kekkai_certificate_remaining_seconds gauge\n"));
        assert!(
            text.contains("\nkekkai_certificate_remaining_seconds -"),
            "{text}"
        );
    }

    #[test]
    fn status_names_each_peer_from_the_configuration() {
        let config = NodeConfig::parse(
            r#"
[node]
private_key_file = "/run/secrets/kekkai-key"
addresses = ["10.0.0.1/32"]

[[peers]]
name = "a"
public_key = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
addresses = ["10.0.0.2/32"]

[[peers]]
name = "b"
public_key = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08="
addresses = ["10.0.0.3/32"]
"#,
        )
        .unwrap();
        // As `main::serve` builds them.
        let (infos, configs) = config
            .peers
            .iter()
            .map(|p| {
                let key = p.key().unwrap();
                let info = PeerInfo {
                    name: p.name.clone(),
                    ..PeerInfo::default()
                };
                let config = PeerConfig {
                    public_key: key,
                    addresses: p.host_addresses(),
                    ..PeerConfig::default()
                };
                ((key, info), config)
            })
            .unzip::<_, _, HashMap<_, _>, Vec<_>>();
        let node = Node::new(StaticKey::from_bytes([1; 32]).clamped(), configs);
        let mut control = Control::new(&config, *node.public_key(), clock::monotonic());
        control.state = Some(Arc::new(Mutex::new(State::new(node, infos))));
        let peers: Vec<_> = control
            .status()
            .peers
            .into_iter()
            .map(|p| (p.name, p.public_key))
            .collect();
        assert_eq!(
            peers,
            [
                (
                    "a".into(),
                    "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=".into()
                ),
                (
                    "b".into(),
                    "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=".into()
                ),
            ]
        );
    }
}
