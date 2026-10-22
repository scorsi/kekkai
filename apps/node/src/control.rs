//! The control API server (ADR 0015): `GetStatus` over the Unix socket.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use kekkai_control::v1::control_service_server::{ControlService, ControlServiceServer};
use kekkai_control::v1::{
    DirectPathFailure, FirewallStatus, GetStatusRequest, GetStatusResponse, LighthouseStatus,
    NodeStatus, Path, PeerStatus, RelayStatus, SessionState,
};
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
                uptime: None,
                listen_port: config.node.listen_port.into(),
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
        let at = |t: Duration| -> prost_types::Timestamp { (wall - now.saturating_sub(t)).into() };
        // By name: the order of the module's file (an attribute set), whatever reloads did.
        let mut configured: Vec<_> = state.peers.iter().collect();
        configured.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        let peers = configured
            .into_iter()
            .filter_map(|(key, info)| {
                let status = state.node.status(key)?;
                Some(PeerStatus {
                    public_key: public_key_to_text(key),
                    // Same source as the metrics `peer` label (ADR 0019).
                    name: info.name.clone(),
                    addresses: info.addresses.clone(),
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
                    allow_inbound: info.allow_inbound.clone(),
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
