//! The control API server (ADR 0015): `GetStatus` over the Unix socket.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use kekkai_control::v1::control_service_server::{ControlService, ControlServiceServer};
use kekkai_control::v1::{
    FirewallStatus, GetStatusRequest, GetStatusResponse, NodeStatus, Path, PeerStatus,
};
use kekkai_core::keys::{PublicKey, public_key_to_text};
use kekkai_io::config::NodeConfig;
use kekkai_io::{State, clock, udp};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

pub struct Control {
    state: Option<Arc<Mutex<State>>>,
    started: Duration,
    node: NodeStatus,
    /// Peers in configuration order, with their addresses and rules as written.
    peers: Vec<(PublicKey, Vec<String>, Vec<String>)>,
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
            peers: config
                .peers
                .iter()
                .map(|p| {
                    let key = p.key().expect("validated");
                    (key, p.addresses.clone(), p.allow_inbound.clone())
                })
                .collect(),
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
        let peers = self
            .peers
            .iter()
            .map(|(key, addresses, allow_inbound)| {
                let status = state
                    .node
                    .status(key)
                    .expect("configured peers are in the node");
                let info = state.peers.get(key);
                PeerStatus {
                    public_key: public_key_to_text(key),
                    // Same source as the metrics `peer` label (ADR 0019).
                    name: info.map(|p| p.name.clone()).unwrap_or_default(),
                    addresses: addresses.clone(),
                    // §12.1: the current session's path; every session is direct before v0.5.
                    path: if status.current {
                        Path::Direct
                    } else {
                        Path::None
                    }
                    .into(),
                    endpoint: info
                        .and_then(|p| p.endpoint)
                        .map(|e| udp::canonical(e).to_string())
                        .unwrap_or_default(),
                    last_handshake: status
                        .last_handshake
                        .map(|at| (wall - now.saturating_sub(at)).into()),
                    rx_bytes: status.counters.rx_bytes,
                    tx_bytes: status.counters.tx_bytes,
                    rx_packets: status.counters.rx_packets,
                    tx_packets: status.counters.tx_packets,
                    replay_rejections: status.counters.replay_rejections,
                    allow_inbound: allow_inbound.clone(),
                    firewall_drops: status.counters.firewall_drops,
                    ..PeerStatus::default()
                }
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
        }
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
                    allow_inbound: vec![],
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
