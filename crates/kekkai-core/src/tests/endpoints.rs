//! §12.2 validity and admission of learnt endpoints, §13.1 at the lighthouse, and the
//! fanout of a punch (§13.2, review gate 2 F6 and X4).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::relay::{Net, ep, key, wall};
use crate::inner::{Endpoint, Inner};
use crate::keys::PublicKey;
use crate::node::{LighthouseConfig, Node, PeerConfig};
use crate::wire::TYPE_HANDSHAKE_INIT;
use crate::{MAX_CANDIDATES, MAX_ENDPOINTS};

const T: Duration = Duration::from_secs(1);
const GOOD: Endpoint = Endpoint {
    address: Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped(),
    port: 4802,
};

/// Node A (0) with peer B and statics `statics`, lighthouse L (1) listing A; session up.
fn lighthouse_net(statics: Vec<Endpoint>) -> (Net, PublicKey, PublicKey) {
    let (a, b, l) = (key(1), key(2), key(4));
    let peer = PeerConfig {
        public_key: b.public(),
        endpoints: statics,
        ..PeerConfig::default()
    };
    let mut na = Node::new(a.clone(), vec![peer]);
    na.set_lighthouses(vec![LighthouseConfig {
        public_key: l.public(),
        endpoints: vec![ep(4, 4800)],
    }]);
    let nl = Node::lighthouse(l, vec![a.public()]);
    let mut net = Net::new(vec![(na, ep(1, 4802)), (nl, ep(4, 4800))]);
    net.tick(Duration::ZERO);
    net.outputs.clear();
    (net, a.public(), b.public())
}

/// L punches A for B with `endpoints`: where A's message 1s go.
fn punch(net: &mut Net, a: PublicKey, b: PublicKey, endpoints: Vec<Endpoint>) -> Vec<Endpoint> {
    let punch = Inner::LighthousePunch {
        pubkey: b,
        endpoints,
    }
    .encode();
    let mut to = Vec::new();
    for (_, d) in net.parties[1].0.send_inner_to(T, wall(T), a, &punch) {
        let out = net.parties[0]
            .0
            .handle_datagram(T, wall(T), ep(4, 4800), &d)
            .unwrap();
        let m1s = out
            .datagrams
            .into_iter()
            .filter(|(_, d)| d[0] == TYPE_HANDSHAKE_INIT);
        to.extend(m1s.map(|(e, _)| e));
    }
    to
}

/// `bad` is neither admitted by a node (punch) nor registered by a lighthouse, `own` being
/// the receiving party's local endpoints; the valid endpoint beside it is.
fn refused(bad: Endpoint, own: Vec<Endpoint>) {
    let (mut net, a, b) = lighthouse_net(Vec::new());
    net.parties[0].0.set_local_endpoints(own.clone());
    assert_eq!(
        punch(&mut net, a, b, vec![bad, GOOD]),
        vec![GOOD],
        "admission"
    );
    let (mut net, a, _) = lighthouse_net(Vec::new());
    net.parties[1].0.set_local_endpoints(own);
    let register = Inner::LighthouseRegister {
        endpoints: vec![bad, GOOD],
    }
    .encode();
    let l = *net.parties[1].0.public_key();
    let out = net.parties[0].0.send_inner_to(T, wall(T), l, &register);
    net.run(T, 0, out);
    let entries = net.parties[1].0.registrations(T);
    let (_, entry) = entries.iter().find(|(k, _)| *k == a).unwrap();
    assert_eq!(entry.locals, vec![GOOD], "register");
}

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> Endpoint {
    Endpoint::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

fn v6(address: Ipv6Addr, port: u16) -> Endpoint {
    Endpoint::new(IpAddr::V6(address), port)
}

#[test]
fn an_unspecified_endpoint_is_refused() {
    refused(v4(0, 0, 0, 0, 4802), Vec::new());
    refused(v6(Ipv6Addr::UNSPECIFIED, 4802), Vec::new());
}

#[test]
fn a_multicast_endpoint_is_refused() {
    refused(v4(224, 0, 0, 1, 4802), Vec::new());
    refused(v6("ff02::1".parse().unwrap(), 4802), Vec::new());
}

#[test]
fn the_broadcast_endpoint_is_refused() {
    refused(v4(255, 255, 255, 255, 4802), Vec::new());
}

#[test]
fn port_0_is_refused() {
    refused(v4(198, 51, 100, 8, 0), Vec::new());
    refused(v6("2001:db8::8".parse().unwrap(), 0), Vec::new());
}

#[test]
fn an_own_endpoint_is_refused() {
    let own = v4(198, 51, 100, 9, 4802);
    refused(own, vec![own]);
}

/// X4, §13.2: a punch that starts a sequence sends message 1 to the whole candidate set, at
/// most `MAX_CANDIDATES`, and every retransmission goes there again; endpoints that found
/// the set full are never sent to. A punch while it is in flight resends to at most
/// `MAX_ENDPOINTS` of its own endpoints.
#[test]
fn a_punch_fans_out_to_the_full_candidate_set() {
    let statics: Vec<Endpoint> = (0..20).map(|i| v4(203, 0, 113, i, 4802)).collect();
    let punched: Vec<Endpoint> = (0..MAX_ENDPOINTS as u8)
        .map(|i| v4(198, 51, 100, 100 + i, 4802))
        .collect();
    let (mut net, a, b) = lighthouse_net(statics.clone());
    let admitted = &punched[..MAX_CANDIDATES - statics.len()];
    let mut expected: Vec<Endpoint> = statics.iter().chain(admitted).copied().collect();
    expected.sort();
    let mut sent = punch(&mut net, a, b, punched.clone());
    sent.sort();
    assert_eq!(sent.len(), MAX_CANDIDATES);
    assert_eq!(sent, expected);
    // In flight: only the punch's endpoints in the set, the in-flight message 1 again.
    let mut resent = punch(&mut net, a, b, punched.clone());
    resent.sort();
    let mut again = admitted.to_vec();
    again.sort();
    assert_eq!(resent, again);
    assert!(resent.len() <= MAX_ENDPOINTS);
    // The scheduled retransmission (5 s + jitter) goes to the whole set.
    let later = T + Duration::from_secs(6);
    let out = net.parties[0].0.tick(later, wall(later));
    let mut retried: Vec<Endpoint> = out
        .datagrams
        .into_iter()
        .filter(|(_, d)| d[0] == TYPE_HANDSHAKE_INIT)
        .map(|(e, _)| e)
        .collect();
    retried.sort();
    assert_eq!(retried, expected);
}
