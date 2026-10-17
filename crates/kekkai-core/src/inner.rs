//! Inner protocol (§10): the plaintext of every `data` packet, `inner_type (1) || body`.

use std::net::{IpAddr, Ipv6Addr};

use crate::keys::PublicKey;
use crate::tlv::{self, Tlv};
use crate::wire::DropReason;
use crate::{MAX_ENDPOINTS, MAX_LOCAL_ENDPOINTS, MAX_RELAY_PAYLOAD};

// §18.2 Inner message types.
pub const IP_PACKET: u8 = 1;
pub const KEEPALIVE: u8 = 2;
pub const LIGHTHOUSE_REGISTER: u8 = 3;
pub const LIGHTHOUSE_QUERY: u8 = 4;
pub const LIGHTHOUSE_QUERY_REPLY: u8 = 5;
pub const LIGHTHOUSE_PUNCH: u8 = 6;
pub const RELAY_FORWARD: u8 = 7;
pub const RELAY_FORWARDED: u8 = 8;

// §18.4 Lighthouse TLV types. `certificate` (4) is reserved for v1 and skipped as unknown.
pub const TLV_PUBKEY: u8 = 1;
pub const TLV_ENDPOINTS: u8 = 2;
pub const TLV_LAST_SEEN: u8 = 3;
const LIGHTHOUSE_KNOWN_TLVS: &[u8] = &[TLV_PUBKEY, TLV_ENDPOINTS, TLV_LAST_SEEN];

pub const ENDPOINT_LEN: usize = 18;

/// `address (16) || port (2)`: an IPv6 address, IPv4 written in its IPv4-mapped form (§10.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub address: Ipv6Addr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(address: IpAddr, port: u16) -> Self {
        let address = match address {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };
        Self { address, port }
    }

    pub fn encode(&self) -> [u8; ENDPOINT_LEN] {
        let mut b = [0u8; ENDPOINT_LEN];
        b[..16].copy_from_slice(&self.address.octets());
        b[16..].copy_from_slice(&self.port.to_be_bytes());
        b
    }

    fn decode(b: &[u8]) -> Self {
        let address: [u8; 16] = b[..16].try_into().expect("16 bytes");
        Self {
            address: address.into(),
            port: u16::from_be_bytes([b[16], b[17]]),
        }
    }
}

/// A decoded inner message. Bodies that are TLV lists are parsed against the lighthouse
/// registry; an `endpoints` list is omitted on the wire when empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inner<'a> {
    IpPacket(&'a [u8]),
    Keepalive,
    LighthouseRegister {
        endpoints: Vec<Endpoint>,
    },
    LighthouseQuery {
        pubkey: PublicKey,
    },
    LighthouseQueryReply {
        pubkey: PublicKey,
        endpoints: Vec<Endpoint>,
        last_seen: Option<u32>,
    },
    LighthousePunch {
        pubkey: PublicKey,
        endpoints: Vec<Endpoint>,
    },
    RelayForward {
        to: PublicKey,
        payload: &'a [u8],
    },
    RelayForwarded {
        from: PublicKey,
        payload: &'a [u8],
    },
}

impl<'a> Inner<'a> {
    pub fn inner_type(&self) -> u8 {
        match self {
            Inner::IpPacket(_) => IP_PACKET,
            Inner::Keepalive => KEEPALIVE,
            Inner::LighthouseRegister { .. } => LIGHTHOUSE_REGISTER,
            Inner::LighthouseQuery { .. } => LIGHTHOUSE_QUERY,
            Inner::LighthouseQueryReply { .. } => LIGHTHOUSE_QUERY_REPLY,
            Inner::LighthousePunch { .. } => LIGHTHOUSE_PUNCH,
            Inner::RelayForward { .. } => RELAY_FORWARD,
            Inner::RelayForwarded { .. } => RELAY_FORWARDED,
        }
    }

    /// `inner_type || body`, ready for the transport AEAD.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.inner_type()];
        match self {
            Inner::IpPacket(packet) => out.extend_from_slice(packet),
            Inner::Keepalive => {}
            Inner::LighthouseRegister { endpoints } => {
                lighthouse_body(&mut out, None, endpoints, None)
            }
            Inner::LighthouseQuery { pubkey } => lighthouse_body(&mut out, Some(pubkey), &[], None),
            Inner::LighthouseQueryReply {
                pubkey,
                endpoints,
                last_seen,
            } => {
                lighthouse_body(&mut out, Some(pubkey), endpoints, *last_seen);
            }
            Inner::LighthousePunch { pubkey, endpoints } => {
                lighthouse_body(&mut out, Some(pubkey), endpoints, None)
            }
            Inner::RelayForward { to: key, payload }
            | Inner::RelayForwarded { from: key, payload } => {
                out.extend_from_slice(key);
                out.extend_from_slice(payload);
            }
        }
        out
    }

    /// §10.1: an unassigned type or a body that does not parse drops the packet (after the
    /// counter was marked: the packet was authentic). Role acceptance (§10.2) is the caller's.
    pub fn decode(plaintext: &'a [u8]) -> Result<Self, DropReason> {
        let (&ty, body) = plaintext.split_first().ok_or(DropReason::InnerMalformed)?;
        match ty {
            IP_PACKET => match body.first().map(|b| b >> 4) {
                Some(4) | Some(6) => Ok(Inner::IpPacket(body)),
                _ => Err(DropReason::InnerMalformed),
            },
            KEEPALIVE if body.is_empty() => Ok(Inner::Keepalive),
            KEEPALIVE => Err(DropReason::InnerMalformed),
            LIGHTHOUSE_REGISTER => {
                let (_, endpoints, _) = lighthouse_fields(body)?;
                if endpoints.len() > MAX_LOCAL_ENDPOINTS {
                    return Err(DropReason::InnerMalformed);
                }
                Ok(Inner::LighthouseRegister { endpoints })
            }
            LIGHTHOUSE_QUERY => {
                let (pubkey, _, _) = lighthouse_fields(body)?;
                Ok(Inner::LighthouseQuery {
                    pubkey: pubkey.ok_or(DropReason::InnerMalformed)?,
                })
            }
            LIGHTHOUSE_QUERY_REPLY => {
                let (pubkey, endpoints, last_seen) = lighthouse_fields(body)?;
                let pubkey = pubkey.ok_or(DropReason::InnerMalformed)?;
                Ok(Inner::LighthouseQueryReply {
                    pubkey,
                    endpoints,
                    last_seen,
                })
            }
            LIGHTHOUSE_PUNCH => {
                let (pubkey, endpoints, _) = lighthouse_fields(body)?;
                if endpoints.is_empty() {
                    return Err(DropReason::InnerMalformed);
                }
                Ok(Inner::LighthousePunch {
                    pubkey: pubkey.ok_or(DropReason::InnerMalformed)?,
                    endpoints,
                })
            }
            RELAY_FORWARD | RELAY_FORWARDED => {
                let (key, payload) = body
                    .split_first_chunk::<32>()
                    .ok_or(DropReason::InnerMalformed)?;
                if payload.len() < 4 || payload.len() > MAX_RELAY_PAYLOAD {
                    return Err(DropReason::InnerMalformed);
                }
                Ok(if ty == RELAY_FORWARD {
                    Inner::RelayForward { to: *key, payload }
                } else {
                    Inner::RelayForwarded {
                        from: *key,
                        payload,
                    }
                })
            }
            _ => Err(DropReason::InnerUnknownType),
        }
    }
}

fn lighthouse_body(
    out: &mut Vec<u8>,
    pubkey: Option<&PublicKey>,
    endpoints: &[Endpoint],
    last_seen: Option<u32>,
) {
    let endpoint_bytes: Vec<u8> = endpoints.iter().flat_map(Endpoint::encode).collect();
    let last_seen = last_seen.map(u32::to_be_bytes);
    let mut tlvs = Vec::with_capacity(3);
    if let Some(pubkey) = pubkey {
        tlvs.push(Tlv {
            ty: TLV_PUBKEY,
            value: pubkey,
        });
    }
    if !endpoints.is_empty() {
        tlvs.push(Tlv {
            ty: TLV_ENDPOINTS,
            value: &endpoint_bytes,
        });
    }
    if let Some(last_seen) = &last_seen {
        tlvs.push(Tlv {
            ty: TLV_LAST_SEEN,
            value: last_seen,
        });
    }
    tlv::encode(&tlvs, out);
}

type LighthouseFields = (Option<PublicKey>, Vec<Endpoint>, Option<u32>);

/// Parses a lighthouse TLV list; which TLVs are required is decided per message by the caller.
fn lighthouse_fields(body: &[u8]) -> Result<LighthouseFields, DropReason> {
    let (mut pubkey, mut endpoints, mut last_seen) = (None, Vec::new(), None);
    for tlv in tlv::decode(body, LIGHTHOUSE_KNOWN_TLVS)? {
        match tlv.ty {
            TLV_PUBKEY => {
                pubkey = Some(
                    tlv.value
                        .try_into()
                        .map_err(|_| DropReason::InnerMalformed)?,
                )
            }
            TLV_ENDPOINTS => {
                if tlv.value.len() % ENDPOINT_LEN != 0
                    || tlv.value.len() / ENDPOINT_LEN > MAX_ENDPOINTS
                {
                    return Err(DropReason::InnerMalformed);
                }
                endpoints = tlv
                    .value
                    .chunks_exact(ENDPOINT_LEN)
                    .map(Endpoint::decode)
                    .collect();
            }
            TLV_LAST_SEEN => {
                let value: [u8; 4] = tlv
                    .value
                    .try_into()
                    .map_err(|_| DropReason::InnerMalformed)?;
                last_seen = Some(u32::from_be_bytes(value));
            }
            _ => unreachable!("tlv::decode only returns known types"),
        }
    }
    Ok((pubkey, endpoints, last_seen))
}
