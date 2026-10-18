//! Outer messages (§5): the common header, the per-type layouts and the drop order of §5.6.

use crate::mac1::{MAC_SLOTS_LEN, Mac1Key};
use crate::tlv::TlvError;
use crate::{MAX_DATAGRAM, WIRE_VERSION};

/// Why a datagram or packet was dropped silently (§16). Every variant is a counter, never a
/// reply; `as_str` gives the name the test vectors and the control API use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    BadLength,
    UnknownVersion,
    UnknownType,
    BadMac1,
    NoiseFailure,
    Tlv(TlvError),
    IdentityRejected,
    TimestampMissing,
    TimestampNotNewer,
    UnknownIndex,
    CounterRejected,
    BadTag,
    InnerUnknownType,
    InnerMalformed,
    /// §10.2: an inner type this role does not accept from this sender.
    NotAccepted,
    /// §11: the source address of an `ip_packet` is not the sending peer's.
    SourceNotPeer,
    /// §11: no peer owns the destination (or the tunnel packet has no parseable header).
    NoRoute,
    /// §11: multicast or broadcast destination.
    NotUnicast,
    /// §17: a tunnel packet larger than `MTU`.
    PacketTooLarge,
    /// §15: refused by the receiving node's inbound firewall.
    Firewall,
}

impl DropReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::BadLength => "bad_length",
            DropReason::UnknownVersion => "unknown_version",
            DropReason::UnknownType => "unknown_type",
            DropReason::BadMac1 => "bad_mac1",
            DropReason::NoiseFailure => "noise_failure",
            DropReason::Tlv(TlvError::Truncated) => "tlv_truncated",
            DropReason::Tlv(TlvError::NotCanonical) => "tlv_not_canonical",
            DropReason::Tlv(TlvError::UnknownCritical) => "tlv_unknown_critical",
            DropReason::Tlv(TlvError::BadLength) => "tlv_bad_length",
            DropReason::IdentityRejected => "identity_rejected",
            DropReason::TimestampMissing => "timestamp_missing",
            DropReason::TimestampNotNewer => "timestamp_not_newer",
            DropReason::UnknownIndex => "unknown_index",
            DropReason::CounterRejected => "counter_rejected",
            DropReason::BadTag => "bad_tag",
            DropReason::InnerUnknownType => "inner_unknown_type",
            DropReason::InnerMalformed => "inner_malformed",
            DropReason::NotAccepted => "not_accepted",
            DropReason::SourceNotPeer => "source_not_peer",
            DropReason::NoRoute => "no_route",
            DropReason::NotUnicast => "not_unicast",
            DropReason::PacketTooLarge => "packet_too_large",
            DropReason::Firewall => "firewall",
        }
    }
}

impl From<TlvError> for DropReason {
    fn from(e: TlvError) -> Self {
        DropReason::Tlv(e)
    }
}

// §18.1 Outer message types.
pub const TYPE_HANDSHAKE_INIT: u8 = 1;
pub const TYPE_HANDSHAKE_RESP: u8 = 2;
/// Reserved: dropped like an unknown type in v0 (§5.3).
pub const TYPE_COOKIE_REPLY: u8 = 3;
pub const TYPE_DATA: u8 = 4;

/// Minimum lengths per type (§5.1, §5.2, §5.4).
pub const HANDSHAKE_INIT_MIN_LEN: usize = 136;
pub const HANDSHAKE_RESP_MIN_LEN: usize = 92;
pub const DATA_HEADER_LEN: usize = 16;
pub const DATA_MIN_LEN: usize = 33;

/// `handshake_init` as parsed; `noise` is Noise message 1, `datagram` the whole message for
/// the `mac1` check.
#[derive(Clone, Copy, Debug)]
pub struct HandshakeInit<'a> {
    pub sender_index: u32,
    pub noise: &'a [u8],
    pub datagram: &'a [u8],
}

/// `handshake_resp` as parsed; `noise` is Noise message 2.
#[derive(Clone, Copy, Debug)]
pub struct HandshakeResp<'a> {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub noise: &'a [u8],
    pub datagram: &'a [u8],
}

/// `data` as parsed; the header is not authenticated (§5.4), the session and the counter are.
#[derive(Clone, Copy, Debug)]
pub struct Data<'a> {
    pub receiver_index: u32,
    pub counter: u64,
    pub ciphertext: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub enum Outer<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResp(HandshakeResp<'a>),
    Data(Data<'a>),
}

impl HandshakeInit<'_> {
    /// §5.6 step 5, keyed on the receiver's own static public key.
    pub fn verify_mac1(&self, own_key: &Mac1Key) -> Result<(), DropReason> {
        own_key.verify(self.datagram)
    }
}

impl HandshakeResp<'_> {
    /// §5.6 step 5, keyed on the receiver's own static public key.
    pub fn verify_mac1(&self, own_key: &Mac1Key) -> Result<(), DropReason> {
        own_key.verify(self.datagram)
    }
}

/// §5.6 steps 1 to 4: length, version, type and per-type length. `mac1` (step 5) needs the
/// receiver's key and is checked by the caller on the handshake variants.
pub fn parse(datagram: &[u8]) -> Result<Outer<'_>, DropReason> {
    if datagram.len() < 4 || datagram.len() > MAX_DATAGRAM {
        return Err(DropReason::BadLength);
    }
    if datagram[1] != WIRE_VERSION {
        return Err(DropReason::UnknownVersion);
    }
    let be32 = |at: usize| u32::from_be_bytes(datagram[at..at + 4].try_into().expect("4 bytes"));
    let body_end = datagram.len().saturating_sub(MAC_SLOTS_LEN);
    match datagram[0] {
        TYPE_HANDSHAKE_INIT => {
            if datagram.len() < HANDSHAKE_INIT_MIN_LEN {
                return Err(DropReason::BadLength);
            }
            Ok(Outer::HandshakeInit(HandshakeInit {
                sender_index: be32(4),
                noise: &datagram[8..body_end],
                datagram,
            }))
        }
        TYPE_HANDSHAKE_RESP => {
            if datagram.len() < HANDSHAKE_RESP_MIN_LEN {
                return Err(DropReason::BadLength);
            }
            Ok(Outer::HandshakeResp(HandshakeResp {
                sender_index: be32(4),
                receiver_index: be32(8),
                noise: &datagram[12..body_end],
                datagram,
            }))
        }
        TYPE_DATA => {
            if datagram.len() < DATA_MIN_LEN {
                return Err(DropReason::BadLength);
            }
            Ok(Outer::Data(Data {
                receiver_index: be32(4),
                counter: u64::from_be_bytes(datagram[8..16].try_into().expect("8 bytes")),
                ciphertext: &datagram[DATA_HEADER_LEN..],
            }))
        }
        _ => Err(DropReason::UnknownType),
    }
}

/// §5.1: header, index, Noise message 1, `mac1` keyed on the responder's key, zero `mac2`.
pub fn encode_handshake_init(sender_index: u32, noise: &[u8], receiver_key: &Mac1Key) -> Vec<u8> {
    let mut d = Vec::with_capacity(8 + noise.len() + MAC_SLOTS_LEN);
    d.extend_from_slice(&[TYPE_HANDSHAKE_INIT, WIRE_VERSION, 0, 0]);
    d.extend_from_slice(&sender_index.to_be_bytes());
    d.extend_from_slice(noise);
    append_macs(&mut d, receiver_key);
    d
}

/// §5.2: header, both indices, Noise message 2, `mac1` keyed on the initiator's key, zero `mac2`.
pub fn encode_handshake_resp(
    sender_index: u32,
    receiver_index: u32,
    noise: &[u8],
    receiver_key: &Mac1Key,
) -> Vec<u8> {
    let mut d = Vec::with_capacity(12 + noise.len() + MAC_SLOTS_LEN);
    d.extend_from_slice(&[TYPE_HANDSHAKE_RESP, WIRE_VERSION, 0, 0]);
    d.extend_from_slice(&sender_index.to_be_bytes());
    d.extend_from_slice(&receiver_index.to_be_bytes());
    d.extend_from_slice(noise);
    append_macs(&mut d, receiver_key);
    d
}

fn append_macs(message: &mut Vec<u8>, receiver_key: &Mac1Key) {
    let mac1 = receiver_key.compute(message);
    message.extend_from_slice(&mac1);
    message.extend_from_slice(&[0u8; 16]);
}

/// §5.4: the 16-byte `data` header; the counter is big endian here and little endian in the
/// AEAD nonce (§8.2).
pub fn data_header(receiver_index: u32, counter: u64) -> [u8; DATA_HEADER_LEN] {
    let mut h = [0u8; DATA_HEADER_LEN];
    h[0] = TYPE_DATA;
    h[1] = WIRE_VERSION;
    h[4..8].copy_from_slice(&receiver_index.to_be_bytes());
    h[8..16].copy_from_slice(&counter.to_be_bytes());
    h
}
