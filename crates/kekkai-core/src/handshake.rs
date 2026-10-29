//! Noise IKpsk2 handshake (§7): the `snow` instantiation, the handshake TLV registry and the
//! identity function. Slot bookkeeping and the timestamp table live in [`crate::peer`].

use snow::{Builder, HandshakeState};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cert::Verified;
use crate::keys::{PublicKey, StaticKey};
use crate::mac1::Mac1Key;
use crate::resolver::Resolver;
use crate::tai64n::Tai64n;
use crate::tlv::{self, Tlv, TlvError};
use crate::wire::{self, DropReason, HandshakeInit, HandshakeResp};
use crate::{MAX_DATAGRAM, NOISE_PATTERN, PROLOGUE, PSK};

// §18.3 Handshake TLV types. Without a PKI, `certificate` (2) is skipped as an unknown
// non-critical TLV, never parsed or hashed (§4.5).
pub const TLV_TIMESTAMP: u8 = 1;
pub const TLV_CERTIFICATE: u8 = 2;
pub const MESSAGE_1_KNOWN_TLVS: &[u8] = &[TLV_TIMESTAMP];
pub const MESSAGE_2_KNOWN_TLVS: &[u8] = &[];
/// With a PKI (§7.3): the certificate in both messages.
pub const MESSAGE_1_PKI_TLVS: &[u8] = &[TLV_TIMESTAMP, TLV_CERTIFICATE];
pub const MESSAGE_2_PKI_TLVS: &[u8] = &[TLV_CERTIFICATE];

/// Identity verification (§4, ADR 0007): the responder's on message 1 (§7.6 step 2) and,
/// with a PKI, the initiator's on message 2 (§7.7 step 3). v0: "is this key in the list";
/// v1.0: §4.3.
pub trait Identity {
    /// With a PKI the `certificate` TLV is read and message 2 is verified (§4.5).
    fn reads_certificate(&self) -> bool {
        false
    }
    fn verify(&self, static_public: &PublicKey, tlvs: &[Tlv<'_>]) -> Result<Verified, DropReason>;
}

impl Identity for Vec<PublicKey> {
    fn verify(&self, static_public: &PublicKey, _tlvs: &[Tlv<'_>]) -> Result<Verified, DropReason> {
        if self.contains(static_public) {
            Ok(Verified::default())
        } else {
            Err(DropReason::IdentityRejected)
        }
    }
}

/// The value of the `certificate` TLV, if any (§4.3).
pub fn certificate<'a>(tlvs: &[Tlv<'a>]) -> Option<&'a [u8]> {
    tlvs.iter()
        .find(|t| t.ty == TLV_CERTIFICATE)
        .map(|t| t.value)
}

/// A TLV list of the given TLVs, with the party's certificate last when it has one (§7.3).
fn payload(tlvs: &[Tlv<'_>], certificate: Option<&[u8]>) -> Vec<u8> {
    let mut all = tlvs.to_vec();
    all.extend(certificate.map(|value| Tlv {
        ty: TLV_CERTIFICATE,
        value,
    }));
    let mut out = Vec::new();
    tlv::encode(&all, &mut out);
    out
}

/// The two transport keys of `Split()` (§7.1), oriented for their owner. The handshake hash
/// is kept for tests and future channel binding; it never goes on the wire.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub(crate) send: [u8; 32],
    pub(crate) recv: [u8; 32],
    pub(crate) handshake_hash: [u8; 32],
}

/// `Builder::with_resolver(name, kekkai resolver).prologue(PROLOGUE).local_private_key(s).remote_public_key(rs).psk(2, PSK)`.
fn builder<'b>(
    local: &'b StaticKey,
    remote: Option<&'b PublicKey>,
    ephemeral: Option<&'b [u8; 32]>,
) -> Builder<'b> {
    let params = NOISE_PATTERN.parse().expect("valid Noise protocol name");
    let mut b = Builder::with_resolver(params, Box::new(Resolver))
        .prologue(PROLOGUE)
        .and_then(|b| b.local_private_key(local.as_bytes()))
        .and_then(|b| b.psk(2, &PSK))
        .expect("every builder parameter is set once");
    if let Some(remote) = remote {
        b = b
            .remote_public_key(remote)
            .expect("the remote key is set once");
    }
    if let Some(ephemeral) = ephemeral {
        b = b.fixed_ephemeral_key_for_testing_only(ephemeral);
    }
    b
}

fn handshake_hash(state: &HandshakeState) -> [u8; 32] {
    state
        .get_handshake_hash()
        .try_into()
        .expect("BLAKE2s hashes are 32 bytes")
}

/// The initiator side of one in-flight handshake (§7.9): message 1 is built at creation and
/// `finish` consumes the response.
pub struct Initiator {
    state: HandshakeState,
    pub sender_index: u32,
}

impl Initiator {
    /// Builds a fresh message 1 (new ephemeral, the given timestamp and index) towards
    /// `remote`; returns the state and the datagram to send.
    pub fn new(
        local: &StaticKey,
        remote: &PublicKey,
        sender_index: u32,
        timestamp: Tai64n,
    ) -> (Self, Vec<u8>) {
        Self::with_ephemeral(local, remote, sender_index, timestamp, None)
    }

    /// [`Self::new`] with the party's certificate after the timestamp (§7.3), if any.
    pub fn with_certificate(
        local: &StaticKey,
        remote: &PublicKey,
        sender_index: u32,
        timestamp: Tai64n,
        certificate: Option<&[u8]>,
    ) -> (Self, Vec<u8>) {
        let timestamp = [Tlv {
            ty: TLV_TIMESTAMP,
            value: &timestamp.0,
        }];
        let payload = payload(&timestamp, certificate);
        Self::with_payload(local, remote, sender_index, &payload, None)
    }

    pub(crate) fn with_ephemeral(
        local: &StaticKey,
        remote: &PublicKey,
        sender_index: u32,
        timestamp: Tai64n,
        ephemeral: Option<&[u8; 32]>,
    ) -> (Self, Vec<u8>) {
        let mut payload = Vec::with_capacity(15);
        tlv::encode(
            &[Tlv {
                ty: TLV_TIMESTAMP,
                value: &timestamp.0,
            }],
            &mut payload,
        );
        Self::with_payload(local, remote, sender_index, &payload, ephemeral)
    }

    /// Message 1 with an arbitrary encoded TLV list, for the tests of §7.6 step 2.
    pub(crate) fn with_payload(
        local: &StaticKey,
        remote: &PublicKey,
        sender_index: u32,
        payload: &[u8],
        ephemeral: Option<&[u8; 32]>,
    ) -> (Self, Vec<u8>) {
        let mut state = builder(local, Some(remote), ephemeral)
            .build_initiator()
            .expect("IKpsk2 initiator");
        let mut noise = vec![0u8; MAX_DATAGRAM];
        let len = state
            .write_message(payload, &mut noise)
            .expect("message 1 fits a datagram");
        noise.truncate(len);
        let datagram =
            wire::encode_handshake_init(sender_index, &noise, &Mac1Key::for_receiver(remote));
        (
            Self {
                state,
                sender_index,
            },
            datagram,
        )
    }

    /// §7.7 steps 2 to 4. The caller did §5.6 and matched `receiver_index` (step 1). On a
    /// Noise failure the state is unchanged and the handshake stays in flight. With a PKI,
    /// `identity` verifies the responder (step 3); a rejection is a TLV failure.
    pub fn finish(
        &mut self,
        resp: &HandshakeResp<'_>,
        identity: &dyn Identity,
    ) -> Result<(SessionKeys, Verified), DropReason> {
        let mut payload = vec![0u8; resp.noise.len()];
        let len = self
            .state
            .read_message(resp.noise, &mut payload)
            .map_err(|_| DropReason::NoiseFailure)?;
        let verified = if identity.reads_certificate() {
            let tlvs = tlv::decode(&payload[..len], MESSAGE_2_PKI_TLVS)?;
            let remote: PublicKey = (self.state.get_remote_static())
                .and_then(|s| s.try_into().ok())
                .ok_or(DropReason::NoiseFailure)?;
            identity.verify(&remote, &tlvs)?
        } else {
            tlv::decode(&payload[..len], MESSAGE_2_KNOWN_TLVS)?;
            Verified::default()
        };
        let (mut i2r, mut r2i) = self.state.dangerously_get_raw_split();
        let keys = SessionKeys {
            send: i2r,
            recv: r2i,
            handshake_hash: handshake_hash(&self.state),
        };
        i2r.zeroize();
        r2i.zeroize();
        Ok((keys, verified))
    }
}

/// A message 1 that passed §7.6 steps 1 to 3 except the timestamp comparison, which needs
/// the per-key table of the peer that owns `initiator_static`.
pub struct Pending {
    state: HandshakeState,
    pub initiator_static: PublicKey,
    pub timestamp: Tai64n,
    pub remote_index: u32,
    /// What the identity function returned (§7.6 step 2).
    pub verified: Verified,
}

/// §7.6 steps 1 to 3: Noise `read_message`, TLV parse, identity, timestamp presence. The
/// caller did §5.6 (length, version, `mac1`) first.
pub fn read_init(
    local: &StaticKey,
    init: &HandshakeInit<'_>,
    identity: &dyn Identity,
) -> Result<Pending, DropReason> {
    read_init_with(local, init, identity, None)
}

pub(crate) fn read_init_with(
    local: &StaticKey,
    init: &HandshakeInit<'_>,
    identity: &dyn Identity,
    ephemeral: Option<&[u8; 32]>,
) -> Result<Pending, DropReason> {
    let mut state = builder(local, None, ephemeral)
        .build_responder()
        .expect("IKpsk2 responder");
    let mut payload = vec![0u8; init.noise.len()];
    let len = state
        .read_message(init.noise, &mut payload)
        .map_err(|_| DropReason::NoiseFailure)?;
    let initiator_static: PublicKey = state
        .get_remote_static()
        .and_then(|s| s.try_into().ok())
        .ok_or(DropReason::NoiseFailure)?;
    let known = if identity.reads_certificate() {
        MESSAGE_1_PKI_TLVS
    } else {
        MESSAGE_1_KNOWN_TLVS
    };
    let tlvs = tlv::decode(&payload[..len], known)?;
    let verified = identity.verify(&initiator_static, &tlvs)?;
    let timestamp = tlvs
        .iter()
        .find(|t| t.ty == TLV_TIMESTAMP)
        .ok_or(DropReason::TimestampMissing)?;
    let timestamp = Tai64n(
        timestamp
            .value
            .try_into()
            .map_err(|_| TlvError::BadLength)?,
    );
    Ok(Pending {
        state,
        initiator_static,
        timestamp,
        remote_index: init.sender_index,
        verified,
    })
}

impl Pending {
    /// §7.6 steps 4 and 5: message 2 with an empty TLV list, or the party's certificate
    /// (§7.3), `mac1` keyed on the initiator's static key, then the transport keys. Returns
    /// the datagram to send.
    pub fn respond(
        mut self,
        sender_index: u32,
        certificate: Option<&[u8]>,
    ) -> (Vec<u8>, SessionKeys) {
        let mut noise = vec![0u8; MAX_DATAGRAM];
        let len = self
            .state
            .write_message(&payload(&[], certificate), &mut noise)
            .expect("message 2 fits a datagram");
        noise.truncate(len);
        let datagram = wire::encode_handshake_resp(
            sender_index,
            self.remote_index,
            &noise,
            &Mac1Key::for_receiver(&self.initiator_static),
        );
        let (mut i2r, mut r2i) = self.state.dangerously_get_raw_split();
        let keys = SessionKeys {
            send: r2i,
            recv: i2r,
            handshake_hash: handshake_hash(&self.state),
        };
        i2r.zeroize();
        r2i.zeroize();
        (datagram, keys)
    }
}
