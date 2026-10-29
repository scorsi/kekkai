//! Certificates (§4.2) and the identity function with a PKI (§4.3): codec, signer, strict
//! Ed25519 verification, CA keys, deny list and overlay prefixes (ADR 0034).

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use blake2::{Blake2s256, Digest};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::keys::PublicKey;
use crate::tlv::{self, Tlv};
use crate::{
    CERTIFICATE_CONTEXT, MAX_CERTIFICATE, MAX_CERTIFICATE_ADDRESSES, MAX_CERTIFICATE_GROUPS,
};

// §18.6 Certificate TLV types.
pub const TLV_NAME: u8 = 1;
pub const TLV_PUBLIC_KEY: u8 = 2;
pub const TLV_ADDRESSES: u8 = 3;
pub const TLV_GROUPS: u8 = 4;
pub const TLV_NOT_BEFORE: u8 = 5;
pub const TLV_NOT_AFTER: u8 = 6;
const KNOWN: &[u8] = &[
    TLV_NAME,
    TLV_PUBLIC_KEY,
    TLV_ADDRESSES,
    TLV_GROUPS,
    TLV_NOT_BEFORE,
    TLV_NOT_AFTER,
];

const SIGNATURE_LEN: usize = 64;

/// §18.7, in the order the steps check them, then the configuration errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Revoked,
    NoCertificate,
    BadLength,
    BadSignature,
    Malformed,
    WrongKey,
    NotYetValid,
    Expired,
    AddressOutsidePrefixes,
    PeerTableFull,
    BadCaKey,
    BadRevokedEntry,
}

impl Reject {
    pub fn as_str(self) -> &'static str {
        match self {
            Reject::Revoked => "revoked",
            Reject::NoCertificate => "no_certificate",
            Reject::BadLength => "bad_length",
            Reject::BadSignature => "bad_signature",
            Reject::Malformed => "malformed",
            Reject::WrongKey => "wrong_key",
            Reject::NotYetValid => "not_yet_valid",
            Reject::Expired => "expired",
            Reject::AddressOutsidePrefixes => "address_outside_prefixes",
            Reject::PeerTableFull => "peer_table_full",
            Reject::BadCaKey => "bad_ca_key",
            Reject::BadRevokedEntry => "bad_revoked_entry",
        }
    }
}

/// The known fields of a certificate body (§4.2). An IPv4 address is its IPv4-mapped form on
/// the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fields {
    pub name: String,
    pub public_key: PublicKey,
    pub addresses: Vec<IpAddr>,
    pub groups: Vec<String>,
    pub not_before: u64,
    pub not_after: u64,
}

/// `name` and group rule (§4.2): `[a-z0-9-]`, 1 to `max` bytes, no leading or trailing `-`.
fn label(b: &[u8], max: usize) -> bool {
    (1..=max).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

/// The 16-byte wire form of an address: IPv4 as `::ffff:a.b.c.d` (§4.2).
pub fn octets(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
        IpAddr::V6(a) => a.octets(),
    }
}

/// The inverse of [`octets`]: `::ffff:0:0/96` is the IPv4 address it maps.
pub fn address(octets: [u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(octets);
    v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
}

impl Fields {
    /// The signer's refusals (§4.2), before anything is encoded.
    fn check(&self) -> Result<(), &'static str> {
        let mut addresses: Vec<[u8; 16]> = self.addresses.iter().map(|a| octets(*a)).collect();
        addresses.sort();
        let mut groups: Vec<&str> = self.groups.iter().map(String::as_str).collect();
        groups.sort();
        if !label(self.name.as_bytes(), 63) {
            return Err("name: 1 to 63 characters of [a-z0-9-], not starting or ending with -");
        }
        if !(1..=MAX_CERTIFICATE_ADDRESSES).contains(&addresses.len())
            || addresses.windows(2).any(|w| w[0] == w[1])
        {
            return Err("addresses: 1 to 4 distinct addresses");
        }
        if groups.len() > MAX_CERTIFICATE_GROUPS
            || groups.windows(2).any(|w| w[0] == w[1])
            || !groups.iter().all(|g| label(g.as_bytes(), 32))
        {
            return Err("groups: at most 16 distinct groups of 1 to 32 characters of [a-z0-9-]");
        }
        if self.not_before >= self.not_after {
            return Err("not_before must be before not_after");
        }
        Ok(())
    }
}

/// The signer's body (§4.2): the known fields in registry order, addresses and groups sorted.
/// The fields must satisfy their rules (a group over 255 bytes would not encode).
pub fn encode_body(fields: &Fields) -> Vec<u8> {
    let mut addresses: Vec<[u8; 16]> = fields.addresses.iter().map(|a| octets(*a)).collect();
    addresses.sort();
    let addresses = addresses.concat();
    let mut groups: Vec<&str> = fields.groups.iter().map(String::as_str).collect();
    groups.sort();
    let groups: Vec<u8> = groups
        .iter()
        .flat_map(|g| std::iter::once(g.len() as u8).chain(g.bytes()))
        .collect();
    let (not_before, not_after) = (
        fields.not_before.to_be_bytes(),
        fields.not_after.to_be_bytes(),
    );
    let mut tlvs = vec![
        Tlv {
            ty: TLV_NAME,
            value: fields.name.as_bytes(),
        },
        Tlv {
            ty: TLV_PUBLIC_KEY,
            value: &fields.public_key,
        },
        Tlv {
            ty: TLV_ADDRESSES,
            value: &addresses,
        },
    ];
    if !groups.is_empty() {
        tlvs.push(Tlv {
            ty: TLV_GROUPS,
            value: &groups,
        });
    }
    tlvs.push(Tlv {
        ty: TLV_NOT_BEFORE,
        value: &not_before,
    });
    tlvs.push(Tlv {
        ty: TLV_NOT_AFTER,
        value: &not_after,
    });
    let mut out = Vec::new();
    tlv::encode(&tlvs, &mut out);
    out
}

/// Parses a body (§4.2); `None` is `malformed`. Unknown non-critical TLVs are skipped.
pub fn parse_body(body: &[u8]) -> Option<Fields> {
    let tlvs = tlv::decode(body, KNOWN).ok()?;
    let get = |ty: u8| tlvs.iter().find(|t| t.ty == ty).map(|t| t.value);
    let name = get(TLV_NAME).filter(|v| label(v, 63))?;
    let public_key = get(TLV_PUBLIC_KEY)?.try_into().ok()?;
    let addresses = get(TLV_ADDRESSES)?;
    let count = addresses.len() / 16;
    if addresses.len() % 16 != 0 || !(1..=MAX_CERTIFICATE_ADDRESSES).contains(&count) {
        return None;
    }
    let addresses: Vec<[u8; 16]> = addresses
        .chunks_exact(16)
        .map(|c| c.try_into().expect("16 bytes"))
        .collect();
    if addresses.windows(2).any(|w| w[0] >= w[1]) {
        return None;
    }
    let groups = match get(TLV_GROUPS) {
        Some(value) => parse_groups(value)?,
        None => Vec::new(),
    };
    let u64_of = |ty: u8| get(ty)?.try_into().ok().map(u64::from_be_bytes);
    Some(Fields {
        name: std::str::from_utf8(name).ok()?.to_owned(),
        public_key,
        addresses: addresses.into_iter().map(address).collect(),
        groups,
        not_before: u64_of(TLV_NOT_BEFORE)?,
        not_after: u64_of(TLV_NOT_AFTER)?,
    })
}

/// `len (1) || group`, repeated: 1 to 16 groups, each a label of 1 to 32 bytes, strictly
/// increasing bytewise.
fn parse_groups(mut value: &[u8]) -> Option<Vec<String>> {
    let mut groups: Vec<&[u8]> = Vec::new();
    while let Some((&len, rest)) = value.split_first() {
        let group = rest.get(..usize::from(len)).filter(|g| label(g, 32))?;
        groups.push(group);
        value = &rest[group.len()..];
    }
    if groups.is_empty()
        || groups.len() > MAX_CERTIFICATE_GROUPS
        || groups.windows(2).any(|w| w[0] >= w[1])
    {
        return None;
    }
    groups
        .into_iter()
        .map(|g| std::str::from_utf8(g).ok().map(str::to_owned))
        .collect()
}

/// `body || Ed25519-Sign(seed, CERTIFICATE_CONTEXT || body)` (§4.2), RFC 8032 deterministic.
pub fn sign_body(ca_seed: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let signature = SigningKey::from_bytes(ca_seed).sign(&[CERTIFICATE_CONTEXT, body].concat());
    [body, &signature.to_bytes()].concat()
}

/// The signer (§4.2, `kekkai cert sign`): refuses a field that breaks its rule, an empty
/// validity interval and a certificate above `MAX_CERTIFICATE`.
pub fn sign(ca_seed: &[u8; 32], fields: &Fields) -> Result<Vec<u8>, &'static str> {
    fields.check()?;
    let certificate = sign_body(ca_seed, &encode_body(fields));
    if certificate.len() > MAX_CERTIFICATE {
        return Err("certificate longer than 960 bytes");
    }
    Ok(certificate)
}

/// The public key of a CA seed.
pub fn ca_public(ca_seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(ca_seed).verifying_key().to_bytes()
}

/// `BLAKE2s(certificate)` (§4.2), over the bytes as received.
pub fn fingerprint(certificate: &[u8]) -> [u8; 32] {
    Blake2s256::digest(certificate).into()
}

/// Text form of a certificate: standard base64 with padding, one line (§4.2).
pub fn to_text(certificate: &[u8]) -> String {
    STANDARD.encode(certificate)
}

pub fn from_text(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text.trim()).ok()
}

/// A trusted CA key, checked at load (§4.2): 32 bytes, canonical under RFC 8032 §5.1.3, not
/// of small order. `ed25519-dalek` accepts non-canonical encodings, so the check is ours.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaKey(VerifyingKey);

impl CaKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Reject> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Reject::BadCaKey)?;
        // Decompression reduces `y` mod p and accepts `-0`; re-encoding exposes both.
        CompressedEdwardsY(bytes)
            .decompress()
            .filter(|p| p.compress().to_bytes() == bytes && !p.is_small_order())
            .ok_or(Reject::BadCaKey)?;
        VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| Reject::BadCaKey)
    }

    /// The text form, as keys (§4).
    pub fn from_text(text: &str) -> Result<Self, Reject> {
        Self::from_bytes(&STANDARD.decode(text).map_err(|_| Reject::BadCaKey)?)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// A deny-list entry (§4.3 step 1): `key:` a static key, `cert:` a certificate fingerprint,
/// each followed by 32 bytes in the key text form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revoked {
    Key(PublicKey),
    Cert([u8; 32]),
}

impl FromStr for Revoked {
    type Err = Reject;

    fn from_str(entry: &str) -> Result<Self, Reject> {
        let (kind, value) = entry.split_once(':').ok_or(Reject::BadRevokedEntry)?;
        let value: [u8; 32] = (STANDARD.decode(value).ok())
            .and_then(|v| v.try_into().ok())
            .ok_or(Reject::BadRevokedEntry)?;
        match kind {
            "key" => Ok(Revoked::Key(value)),
            "cert" => Ok(Revoked::Cert(value)),
            _ => Err(Reject::BadRevokedEntry),
        }
    }
}

/// An overlay prefix of `[pki] prefixes`, held over 16-byte addresses: an IPv4 prefix is its
/// IPv4-mapped form, so that certificate addresses compare in one space (§4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    address: [u8; 16],
    length: u8,
}

impl Prefix {
    /// `None` when `length` exceeds the family's width.
    pub fn new(address: IpAddr, length: u8) -> Option<Self> {
        let length = match address {
            IpAddr::V4(_) if length <= 32 => length + 96,
            IpAddr::V6(_) if length <= 128 => length,
            _ => return None,
        };
        Some(Self {
            address: octets(address),
            length,
        })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        let mask = u128::MAX
            .checked_shl(128 - u32::from(self.length))
            .unwrap_or(0);
        let (a, p) = (
            u128::from_be_bytes(octets(address)),
            u128::from_be_bytes(self.address),
        );
        a & mask == p & mask
    }
}

/// A party's `[pki]` (§4.2, §4.3, §4.4): what the IO layer loaded and checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pki {
    /// At most `MAX_CA_KEYS`, enforced by the IO layer.
    pub ca_keys: Vec<CaKey>,
    /// The party's own certificate, sent in every handshake message (§7.3).
    pub certificate: Vec<u8>,
    pub revoked: Vec<Revoked>,
    pub prefixes: Vec<Prefix>,
    /// Bound of the certificate peer table (§4.4); fixed at start by the IO layer.
    pub max_peers: usize,
}

/// A certificate that verified (§4.3 step 10): its fields, fingerprint and bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub fields: Fields,
    pub fingerprint: [u8; 32],
    pub certificate: Vec<u8>,
}

/// What `verify` accepted: the fingerprint of the presented certificate, if any (§8.1), and
/// the record for source `certificate`; `None` is source `static`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Verified {
    pub fingerprint: Option<[u8; 32]>,
    pub record: Option<Record>,
}

impl Pki {
    /// §4.3: `is_static` is step 2 (the key is in the party's configured lists), `now` the
    /// wall clock in whole Unix seconds.
    pub fn verify(
        &self,
        key: &PublicKey,
        certificate: Option<&[u8]>,
        is_static: bool,
        now: u64,
    ) -> Result<Verified, Reject> {
        let fingerprint = certificate.map(fingerprint);
        if self.revoked.contains(&Revoked::Key(*key))
            || fingerprint.is_some_and(|f| self.revoked.contains(&Revoked::Cert(f)))
        {
            return Err(Reject::Revoked);
        }
        if is_static {
            return Ok(Verified {
                fingerprint,
                record: None,
            });
        }
        let certificate = certificate.ok_or(Reject::NoCertificate)?;
        let record = self.check(certificate, key, Some(now))?;
        Ok(Verified {
            fingerprint,
            record: Some(record),
        })
    }

    /// §4.3 steps 4 to 9, step 8 only with `now`.
    pub fn check(
        &self,
        certificate: &[u8],
        key: &PublicKey,
        now: Option<u64>,
    ) -> Result<Record, Reject> {
        if !(SIGNATURE_LEN + 1..=MAX_CERTIFICATE).contains(&certificate.len()) {
            return Err(Reject::BadLength);
        }
        let (body, signature) = certificate.split_at(certificate.len() - SIGNATURE_LEN);
        let signature = Signature::from_bytes(signature.try_into().expect("64 bytes"));
        let message = [CERTIFICATE_CONTEXT, body].concat();
        let signed =
            (self.ca_keys.iter()).any(|ca| ca.0.verify_strict(&message, &signature).is_ok());
        if !signed {
            return Err(Reject::BadSignature);
        }
        let fields = parse_body(body).ok_or(Reject::Malformed)?;
        if fields.public_key != *key {
            return Err(Reject::WrongKey);
        }
        if let Some(now) = now {
            if now < fields.not_before {
                return Err(Reject::NotYetValid);
            }
            if now >= fields.not_after {
                return Err(Reject::Expired);
            }
        }
        let inside = |a: &IpAddr| self.prefixes.iter().any(|p| p.contains(*a));
        if !fields.addresses.iter().all(inside) {
            return Err(Reject::AddressOutsidePrefixes);
        }
        Ok(Record {
            fields,
            fingerprint: fingerprint(certificate),
            certificate: certificate.to_vec(),
        })
    }

    /// The IO layer's check of the party's own certificate at start and reload (§4.2):
    /// steps 4 to 7 and 9; validity is not checked there.
    pub fn check_own(&self, own: &PublicKey) -> Result<Record, Reject> {
        self.check(&self.certificate, own, None)
    }
}
