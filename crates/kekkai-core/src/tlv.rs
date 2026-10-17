//! TLV lists (§6): `type (1) | length (2, big endian) | value`, canonical form mandatory.

/// High bit of a TLV type: the sender marks a TLV the receiver must understand.
pub const CRITICAL: u8 = 0x80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub ty: u8,
    pub value: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlvError {
    /// A header or value runs past the end of the list.
    Truncated,
    /// Types not strictly increasing (duplicate or decrease).
    NotCanonical,
    /// A TLV with the critical bit that the receiver does not understand.
    UnknownCritical,
    /// A known TLV whose value has the wrong length for its type.
    BadLength,
}

impl TlvError {
    pub fn as_str(self) -> &'static str {
        match self {
            TlvError::Truncated => "truncated",
            TlvError::NotCanonical => "not_canonical",
            TlvError::UnknownCritical => "unknown_critical",
            TlvError::BadLength => "bad_length",
        }
    }
}

/// Appends the list to `out`. The caller passes the TLVs in canonical order; every value in
/// this protocol is bounded far below 64 KiB (§17).
pub fn encode(tlvs: &[Tlv<'_>], out: &mut Vec<u8>) {
    debug_assert!(
        tlvs.windows(2).all(|w| w[0].ty < w[1].ty),
        "TLV lists are sent in canonical form"
    );
    for tlv in tlvs {
        let len = u16::try_from(tlv.value.len()).expect("TLV value longer than 65535 bytes");
        out.push(tlv.ty);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(tlv.value);
    }
}

/// Parses a list against a registry. Returns the known TLVs in order; unknown non-critical
/// TLVs are skipped, an unknown critical one rejects the list. "Known" is relative to the
/// enclosing message's registry (§18), so `known` is the set of types expected there.
pub fn decode<'a>(bytes: &'a [u8], known: &[u8]) -> Result<Vec<Tlv<'a>>, TlvError> {
    let mut out = Vec::new();
    let mut previous: Option<u8> = None;
    let mut rest = bytes;
    while !rest.is_empty() {
        let (&[ty, len_hi, len_lo], after) =
            rest.split_first_chunk::<3>().ok_or(TlvError::Truncated)?;
        if previous.is_some_and(|p| ty <= p) {
            return Err(TlvError::NotCanonical);
        }
        previous = Some(ty);
        let len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        if after.len() < len {
            return Err(TlvError::Truncated);
        }
        let (value, tail) = after.split_at(len);
        if known.contains(&ty) {
            out.push(Tlv { ty, value });
        } else if ty & CRITICAL != 0 {
            return Err(TlvError::UnknownCritical);
        }
        rest = tail;
    }
    Ok(out)
}
