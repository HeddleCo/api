//! Fixed-order counted framing shared by the new HYBRID records. See
//! owner_records.proto L22–31; signatures never cover protobuf serialization.
use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Reject {
    #[error("unsupported format")]
    Version,
    #[error("noncanonical or missing field")]
    Canonical,
    #[error("size or count bound exceeded")]
    Bounds,
    #[error("invalid signature")]
    Signature,
    #[error("independent authority/root mismatch")]
    Root,
    #[error("semantically invalid record")]
    Semantic,
    #[error("generation rollback or equivocation")]
    HighWater,
    #[error("illegal signer lifecycle transition")]
    Transition,
    #[error("job key cannot be a witness")]
    JobAsWitness,
    #[error("key roles overlap")]
    KeyRole,
    #[error("authority is not valid at verification time")]
    Expired,
    #[error("delegation scope violation")]
    Scope,
    #[error("missing typed owner import permission")]
    ImportPermission,
    #[error("renewal forks the logical job or widens remaining scope")]
    RenewalFork,
    #[error("committed manifest changed before renewal")]
    StaleManifest,
    #[error("replacement includes an already committed slot")]
    CommittedSlot,
    #[error("context is stale at mutation boundary")]
    StaleContext,
    #[error("missing or invalid exact retirement inclusion proof")]
    Proof,
    #[error("witness is revoked")]
    Revoked,
    #[error("committed slot conflict")]
    SlotConflict,
    #[error("missing or mismatched exact boundary acceptance binding")]
    BoundaryAcceptance,
    #[error("incompatible peer")]
    Protocol,
}

pub trait Canonical {
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Reject>;
}
pub fn canonical<T: Canonical>(value: &T) -> Result<Vec<u8>, Reject> {
    let mut out = Vec::new();
    value.write(&mut out)?;
    if out.len() > 1024 * 1024 {
        return Err(Reject::Bounds);
    }
    Ok(out)
}
pub fn counted(out: &mut Vec<u8>, value: &[u8]) -> Result<(), Reject> {
    if value.len() > 1024 * 1024
        || out.len().saturating_add(value.len()).saturating_add(4) > 1024 * 1024
    {
        return Err(Reject::Bounds);
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
pub fn hash(parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().to_vec()
}
pub fn signing_digest<T: Canonical>(domain: &str, value: &T) -> Result<Vec<u8>, Reject> {
    Ok(hash(&[domain.as_bytes(), &canonical(value)?]))
}
pub fn key_id(public_key: &[u8]) -> Vec<u8> {
    hash(&[b"heddle-key-v1", &1_u32.to_be_bytes(), public_key])
}
pub fn width(value: &[u8], expected: usize) -> Result<(), Reject> {
    if value.len() != expected {
        return Err(Reject::Canonical);
    }
    Ok(())
}
pub fn verify(public_key: &[u8], input: &[u8], signature: &[u8]) -> Result<(), Reject> {
    let key: &[u8; 32] = public_key.try_into().map_err(|_| Reject::Canonical)?;
    let signature: &[u8; 64] = signature.try_into().map_err(|_| Reject::Canonical)?;
    VerifyingKey::from_bytes(key)
        .map_err(|_| Reject::Signature)?
        .verify_strict(input, &Signature::from_bytes(signature))
        .map_err(|_| Reject::Signature)
}
/// Invoke at the untrusted protobuf boundary. Prost discards unknown fields;
/// byte-for-byte re-encoding also rejects duplicate tags, overlong varints,
/// noncanonical field order and trailing data. No discarded field is signed.
pub fn strict_decode<T: Message + Default>(bytes: &[u8], max: usize) -> Result<T, Reject> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(Reject::Bounds);
    }
    let value = T::decode(bytes).map_err(|_| Reject::Canonical)?;
    if value.encode_to_vec() != bytes {
        return Err(Reject::Canonical);
    }
    Ok(value)
}

macro_rules! field {
    ($out:ident, $v:expr, b) => {
        $crate::hybrid_codec::counted($out, &$v)?
    };
    ($out:ident, $v:expr, s) => {
        $crate::hybrid_codec::counted($out, $v.as_bytes())?
    };
    ($out:ident, $v:expr, u) => {
        $out.extend_from_slice(&$v.to_be_bytes())
    };
    ($out:ident, $v:expr, e) => {
        $out.extend_from_slice(
            &u32::try_from($v)
                .map_err(|_| $crate::hybrid_codec::Reject::Canonical)?
                .to_be_bytes(),
        )
    };
    ($out:ident, $v:expr, m) => {
        $crate::hybrid_codec::Canonical::write(
            $v.as_ref().ok_or($crate::hybrid_codec::Reject::Canonical)?,
            $out,
        )?
    };
    ($out:ident, $v:expr, o) => {
        $out.extend_from_slice(&u32::from($v.is_some()).to_be_bytes());
        if let Some(value) = &$v {
            $crate::hybrid_codec::Canonical::write(value, $out)?;
        }
    };
    ($out:ident, $v:expr, l) => {
        if $v.len() > 4096 {
            return Err($crate::hybrid_codec::Reject::Bounds);
        }
        $out.extend_from_slice(&($v.len() as u32).to_be_bytes());
        for value in &$v {
            $crate::hybrid_codec::Canonical::write(value, $out)?;
        }
    };
    ($out:ident, $v:expr, p) => {
        if $v.len() > 4 {
            return Err($crate::hybrid_codec::Reject::Bounds);
        }
        $out.extend_from_slice(&($v.len() as u32).to_be_bytes());
        for value in &$v {
            $out.extend_from_slice(
                &u32::try_from(*value)
                    .map_err(|_| $crate::hybrid_codec::Reject::Canonical)?
                    .to_be_bytes(),
            );
        }
    };
    ($out:ident, $v:expr, h) => {
        if $v.len() > 128 {
            return Err($crate::hybrid_codec::Reject::Bounds);
        }
        $out.extend_from_slice(&($v.len() as u32).to_be_bytes());
        for value in &$v {
            $crate::hybrid_codec::counted($out, value)?;
        }
    };
    ($out:ident, $v:expr, q) => {
        if $v.len() > 64 {
            return Err($crate::hybrid_codec::Reject::Bounds);
        }
        $out.extend_from_slice(&($v.len() as u32).to_be_bytes());
        for value in &$v {
            $crate::hybrid_codec::counted($out, value)?;
        }
    };
}
macro_rules! record {
    ($ty:ty, $($field:ident : $kind:ident),+ $(,)?) => {
        impl $crate::hybrid_codec::Canonical for $ty {
            fn write(&self, out: &mut Vec<u8>) -> Result<(), $crate::hybrid_codec::Reject> {
                $(field!(out, self.$field, $kind);
                  if out.len() > 1024 * 1024 { return Err($crate::hybrid_codec::Reject::Bounds); })+
                Ok(())
            }
        }
    };
}
pub(crate) use {field, record};
