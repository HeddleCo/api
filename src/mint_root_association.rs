//! Checked wire decoding for messages whose mint-root association is security
//! sensitive. Protobuf oneofs otherwise decode duplicate alternatives last-wins.

use prost::Message;

use crate::heddle::api::v1alpha2::{SpoolCreationProof, ThreadControlAuthority};

const OWNER_MINT_ROOT_ATTACHMENT_FIELD: u64 = 4;
const PASSKEY_MINT_ROOT_ATTACHMENT_FIELD: u64 = 6;
const MAX_PROTOBUF_FIELD_NUMBER: u64 = (1 << 29) - 1;

/// Failure while checking or decoding a mint-root association envelope.
#[derive(Debug, thiserror::Error)]
pub enum MintRootAssociationWireError {
    /// Both proof alternatives occurred in the original bytes.
    #[error("mint-root association contains both owner-v1 and passkey-v2 fields")]
    BothArms,
    /// The input is not a well-formed protobuf message.
    #[error("mint-root association contains malformed protobuf wire bytes")]
    Malformed,
    /// The checked bytes could not be decoded as the requested message.
    #[error("mint-root association protobuf decode failed: {0}")]
    Decode(#[from] prost::DecodeError),
}

fn read_varint(bytes: &[u8], offset: &mut usize) -> Result<u64, MintRootAssociationWireError> {
    let mut value = 0_u64;
    for index in 0..10 {
        let byte = *bytes
            .get(*offset)
            .ok_or(MintRootAssociationWireError::Malformed)?;
        *offset += 1;
        if index == 9 && byte > 1 {
            return Err(MintRootAssociationWireError::Malformed);
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(MintRootAssociationWireError::Malformed)
}

fn skip(
    bytes: &[u8],
    offset: &mut usize,
    length: usize,
) -> Result<(), MintRootAssociationWireError> {
    *offset = offset
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or(MintRootAssociationWireError::Malformed)?;
    Ok(())
}

/// Scan top-level protobuf tags and reject an encoding that contains both
/// mint-root alternatives. Call this before any ordinary protobuf decoder.
pub fn verify_mint_root_association_wire(bytes: &[u8]) -> Result<(), MintRootAssociationWireError> {
    let mut offset = 0;
    let mut owner = false;
    let mut passkey = false;
    while offset < bytes.len() {
        let key = read_varint(bytes, &mut offset)?;
        let field = key >> 3;
        let wire_type = key & 0x07;
        if field == 0 || field > MAX_PROTOBUF_FIELD_NUMBER {
            return Err(MintRootAssociationWireError::Malformed);
        }
        match field {
            OWNER_MINT_ROOT_ATTACHMENT_FIELD => owner = true,
            PASSKEY_MINT_ROOT_ATTACHMENT_FIELD => passkey = true,
            _ => {}
        }
        if owner && passkey {
            return Err(MintRootAssociationWireError::BothArms);
        }
        match wire_type {
            0 => {
                read_varint(bytes, &mut offset)?;
            }
            1 => skip(bytes, &mut offset, 8)?,
            2 => {
                let length = usize::try_from(read_varint(bytes, &mut offset)?)
                    .map_err(|_| MintRootAssociationWireError::Malformed)?;
                skip(bytes, &mut offset, length)?;
            }
            5 => skip(bytes, &mut offset, 4)?,
            _ => return Err(MintRootAssociationWireError::Malformed),
        }
    }
    Ok(())
}

/// Verify the raw oneof tags, then decode a `ThreadControlAuthority`.
pub fn decode_thread_control_authority_for_verification(
    bytes: &[u8],
) -> Result<ThreadControlAuthority, MintRootAssociationWireError> {
    verify_mint_root_association_wire(bytes)?;
    Ok(ThreadControlAuthority::decode(bytes)?)
}

/// Verify the raw oneof tags, then decode a `SpoolCreationProof`.
pub fn decode_spool_creation_proof_for_verification(
    bytes: &[u8],
) -> Result<SpoolCreationProof, MintRootAssociationWireError> {
    verify_mint_root_association_wire(bytes)?;
    Ok(SpoolCreationProof::decode(bytes)?)
}
