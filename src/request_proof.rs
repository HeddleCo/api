//! Portable verification of the native CallContext request proof.
//! Verification grants no resource authority and does not consume the nonce;
//! the receiving host must durably reject replay before serving or writing.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::{heddle::api::v1alpha1::CallContext, v2::MethodDescriptor};

pub const PROOF_WINDOW_MILLIS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestProofError {
    #[error("request and context operation IDs differ or are missing")]
    OperationId,
    #[error("request proof is missing, malformed, or outside its time window")]
    InvalidProof,
    #[error("request signing identity differs from verified capability key")]
    Identity,
    #[error("request signature is invalid")]
    Signature,
    #[error("request operation ID could not be decoded")]
    RequestMetadata,
}

pub struct VerifiedRequestProof<'a> {
    pub identity: &'a str,
    pub nonce: &'a [u8],
}

/// Verify the exact v2 method and protobuf request bytes against the key
/// resolved from an independently verified, currently authorized capability.
pub fn verify_native_request_proof<'a>(
    context: &'a CallContext,
    method: &'static MethodDescriptor,
    body: &[u8],
    effective_key: &[u8; 32],
    now_millis: i64,
) -> Result<VerifiedRequestProof<'a>, RequestProofError> {
    let operation_id = method
        .client_operation_id(body)
        .map_err(|_| RequestProofError::RequestMetadata)?
        .unwrap_or_default();
    if operation_id != context.client_operation_id
        || (method.client_operation_id_required && operation_id.is_empty())
    {
        return Err(RequestProofError::OperationId);
    }
    let proof = context
        .request_proof
        .as_ref()
        .ok_or(RequestProofError::InvalidProof)?;
    if proof.algorithm != "ed25519"
        || proof.nonce.len() != 16
        || now_millis.abs_diff(proof.timestamp_millis) > PROOF_WINDOW_MILLIS
    {
        return Err(RequestProofError::InvalidProof);
    }
    let identity = format!("principal:device-key:{}", hex::encode(effective_key));
    if proof.signing_identity != identity {
        return Err(RequestProofError::Identity);
    }
    let verifying_key =
        VerifyingKey::from_bytes(effective_key).map_err(|_| RequestProofError::Signature)?;
    let signature: [u8; 64] = proof
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| RequestProofError::Signature)?;
    verifying_key
        .verify_strict(
            &crate::signing::unary_bytes(
                &identity,
                method.path,
                proof.timestamp_millis,
                &proof.nonce,
                body,
            ),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| RequestProofError::Signature)?;
    Ok(VerifiedRequestProof {
        identity: &proof.signing_identity,
        nonce: &proof.nonce,
    })
}
