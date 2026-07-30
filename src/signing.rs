//! Contract-owned request-signing bytes and header vocabulary.

use sha2::{Digest, Sha256};

use crate::heddle::api::v1alpha1::{EndpointDescriptor, RelayAdmissionClaims};
use prost::Message;

pub const DOMAIN: &str = "heddle-req-sig-v1";
pub const PROVIDER_PLAN_DOMAIN: &str = "heddle-provider-plan-v1";
pub const HEADER_ALGORITHM: &str = "x-heddle-sig-alg";
pub const HEADER_SIGNATURE_BIN: &str = "x-heddle-sig-bin";
pub const HEADER_TIMESTAMP: &str = "x-heddle-sig-ts";
pub const HEADER_NONCE_BIN: &str = "x-heddle-sig-nonce-bin";
pub const HEADER_IDENTITY: &str = "x-heddle-sig-identity";
pub const HEADER_WEBAUTHN_CLIENT_DATA_BIN: &str = "x-heddle-sig-webauthn-client-data-bin";
pub const HEADER_WEBAUTHN_AUTH_DATA_BIN: &str = "x-heddle-sig-webauthn-auth-data-bin";
pub const HEADER_WEBAUTHN_USER_HANDLE_BIN: &str = "x-heddle-sig-webauthn-user-handle-bin";
pub const HEADER_REQUIRED: &str = "x-heddle-sig-required";
pub const HEADER_ACTION_URL: &str = "x-heddle-sig-action-url";

/// Returns the canonical bytes signed for a unary request.
pub fn unary_bytes(
    signing_identity: &str,
    route: &str,
    timestamp_millis: i64,
    nonce: &[u8],
    deterministic_request: &[u8],
) -> Vec<u8> {
    canonical(
        "unary",
        &[
            ("identity", signing_identity.as_bytes().to_vec()),
            ("route", route.as_bytes().to_vec()),
            ("timestamp_ms", timestamp_millis.to_string().into_bytes()),
            ("nonce", hex::encode(nonce).into_bytes()),
            (
                "request_sha256",
                hex::encode(Sha256::digest(deterministic_request)).into_bytes(),
            ),
        ],
    )
}

/// Returns the canonical bytes signed by the opening frame of a stream.
pub fn stream_open_bytes(
    signing_identity: &str,
    stream_id: &str,
    route: &str,
    repository: &str,
    resume_cursor: &str,
    capability_context: &[u8],
) -> Vec<u8> {
    canonical(
        "stream-open",
        &[
            ("identity", signing_identity.as_bytes().to_vec()),
            ("stream_id", stream_id.as_bytes().to_vec()),
            ("route", route.as_bytes().to_vec()),
            ("repository", repository.as_bytes().to_vec()),
            ("resume_cursor", resume_cursor.as_bytes().to_vec()),
            (
                "capability_sha256",
                hex::encode(Sha256::digest(capability_context)).into_bytes(),
            ),
        ],
    )
}

/// Returns the canonical bytes signed to consent to one exact provider batch.
///
/// The server and Worker independently establish authorization from the
/// owner-anchored capability. This signature proves possession of the same
/// device key used for the stream opening and binds consent to one repository,
/// endpoint, nonce, and exact private-batch digest.
pub fn provider_plan_bytes(
    signing_identity: &str,
    stream_id: &str,
    repository: &str,
    client_endpoint_id: &str,
    plan_nonce: &[u8],
    grant_batch_digest: &[u8],
) -> Vec<u8> {
    provider_plan_canonical(
        "exact-batch",
        &[
            ("identity", signing_identity.as_bytes().to_vec()),
            ("stream_id", stream_id.as_bytes().to_vec()),
            ("repository", repository.as_bytes().to_vec()),
            ("client_endpoint_id", client_endpoint_id.as_bytes().to_vec()),
            ("plan_nonce", hex::encode(plan_nonce).into_bytes()),
            (
                "grant_batch_digest",
                hex::encode(grant_batch_digest).into_bytes(),
            ),
        ],
    )
}

/// Hashes the retry identity without conflating it with the request payload.
pub fn retry_key_hash(route: &str, client_operation_id: &str, request: &[u8]) -> [u8; 32] {
    Sha256::digest(canonical(
        "retry-key",
        &[
            ("route", route.as_bytes().to_vec()),
            (
                "client_operation_id",
                client_operation_id.as_bytes().to_vec(),
            ),
            (
                "request_sha256",
                hex::encode(Sha256::digest(request)).into_bytes(),
            ),
        ],
    ))
    .into()
}

/// Returns the domain-separated bytes signed for an HTTPS endpoint descriptor.
pub fn endpoint_descriptor_bytes(descriptor: &EndpointDescriptor) -> Vec<u8> {
    bootstrap_bytes("endpoint-descriptor", descriptor)
}

/// Returns the domain-separated bytes signed for a relay admission token.
pub fn relay_admission_bytes(claims: &RelayAdmissionClaims) -> Vec<u8> {
    bootstrap_bytes("relay-admission", claims)
}

fn bootstrap_bytes(kind: &str, message: &impl Message) -> Vec<u8> {
    canonical(kind, &[("protobuf", message.encode_to_vec())])
}

fn canonical(kind: &str, fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut result = format!("{DOMAIN}\nkind={}:{}", kind.len(), kind).into_bytes();
    for (name, value) in fields {
        result.extend_from_slice(format!("\n{name}={}:", value.len()).as_bytes());
        result.extend_from_slice(value);
    }
    result
}

fn provider_plan_canonical(kind: &str, fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut result = format!("{PROVIDER_PLAN_DOMAIN}\nkind={}:{}", kind.len(), kind).into_bytes();
    for (name, value) in fields {
        result.extend_from_slice(format!("\n{name}={}:", value.len()).as_bytes());
        result.extend_from_slice(value);
    }
    result
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct UnaryVector {
        identity: String,
        route: String,
        timestamp_millis: i64,
        nonce_hex: String,
        request_hex: String,
        canonical_hex: String,
    }

    #[test]
    fn canonical_fields_are_length_delimited() {
        let first = unary_bytes("ab", "/c", 1, &[0], &[1]);
        let second = unary_bytes("a", "b/c", 1, &[0], &[1]);
        assert_ne!(first, second);
        assert!(first.starts_with(b"heddle-req-sig-v1\nkind=5:unary"));
    }

    #[test]
    fn provider_plan_signature_changes_with_every_authorization_binding() {
        let endpoint = "11".repeat(32);
        let baseline = provider_plan_bytes(
            "principal:alice",
            "pull:one",
            "acme/widgets",
            &endpoint,
            &[7; 16],
            &[9; 32],
        );
        let different_digest = provider_plan_bytes(
            "principal:alice",
            "pull:one",
            "acme/widgets",
            &endpoint,
            &[7; 16],
            &[8; 32],
        );
        let different_nonce = provider_plan_bytes(
            "principal:alice",
            "pull:one",
            "acme/widgets",
            &endpoint,
            &[6; 16],
            &[9; 32],
        );

        assert!(baseline.starts_with(b"heddle-provider-plan-v1\nkind=11:exact-batch"));
        assert_ne!(baseline, different_digest);
        assert_ne!(baseline, different_nonce);
    }

    #[test]
    fn unary_signature_matches_cross_language_vector() {
        let vector: UnaryVector =
            serde_json::from_str(include_str!("../tests/fixtures/unary-signing-v1.json"))
                .expect("valid fixture");
        let actual = unary_bytes(
            &vector.identity,
            &vector.route,
            vector.timestamp_millis,
            &hex::decode(vector.nonce_hex).expect("nonce hex"),
            &hex::decode(vector.request_hex).expect("request hex"),
        );
        assert_eq!(hex::encode(actual), vector.canonical_hex);
    }
}
