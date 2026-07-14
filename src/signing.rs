//! Contract-owned request-signing bytes and header vocabulary.

use sha2::{Digest, Sha256};

pub const DOMAIN: &str = "heddle-req-sig-v1";
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

fn canonical(kind: &str, fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut result = format!("{DOMAIN}\nkind={}:{}", kind.len(), kind).into_bytes();
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
