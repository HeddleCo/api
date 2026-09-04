//! Contract-owned request-signing bytes and header vocabulary.

use sha2::{Digest, Sha256};

use crate::heddle::api::v1alpha1::{EndpointDescriptor, RelayAdmissionClaims};
use prost::Message;

/// Domain for the WebAuthn assertion that binds both client-minted session
/// signing roles. Includes its terminal NUL byte.
pub const IDENTITY_BINDING_CHALLENGE_V2_DOMAIN: &[u8] = b"heddle-device-binding-v2\0";
/// Domain for proof that each client-minted session role possesses its private
/// key. Includes its terminal NUL byte.
pub const DEVICE_KEY_SELF_POP_V1_DOMAIN: &[u8] = b"heddle-device-key-self-pop-v1\0";
/// Domain owned authoritatively by Weft's strict `pop_delegation` verifier.
/// Mirrored here so Rust and TypeScript producers cannot drift.
pub const POP_DELEGATION_V1_DOMAIN: &[u8] = b"heddle-pop-delegation-v1\0";
/// Deployed domain for Tier-1 request signatures. This legacy v1 value
/// predates the terminal-NUL convention and MUST remain byte-for-byte stable.
pub const TIER_1_REQUEST_SIGNING_V1_DOMAIN: &str = "heddle-req-sig-v1";
/// Deployed domain used by endpoint-descriptor and relay-admission bootstrap
/// signatures. It currently has the same bytes as request signing, but remains
/// a separate constant so the two protocol purposes cannot drift implicitly.
pub const TRANSPORT_BOOTSTRAP_SIGNING_V1_DOMAIN: &str = "heddle-req-sig-v1";
/// Domain prepended to every server-signed GrantEnvelope v2 canonical payload.
pub const GRANT_ENVELOPE_V2_DOMAIN: &[u8] = b"heddle-grant-envelope-v2\0";

/// Exact signed/wire role label for the ephemeral Biscuit authority key.
pub const BISCUIT_AUTHORITY_PUBLIC_KEY_ROLE: &[u8] = b"biscuit_authority_public_key\0";
/// Exact signed/wire role label for the non-extractable device proof key.
pub const DEVICE_PROOF_PUBLIC_KEY_ROLE: &[u8] = b"device_proof_public_key\0";
/// Signed format discriminator immediately following the GrantEnvelope domain.
pub const GRANT_ENVELOPE_V2_FORMAT_VERSION: u8 = 2;
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

const MAX_GRANT_ENVELOPE_SUBJECT_BYTES: usize = 256;
const MAX_GRANT_ENVELOPE_RIGHTS: usize = 64;
const MAX_GRANT_ENVELOPE_RIGHT_FIELD_BYTES: usize = 1024;

/// One ordered right in a GrantEnvelope v2 canonical payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantEnvelopeV2Right {
    pub kind: String,
    pub path: String,
    pub action: String,
}

/// The fields covered by a GrantEnvelope v2 server signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantEnvelopeV2Payload {
    pub biscuit_authority_public_key: [u8; 32],
    pub device_proof_public_key: [u8; 32],
    pub subject: String,
    pub rights: Vec<GrantEnvelopeV2Right>,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// A fail-closed GrantEnvelope v2 canonical-payload codec error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantEnvelopeV2CodecError {
    #[error("biscuit authority and device proof keys must be distinct")]
    EqualKeys,
    #[error("{field} exceeds {max} bytes")]
    FieldTooLong { field: &'static str, max: usize },
    #[error("rights_count exceeds {max}")]
    TooManyRights { max: usize },
    #[error("invalid GrantEnvelope v2 domain")]
    InvalidDomain,
    #[error("unsupported GrantEnvelope format version {0:#04x}")]
    InvalidFormatVersion(u8),
    #[error("invalid {0} role label")]
    InvalidRoleLabel(&'static str),
    #[error("truncated GrantEnvelope v2 while reading {0}")]
    Truncated(&'static str),
    #[error("{0} is not valid UTF-8")]
    InvalidUtf8(&'static str),
    #[error("GrantEnvelope v2 has {0} trailing bytes")]
    TrailingBytes(usize),
}

/// Encodes the exact bytes that a GrantEnvelope v2 issuer signs.
///
/// The encoder enforces all contract bounds and rejects equal role keys before
/// an envelope can be issued.
pub fn grant_envelope_v2_canonical_payload(
    payload: &GrantEnvelopeV2Payload,
) -> Result<Vec<u8>, GrantEnvelopeV2CodecError> {
    if payload.biscuit_authority_public_key == payload.device_proof_public_key {
        return Err(GrantEnvelopeV2CodecError::EqualKeys);
    }
    checked_u16_len(
        "subject",
        payload.subject.len(),
        MAX_GRANT_ENVELOPE_SUBJECT_BYTES,
    )?;
    if payload.rights.len() > MAX_GRANT_ENVELOPE_RIGHTS {
        return Err(GrantEnvelopeV2CodecError::TooManyRights {
            max: MAX_GRANT_ENVELOPE_RIGHTS,
        });
    }

    let mut encoded = Vec::new();
    encoded.extend_from_slice(GRANT_ENVELOPE_V2_DOMAIN);
    encoded.push(GRANT_ENVELOPE_V2_FORMAT_VERSION);
    encoded.extend_from_slice(BISCUIT_AUTHORITY_PUBLIC_KEY_ROLE);
    encoded.extend_from_slice(&payload.biscuit_authority_public_key);
    encoded.extend_from_slice(DEVICE_PROOF_PUBLIC_KEY_ROLE);
    encoded.extend_from_slice(&payload.device_proof_public_key);
    push_counted_string(
        &mut encoded,
        "subject",
        &payload.subject,
        MAX_GRANT_ENVELOPE_SUBJECT_BYTES,
    )?;
    encoded.extend_from_slice(&(payload.rights.len() as u16).to_be_bytes());
    for right in &payload.rights {
        push_counted_string(
            &mut encoded,
            "right.kind",
            &right.kind,
            MAX_GRANT_ENVELOPE_RIGHT_FIELD_BYTES,
        )?;
        push_counted_string(
            &mut encoded,
            "right.path",
            &right.path,
            MAX_GRANT_ENVELOPE_RIGHT_FIELD_BYTES,
        )?;
        push_counted_string(
            &mut encoded,
            "right.action",
            &right.action,
            MAX_GRANT_ENVELOPE_RIGHT_FIELD_BYTES,
        )?;
    }
    encoded.extend_from_slice(&payload.issued_at.to_be_bytes());
    encoded.extend_from_slice(&payload.expires_at.to_be_bytes());
    Ok(encoded)
}

/// Parses one complete GrantEnvelope v2 canonical payload without fallback.
pub fn parse_grant_envelope_v2_canonical_payload(
    encoded: &[u8],
) -> Result<GrantEnvelopeV2Payload, GrantEnvelopeV2CodecError> {
    let mut reader = GrantEnvelopeReader::new(encoded);
    if reader.take(GRANT_ENVELOPE_V2_DOMAIN.len(), "domain")? != GRANT_ENVELOPE_V2_DOMAIN {
        return Err(GrantEnvelopeV2CodecError::InvalidDomain);
    }
    let version = reader.take(1, "format_version")?[0];
    if version != GRANT_ENVELOPE_V2_FORMAT_VERSION {
        return Err(GrantEnvelopeV2CodecError::InvalidFormatVersion(version));
    }
    if reader.take(
        BISCUIT_AUTHORITY_PUBLIC_KEY_ROLE.len(),
        "authority role label",
    )? != BISCUIT_AUTHORITY_PUBLIC_KEY_ROLE
    {
        return Err(GrantEnvelopeV2CodecError::InvalidRoleLabel(
            "biscuit authority",
        ));
    }
    let biscuit_authority_public_key = reader.take_array("biscuit authority public key")?;
    if reader.take(
        DEVICE_PROOF_PUBLIC_KEY_ROLE.len(),
        "device proof role label",
    )? != DEVICE_PROOF_PUBLIC_KEY_ROLE
    {
        return Err(GrantEnvelopeV2CodecError::InvalidRoleLabel("device proof"));
    }
    let device_proof_public_key = reader.take_array("device proof public key")?;
    if biscuit_authority_public_key == device_proof_public_key {
        return Err(GrantEnvelopeV2CodecError::EqualKeys);
    }
    let subject = reader.take_counted_string("subject", MAX_GRANT_ENVELOPE_SUBJECT_BYTES)?;
    let rights_count = reader.take_u16("rights_count")? as usize;
    if rights_count > MAX_GRANT_ENVELOPE_RIGHTS {
        return Err(GrantEnvelopeV2CodecError::TooManyRights {
            max: MAX_GRANT_ENVELOPE_RIGHTS,
        });
    }
    let mut rights = Vec::with_capacity(rights_count);
    for _ in 0..rights_count {
        rights.push(GrantEnvelopeV2Right {
            kind: reader.take_counted_string("right.kind", MAX_GRANT_ENVELOPE_RIGHT_FIELD_BYTES)?,
            path: reader.take_counted_string("right.path", MAX_GRANT_ENVELOPE_RIGHT_FIELD_BYTES)?,
            action: reader
                .take_counted_string("right.action", MAX_GRANT_ENVELOPE_RIGHT_FIELD_BYTES)?,
        });
    }
    let issued_at = reader.take_i64("issued_at")?;
    let expires_at = reader.take_i64("expires_at")?;
    if reader.remaining() != 0 {
        return Err(GrantEnvelopeV2CodecError::TrailingBytes(reader.remaining()));
    }
    Ok(GrantEnvelopeV2Payload {
        biscuit_authority_public_key,
        device_proof_public_key,
        subject,
        rights,
        issued_at,
        expires_at,
    })
}

fn checked_u16_len(
    field: &'static str,
    length: usize,
    maximum: usize,
) -> Result<u16, GrantEnvelopeV2CodecError> {
    if length > maximum {
        return Err(GrantEnvelopeV2CodecError::FieldTooLong {
            field,
            max: maximum,
        });
    }
    Ok(length as u16)
}

fn push_counted_string(
    encoded: &mut Vec<u8>,
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), GrantEnvelopeV2CodecError> {
    let length = checked_u16_len(field, value.len(), maximum)?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(value.as_bytes());
    Ok(())
}

struct GrantEnvelopeReader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> GrantEnvelopeReader<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], GrantEnvelopeV2CodecError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.encoded.len())
            .ok_or(GrantEnvelopeV2CodecError::Truncated(field))?;
        let value = &self.encoded[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn take_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], GrantEnvelopeV2CodecError> {
        Ok(self.take(N, field)?.try_into().expect("length checked"))
    }

    fn take_u16(&mut self, field: &'static str) -> Result<u16, GrantEnvelopeV2CodecError> {
        Ok(u16::from_be_bytes(self.take_array(field)?))
    }

    fn take_i64(&mut self, field: &'static str) -> Result<i64, GrantEnvelopeV2CodecError> {
        Ok(i64::from_be_bytes(self.take_array(field)?))
    }

    fn take_counted_string(
        &mut self,
        field: &'static str,
        maximum: usize,
    ) -> Result<String, GrantEnvelopeV2CodecError> {
        let length = self.take_u16(field)? as usize;
        if length > maximum {
            return Err(GrantEnvelopeV2CodecError::FieldTooLong {
                field,
                max: maximum,
            });
        }
        let value = self.take(length, field)?;
        String::from_utf8(value.to_vec()).map_err(|_| GrantEnvelopeV2CodecError::InvalidUtf8(field))
    }

    fn remaining(&self) -> usize {
        self.encoded.len() - self.offset
    }
}

/// Returns the exact WebAuthn challenge bytes that bind both client-minted
/// session roles. The array types pin both keys to raw 32-byte Ed25519 public
/// keys; callers base64url-encode the returned bytes without padding for
/// `clientDataJSON.challenge`.
pub fn identity_binding_challenge_v2_bytes(
    biscuit_authority_public_key: &[u8; 32],
    device_proof_public_key: &[u8; 32],
) -> Vec<u8> {
    [
        IDENTITY_BINDING_CHALLENGE_V2_DOMAIN,
        BISCUIT_AUTHORITY_PUBLIC_KEY_ROLE,
        biscuit_authority_public_key,
        DEVICE_PROOF_PUBLIC_KEY_ROLE,
        device_proof_public_key,
    ]
    .concat()
}

/// Returns the domain-separated bytes signed by both client-minted session
/// role keys to prove possession during device registration.
pub fn device_key_self_pop_v1_bytes(authority: &[u8], proof: &[u8]) -> Vec<u8> {
    let identity_binding = [
        IDENTITY_BINDING_CHALLENGE_V2_DOMAIN,
        BISCUIT_AUTHORITY_PUBLIC_KEY_ROLE,
        authority,
        DEVICE_PROOF_PUBLIC_KEY_ROLE,
        proof,
    ]
    .concat();
    [DEVICE_KEY_SELF_POP_V1_DOMAIN, identity_binding.as_slice()].concat()
}

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
    canonical_with_domain(
        TRANSPORT_BOOTSTRAP_SIGNING_V1_DOMAIN,
        kind,
        &[("protobuf", message.encode_to_vec())],
    )
}

fn canonical(kind: &str, fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    canonical_with_domain(TIER_1_REQUEST_SIGNING_V1_DOMAIN, kind, fields)
}

fn canonical_with_domain(domain: &str, kind: &str, fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut result = format!("{domain}\nkind={}:{}", kind.len(), kind).into_bytes();
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
    fn client_mint_domains_are_distinct_and_versioned() {
        let domains: [&[u8]; 4] = [
            IDENTITY_BINDING_CHALLENGE_V2_DOMAIN,
            DEVICE_KEY_SELF_POP_V1_DOMAIN,
            POP_DELEGATION_V1_DOMAIN,
            GRANT_ENVELOPE_V2_DOMAIN,
        ];
        assert!(domains.iter().all(|domain| domain.ends_with(&[0])));
        assert!(
            domains
                .iter()
                .all(|domain| domain.windows(2).any(|part| part == b"-v"))
        );
        assert_ne!(domains[0], domains[1]);
        assert_ne!(domains[0], domains[2]);
        assert_ne!(domains[0], domains[3]);
        assert_ne!(domains[1], domains[2]);
        assert_ne!(domains[1], domains[3]);
        assert_ne!(domains[2], domains[3]);
        assert_eq!(TIER_1_REQUEST_SIGNING_V1_DOMAIN, "heddle-req-sig-v1");
        assert!(!TIER_1_REQUEST_SIGNING_V1_DOMAIN.as_bytes().contains(&0));
    }

    #[test]
    fn binding_challenge_contains_both_fixed_role_key_pairs() {
        let authority = [0x11; 32];
        let proof = [0x22; 32];
        let challenge = identity_binding_challenge_v2_bytes(&authority, &proof);
        let expected = [
            IDENTITY_BINDING_CHALLENGE_V2_DOMAIN,
            BISCUIT_AUTHORITY_PUBLIC_KEY_ROLE,
            authority.as_slice(),
            DEVICE_PROOF_PUBLIC_KEY_ROLE,
            proof.as_slice(),
        ]
        .concat();
        assert_eq!(challenge, expected);
        assert_ne!(
            challenge,
            identity_binding_challenge_v2_bytes(&proof, &authority)
        );
    }

    #[test]
    fn device_key_self_pop_is_distinct_and_role_ordered() {
        let authority = [0x11; 32];
        let proof = [0x22; 32];
        let binding = identity_binding_challenge_v2_bytes(&authority, &proof);
        let self_pop = device_key_self_pop_v1_bytes(&authority, &proof);

        assert!(self_pop.starts_with(DEVICE_KEY_SELF_POP_V1_DOMAIN));
        assert_eq!(&self_pop[DEVICE_KEY_SELF_POP_V1_DOMAIN.len()..], binding);
        assert_ne!(self_pop, binding);
        assert_ne!(self_pop, device_key_self_pop_v1_bytes(&proof, &authority));
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
