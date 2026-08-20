// SPDX-License-Identifier: Apache-2.0

use heddle_api::heddle::api::v1alpha1::{
    AccessTokenResponse, BeginWebAuthnRegistrationRequest, ClaimSignupInviteResponse, Entitlement,
    PromoteAgentAccountRequest, SignupBootstrapMethod, StorageUsage, WhoAmIResponse,
};
use prost::Message;

const IDENTITY_PROTO: &str = include_str!("../proto/heddle/api/v1alpha1/identity.proto");

fn message_body(name: &str) -> &str {
    let header = format!("message {name} {{");
    let start = IDENTITY_PROTO
        .find(&header)
        .unwrap_or_else(|| panic!("missing {name}"));
    let after = start + header.len();
    let end = IDENTITY_PROTO[after..]
        .find("\n}")
        .unwrap_or_else(|| panic!("unclosed {name}"));
    &IDENTITY_PROTO[after..after + end]
}

fn assert_counted_consent_encoding(body: &str) {
    assert!(
        body.contains("the lowercase hex SHA-256 of the claim secret (64 hex chars)"),
        "counted authorization_hash encoding missing:\n{body}"
    );
    assert!(
        body.contains("Do not send uppercase or raw 32-byte digest"),
        "authorization_hash forbidden encodings missing:\n{body}"
    );
    assert!(
        body.contains("On the wire this stays proto `int64`"),
        "wire expires_at_millis type missing:\n{body}"
    );
    assert!(
        body.contains(
            "exactly 8 big-endian two's-complement bytes of that i64 (`i64::to_be_bytes`)"
        ),
        "counted expires_at_millis encoding missing:\n{body}"
    );
    assert!(
        body.contains("Not decimal text, not protobuf varint"),
        "expires_at_millis forbidden encodings missing:\n{body}"
    );
    assert!(
        body.contains("Empty hash + 0 is old-client v1"),
        "old-client pairing rule missing:\n{body}"
    );
}

#[test]
fn begin_registration_documents_counted_consent_encoding() {
    assert_counted_consent_encoding(message_body("BeginWebAuthnRegistrationRequest"));
}

#[test]
fn promote_agent_account_documents_counted_consent_encoding() {
    assert_counted_consent_encoding(message_body("PromoteAgentAccountRequest"));
}

#[test]
fn begin_registration_round_trips_optional_claim_consent_issuance() {
    let expected = BeginWebAuthnRegistrationRequest {
        username: "luke".to_string(),
        display_name: "Luke".to_string(),
        account_id: "account-1".to_string(),
        agent_node_id: "agent-node-1".to_string(),
        pre_consent_signature: vec![0x11, 0x22],
        nonce: vec![0x33, 0x44],
        authorization_hash: "ab".repeat(32),
        expires_at_millis: 1_750_003_600_000,
    };

    let decoded = BeginWebAuthnRegistrationRequest::decode(expected.encode_to_vec().as_slice())
        .expect("decode BeginWebAuthnRegistrationRequest");
    assert_eq!(decoded, expected);
}

#[test]
fn begin_registration_omits_claim_consent_issuance_for_old_clients() {
    let legacy = BeginWebAuthnRegistrationRequest {
        username: "luke".to_string(),
        account_id: "account-1".to_string(),
        agent_node_id: "agent-node-1".to_string(),
        pre_consent_signature: vec![0x11],
        nonce: vec![0x22],
        ..Default::default()
    };
    let encoded = legacy.encode_to_vec();
    let decoded = BeginWebAuthnRegistrationRequest::decode(encoded.as_slice())
        .expect("decode legacy BeginWebAuthnRegistrationRequest");
    assert_eq!(decoded.authorization_hash, "");
    assert_eq!(decoded.expires_at_millis, 0);

    let with_issuance = BeginWebAuthnRegistrationRequest {
        authorization_hash: "ab".repeat(32),
        expires_at_millis: 1_750_003_600_000,
        ..legacy
    };
    let extended = with_issuance.encode_to_vec();
    assert!(
        extended.starts_with(&encoded),
        "issuance fields are trailing additions; old encodings remain a prefix"
    );
}

#[test]
fn promote_agent_account_round_trips_optional_claim_consent_issuance() {
    let expected = PromoteAgentAccountRequest {
        account_id: "account-1".to_string(),
        handle: "luke".to_string(),
        credential_id: "cred-1".to_string(),
        challenge_id: "challenge-1".to_string(),
        client_data_json: vec![0x01],
        attestation_object: vec![0x02],
        agent_node_id: "agent-node-1".to_string(),
        promote_consent_signature: vec![0x03],
        client_operation_id: "promote-operation-123".to_string(),
        authorization_hash: "cd".repeat(32),
        expires_at_millis: 1_750_003_600_000,
    };

    let decoded = PromoteAgentAccountRequest::decode(expected.encode_to_vec().as_slice())
        .expect("decode PromoteAgentAccountRequest");
    assert_eq!(decoded, expected);
}

#[test]
fn promote_agent_account_omits_claim_consent_issuance_for_old_clients() {
    let legacy = PromoteAgentAccountRequest {
        account_id: "account-1".to_string(),
        handle: "luke".to_string(),
        credential_id: "cred-1".to_string(),
        client_operation_id: "promote-operation-123".to_string(),
        ..Default::default()
    };
    let encoded = legacy.encode_to_vec();
    let decoded = PromoteAgentAccountRequest::decode(encoded.as_slice())
        .expect("decode legacy PromoteAgentAccountRequest");
    assert_eq!(decoded.authorization_hash, "");
    assert_eq!(decoded.expires_at_millis, 0);

    let with_issuance = PromoteAgentAccountRequest {
        authorization_hash: "cd".repeat(32),
        expires_at_millis: 1_750_003_600_000,
        ..legacy
    };
    let extended = with_issuance.encode_to_vec();
    assert!(
        extended.starts_with(&encoded),
        "issuance fields are trailing additions; old encodings remain a prefix"
    );
}

#[test]
fn claim_signup_invite_response_round_trips_mint_inputs() {
    let expected = ClaimSignupInviteResponse {
        bootstrap_token: Vec::new(),
        reservation_id: "11111111-2222-3333-4444-555555555555".to_string(),
        session_id: "signup-bootstrap-session-rev".to_string(),
        allowed_methods: vec![
            SignupBootstrapMethod::BeginWebAuthnRegistration as i32,
            SignupBootstrapMethod::RegisterPublicKey as i32,
        ],
        ..Default::default()
    };

    let decoded = ClaimSignupInviteResponse::decode(expected.encode_to_vec().as_slice())
        .expect("decode ClaimSignupInviteResponse");

    assert_eq!(decoded, expected);
    assert!(decoded.bootstrap_token.is_empty());
    assert_eq!(
        decoded.reservation_id,
        "11111111-2222-3333-4444-555555555555"
    );
    assert_eq!(decoded.session_id, "signup-bootstrap-session-rev");
}

#[test]
fn access_token_response_round_trips_device_id_mint_input() {
    let expected = AccessTokenResponse {
        token: String::new(),
        subject: "user:alice".to_string(),
        session_id: "session-rev".to_string(),
        device_id: "device-root-id".to_string(),
        ..Default::default()
    };

    let decoded = AccessTokenResponse::decode(expected.encode_to_vec().as_slice())
        .expect("decode AccessTokenResponse");

    assert_eq!(decoded, expected);
    assert!(decoded.token.is_empty());
    assert_eq!(decoded.device_id, "device-root-id");
}

#[test]
fn entitlement_round_trips_usage_and_subscription_projection() {
    let expected = WhoAmIResponse {
        entitlement: Some(Entitlement {
            billing_interval: Some("year".to_string()),
            billing_interval_count: Some(1),
            currency: Some("eur".to_string()),
            amount: Some(19_900),
            provider_subscription_id: Some("sub_customer".to_string()),
            ..Default::default()
        }),
        storage_usage: Some(StorageUsage {
            current_storage_bytes: 83,
            storage_allowance_bytes: 500_000_000_000,
        }),
        ..Default::default()
    };

    let decoded =
        WhoAmIResponse::decode(expected.encode_to_vec().as_slice()).expect("decode WhoAmI");

    assert_eq!(decoded, expected);
}
