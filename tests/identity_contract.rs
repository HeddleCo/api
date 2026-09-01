// SPDX-License-Identifier: Apache-2.0

use heddle_api::heddle::api::v1alpha1::{
    AccessTokenResponse, BeginWebAuthnRegistrationRequest, ClaimSignupInviteResponse, Entitlement,
    FinishWebAuthnAuthenticationRequest, GitHubInstallationRepository, PromoteAgentAccountRequest,
    RegisterGitHubInstallationRequest, RegisterGitHubInstallationResponse,
    RegisterPublicKeyRequest, StorageUsage, WhoAmIResponse,
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
        reservation_id: "invite-reservation-1".to_string(),
        verified_email_id: "verified-email-1".to_string(),
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
fn claim_signup_invite_response_round_trips_reservation() {
    let expected = ClaimSignupInviteResponse {
        reservation_id: "11111111-2222-3333-4444-555555555555".to_string(),
        reservation_expires_at: Some(prost_types::Timestamp {
            seconds: 1_775_000_000,
            nanos: 0,
        }),
    };

    let decoded = ClaimSignupInviteResponse::decode(expected.encode_to_vec().as_slice())
        .expect("decode ClaimSignupInviteResponse");

    assert_eq!(decoded, expected);
    assert_eq!(
        decoded.reservation_id,
        "11111111-2222-3333-4444-555555555555"
    );
    assert_eq!(
        decoded.reservation_expires_at,
        Some(prost_types::Timestamp {
            seconds: 1_775_000_000,
            nanos: 0,
        })
    );
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
fn generated_identity_requests_round_trip_both_client_mint_key_roles() {
    let authority = vec![0x11; 32];
    let proof = vec![0x22; 32];
    let registration = RegisterPublicKeyRequest {
        biscuit_authority_public_key: authority.clone(),
        device_proof_public_key: proof.clone(),
        ..Default::default()
    };
    let registration = RegisterPublicKeyRequest::decode(registration.encode_to_vec().as_slice())
        .expect("decode RegisterPublicKeyRequest");
    assert_eq!(registration.biscuit_authority_public_key, authority);
    assert_eq!(registration.device_proof_public_key, proof);

    let authentication = FinishWebAuthnAuthenticationRequest {
        biscuit_authority_public_key: vec![0x33; 32],
        device_proof_public_key: vec![0x44; 32],
        ..Default::default()
    };
    let authentication =
        FinishWebAuthnAuthenticationRequest::decode(authentication.encode_to_vec().as_slice())
            .expect("decode FinishWebAuthnAuthenticationRequest");
    assert_eq!(authentication.biscuit_authority_public_key, vec![0x33; 32]);
    assert_eq!(authentication.device_proof_public_key, vec![0x44; 32]);
}

#[test]
fn dual_role_wire_fields_and_domain_registry_are_explicit() {
    let registration = message_body("RegisterPublicKeyRequest");
    assert!(registration.contains("bytes biscuit_authority_public_key = 17;"));
    assert!(registration.contains("bytes device_proof_public_key = 18;"));
    let authentication = message_body("FinishWebAuthnAuthenticationRequest");
    assert!(authentication.contains("bytes biscuit_authority_public_key = 9;"));
    assert!(authentication.contains("bytes device_proof_public_key = 10;"));

    for domain in [
        "heddle-device-binding-v2\\0",
        "heddle-pop-delegation-v1\\0",
        "heddle-grant-envelope-v2\\0",
    ] {
        assert!(IDENTITY_PROTO.contains(domain), "missing domain {domain}");
    }
    assert!(IDENTITY_PROTO.contains("Tier-1 request:    \"heddle-req-sig-v1\""));
    assert!(!IDENTITY_PROTO.contains("heddle-req-sig-v1\\0"));
}

#[test]
fn register_github_installation_round_trips_verified_projection() {
    let request = RegisterGitHubInstallationRequest {
        installation_id: 12_345_678,
        client_operation_id: "register-installation-123".to_string(),
    };
    let decoded_request =
        RegisterGitHubInstallationRequest::decode(request.encode_to_vec().as_slice())
            .expect("decode RegisterGitHubInstallationRequest");
    assert_eq!(decoded_request, request);

    let response = RegisterGitHubInstallationResponse {
        installation_id: 12_345_678,
        account_login: "heddleco".to_string(),
        repository_selection: "selected".to_string(),
        repositories: vec![GitHubInstallationRepository {
            id: 87_654_321,
            full_name: "HeddleCo/private-repo".to_string(),
        }],
    };
    let decoded_response =
        RegisterGitHubInstallationResponse::decode(response.encode_to_vec().as_slice())
            .expect("decode RegisterGitHubInstallationResponse");
    assert_eq!(decoded_response, response);
}

#[test]
fn register_github_installation_documents_server_verified_ownership() {
    assert!(
        IDENTITY_PROTO
            .contains("Weft MUST verify that the authenticated caller administers the requested")
    );
    assert!(IDENTITY_PROTO.contains("GET /user/installations"));
    assert!(IDENTITY_PROTO.contains("The client-supplied installation_id is not ownership proof"));
    assert!(IDENTITY_PROTO.contains("linked GitHub OAuth token"));
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
            current_storage_bytes: Some(83),
            storage_allowance_bytes: Some(500_000_000_000),
        }),
        ..Default::default()
    };

    let decoded =
        WhoAmIResponse::decode(expected.encode_to_vec().as_slice()).expect("decode WhoAmI");

    assert_eq!(decoded, expected);
}
