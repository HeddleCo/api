// SPDX-License-Identifier: Apache-2.0

use heddle_api::heddle::api::v1alpha1::{
    BeginWebAuthnRegistrationRequest, Entitlement, PromoteAgentAccountRequest, StorageUsage,
    WhoAmIResponse,
};
use prost::Message;

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
