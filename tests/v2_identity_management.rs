use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use heddle_api::{heddle::api::v2alpha1 as api, v2::identity_management::*};
#[test]
fn delegation_is_bounded_canonical_and_signature_binds_scope_and_key() {
    let value = DelegationStatement {
        account_id: "00000000-0000-0000-0000-000000000001".into(),
        delegation_id: "00000000-0000-0000-0000-000000000002".into(),
        label: "worker".into(),
        kind: 1,
        root_public_key: vec![1; 32],
        subject_public_key: vec![2; 32],
        endpoint_public_key: vec![],
        scope: "read".into(),
        expires_at_unix_seconds: 1900000000,
        parent_credential_digest: vec![3; 32],
    };
    let bytes = value.encode().expect("encode");
    assert_eq!(DelegationStatement::decode(&bytes).expect("decode"), value);
    for end in 0..bytes.len() {
        assert!(DelegationStatement::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(DelegationStatement::decode(&trailing).is_err());
    let signer = SigningKey::from_bytes(&[7; 32]);
    let signature = signer.sign(&signing_bytes(DELEGATION, &bytes).expect("statement"));
    let mut broader = value.clone();
    broader.scope = "admin".into();
    assert!(
        signer
            .verifying_key()
            .verify(
                &signing_bytes(DELEGATION, &broader.encode().expect("encode")).expect("statement"),
                &signature
            )
            .is_err()
    );
    assert_ne!(
        signing_bytes(DELEGATION, &bytes).expect("delegation"),
        signing_bytes(ISSUE_AUTHORITY, &bytes).expect("issuance")
    );
}
#[test]
fn issuance_proofs_bind_operation_version_scope_and_subject() {
    let request = api::IssueDelegationCredentialRequest {
        client_operation_id: "op".into(),
        delegation: Some(api::RecordRef {
            id: "delegation".into(),
            spool: None,
        }),
        proof_public_key: vec![7; 32],
        scope: "read".into(),
        expected_delegation_version: vec![8; 32],
        ..Default::default()
    };
    let original = issuance("account", &request).expect("intent");
    let mut changed = request.clone();
    changed.client_operation_id = "another".into();
    assert_ne!(original, issuance("account", &changed).expect("intent"));
    changed = request.clone();
    changed.proof_public_key[0] = 9;
    assert_ne!(original, issuance("account", &changed).expect("intent"));
    changed = request.clone();
    changed.expected_delegation_version[0] = 9;
    assert_ne!(original, issuance("account", &changed).expect("intent"));
    changed = request.clone();
    changed.scope = "admin".into();
    assert_ne!(original, issuance("account", &changed).expect("intent"));
}

#[test]
fn owner_lifecycle_proof_domains_are_supported_and_separated() {
    use heddle_api::v2::identity_management as wire;
    let complete = wire::signing_bytes(wire::OWNER_TRANSITION_POSSESSION, b"action")
        .expect("owner completion proof supported");
    let veto = wire::signing_bytes(wire::OWNER_TRANSITION_VETO, b"action")
        .expect("owner veto proof supported");
    assert_ne!(complete, veto);
    assert_ne!(
        complete,
        wire::signing_bytes(wire::RECOVERY_POSSESSION, b"action").expect("recovery domain")
    );
}
