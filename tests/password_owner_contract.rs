#![cfg(feature = "reflection")]

use ed25519_dalek::{Signer, SigningKey};
use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::v1alpha2::{
        AuthorizationSignature, PasswordChallengeMetadata, PasswordChallengeProof,
        PasswordDeviceAdmission, PasswordOwnerEnvelopeV1, PasswordOwnerSetup,
        PasswordOwnerSetupAuthorization, SignedPasswordDeviceAdmission,
        SignedPasswordOwnerSetupAuthorization,
    },
    password_owner::{
        PasswordOwnerError, decode_password_owner_envelope_canonical,
        decode_password_owner_setup_canonical, password_challenge_signing_digest,
        password_device_admission_digest, password_owner_setup_authorization_digest,
        password_owner_setup_digest, password_owner_wrap_aad, validate_password_owner_envelope,
        validate_password_owner_setup, verify_password_challenge_signature,
        verify_password_device_admission_signature,
        verify_password_owner_setup_authorization_signature,
    },
};
use prost::Message;
use prost_reflect::DescriptorPool;
use sha2::{Digest, Sha256};

fn envelope() -> PasswordOwnerEnvelopeV1 {
    PasswordOwnerEnvelopeV1 {
        format_version: 1,
        account_uuid: vec![1; 16],
        owner_public_key: vec![2; 32],
        owner_id: vec![3; 32],
        kdf_id: 1,
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 4,
        wrap_salt: vec![4; 16],
        nonce: vec![5; 12],
        ciphertext_and_tag: vec![6; 48],
    }
}

#[test]
fn envelope_rejects_unknown_versions_costs_salt_reuse_and_unknown_wire_fields() {
    let good = envelope();
    validate_password_owner_envelope(&good).unwrap();
    decode_password_owner_envelope_canonical(&good.encode_to_vec()).unwrap();
    assert_eq!(password_owner_wrap_aad(&good).unwrap().len(), 141);
    let mut changed = good.clone();
    changed.format_version = 2;
    assert_eq!(
        validate_password_owner_envelope(&changed),
        Err(PasswordOwnerError::Version)
    );
    changed = good.clone();
    changed.memory_kib = 1;
    assert_eq!(
        validate_password_owner_envelope(&changed),
        Err(PasswordOwnerError::KdfCosts)
    );
    let mut wire = good.encode_to_vec();
    wire.extend_from_slice(&[0x60, 0x01]); // Unknown field 12.
    assert_eq!(
        decode_password_owner_envelope_canonical(&wire),
        Err(PasswordOwnerError::EnvelopeEncoding)
    );
    let mut setup = PasswordOwnerSetup {
        envelope: Some(good),
        auth_salt: vec![4; 16],
        auth_verifier_public_key: vec![7; 32],
        auth_memory_kib: 65_536,
        auth_iterations: 3,
        auth_parallelism: 4,
    };
    assert_eq!(
        validate_password_owner_setup(&setup),
        Err(PasswordOwnerError::Binding)
    );
    setup.auth_salt = vec![8; 16];
    validate_password_owner_setup(&setup).unwrap();
    decode_password_owner_setup_canonical(&setup.encode_to_vec()).unwrap();
    let mut setup_wire = setup.encode_to_vec();
    setup_wire.extend_from_slice(&[0x38, 0x01]); // Unknown field 7.
    assert_eq!(
        decode_password_owner_setup_canonical(&setup_wire),
        Err(PasswordOwnerError::EnvelopeEncoding)
    );
}

#[test]
fn password_verifier_signature_does_not_substitute_for_owner_admission() {
    let verifier = SigningKey::from_bytes(&[11; 32]);
    let owner = SigningKey::from_bytes(&[12; 32]);
    let challenge = PasswordChallengeMetadata {
        account_uuid: vec![1; 16],
        auth_salt: vec![2; 16],
        auth_memory_kib: 65_536,
        auth_iterations: 3,
        auth_parallelism: 4,
        envelope_revision: 1,
        challenge_id: vec![3; 32],
        nonce: vec![4; 32],
    };
    let mut proof = PasswordChallengeProof {
        challenge_id: challenge.challenge_id.clone(),
        signature: Vec::new(),
        envelope_revision: 1,
        caller_device_public_key: vec![5; 32],
    };
    let digest =
        password_challenge_signing_digest(&challenge, &proof, "op-1", 1_700_000_000).unwrap();
    proof.signature = verifier.sign(&digest).to_bytes().to_vec();
    verify_password_challenge_signature(
        &challenge,
        &proof,
        "op-1",
        1_700_000_000,
        verifier.verifying_key().as_bytes(),
    )
    .unwrap();
    assert_eq!(
        verify_password_challenge_signature(
            &challenge,
            &proof,
            "op-2",
            1_700_000_000,
            verifier.verifying_key().as_bytes()
        ),
        Err(PasswordOwnerError::Signature)
    );

    let admission = PasswordDeviceAdmission {
        format_version: 1,
        account_uuid: challenge.account_uuid,
        challenge_id: challenge.challenge_id,
        continuation_id: vec![6; 32],
        caller_device_public_key: proof.caller_device_public_key,
        owner_state_hash: vec![7; 32],
        owner_sequence: 1,
        client_operation_id: "complete-1".into(),
    };
    let admission_digest = password_device_admission_digest(&admission).unwrap();
    let mut key_id = Sha256::new();
    key_id.update(b"heddle-key-v1");
    key_id.update(1_u32.to_be_bytes());
    key_id.update(owner.verifying_key().as_bytes());
    let signed = SignedPasswordDeviceAdmission {
        admission: Some(admission),
        owner_signature: Some(AuthorizationSignature {
            signer_key_id: key_id.finalize().to_vec(),
            signature: owner.sign(&admission_digest).to_bytes().to_vec(),
        }),
    };
    verify_password_device_admission_signature(&signed, owner.verifying_key().as_bytes()).unwrap();
    assert_eq!(
        verify_password_device_admission_signature(&signed, verifier.verifying_key().as_bytes()),
        Err(PasswordOwnerError::Signature)
    );
}

#[test]
fn setup_change_signature_binds_action_revision_operation_and_exact_ciphertext() {
    let owner = SigningKey::from_bytes(&[12; 32]);
    let setup = PasswordOwnerSetup {
        envelope: Some(envelope()),
        auth_salt: vec![8; 16],
        auth_verifier_public_key: vec![9; 32],
        auth_memory_kib: 65_536,
        auth_iterations: 3,
        auth_parallelism: 4,
    };
    let authorization = PasswordOwnerSetupAuthorization {
        format_version: 1,
        action: 1,
        account_uuid: vec![1; 16],
        owner_state_hash: vec![7; 32],
        expected_revision: 3,
        setup_sha256: password_owner_setup_digest(&setup).unwrap().to_vec(),
        client_operation_id: "change-1".into(),
    };
    let digest = password_owner_setup_authorization_digest(&authorization, Some(&setup)).unwrap();
    let mut key_id = Sha256::new();
    key_id.update(b"heddle-key-v1");
    key_id.update(1_u32.to_be_bytes());
    key_id.update(owner.verifying_key().as_bytes());
    let signed = SignedPasswordOwnerSetupAuthorization {
        authorization: Some(authorization.clone()),
        owner_signature: Some(AuthorizationSignature {
            signer_key_id: key_id.finalize().to_vec(),
            signature: owner.sign(&digest).to_bytes().to_vec(),
        }),
    };
    verify_password_owner_setup_authorization_signature(
        &signed,
        Some(&setup),
        owner.verifying_key().as_bytes(),
    )
    .unwrap();
    let mut tampered = setup.clone();
    tampered.envelope.as_mut().unwrap().ciphertext_and_tag[0] ^= 1;
    assert_eq!(
        verify_password_owner_setup_authorization_signature(
            &signed,
            Some(&tampered),
            owner.verifying_key().as_bytes()
        ),
        Err(PasswordOwnerError::Binding)
    );
    let mut changed_revision = authorization;
    changed_revision.expected_revision += 1;
    assert_ne!(
        password_owner_setup_authorization_digest(&changed_revision, Some(&setup)).unwrap(),
        digest
    );
}

#[test]
fn descriptor_keeps_proof_delivery_separate_from_credential_completion() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    assert!(
        pool.get_message_by_name("heddle.api.v1alpha2.PasswordProof")
            .is_none()
    );
    let identity = pool
        .get_service_by_name("heddle.api.v1alpha2.IdentityService")
        .unwrap();
    let prove = identity
        .methods()
        .find(|method| method.name() == "ProvePasswordUnlock")
        .unwrap();
    assert_eq!(
        prove.input().full_name(),
        "heddle.api.v1alpha2.ProvePasswordUnlockRequest"
    );
    assert_eq!(
        prove.output().full_name(),
        "heddle.api.v1alpha2.PasswordUnlockContinuation"
    );
    for forbidden in ["credential", "session", "biscuit", "owner_authorization"] {
        assert!(prove.output().get_field_by_name(forbidden).is_none());
    }
    let complete = pool
        .get_message_by_name("heddle.api.v1alpha2.CompleteAuthenticationRequest")
        .unwrap();
    assert!(complete.get_field_by_name("password").is_none());
    assert!(complete.get_field_by_name("password_unlock").is_some());
    let registration = pool
        .get_message_by_name("heddle.api.v1alpha2.CompleteRegistrationRequest")
        .unwrap();
    assert!(registration.get_field_by_name("password").is_none());
    assert!(registration.get_field_by_name("password_setup").is_some());
    let completion = pool
        .get_message_by_name("heddle.api.v1alpha2.PasswordUnlockCompletion")
        .unwrap();
    for required in ["continuation_id", "owner_admission", "mint_root_attachment"] {
        assert!(completion.get_field_by_name(required).is_some());
    }
}
