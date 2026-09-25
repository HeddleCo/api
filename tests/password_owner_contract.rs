#![cfg(feature = "reflection")]

use ed25519_dalek::{Signer, SigningKey};
use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::v1alpha2::{
        AuthenticationChallenge, AuthorizationSignature, AuthorizationVerificationKey,
        CompleteAuthenticationRequest, MintRootAttachment, PasswordChallengeMetadata,
        PasswordChallengeProof, PasswordDeviceAdmission, PasswordOwnerEnvelopeV1,
        PasswordOwnerSetup, PasswordOwnerSetupAuthorization, PasswordUnlockCompletion,
        PasswordUnlockContinuation, RecordRef, SignedOwnerMintRootAttachment,
        SignedPasswordDeviceAdmission, SignedPasswordOwnerSetupAuthorization,
        complete_authentication_request,
    },
    password_owner::{
        PasswordOwnerError, decode_password_owner_envelope_canonical,
        decode_password_owner_setup_canonical, next_password_envelope_revision,
        password_challenge_signing_digest, password_device_admission_digest,
        password_mint_attachment_nonce, password_owner_setup_authorization_digest,
        password_owner_setup_digest, password_owner_wrap_aad,
        password_registration_verifier_possession_digest, validate_password_challenge_metadata,
        validate_password_completion_bindings, validate_password_owner_envelope,
        validate_password_owner_setup, validate_password_owner_setup_authorization_expiry,
        validate_password_owner_setup_binding, verify_password_auth_verifier_possession,
        verify_password_auth_verifier_registration_possession, verify_password_challenge_signature,
        verify_password_device_admission_signature,
        verify_password_owner_setup_authorization_signature,
    },
};
use prost::Message;
use prost_reflect::DescriptorPool;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};

fn envelope() -> PasswordOwnerEnvelopeV1 {
    PasswordOwnerEnvelopeV1 {
        format_version: 1,
        account_uuid: vec![1; 16],
        owner_public_key: SigningKey::from_bytes(&[12; 32])
            .verifying_key()
            .to_bytes()
            .to_vec(),
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
    changed = good.clone();
    changed.owner_public_key = vec![0; 32];
    assert_eq!(
        validate_password_owner_envelope(&changed),
        Err(PasswordOwnerError::Signature)
    );
    changed.owner_public_key = vec![0xff; 32];
    assert_eq!(
        validate_password_owner_envelope(&changed),
        Err(PasswordOwnerError::Signature)
    );
    changed.owner_public_key = vec![2; 32];
    assert_eq!(
        validate_password_owner_envelope(&changed),
        Err(PasswordOwnerError::Signature)
    );
    let mut wire = good.encode_to_vec();
    wire.extend_from_slice(&[0x60, 0x01]); // Unknown field 12 is discarded.
    assert_eq!(
        decode_password_owner_envelope_canonical(&wire),
        Ok(good.clone())
    );
    let mut setup = PasswordOwnerSetup {
        envelope: Some(good),
        auth_salt: vec![4; 16],
        auth_verifier_public_key: SigningKey::from_bytes(&[11; 32])
            .verifying_key()
            .to_bytes()
            .to_vec(),
        auth_memory_kib: 65_536,
        auth_iterations: 3,
        auth_parallelism: 4,
        auth_kdf_id: 1,
        format_version: 1,
        auth_verifier_possession_signature: vec![0; 64],
    };
    assert_eq!(
        validate_password_owner_setup(&setup),
        Err(PasswordOwnerError::Binding)
    );
    setup.auth_salt = vec![8; 16];
    validate_password_owner_setup(&setup).unwrap();
    decode_password_owner_setup_canonical(&setup.encode_to_vec()).unwrap();
    let mut setup_wire = setup.encode_to_vec();
    setup_wire.extend_from_slice(&[0x50, 0x01]); // Unknown field 10 is discarded.
    assert_eq!(
        decode_password_owner_setup_canonical(&setup_wire),
        Ok(setup)
    );
}

#[test]
fn password_verifier_signature_does_not_substitute_for_owner_admission() {
    let verifier = SigningKey::from_bytes(&[11; 32]);
    let owner = SigningKey::from_bytes(&[12; 32]);
    let challenge = PasswordChallengeMetadata {
        auth_salt: vec![2; 16],
        auth_memory_kib: 65_536,
        auth_iterations: 3,
        auth_parallelism: 4,
        challenge_id: vec![3; 32],
        nonce: vec![4; 32],
        auth_kdf_id: 1,
        format_version: 1,
    };
    let mut proof = PasswordChallengeProof {
        challenge_id: challenge.challenge_id.clone(),
        signature: Vec::new(),
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
        account_uuid: vec![1; 16],
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
        auth_verifier_public_key: SigningKey::from_bytes(&[11; 32])
            .verifying_key()
            .to_bytes()
            .to_vec(),
        auth_memory_kib: 65_536,
        auth_iterations: 3,
        auth_parallelism: 4,
        auth_kdf_id: 1,
        format_version: 1,
        auth_verifier_possession_signature: vec![0; 64],
    };
    let mut setup = setup;
    let verifier = SigningKey::from_bytes(&[11; 32]);
    let mut unsigned_setup = setup.clone();
    unsigned_setup.auth_verifier_possession_signature.clear();
    assert_eq!(
        password_owner_setup_digest(&unsigned_setup),
        password_owner_setup_digest(&setup)
    );
    assert_eq!(
        validate_password_owner_setup(&unsigned_setup),
        Err(PasswordOwnerError::Length)
    );
    let authorization = PasswordOwnerSetupAuthorization {
        format_version: 1,
        action: 1,
        account_uuid: vec![1; 16],
        owner_state_hash: vec![7; 32],
        expected_revision: 3,
        setup_sha256: password_owner_setup_digest(&setup).unwrap().to_vec(),
        client_operation_id: "change-1".into(),
        expires_at: Some(Timestamp {
            seconds: 1_700_000_600,
            nanos: 0,
        }),
    };
    let digest = password_owner_setup_authorization_digest(&authorization, Some(&setup)).unwrap();
    assert_eq!(
        validate_password_owner_setup_authorization_expiry(&authorization, 1_700_000_000),
        Ok(())
    );
    assert_eq!(
        validate_password_owner_setup_authorization_expiry(&authorization, 1_700_000_600),
        Err(PasswordOwnerError::Binding)
    );
    setup.auth_verifier_possession_signature = verifier.sign(&digest).to_bytes().to_vec();
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
    verify_password_auth_verifier_possession(&setup, &digest).unwrap();
    validate_password_owner_setup_binding(
        &setup,
        &[1; 16],
        owner.verifying_key().as_bytes(),
        &[3; 32],
    )
    .unwrap();
    assert_eq!(
        validate_password_owner_setup_binding(
            &setup,
            &[1; 16],
            owner.verifying_key().as_bytes(),
            &[4; 32]
        ),
        Err(PasswordOwnerError::Binding)
    );
    let mut swapped_verifier = setup.clone();
    swapped_verifier.auth_verifier_public_key = [11; 32].to_vec();
    assert!(verify_password_auth_verifier_possession(&swapped_verifier, &digest).is_err());
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
    changed_revision.expected_revision -= 1;
    changed_revision.expires_at.as_mut().unwrap().seconds += 1;
    assert_ne!(
        password_owner_setup_authorization_digest(&changed_revision, Some(&setup)).unwrap(),
        digest
    );
}

#[test]
fn setup_revision_survives_delete_and_invalidates_old_authorization() {
    let first = next_password_envelope_revision(None, 0).unwrap();
    let replaced = next_password_envelope_revision(Some(first), first).unwrap();
    let tombstone = next_password_envelope_revision(Some(replaced), replaced).unwrap();
    let recreated = next_password_envelope_revision(Some(tombstone), tombstone).unwrap();
    assert_eq!((first, replaced, tombstone, recreated), (1, 2, 3, 4));
    assert_eq!(
        next_password_envelope_revision(Some(recreated), 1),
        Err(PasswordOwnerError::Binding)
    );
    assert_eq!(
        next_password_envelope_revision(Some(tombstone), 0),
        Err(PasswordOwnerError::Binding)
    );
}

#[test]
fn password_begin_has_no_account_uuid_or_existence_disclosure() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    let metadata = pool
        .get_message_by_name("heddle.api.v1alpha2.PasswordChallengeMetadata")
        .unwrap();
    assert!(metadata.get_field_by_name("account_uuid").is_none());
    assert!(metadata.get_field_by_name("envelope_revision").is_none());
    let proof = pool
        .get_message_by_name("heddle.api.v1alpha2.PasswordChallengeProof")
        .unwrap();
    assert!(proof.get_field_by_name("envelope_revision").is_none());
    let services = include_str!("../proto/heddle/api/v1alpha2/services.proto");
    let prove = services
        .split("rpc ProvePasswordUnlock(")
        .nth(1)
        .unwrap()
        .split("rpc CompleteAuthentication(")
        .next()
        .unwrap();
    assert!(prove.contains("authorization_existence: AUTHORIZATION_EXISTENCE_HIDE"));
    let complete = services
        .split("rpc CompleteAuthentication(")
        .nth(1)
        .unwrap()
        .split("rpc BeginRegistration(")
        .next()
        .unwrap();
    assert!(complete.contains("authorization_existence: AUTHORIZATION_EXISTENCE_HIDE"));
}

#[test]
fn inactive_password_metadata_has_active_shape_and_ranges() {
    let active = PasswordChallengeMetadata {
        auth_salt: vec![7; 16],
        auth_memory_kib: 65_536,
        auth_iterations: 3,
        auth_parallelism: 4,
        challenge_id: vec![9; 32],
        nonce: vec![10; 32],
        auth_kdf_id: 1,
        format_version: 1,
    };
    let inactive = PasswordChallengeMetadata {
        auth_salt: vec![21; 16],
        challenge_id: vec![22; 32],
        nonce: vec![23; 32],
        ..active.clone()
    };
    for value in [&active, &inactive] {
        validate_password_challenge_metadata(value).unwrap();
        assert_eq!(value.auth_salt.len(), 16);
        assert_eq!(value.challenge_id.len(), 32);
        assert_eq!(value.nonce.len(), 32);
        assert_eq!(
            (
                value.auth_memory_kib,
                value.auth_iterations,
                value.auth_parallelism
            ),
            (65_536, 3, 4)
        );
        assert_eq!((value.auth_kdf_id, value.format_version), (1, 1));
    }
    assert_eq!(active.encoded_len(), inactive.encoded_len());
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    let metadata = pool
        .get_message_by_name("heddle.api.v1alpha2.PasswordChallengeMetadata")
        .unwrap();
    let fields: Vec<_> = metadata
        .fields()
        .map(|field| field.name().to_owned())
        .collect();
    assert_eq!(
        fields,
        [
            "auth_salt",
            "auth_memory_kib",
            "auth_iterations",
            "auth_parallelism",
            "challenge_id",
            "nonce",
            "auth_kdf_id",
            "format_version"
        ]
    );
    let mut downgraded = active.clone();
    downgraded.auth_kdf_id = 0;
    assert_eq!(
        validate_password_challenge_metadata(&downgraded),
        Err(PasswordOwnerError::Version)
    );
    downgraded = active;
    downgraded.format_version = 2;
    assert_eq!(
        validate_password_challenge_metadata(&downgraded),
        Err(PasswordOwnerError::Version)
    );
}

#[test]
fn password_owner_v1_golden_vectors_match_typescript() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/password-owner-v1.json")).unwrap();
    let field = |name: &str| vector[name].as_str().unwrap();
    let decoded = |name: &str| hex::decode(field(name)).unwrap();
    let mut envelope = envelope();
    envelope.owner_public_key = decoded("owner_public_key_hex");
    assert_eq!(
        hex::encode(password_owner_wrap_aad(&envelope).unwrap()),
        field("aad_hex")
    );
    let verifier = SigningKey::from_bytes(&[11; 32]);
    let setup = PasswordOwnerSetup {
        envelope: Some(envelope.clone()),
        auth_salt: vec![7; 16],
        auth_verifier_public_key: decoded("verifier_public_key_hex"),
        auth_memory_kib: 65_536,
        auth_iterations: 3,
        auth_parallelism: 4,
        auth_kdf_id: 1,
        format_version: 1,
        auth_verifier_possession_signature: decoded("verifier_possession_signature_hex"),
    };
    assert_eq!(
        hex::encode(password_owner_setup_digest(&setup).unwrap()),
        field("setup_digest_hex")
    );
    assert_eq!(
        setup.auth_verifier_public_key,
        verifier.verifying_key().to_bytes()
    );
    let challenge = PasswordChallengeMetadata {
        auth_salt: vec![7; 16],
        auth_memory_kib: 65_536,
        auth_iterations: 3,
        auth_parallelism: 4,
        challenge_id: vec![9; 32],
        nonce: vec![10; 32],
        auth_kdf_id: 1,
        format_version: 1,
    };
    let mut proof = PasswordChallengeProof {
        challenge_id: challenge.challenge_id.clone(),
        signature: vec![0; 64],
        caller_device_public_key: decoded("device_public_key_hex"),
    };
    assert_eq!(
        hex::encode(
            password_challenge_signing_digest(
                &challenge,
                &proof,
                field("operation_id"),
                1_700_000_000
            )
            .unwrap()
        ),
        field("proof_digest_hex")
    );
    let admission = PasswordDeviceAdmission {
        format_version: 1,
        account_uuid: envelope.account_uuid.clone(),
        challenge_id: challenge.challenge_id.clone(),
        continuation_id: vec![12; 32],
        caller_device_public_key: proof.caller_device_public_key.clone(),
        owner_state_hash: vec![13; 32],
        owner_sequence: 7,
        client_operation_id: field("operation_id").into(),
    };
    assert_eq!(
        hex::encode(password_device_admission_digest(&admission).unwrap()),
        field("admission_digest_hex")
    );
    let authorization = PasswordOwnerSetupAuthorization {
        format_version: 1,
        action: 1,
        account_uuid: envelope.account_uuid,
        owner_state_hash: admission.owner_state_hash,
        expected_revision: 3,
        setup_sha256: password_owner_setup_digest(&setup).unwrap().to_vec(),
        client_operation_id: field("operation_id").into(),
        expires_at: Some(Timestamp {
            seconds: 1_700_000_600,
            nanos: 0,
        }),
    };
    assert_eq!(
        hex::encode(
            password_owner_setup_authorization_digest(&authorization, Some(&setup)).unwrap()
        ),
        field("setup_authorization_digest_hex")
    );
    verify_password_auth_verifier_possession(
        &setup,
        &password_owner_setup_authorization_digest(&authorization, Some(&setup)).unwrap(),
    )
    .unwrap();
    let registration_challenge = [42; 32];
    let registration_digest =
        password_registration_verifier_possession_digest(&registration_challenge).unwrap();
    assert_eq!(
        hex::encode(registration_digest),
        field("registration_challenge_digest_hex")
    );
    let mut registration_setup = setup.clone();
    registration_setup.auth_verifier_possession_signature =
        decoded("registration_verifier_possession_signature_hex");
    verify_password_auth_verifier_registration_possession(
        &registration_setup,
        &registration_challenge,
    )
    .unwrap();
    assert_eq!(
        verify_password_auth_verifier_possession(&registration_setup, &registration_challenge),
        Err(PasswordOwnerError::Signature)
    );
    proof.signature = decoded("edge_signature_hex");
    assert_eq!(
        verify_password_challenge_signature(
            &challenge,
            &proof,
            field("operation_id"),
            1_700_000_000,
            &setup.auth_verifier_public_key
        ),
        Err(PasswordOwnerError::Signature)
    );
}

#[test]
fn completion_binds_challenge_device_attachment_nonce_and_expiry() {
    let challenge_ref = RecordRef {
        id: "password-challenge".into(),
        ..Default::default()
    };
    let metadata = PasswordChallengeMetadata {
        auth_salt: vec![7; 16],
        auth_memory_kib: 65_536,
        auth_iterations: 3,
        auth_parallelism: 4,
        challenge_id: vec![9; 32],
        nonce: vec![10; 32],
        auth_kdf_id: 1,
        format_version: 1,
    };
    let challenge = AuthenticationChallenge {
        r#ref: Some(challenge_ref.clone()),
        method: 2,
        password_challenge: Some(metadata.clone()),
        credential_expires_at: Some(Timestamp {
            seconds: 1_700_001_000,
            nanos: 0,
        }),
        ..Default::default()
    };
    let continuation = PasswordUnlockContinuation {
        envelope: Some(envelope()),
        continuation_id: vec![12; 32],
        envelope_revision: 3,
        ..Default::default()
    };
    let device_key = SigningKey::from_bytes(&[13; 32])
        .verifying_key()
        .to_bytes()
        .to_vec();
    let admission = PasswordDeviceAdmission {
        format_version: 1,
        account_uuid: vec![1; 16],
        challenge_id: metadata.challenge_id,
        continuation_id: continuation.continuation_id.clone(),
        caller_device_public_key: device_key.clone(),
        owner_state_hash: vec![13; 32],
        owner_sequence: 7,
        client_operation_id: "complete".into(),
    };
    let attachment = MintRootAttachment {
        account_uuid: admission.account_uuid.clone(),
        owner_state_hash: admission.owner_state_hash.clone(),
        owner_sequence: 7,
        mint_root_key: Some(AuthorizationVerificationKey {
            algorithm: 1,
            public_key: device_key.clone(),
        }),
        nonce: password_mint_attachment_nonce(&metadata.nonce, &continuation.continuation_id)
            .unwrap()
            .to_vec(),
        expires_at_unix_seconds: 1_700_001_000,
        ..Default::default()
    };
    let mut request = CompleteAuthenticationRequest {
        client_operation_id: "complete".into(),
        challenge: Some(challenge_ref),
        proof: Some(complete_authentication_request::Proof::PasswordUnlock(
            PasswordUnlockCompletion {
                continuation_id: continuation.continuation_id.clone(),
                owner_admission: Some(SignedPasswordDeviceAdmission {
                    admission: Some(admission),
                    owner_signature: None,
                }),
                mint_root_attachment: Some(SignedOwnerMintRootAttachment {
                    attachment: Some(attachment),
                    owner_signature: None,
                }),
            },
        )),
        caller_public_key: device_key.clone(),
        enroll_device: true,
        ..Default::default()
    };
    assert_eq!(
        validate_password_completion_bindings(&request, &challenge, &continuation, &device_key),
        Ok(())
    );
    let mut missing_ref_challenge = challenge.clone();
    missing_ref_challenge.r#ref = None;
    let mut missing_ref_request = request.clone();
    missing_ref_request.challenge = None;
    assert_eq!(
        validate_password_completion_bindings(
            &missing_ref_request,
            &missing_ref_challenge,
            &continuation,
            &device_key
        ),
        Err(PasswordOwnerError::Binding)
    );
    request.challenge.as_mut().unwrap().id = "other".into();
    assert_eq!(
        validate_password_completion_bindings(&request, &challenge, &continuation, &device_key),
        Err(PasswordOwnerError::Binding)
    );
    request.challenge.as_mut().unwrap().id = "password-challenge".into();
    let complete_authentication_request::Proof::PasswordUnlock(completion) =
        request.proof.as_mut().unwrap()
    else {
        panic!("password completion");
    };
    completion
        .mint_root_attachment
        .as_mut()
        .unwrap()
        .attachment
        .as_mut()
        .unwrap()
        .nonce[0] ^= 1;
    assert_eq!(
        validate_password_completion_bindings(&request, &challenge, &continuation, &device_key),
        Err(PasswordOwnerError::Binding)
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
