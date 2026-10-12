//! Byte snapshots captured with sha2 0.10.9 at origin/main
//! a1a4b6e34fc0737bc0cad3d388cc4a2e3fe28dae. Expected bytes must not be regenerated
//! during dependency upgrades. Inputs use the existing fixed protocol fixtures
//! and the explicit values below; no clocks, random keys or network are involved.
use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use heddle_api::{
    heddle::api::{common as host, v1alpha2 as api},
    hybrid_codec as codec, import_authority as import, native_witness as native,
    password_owner as password, signing, timeline_upload as timeline, witness_trust as witness,
};
use prost::Message;
use serde_json::Value;

fn fixture(text: &str) -> Value {
    serde_json::from_str(text).expect("fixed fixture JSON")
}
fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("fixed hex string")).expect("fixed hex bytes")
}
fn decode<T: Message + Default>(value: &Value) -> T {
    T::decode(bytes(value).as_slice()).expect("fixed protobuf")
}
fn wire<T: Message + Default>(f: &Value, name: &str) -> T {
    decode(&f["wire_vectors"][name]["wire_hex"])
}
fn record(out: &mut BTreeMap<String, String>, name: &str, value: impl AsRef<[u8]>) {
    assert!(
        out.insert(name.into(), hex::encode(value.as_ref()))
            .is_none()
    );
    // Also freeze a deterministic Ed25519 signature over every returned digest
    // or signed transcript, exercising dalek's SHA-512 dependency alongside SHA-256.
    let signature = SigningKey::from_bytes(&[42; 32]).sign(value.as_ref());
    out.insert(
        format!("{name}/signature"),
        hex::encode(signature.to_bytes()),
    );
}

fn transport(out: &mut BTreeMap<String, String>) {
    record(
        out,
        "signing/one_key_device_binding_challenge",
        signing::one_key_device_binding_challenge(&[7; 32]),
    );
    record(
        out,
        "signing/recovery_new_device_pop_digest",
        signing::recovery_new_device_pop_digest("recovery-123", &[7; 32]),
    );
    record(
        out,
        "signing/unary_bytes",
        signing::unary_bytes(
            "principal:device-key:07",
            "/heddle.api.v1alpha2.SyncService/Fetch",
            1_700_000_000_123,
            &[8; 16],
            b"\x08\x01\x12\x03abc",
        ),
    );
    record(
        out,
        "signing/stream_open_bytes",
        signing::stream_open_bytes(
            "principal:device-key:07",
            "stream-1",
            "/heddle.api.v1alpha2.SyncService/Fetch",
            "spool-1",
            "cursor-1",
            b"capability\0context",
        ),
    );
    record(
        out,
        "signing/retry_key_hash",
        signing::retry_key_hash(
            "/heddle.api.v1alpha2.SyncService/Fetch",
            "operation-1",
            b"\x08\x01\x12\x03abc",
        ),
    );
    for (name, parts) in [
        ("empty", vec![b"".as_slice()]),
        ("split", vec![b"abc".as_slice(), b"\0def".as_slice()]),
        ("multi_block", vec![&[0xa5; 129][..]]),
    ] {
        record(out, &format!("codec/hash/{name}"), codec::hash(&parts));
    }
    record(out, "codec/key_id", codec::key_id(&[7; 32]));
}

fn password_and_passkey(out: &mut BTreeMap<String, String>) {
    record(
        out,
        "password/registration_possession",
        password::password_registration_verifier_possession_digest(&[3; 32]).expect("challenge"),
    );
    record(
        out,
        "password/mint_nonce",
        password::password_mint_attachment_nonce(&[4; 32], &[6; 32]).expect("nonce"),
    );
    let owner = SigningKey::from_bytes(&[12; 32]);
    record(
        out,
        "password/owner_key_id",
        codec::key_id(owner.verifying_key().as_bytes()),
    );
    let mut setup = api::PasswordOwnerSetup {
        envelope: Some(api::PasswordOwnerEnvelopeV1 {
            format_version: 1,
            account_uuid: vec![1; 16],
            owner_public_key: owner.verifying_key().to_bytes().to_vec(),
            owner_id: vec![3; 32],
            kdf_id: 1,
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 4,
            wrap_salt: vec![4; 16],
            nonce: vec![5; 12],
            ciphertext_and_tag: vec![6; 48],
        }),
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
    let setup_digest = password::password_owner_setup_digest(&setup).expect("setup");
    record(out, "password/owner_setup", setup_digest);
    let authorization = api::PasswordOwnerSetupAuthorization {
        format_version: 1,
        action: 1,
        account_uuid: vec![1; 16],
        owner_state_hash: vec![7; 32],
        expected_revision: 3,
        setup_sha256: setup_digest.to_vec(),
        client_operation_id: "change-1".into(),
        expires_at: Some(prost_types::Timestamp {
            seconds: 1_700_000_600,
            nanos: 0,
        }),
    };
    let digest = password::password_owner_setup_authorization_digest(&authorization, Some(&setup))
        .expect("authorization");
    record(out, "password/setup_authorization", digest);
    setup.auth_verifier_possession_signature = SigningKey::from_bytes(&[11; 32])
        .sign(&digest)
        .to_bytes()
        .to_vec();
    let signed = api::SignedPasswordOwnerSetupAuthorization {
        authorization: Some(authorization),
        owner_signature: Some(api::AuthorizationSignature {
            signer_key_id: codec::key_id(owner.verifying_key().as_bytes()),
            signature: owner.sign(&digest).to_bytes().to_vec(),
        }),
    };
    // Exercises password_owner's private SHA-256 key-id calculation as well.
    password::verify_password_owner_setup_authorization_signature(
        &signed,
        Some(&setup),
        owner.verifying_key().as_bytes(),
    )
    .expect("owner key ID and signature");
    let challenge = api::PasswordChallengeMetadata {
        auth_salt: vec![2; 16],
        auth_memory_kib: 65_536,
        auth_iterations: 3,
        auth_parallelism: 4,
        challenge_id: vec![3; 32],
        nonce: vec![4; 32],
        auth_kdf_id: 1,
        format_version: 1,
    };
    let proof = api::PasswordChallengeProof {
        challenge_id: vec![3; 32],
        signature: vec![],
        caller_device_public_key: vec![5; 32],
    };
    record(
        out,
        "password/challenge",
        password::password_challenge_signing_digest(&challenge, &proof, "op-1", 1_700_000_000)
            .expect("challenge"),
    );
    let admission = api::PasswordDeviceAdmission {
        format_version: 1,
        account_uuid: vec![1; 16],
        challenge_id: vec![3; 32],
        continuation_id: vec![6; 32],
        caller_device_public_key: vec![5; 32],
        owner_state_hash: vec![7; 32],
        owner_sequence: 1,
        client_operation_id: "complete-1".into(),
    };
    record(
        out,
        "password/device_admission",
        password::password_device_admission_digest(&admission).expect("admission"),
    );
    let f = fixture(include_str!("fixtures/passkey-mint-grant-v1.json"));
    let attachment: api::SignedMintRootAttachment = decode(&f["positive"]["attachment_proto_hex"]);
    record(
        out,
        "passkey/mint_grant",
        heddle_api::passkey_mint_grant::passkey_mint_grant_signing_digest(
            attachment.grant.as_ref().expect("grant"),
        )
        .expect("digest"),
    );
    let f = fixture(include_str!("fixtures/custodial-recovery-v1.json"));
    let proof: api::CustodialEmailProof = decode(&f["email_proof_wire_hex"]);
    let proposal: api::CustodialRecoverProposal = decode(&f["proposal_wire_hex"]);
    record(
        out,
        "custody/email_secret",
        heddle_api::v2::custodial_recovery::email_secret_hash(&proof).expect("email"),
    );
    record(
        out,
        "custody/proposal",
        heddle_api::v2::custodial_recovery::proposal_signing_digest(&proposal).expect("proposal"),
    );
    // Exercises custody's private SHA-256 guardian-key selector.
    heddle_api::v2::custodial_recovery::validate_submission(
        &decode(&f["attempt_wire_hex"]),
        &proposal,
        &decode(&f["submit_wire_hex"]),
        &decode(&f["old_guardian_wire_hex"]),
        1_700_604_800,
    )
    .expect("custody signatures and selectors");
}

fn timeline(out: &mut BTreeMap<String, String>) {
    const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
    let origin = api::TimelineOriginEndorsement {
        deployment_public_key: vec![1; 32],
        spool_id: UUID.into(),
        thread_id: vec![2; 32],
        run_id: "run_7".into(),
        principal_id: UUID.into(),
        credential_class: api::TimelineOriginCredentialClass::Agent as i32,
        effective_pop_key_sha256: vec![3; 32],
        credential_identity: Some(api::TimelineOriginCredentialIdentity {
            identity: Some(
                api::timeline_origin_credential_identity::Identity::ServerIssued(
                    api::TimelineServerIssuedCredential {
                        credential_id: vec![4; 16],
                    },
                ),
            ),
        }),
        uploader_device_public_key: vec![5; 32],
        signature: vec![6; 64],
    };
    record(
        out,
        "timeline/origin",
        timeline::origin_digest(&origin).expect("origin"),
    );
    record(
        out,
        "timeline/derivation_path",
        timeline::derivation_path_sha256(&[vec![8; 64], vec![9; 64], vec![10; 64]]).expect("path"),
    );
    let request = api::UploadScrubbedTimelineRequest {
        client_operation_id: UUID.into(),
        thread: Some(api::ThreadRef {
            spool: Some(api::SpoolRef { id: UUID.into() }),
            id: Some(api::ThreadId { value: vec![2; 32] }),
        }),
        run: Some(api::RecordRef {
            spool: Some(api::SpoolRef { id: UUID.into() }),
            id: "run_7".into(),
        }),
        canonicalization_version: 1,
        run_revision: 1,
        snapshot: Some(api::UploadRunSummary {
            state: api::operation_record::State::Running as i32,
            harness: "codex".into(),
        }),
        events: vec![api::UploadTimelineEvent {
            position: 0,
            kind: api::UploadTimelineEventKind::ToolStarted as i32,
            recorded_at: Some(prost_types::Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_000_000,
            }),
            tool_name: Some(api::UploadTimelineTool::Bash as i32),
        }],
        origin: Some(origin),
        ..Default::default()
    };
    record(
        out,
        "timeline/logical_request",
        timeline::logical_request_digest(&request, 1_700_000_001_000_000).expect("upload"),
    );
}

fn hybrid(out: &mut BTreeMap<String, String>) {
    let f = fixture(include_str!(
        "fixtures/import-authority-host-witness-v1.json"
    ));
    macro_rules! signed {
        ($name:literal, $ty:ty, $digest:path, $domain:expr) => {{
            let value: $ty = decode(&f["signed_vectors"][$name]["wire_hex"]);
            record(
                out,
                concat!("import/", $name, "/signed"),
                $digest(&value).expect("signed digest"),
            );
            record(
                out,
                concat!("import/", $name, "/body"),
                codec::signing_digest($domain, value.body.as_ref().expect("body"))
                    .expect("body digest"),
            );
        }};
    }
    signed!(
        "permission",
        api::SignedImportMemberPermissionV1,
        import::signed_permission_digest,
        import::PERMISSION_DOMAIN
    );
    signed!(
        "genesis_main",
        api::SignedImportGenesisAuthorityV1,
        import::signed_genesis_digest,
        import::GENESIS_DOMAIN
    );
    signed!(
        "delegation",
        api::SignedImportJobDelegationV1,
        import::signed_delegation_digest,
        import::DELEGATION_DOMAIN
    );
    signed!(
        "operation_main",
        api::SignedDelegatedImportOperationV1,
        import::signed_operation_digest,
        import::OPERATION_DOMAIN
    );
    record(
        out,
        "import/owner_chain",
        import::owner_chain_digest(&wire(&f, "owner_chain")).expect("chain"),
    );
    record(
        out,
        "import/manifest",
        import::manifest_digest(&wire(&f, "terminal_manifest")).expect("manifest"),
    );
    let policy: api::SignedSpoolPolicyRecord = wire(&f, "signed_policy");
    record(
        out,
        "import/policy_state",
        import::policy_state_digest(policy.body.as_ref().expect("policy")).expect("policy digest"),
    );
    record(
        out,
        "import/conversion_options",
        import::conversion_options_digest("git-converter/1.0", b"").expect("options"),
    );
    for (name, value) in f["commitment_vectors"].as_object().expect("commitments") {
        // Freeze every canonical commitment, including malformed-but-encodable
        // inputs. This covers signed payloads that share the generic hash helper.
        let domain = value["domain"].as_str().expect("domain");
        let digest = match value["schema"].as_str().expect("schema") {
            "heddle.api.v1alpha2.ImportOwnerChainV1" => {
                import::owner_chain_digest(&decode(&value["wire_hex"])).expect("owner chain")
            }
            "heddle.api.v1alpha2.ImportPublicationWitnessV1" => codec::signing_digest(
                domain,
                &decode::<api::ImportPublicationWitnessV1>(&value["wire_hex"]),
            )
            .expect("publication payload"),
            "heddle.api.v1alpha2.ImportResultManifestV1" => {
                import::manifest_digest(&decode(&value["wire_hex"])).expect("manifest")
            }
            "heddle.api.v1alpha2.SignedDelegatedImportOperationV1" => {
                import::signed_operation_digest(&decode(&value["wire_hex"]))
                    .expect("signed operation")
            }
            "heddle.api.v1alpha2.SignedImportGenesisAuthorityV1" => {
                import::signed_genesis_digest(&decode(&value["wire_hex"])).expect("signed genesis")
            }
            "heddle.api.v1alpha2.SignedImportJobDelegationV1" => {
                import::signed_delegation_digest(&decode(&value["wire_hex"]))
                    .expect("signed delegation")
            }
            "heddle.api.v1alpha2.SignedImportMemberPermissionV1" => {
                import::signed_permission_digest(&decode(&value["wire_hex"]))
                    .expect("signed permission")
            }
            "heddle.api.v1alpha2.ImportContentV1" => {
                import::content_digest(&decode(&value["wire_hex"])).expect("content")
            }
            "heddle.api.v1alpha2.ImportFrontierV1" => {
                import::frontier_digest(&decode(&value["wire_hex"])).expect("frontier")
            }
            "heddle.api.v1alpha2.ImportJobPreparationV1" => codec::signing_digest(
                domain,
                &decode::<api::ImportJobPreparationV1>(&value["wire_hex"]),
            )
            .expect("preparation"),
            "heddle.api.v1alpha2.ImportGenesisWitnessV1" => codec::signing_digest(
                domain,
                &decode::<api::ImportGenesisWitnessV1>(&value["wire_hex"]),
            )
            .expect("genesis payload"),
            "heddle.api.v1alpha2.ImportAuthorityWitnessV1" => codec::signing_digest(
                domain,
                &decode::<api::ImportAuthorityWitnessV1>(&value["wire_hex"]),
            )
            .expect("authority payload"),
            "heddle.api.v1alpha2.HostedLandingWitnessV1" => codec::signing_digest(
                domain,
                &decode::<api::HostedLandingWitnessV1>(&value["wire_hex"]),
            )
            .expect("landing payload"),
            "heddle.api.common.HostedWitnessBoundaryAcceptanceV1" => codec::signing_digest(
                domain,
                &decode::<host::HostedWitnessBoundaryAcceptanceV1>(&value["wire_hex"]),
            )
            .expect("boundary binding"),
            schema => panic!("uncovered commitment schema: {schema}"),
        };
        record(out, &format!("import/commitment/{name}"), digest);
    }
    let publication: api::ImportPublicationWitnessV1 = wire(&f, "publication");
    record(
        out,
        "import/publication_payload",
        codec::signing_digest(import::PUBLICATION_DOMAIN, &publication).expect("publication"),
    );
    let record_value: api::SignedRecord = wire(&f, "converted_main");
    record(
        out,
        "import/signed_native",
        import::signed_native_digest(&record_value).expect("native"),
    );
    for domain in [
        "heddle-hosted-authority-envelope-v1",
        "heddle-boundary-originals-manifest-v1",
        "heddle-boundary-publication-intent-v1",
    ] {
        record(
            out,
            &format!("import/boundary_octets/{domain}"),
            import::boundary_octets_digest(domain, b"fixed\0octets"),
        );
    }
    let f = fixture(include_str!("fixtures/native-host-witness-v1.json"));
    let binding: api::SignedNativeGenesisAuthorityV1 = wire(&f, "start_thread_binding");
    record(
        out,
        "native/signed_genesis",
        native::signed_genesis_digest(&binding).expect("binding"),
    );
    record(
        out,
        "native/genesis_body",
        codec::signing_digest(native::GENESIS_DOMAIN, binding.body.as_ref().expect("body"))
            .expect("body"),
    );
    let payload: api::NativeGenesisWitnessV1 = wire(&f, "start_thread_payload");
    record(
        out,
        "native/creator_envelope",
        codec::hash(&[&payload.creator_authority_envelope]),
    );
    record(
        out,
        "native/original_record",
        codec::hash(&[&payload
            .original_genesis
            .as_ref()
            .expect("original")
            .canonical_record]),
    );
}

fn witnesses(out: &mut BTreeMap<String, String>) {
    let f = fixture(include_str!(
        "fixtures/import-authority-host-witness-v1.json"
    ));
    record(out, "witness/id", witness::witness_id(&[7; 32]));
    let mut leaves = Vec::new();
    for name in [
        "genesis_admission",
        "authority_admission",
        "publication_statement",
        "landing_statement",
    ] {
        let signed: host::SignedHostedWitnessStatementV1 =
            decode(&f["signed_vectors"][name]["wire_hex"]);
        let body = signed.body.as_ref().expect("statement");
        record(
            out,
            &format!("witness/statement/{name}"),
            witness::statement_signing_digest(body).expect("statement digest"),
        );
        let leaf = witness::leaf_digest(
            body.purpose,
            &codec::canonical(body).expect("canonical"),
            &signed.signature,
        )
        .expect("leaf");
        record(out, &format!("witness/leaf/{name}"), &leaf);
        leaves.push(leaf);
    }
    leaves.sort();
    for count in 0..=4 {
        record(
            out,
            &format!("witness/merkle/{count}"),
            witness::merkle_root(&leaves[..count]).expect("tree"),
        );
    }
    let f = fixture(include_str!("fixtures/native-host-witness-v1.json"));
    let set: host::SignedHostedWitnessSetV1 = wire(&f, "current_set");
    record(
        out,
        "witness/set_digest",
        codec::hash(&[
            &witness::set_signing_bytes(set.body.as_ref().expect("set body")).expect("set bytes"),
        ]),
    );
}

#[test]
fn sha2_golden_vectors() {
    let mut actual = BTreeMap::new();
    transport(&mut actual);
    password_and_passkey(&mut actual);
    timeline(&mut actual);
    hybrid(&mut actual);
    witnesses(&mut actual);
    let expected: BTreeMap<String, String> =
        serde_json::from_str(include_str!("fixtures/sha2-golden-main.json"))
            .expect("frozen baseline bytes");
    assert_eq!(actual.len(), expected.len(), "golden vector inventory");
    for (name, value) in actual {
        assert_eq!(Some(&value), expected.get(&name), "golden vector: {name}");
    }
}
