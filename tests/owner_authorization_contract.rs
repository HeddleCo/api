// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use heddle_api::heddle::api::v1alpha1::{
    AnonymousKeyCredential, AuthorizationSignature, BootstrapOwnerRootRequest,
    CloneAuthorizationKeyring, GetOwnerGovernanceHeadRequest, GetOwnerGovernanceHeadResponse,
    GovernanceSettingMergePolicy, GovernanceSettingMergeSemantics, GovernanceStateHead,
    OwnerAuthorizationBundle, OwnerGovernanceState, OwnerKeyTransition, OwnerRoot,
    RecoveryGuardian, RecoveryGuardianKind, RecoveryPolicy, SignedOwnerCapability,
    SignedOwnerGovernanceState, SignedOwnerKeyTransition, SignedOwnerRoot, SignedSpoolOwnerGenesis,
    SpoolInitialTooling, SpoolSettings, SpoolWritePolicy, SubmitOwnerAuthorizationRequest,
    SubmitOwnerGovernanceStateRequest, SubmitOwnerGovernanceStateResponse,
};
use prost::Message;
use sha2::{Digest, Sha256};

use heddle_api::STATE_ATTACHMENT_AUTHORIZATION_CONFORMANCE;

fn assert_round_trip<T>(value: T)
where
    T: Message + Default + PartialEq + Debug,
{
    let encoded = value.encode_to_vec();
    let decoded = T::decode(encoded.as_slice()).expect("generated owner contract decodes");
    assert_eq!(decoded, value);
}

#[test]
fn generated_rust_round_trips_all_six_owner_contract_families() {
    assert_round_trip(SignedOwnerRoot {
        root: Some(OwnerRoot::default()),
        ..Default::default()
    });
    assert_round_trip(BootstrapOwnerRootRequest::default());
    assert_round_trip(SignedOwnerKeyTransition {
        transition: Some(OwnerKeyTransition::default()),
        ..Default::default()
    });
    assert_round_trip(SubmitOwnerAuthorizationRequest {
        authorization: Some(OwnerAuthorizationBundle {
            capability_chain: vec![SignedOwnerCapability::default()],
            ..Default::default()
        }),
        ..Default::default()
    });
    assert_round_trip(AnonymousKeyCredential::default());
    assert_round_trip(CloneAuthorizationKeyring::default());
    assert_round_trip(SignedSpoolOwnerGenesis::default());
}

#[test]
fn generated_recovery_policy_preserves_guardian_provenance() {
    let policy = RecoveryPolicy {
        threshold: 2,
        guardians: vec![
            RecoveryGuardian {
                kind: RecoveryGuardianKind::Paper as i32,
                ..Default::default()
            },
            RecoveryGuardian {
                kind: RecoveryGuardianKind::Weft as i32,
                ..Default::default()
            },
        ],
        window_secs: Some(604_800),
    };

    let encoded = policy.encode_to_vec();
    let decoded = RecoveryPolicy::decode(encoded.as_slice()).expect("recovery policy decodes");
    assert_eq!(decoded, policy);
    assert_ne!(decoded.guardians[0].kind, decoded.guardians[1].kind);
    assert_eq!(decoded.window_secs, Some(604_800));
}

#[test]
fn generated_attachment_authorization_classifies_every_current_kind() {
    use heddle_api::heddle::api::v1alpha1::{
        StateAttachmentAuthorizationClassification, StateAttachmentKind,
    };

    let expected = [
        StateAttachmentKind::Context,
        StateAttachmentKind::RiskSignals,
        StateAttachmentKind::ReviewSignatures,
        StateAttachmentKind::Discussions,
        StateAttachmentKind::StructuredConflicts,
        StateAttachmentKind::SemanticIndex,
        StateAttachmentKind::Signature,
    ];
    assert_eq!(
        STATE_ATTACHMENT_AUTHORIZATION_CONFORMANCE.len(),
        expected.len()
    );
    for kind in expected {
        assert!(
            STATE_ATTACHMENT_AUTHORIZATION_CONFORMANCE
                .contains(&(kind, StateAttachmentAuthorizationClassification::SpoolWrite,))
        );
    }
}

fn length_prefixed(value: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn canonical_settings_v1(settings: &SpoolSettings, output: &mut Vec<u8>) {
    output.extend_from_slice(&settings.visibility.to_be_bytes());
    output.extend_from_slice(&settings.state_visibility.to_be_bytes());
    output.extend_from_slice(&settings.bootstrap_kind.to_be_bytes());
    length_prefixed(settings.bootstrap_source.as_bytes(), output);
    output.extend_from_slice(&settings.write_policy.to_be_bytes());
    output.extend_from_slice(&settings.child_policy.to_be_bytes());

    let tooling = settings
        .initial_tooling
        .as_ref()
        .cloned()
        .unwrap_or_default();
    output.push(u8::from(tooling.readme));
    length_prefixed(tooling.license.as_bytes(), output);
    length_prefixed(tooling.gitignore.as_bytes(), output);
    length_prefixed(tooling.language_preset.as_bytes(), output);

    output.extend_from_slice(&settings.sync_behavior.to_be_bytes());
    output.extend_from_slice(&settings.bootstrap_sync_direction.to_be_bytes());
    length_prefixed(settings.description.as_bytes(), output);
    output.extend_from_slice(&settings.hold_lifecycle.to_be_bytes());
}

fn canonical_owner_governance_state_v1(
    state: &OwnerGovernanceState,
    include_state_hash: bool,
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&state.format_version.to_be_bytes());
    length_prefixed(&state.spool_uuid, &mut output);

    let expected_head = state.expected_head.as_ref().cloned().unwrap_or_default();
    length_prefixed(&expected_head.state_hash, &mut output);
    output.extend_from_slice(&expected_head.sequence.to_be_bytes());
    output.extend_from_slice(&state.sequence.to_be_bytes());

    output.extend_from_slice(&(state.merge_parent_state_hashes.len() as u32).to_be_bytes());
    for parent in &state.merge_parent_state_hashes {
        length_prefixed(parent, &mut output);
    }

    canonical_settings_v1(
        state
            .settings
            .as_ref()
            .expect("test state carries settings"),
        &mut output,
    );
    output.extend_from_slice(&(state.merge_policies.len() as u32).to_be_bytes());
    for policy in &state.merge_policies {
        length_prefixed(policy.setting_key.as_bytes(), &mut output);
        output.extend_from_slice(&policy.semantics.to_be_bytes());
    }

    length_prefixed(&state.owner_state_hash, &mut output);
    if include_state_hash {
        length_prefixed(&state.governance_state_hash, &mut output);
    }
    output
}

fn domain_hash(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(body);
    digest.finalize().to_vec()
}

fn owner_key_id(public_key: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"heddle-key-v1");
    digest.update(1_u32.to_be_bytes());
    digest.update(public_key);
    digest.finalize().to_vec()
}

#[test]
fn owner_governance_state_constructs_signs_serializes_and_verifies() {
    let signing_key = SigningKey::from_bytes(&[0x58; 32]);
    let verifying_key = signing_key.verifying_key();

    let mut state = OwnerGovernanceState {
        format_version: 1,
        spool_uuid: vec![0x11; 16],
        expected_head: Some(GovernanceStateHead {
            state_hash: vec![0x22; 32],
            sequence: 8,
        }),
        sequence: 9,
        merge_parent_state_hashes: vec![vec![0x33; 32]],
        settings: Some(SpoolSettings {
            write_policy: SpoolWritePolicy::OwnerOnly as i32,
            initial_tooling: Some(SpoolInitialTooling {
                readme: true,
                license: "Apache-2.0".to_string(),
                ..Default::default()
            }),
            description: "owner-signed settings".to_string(),
            ..Default::default()
        }),
        merge_policies: [
            "bootstrap_kind",
            "bootstrap_source",
            "bootstrap_sync_direction",
            "child_policy",
            "state_visibility",
            "description",
            "hold_lifecycle",
            "initial_tooling",
            "sync_behavior",
            "visibility",
            "write_policy",
        ]
        .into_iter()
        .map(|setting_key| GovernanceSettingMergePolicy {
            setting_key: setting_key.to_string(),
            semantics: GovernanceSettingMergeSemantics::LastWriterWins as i32,
        })
        .collect(),
        owner_state_hash: vec![0x44; 32],
        governance_state_hash: Vec::new(),
    };
    state.governance_state_hash = domain_hash(
        b"heddle-owner-governance-state-v1",
        &canonical_owner_governance_state_v1(&state, false),
    );

    let signing_digest = domain_hash(
        b"heddle-owner-governance-signature-v1",
        &canonical_owner_governance_state_v1(&state, true),
    );
    let signature = signing_key.sign(&signing_digest);
    let signed = SignedOwnerGovernanceState {
        state: Some(state),
        owner_signature: Some(AuthorizationSignature {
            signer_key_id: owner_key_id(verifying_key.as_bytes()),
            signature: signature.to_bytes().to_vec(),
        }),
    };

    let encoded = signed.encode_to_vec();
    let decoded = SignedOwnerGovernanceState::decode(encoded.as_slice())
        .expect("signed governance state decodes");
    assert_eq!(decoded, signed);

    let decoded_state = decoded.state.as_ref().expect("decoded state");
    assert_eq!(
        decoded_state.governance_state_hash,
        domain_hash(
            b"heddle-owner-governance-state-v1",
            &canonical_owner_governance_state_v1(decoded_state, false),
        )
    );

    let decoded_proof = decoded
        .owner_signature
        .as_ref()
        .expect("decoded owner signature");
    assert_eq!(
        decoded_proof.signer_key_id,
        owner_key_id(verifying_key.as_bytes())
    );
    let signature_bytes: [u8; 64] = decoded_proof
        .signature
        .as_slice()
        .try_into()
        .expect("64-byte Ed25519 signature");
    let decoded_signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(
            &domain_hash(
                b"heddle-owner-governance-signature-v1",
                &canonical_owner_governance_state_v1(decoded_state, true),
            ),
            &decoded_signature,
        )
        .expect("owner signature verifies after protobuf round trip");

    let mut tampered_state = decoded_state.clone();
    tampered_state
        .settings
        .as_mut()
        .expect("decoded settings")
        .description = "server-rewritten settings".to_string();
    assert!(
        verifying_key
            .verify(
                &domain_hash(
                    b"heddle-owner-governance-signature-v1",
                    &canonical_owner_governance_state_v1(&tampered_state, true),
                ),
                &decoded_signature,
            )
            .is_err(),
        "rewriting settings after signing must invalidate the owner signature",
    );
}

#[test]
fn owner_governance_read_and_submission_messages_round_trip() {
    let head = GovernanceStateHead {
        state_hash: vec![0x55; 32],
        sequence: 12,
    };
    assert_round_trip(GetOwnerGovernanceHeadRequest {
        spool_uuid: vec![0x66; 16],
    });
    assert_round_trip(GetOwnerGovernanceHeadResponse {
        spool_uuid: vec![0x66; 16],
        head: Some(head.clone()),
        owner_state_hash: vec![0x77; 32],
    });
    assert_round_trip(SubmitOwnerGovernanceStateRequest {
        governance_state: Some(SignedOwnerGovernanceState::default()),
        client_operation_id: "0197-governance-update".to_string(),
    });
    assert_round_trip(SubmitOwnerGovernanceStateResponse {
        accepted_head: Some(head),
    });
}
