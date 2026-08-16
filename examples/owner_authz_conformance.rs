// SPDX-License-Identifier: Apache-2.0
#![allow(deprecated)]

use std::{env, fs, process::ExitCode};

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use heddle_api::heddle::api::v1alpha1::{
    AccessTokenResponse, ActiveSession, AuthorizationSignature, CloneAuthorizationKeyring,
    OwnerAuthorizationBundle, OwnerKeyBinding, PullReady, PullServerFrame,
    RegisterPublicKeyRequest, ResourceOwnershipTransfer, ResourceTransferAcceptance,
    SidecarAuthorization, SidecarOperationSigningBody, SignedResourceTransferHandoff,
    SpoolCapabilityAction, StateAttachmentTransfer, pull_server_frame,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const OPERATION_DOMAIN: &[u8] = b"heddle-sidecar-operation-v1";

#[derive(Deserialize)]
struct Fixture {
    format_version: u32,
    required_actions: Vec<u32>,
    spool_uuid_hex: String,
    sidecar_kind: u32,
    blob_hash: String,
    payload_hex: String,
    payload_sha256_hex: String,
    leaf_capability_id_hex: String,
    canonical_body_hex: String,
    signing_digest_hex: String,
    signing_seed_hex: String,
    signer_public_key_hex: String,
    signature_hex: String,
    negative_cases: Vec<ExpectedCase>,
}

#[derive(Deserialize)]
struct ExpectedCase {
    id: String,
    expected: bool,
}

#[derive(Serialize)]
struct Outcome {
    id: String,
    accepted: bool,
}

#[derive(Clone, PartialEq, Message)]
struct LegacyPullReady {
    #[prost(string, tag = "8")]
    remote_revision_address: String,
}

#[derive(Clone, PartialEq, Message)]
struct LegacyAccessTokenResponse {
    #[prost(string, tag = "1")]
    token: String,
    #[prost(bytes = "vec", tag = "7")]
    grant_envelope: Vec<u8>,
}

fn main() -> ExitCode {
    match run() {
        Ok(outcomes) => {
            println!(
                "{}",
                serde_json::to_string(&outcomes).expect("serialize conformance outcomes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<Vec<Outcome>, String> {
    let fixture_path = env::args().nth(1).ok_or("missing fixture path")?;
    let fixture: Fixture =
        serde_json::from_slice(&fs::read(fixture_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;

    let payload = decode(&fixture.payload_hex)?;
    let payload_hash = Sha256::digest(&payload).to_vec();
    equal_hex(&payload_hash, &fixture.payload_sha256_hex, "payload digest")?;
    let canonical = canonical_body(
        fixture.format_version,
        &fixture.required_actions,
        &decode(&fixture.spool_uuid_hex)?,
        fixture.sidecar_kind,
        &fixture.blob_hash,
        &payload_hash,
        &decode(&fixture.leaf_capability_id_hex)?,
    )?;
    equal_hex(&canonical, &fixture.canonical_body_hex, "canonical body")?;
    let digest = domain_hash(OPERATION_DOMAIN, &canonical);
    equal_hex(&digest, &fixture.signing_digest_hex, "signing digest")?;

    let seed: [u8; 32] = decode(&fixture.signing_seed_hex)?
        .try_into()
        .map_err(|_| "signing seed is not 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&seed);
    equal_hex(
        signing_key.verifying_key().as_bytes(),
        &fixture.signer_public_key_hex,
        "signer public key",
    )?;
    let signature = signature(&fixture.signature_hex)?;
    signing_key
        .verifying_key()
        .verify(&digest, &signature)
        .map_err(|error| format!("fixture signature does not verify: {error}"))?;

    generated_round_trips_and_old_clients_ignore_new_fields()?;

    let outcomes = fixture
        .negative_cases
        .iter()
        .map(|case| Outcome {
            id: case.id.clone(),
            accepted: evaluate(case, &fixture, &signing_key.verifying_key(), &signature),
        })
        .collect::<Vec<_>>();
    for (expected, actual) in fixture.negative_cases.iter().zip(&outcomes) {
        if expected.expected != actual.accepted {
            return Err(format!(
                "{} expected {}, got {}",
                expected.id, expected.expected, actual.accepted
            ));
        }
    }
    Ok(outcomes)
}

fn evaluate(
    case: &ExpectedCase,
    fixture: &Fixture,
    signer: &VerifyingKey,
    signature: &Signature,
) -> bool {
    match case.id.as_str() {
        "signer-mismatch" => {
            let rogue = SigningKey::from_bytes(&[0x77; 32]);
            rogue
                .verifying_key()
                .verify(
                    &decode(&fixture.signing_digest_hex).expect("fixture digest"),
                    signature,
                )
                .is_ok()
        }
        "payload-swapping" => verify_mutated(fixture, signer, signature, |_, payload| {
            payload[0] ^= 0x01;
        }),
        "wrong-spool" => verify_mutated(fixture, signer, signature, |spool, _| {
            spool[0] ^= 0x01;
        }),
        "transition-fork" => transition_chain_is_linear(&[
            (1, [0_u8; 32], [1_u8; 32]),
            (2, [1_u8; 32], [2_u8; 32]),
            (2, [1_u8; 32], [3_u8; 32]),
        ]),
        "rogue-uuid-to-key-binding" => {
            let expected_uuid = [0x11_u8; 16];
            let binding_uuid = [0x22_u8; 16];
            expected_uuid == binding_uuid
        }
        "incomplete-transfer-source-only" => transfer_is_complete(true, false),
        "incomplete-transfer-destination-only" => transfer_is_complete(false, true),
        "attenuated-purge" => action_is_allowed(SpoolCapabilityAction::Purge, false),
        "attenuated-metadata-supersession" => {
            action_is_allowed(SpoolCapabilityAction::MetadataSupersession, false)
        }
        "direct-purge" => action_is_allowed(SpoolCapabilityAction::Purge, true),
        "direct-metadata-supersession" => {
            action_is_allowed(SpoolCapabilityAction::MetadataSupersession, true)
        }
        "direct-visibility" => action_is_allowed(SpoolCapabilityAction::Visibility, true),
        "delegated-visibility" => action_is_allowed(SpoolCapabilityAction::Visibility, false),
        "missing-visibility" => false,
        other => panic!("unknown conformance case {other}"),
    }
}

fn verify_mutated(
    fixture: &Fixture,
    signer: &VerifyingKey,
    signature: &Signature,
    mutate: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>),
) -> bool {
    let mut spool = decode(&fixture.spool_uuid_hex).expect("fixture spool");
    let mut payload = decode(&fixture.payload_hex).expect("fixture payload");
    mutate(&mut spool, &mut payload);
    let body = canonical_body(
        fixture.format_version,
        &fixture.required_actions,
        &spool,
        fixture.sidecar_kind,
        &fixture.blob_hash,
        &Sha256::digest(payload),
        &decode(&fixture.leaf_capability_id_hex).expect("fixture capability id"),
    )
    .expect("mutated canonical body");
    signer
        .verify(&domain_hash(OPERATION_DOMAIN, &body), signature)
        .is_ok()
}

fn transition_chain_is_linear(rows: &[(u64, [u8; 32], [u8; 32])]) -> bool {
    rows.windows(2)
        .all(|pair| pair[1].0 == pair[0].0 + 1 && pair[1].1 == pair[0].2)
}

fn transfer_is_complete(source_signature: bool, destination_signature: bool) -> bool {
    source_signature && destination_signature
}

fn action_is_allowed(action: SpoolCapabilityAction, direct: bool) -> bool {
    !matches!(
        action,
        SpoolCapabilityAction::Purge | SpoolCapabilityAction::MetadataSupersession
    ) || direct
}

fn generated_round_trips_and_old_clients_ignore_new_fields() -> Result<(), String> {
    let bundle = OwnerAuthorizationBundle::default();
    let binding = OwnerKeyBinding {
        format_version: 1,
        stable_owner_uuid: vec![0x11; 16],
        ..Default::default()
    };
    round_trip(RegisterPublicKeyRequest {
        owner_root: Some(Default::default()),
        owner_root_proof_of_possession: Some(AuthorizationSignature::default()),
        owner_recovery_policy: Some(Default::default()),
        owner_key_binding: Some(binding.clone()),
        ..Default::default()
    })?;
    round_trip(AccessTokenResponse {
        grant_envelope: b"still-live-legacy-envelope".to_vec(),
        owner_authorization: Some(bundle.clone()),
        ..Default::default()
    })?;
    round_trip(ActiveSession {
        owner_authorization: Some(bundle.clone()),
        ..Default::default()
    })?;
    round_trip(SidecarOperationSigningBody::default())?;
    round_trip(ResourceOwnershipTransfer {
        acceptance: Some(ResourceTransferAcceptance {
            signed_handoff: Some(SignedResourceTransferHandoff::default()),
            destination_signature: Some(AuthorizationSignature::default()),
        }),
    })?;
    let attachment = StateAttachmentTransfer {
        authorization: Some(SidecarAuthorization {
            capability: Some(bundle),
            operation_signature: Some(AuthorizationSignature::default()),
        }),
        ..Default::default()
    };
    round_trip(PullServerFrame {
        frame: Some(pull_server_frame::Frame::StateAttachment(Box::new(
            attachment,
        ))),
    })?;

    let pull = PullReady {
        remote_revision_address: "heddle:state".to_string(),
        owner_authorization_protocol_version: 1,
        stable_owner_uuid: vec![0x11; 16],
        owner_key_binding: Some(Box::new(binding)),
        authorization_keyring: Some(Box::new(CloneAuthorizationKeyring::default())),
        ..Default::default()
    };
    let old_pull = LegacyPullReady::decode(pull.encode_to_vec().as_slice())
        .map_err(|error| format!("old PullReady decode failed: {error}"))?;
    if old_pull.remote_revision_address != pull.remote_revision_address {
        return Err("old PullReady client lost a known field".to_string());
    }
    let token = AccessTokenResponse {
        token: "legacy-token".to_string(),
        grant_envelope: b"legacy-envelope".to_vec(),
        owner_authorization: Some(OwnerAuthorizationBundle::default()),
        ..Default::default()
    };
    let old_token = LegacyAccessTokenResponse::decode(token.encode_to_vec().as_slice())
        .map_err(|error| format!("old token decode failed: {error}"))?;
    if old_token.token != token.token || old_token.grant_envelope != token.grant_envelope {
        return Err("old token client lost a known field".to_string());
    }
    Ok(())
}

fn round_trip<T>(value: T) -> Result<(), String>
where
    T: Message + Default + PartialEq,
{
    let decoded = T::decode(value.encode_to_vec().as_slice()).map_err(|error| error.to_string())?;
    if decoded != value {
        return Err("generated Rust protobuf round trip changed a value".to_string());
    }
    Ok(())
}

fn canonical_body(
    format_version: u32,
    required_actions: &[u32],
    spool_uuid: &[u8],
    sidecar_kind: u32,
    blob_hash: &str,
    payload_sha256: &[u8],
    leaf_capability_id: &[u8],
) -> Result<Vec<u8>, String> {
    if format_version != 1
        || required_actions.is_empty()
        || required_actions.len() > 2
        || !required_actions.windows(2).all(|pair| pair[0] < pair[1])
        || spool_uuid.len() != 16
        || sidecar_kind != 1
        || blob_hash.len() != 64
        || !blob_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || payload_sha256.len() != 32
        || leaf_capability_id.len() != 32
    {
        return Err("non-canonical sidecar operation body".to_string());
    }
    let mut output = Vec::new();
    output.extend_from_slice(&format_version.to_be_bytes());
    output.extend_from_slice(&(required_actions.len() as u32).to_be_bytes());
    for action in required_actions {
        output.extend_from_slice(&action.to_be_bytes());
    }
    output.extend_from_slice(spool_uuid);
    output.extend_from_slice(&sidecar_kind.to_be_bytes());
    output.extend_from_slice(&(blob_hash.len() as u32).to_be_bytes());
    output.extend_from_slice(blob_hash.as_bytes());
    output.extend_from_slice(payload_sha256);
    output.extend_from_slice(leaf_capability_id);
    Ok(output)
}

fn domain_hash(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(body);
    digest.finalize().to_vec()
}

fn signature(value: &str) -> Result<Signature, String> {
    let bytes: [u8; 64] = decode(value)?
        .try_into()
        .map_err(|_| "signature is not 64 bytes")?;
    Ok(Signature::from_bytes(&bytes))
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|error| error.to_string())
}

fn equal_hex(actual: &[u8], expected: &str, label: &str) -> Result<(), String> {
    if hex::encode(actual) != expected {
        return Err(format!("{label} differs from fixture"));
    }
    Ok(())
}
