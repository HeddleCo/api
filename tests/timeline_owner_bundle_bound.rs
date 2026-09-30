use ed25519_dalek::{Signer, SigningKey, Verifier};
use heddle_api::heddle::api::v1alpha2::{
    OwnerAuthorizationBundle, OwnerKeyTransitionKind, TimelineAdmissionAcceptance,
    timeline_admission_acceptance::Authority,
};
use heddle_api::timeline_upload::{acceptance_signing_bytes, validate_acceptance};
use prost::Message;

fn acceptance(bytes: Vec<u8>) -> TimelineAdmissionAcceptance {
    TimelineAdmissionAcceptance {
        origin_sha256: vec![1; 32],
        uploader_device_public_key: vec![2; 32],
        deployment_public_key: vec![3; 32],
        request_sha256: vec![4; 32],
        first_position: 0,
        event_count: 1,
        authority: Some(Authority::OwnerDerivedCapability(bytes)),
        signature: vec![5; 64],
    }
}

#[test]
fn long_owner_history_with_twenty_rotations_and_recovery_is_accepted() {
    // Generated and cryptographically checked by the pinned independent owner
    // verifier, including the recovered issuer and single-block subject Biscuit.
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/timeline-owner-long-history.json"))
            .expect("verified long-history fixture");
    let bytes =
        hex::decode(fixture["bundle_hex"].as_str().expect("bundle hex")).expect("bundle bytes");
    assert_eq!(
        bytes.len(),
        fixture["bundle_bytes"].as_u64().expect("size") as usize
    );
    assert!(bytes.len() > 4096 && bytes.len() < 65536);
    let bundle = OwnerAuthorizationBundle::decode(bytes.as_slice()).expect("canonical bundle");
    assert_eq!(bundle.encode_to_vec(), bytes);
    assert_eq!(bundle.owner_state_chain.len(), 21);
    for (index, signed) in bundle.owner_state_chain.iter().enumerate() {
        let transition = signed.transition.as_ref().expect("signed transition");
        assert_eq!(transition.sequence, index as u64 + 1);
        assert_eq!(
            transition.kind,
            if index < 20 {
                OwnerKeyTransitionKind::Rotate
            } else {
                OwnerKeyTransitionKind::Recover
            } as i32,
        );
    }
    let capability = bundle.capability_chain[0]
        .capability
        .as_ref()
        .expect("capability");
    assert_eq!(capability.format_version, 3);
    assert_eq!(
        capability.issuer_state_hash,
        hex::decode(
            fixture["accepted_state_hash_hex"]
                .as_str()
                .expect("checkpoint")
        )
        .expect("checkpoint bytes"),
    );
    let seed: [u8; 32] = hex::decode(fixture["subject_seed_hex"].as_str().expect("subject seed"))
        .expect("seed bytes")
        .try_into()
        .expect("32-byte seed");
    let signer = SigningKey::from_bytes(&seed);
    assert_eq!(
        capability
            .subject
            .as_ref()
            .expect("subject")
            .key
            .as_ref()
            .expect("subject key")
            .public_key,
        signer.verifying_key().to_bytes(),
    );
    let mut value = acceptance(bytes);
    validate_acceptance(&value).expect("long current-owner history is within the acceptance bound");
    let transcript = acceptance_signing_bytes(&value).expect("long-history transcript");
    let signature = signer.sign(&transcript);
    value.signature = signature.to_bytes().to_vec();
    signer
        .verifying_key()
        .verify(&transcript, &signature)
        .expect("subject acceptance signature");
    validate_acceptance(&value).expect("signed long-history acceptance");
}

#[test]
fn owner_bundle_bound_is_inclusive_and_rejects_over_64_kib() {
    // The API validates the envelope size; consumers verify the bundle contents.
    let at_limit = acceptance(vec![7; 65536]);
    validate_acceptance(&at_limit).expect("exactly 64 KiB is allowed");
    acceptance_signing_bytes(&at_limit).expect("64 KiB authority can be signed");
    for size in [0, 65537] {
        let value = acceptance(vec![7; size]);
        assert_eq!(
            validate_acceptance(&value).expect_err("outside bound").0,
            "acceptance capability"
        );
        assert_eq!(
            acceptance_signing_bytes(&value)
                .expect_err("cannot sign outside bound")
                .0,
            "acceptance capability"
        );
    }
}
