use ed25519_dalek::{Signature, VerifyingKey};
use heddle_api::{
    heddle::api::v1alpha2 as api,
    v2::{custodial_recovery as custody, identity_management},
};
use prost::Message;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/custodial-recovery-v1.json"))
        .expect("shared vectors")
}
fn bytes(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(value[field].as_str().expect("hex field")).expect("hex")
}
fn decode<M: Message + Default>(value: &Value, field: &str) -> M {
    M::decode(bytes(value, field).as_slice()).expect("typed wire")
}
fn verify(
    key: &api::AuthorizationVerificationKey,
    proof: &api::AuthorizationSignature,
    digest: &[u8],
) {
    let public: [u8; 32] = key.public_key.as_slice().try_into().expect("key width");
    let signature = Signature::from_slice(&proof.signature).expect("signature width");
    VerifyingKey::from_bytes(&public)
        .expect("public key")
        .verify_strict(digest, &signature)
        .expect("portable signature");
}

#[test]
fn custody_wire_vectors_round_trip_in_both_languages() {
    let f = fixture();
    macro_rules! round_trip {
        ($ty:ty, $field:literal) => {
            assert_eq!(decode::<$ty>(&f, $field).encode_to_vec(), bytes(&f, $field));
        };
    }
    round_trip!(api::BeginCustodialRecoveryRequest, "begin_wire_hex");
    round_trip!(api::CustodialEmailProof, "email_proof_wire_hex");
    round_trip!(api::SubmitRecoveryProofRequest, "proof_request_wire_hex");
    round_trip!(api::RecoveryAttempt, "attempt_wire_hex");
    round_trip!(api::CustodialRecoverProposal, "proposal_wire_hex");
    round_trip!(api::SubmitCustodialRecoverRequest, "submit_wire_hex");
    round_trip!(api::VetoCustodialRecoveryRequest, "veto_wire_hex");
    let request: api::SubmitRecoveryProofRequest = decode(&f, "proof_request_wire_hex");
    assert!(matches!(
        request.proof,
        Some(api::submit_recovery_proof_request::Proof::CustodialEmail(_))
    ));
}

#[test]
fn canonical_email_intent_matches_golden_and_binds_all_fields() {
    let f = fixture();
    let proof: api::CustodialEmailProof = decode(&f, "email_proof_wire_hex");
    let binding = proof.binding.as_ref().expect("binding");
    assert_eq!(
        custody::canonical_email_binding(binding).expect("canonical"),
        bytes(&f, "email_canonical_hex")
    );
    assert_eq!(
        custody::email_secret_hash(&proof).expect("hash").as_slice(),
        bytes(&f, "email_secret_hash_hex")
    );
    assert_eq!(
        custody::validate_email_proof(&proof, binding, 1700000000),
        Ok(())
    );
    assert_eq!(
        custody::validate_email_proof(&proof, binding, binding.expires_at_unix_seconds),
        Err(custody::Error::Expired)
    );
    for field in 0..4 {
        let mut changed = binding.clone();
        match field {
            0 => changed.account_uuid[0] ^= 1,
            1 => changed.attempt_uuid[0] ^= 1,
            2 => changed.proposed_root_public_key[0] ^= 1,
            _ => changed.challenge[0] ^= 1,
        }
        assert_eq!(
            custody::validate_email_proof(&proof, &changed, 1700000000),
            Err(custody::Error::Binding)
        );
    }
}

#[test]
fn recover_preserves_canonical_domain_and_all_three_signature_roles() {
    let f = fixture();
    let proposal: api::CustodialRecoverProposal = decode(&f, "proposal_wire_hex");
    let request: api::SubmitCustodialRecoverRequest = decode(&f, "submit_wire_hex");
    let old: api::AuthorizationVerificationKey = decode(&f, "old_guardian_wire_hex");
    let signed = request.recover.as_ref().expect("Recover");
    let body = signed.transition.as_ref().expect("body");
    assert_eq!(
        custody::canonical_recover(body).expect("canonical"),
        bytes(&f, "canonical_transition_hex")
    );
    let digest = custody::proposal_signing_digest(&proposal)
        .expect("recompute, never trust supplied digest");
    assert_eq!(digest.as_slice(), bytes(&f, "signing_digest_hex"));
    verify(&old, &signed.authorizations[0], &digest);
    verify(
        body.next_authority_key.as_ref().expect("R1"),
        signed.next_authority_key_proof.as_ref().expect("R1 proof"),
        &digest,
    );
    verify(
        body.next_recovery_policy
            .as_ref()
            .expect("policy")
            .guardians[0]
            .key
            .as_ref()
            .expect("W1"),
        &signed.next_recovery_key_proofs[0],
        &digest,
    );
    let attempt: api::RecoveryAttempt = decode(&f, "attempt_wire_hex");
    assert_eq!(
        custody::validate_submission(&attempt, &proposal, &request, &old, 1700604800),
        Ok(())
    );
    let mut changed = proposal.clone();
    changed.signing_digest[0] ^= 1;
    assert_eq!(
        custody::proposal_signing_digest(&changed),
        Err(custody::Error::Proposal)
    );
    changed = proposal.clone();
    changed.canonical_transition[0] ^= 1;
    assert_eq!(
        custody::proposal_signing_digest(&changed),
        Err(custody::Error::Proposal)
    );
    let mut implicit = body.clone();
    implicit
        .next_recovery_policy
        .as_mut()
        .expect("policy")
        .window_secs = None;
    assert_eq!(
        custody::canonical_recover(&implicit),
        custody::canonical_recover(body)
    );
}

#[test]
fn veto_uses_current_root_and_a_separate_exact_attempt_domain() {
    let f = fixture();
    let request: api::VetoCustodialRecoveryRequest = decode(&f, "veto_wire_hex");
    let proposal: api::CustodialRecoverProposal = decode(&f, "proposal_wire_hex");
    let veto = request.veto.as_ref().expect("veto");
    let binding = proposal
        .recovery
        .as_ref()
        .expect("attempt")
        .custodial
        .as_ref()
        .expect("custody")
        .binding
        .as_ref()
        .expect("binding");
    let canonical = identity_management::recovery_action(
        f["account_id"].as_str().expect("account"),
        &request.client_operation_id,
        request.recovery.as_ref(),
        &request.expected_version,
        &binding.proposed_root_public_key,
    )
    .expect("exact action");
    assert_eq!(veto.canonical_record, canonical);
    let signing = identity_management::signing_bytes(custody::CUSTODIAL_VETO, &canonical)
        .expect("veto domain");
    assert_eq!(signing, bytes(&f, "veto_signing_hex"));
    let signature = &veto.signatures[0];
    assert_eq!(
        signature.public_key,
        proposal
            .ownership
            .as_ref()
            .expect("history")
            .root
            .as_ref()
            .expect("root")
            .root
            .as_ref()
            .expect("root body")
            .authority_key
            .as_ref()
            .expect("current root")
            .public_key
    );
    VerifyingKey::from_bytes(&signature.public_key.as_slice().try_into().expect("key"))
        .expect("root key")
        .verify_strict(
            &signing,
            &Signature::from_slice(&signature.signature).expect("signature"),
        )
        .expect("root veto");
    assert_ne!(
        identity_management::signing_bytes(identity_management::RECOVERY_VETO, &canonical)
            .expect("old domain"),
        signing
    );
}

fn negative(name: &str, expected: custody::Error) {
    let f = fixture();
    let vector = f["negatives"]
        .as_array()
        .expect("negatives")
        .iter()
        .find(|v| v["name"] == name)
        .expect("named negative");
    let attempt: api::RecoveryAttempt = if vector["attempt_wire_hex"].is_string() {
        decode(vector, "attempt_wire_hex")
    } else {
        decode(&f, "attempt_wire_hex")
    };
    let proposal: api::CustodialRecoverProposal = decode(&f, "proposal_wire_hex");
    let request: api::SubmitCustodialRecoverRequest = if vector["submit_wire_hex"].is_string() {
        decode(vector, "submit_wire_hex")
    } else {
        decode(&f, "submit_wire_hex")
    };
    let old: api::AuthorizationVerificationKey = decode(&f, "old_guardian_wire_hex");
    let result = if vector["email_proof_wire_hex"].is_string() {
        custody::validate_email_proof(
            &decode(vector, "email_proof_wire_hex"),
            attempt
                .custodial
                .as_ref()
                .expect("custody")
                .binding
                .as_ref()
                .expect("binding"),
            1700000000,
        )
    } else {
        custody::validate_submission(
            &attempt,
            &proposal,
            &request,
            &old,
            vector["now"]
                .as_str()
                .map(|s| s.parse().expect("seconds"))
                .unwrap_or(1700604800),
        )
    };
    assert_eq!(
        result,
        Err(expected),
        "{name} must fail for its intended reason"
    );
}
macro_rules! negative_test {
    ($name:ident, $error:ident) => {
        #[test]
        fn $name() {
            negative(stringify!($name), custody::Error::$error);
        }
    };
}
negative_test!(replayed_email_from_other_attempt, Binding);
negative_test!(omitted_fresh_guardian, FreshKey);
negative_test!(retained_old_guardian, FreshKey);
negative_test!(submission_before_window, Early);
negative_test!(submission_after_veto, State);
negative_test!(submission_at_expiry, Expired);
negative_test!(stale_attempt_version, Version);
negative_test!(altered_prepared_nonce, Proposal);

#[test]
fn absent_custody_details_and_missing_next_guardian_proof_fail_closed() {
    let f = fixture();
    let mut attempt: api::RecoveryAttempt = decode(&f, "attempt_wire_hex");
    let proposal: api::CustodialRecoverProposal = decode(&f, "proposal_wire_hex");
    let mut request: api::SubmitCustodialRecoverRequest = decode(&f, "submit_wire_hex");
    let old = decode(&f, "old_guardian_wire_hex");
    attempt.custodial = None;
    assert_eq!(
        custody::validate_submission(&attempt, &proposal, &request, &old, 1700604800),
        Err(custody::Error::Binding)
    );
    attempt = decode(&f, "attempt_wire_hex");
    request
        .recover
        .as_mut()
        .expect("Recover")
        .next_recovery_key_proofs
        .clear();
    assert_eq!(
        custody::validate_submission(&attempt, &proposal, &request, &old, 1700604800),
        Err(custody::Error::FreshKey)
    );
}
