use contract::{heddle::api::v1alpha2 as api, v2::custodial_recovery as custody};
use ed25519_dalek::{Signer, SigningKey};
use heddleco_capability_verifier::{
    Error, VerificationLimits, VerifiedOwnerState, apply_transition,
    apply_transition_with_timelock, verify_owner_root,
};
use native_api::heddle::api::v1alpha2 as native;
use prost::Message;
use serde_json::Value;

const NOW: i64 = 1700604800;
const START: i64 = 1700000000;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/custodial-recovery-v1.json")).expect("fixture")
}
fn decode<M: Message + Default>(f: &Value, field: &str) -> M {
    let bytes = hex::decode(f[field].as_str().expect("hex field")).expect("hex");
    M::decode(bytes.as_slice()).expect("wire")
}
// The published verifier is compiled against the published `native_api` types
// and this branch's contract types are a different crate version, so the two
// are crossed only through protobuf bytes (the same boundary as hybrid-native).
fn to_native<M: Message, N: Message + Default>(message: &M) -> N {
    N::decode(message.encode_to_vec().as_slice()).expect("contract bytes decode as published type")
}
fn state(f: &Value) -> VerifiedOwnerState {
    let p: api::CustodialRecoverProposal = decode(f, "proposal_wire_hex");
    let root: native::SignedOwnerRoot = to_native(
        p.ownership
            .as_ref()
            .expect("history")
            .root
            .as_ref()
            .expect("root"),
    );
    verify_owner_root(&root).expect("admitted original root")
}
fn limits() -> VerificationLimits {
    VerificationLimits::new(2592000).expect("30-day capability ceiling")
}
fn error(f: &Value) -> Error {
    match f["error"].as_str().expect("verifier error") {
        "Invalid" => Error::Invalid(f["detail"].as_str().expect("specific error").into()),
        "InvalidSignature" => Error::InvalidSignature,
        "NotYetValid" => Error::NotYetValid,
        "RecoveryThreshold" => Error::RecoveryThreshold {
            required: 1,
            actual: 0,
        },
        other => panic!("unknown verifier error {other}"),
    }
}

#[test]
fn published_verifier_admits_only_the_completed_fresh_policy() {
    let f = fixture();
    let state = state(&f);
    let completed: native::SignedOwnerKeyTransition = decode(&f, "completed_recover_wire_hex");
    let next = apply_transition_with_timelock(&state, &completed, NOW, START, limits())
        .expect("published admission");
    assert_eq!(next.sequence(), 1);
    assert_eq!(
        next.authority_key(),
        completed
            .transition
            .as_ref()
            .expect("body")
            .next_authority_key
            .as_ref()
            .expect("R1")
    );
    assert_ne!(next.recovery_policy(), state.recovery_policy());
    assert_eq!(
        completed
            .transition
            .as_ref()
            .expect("body")
            .previous_key_valid_until_unix_seconds,
        0
    );
}

#[test]
fn focused_portable_negative_matrix_checks_specific_published_errors() {
    let f = fixture();
    let state = state(&f);
    for vector in f["verifier_negatives"].as_array().expect("matrix") {
        let signed: native::SignedOwnerKeyTransition = decode(vector, "recover_wire_hex");
        let now = vector["now"]
            .as_str()
            .map(|v| v.parse().expect("seconds"))
            .unwrap_or(NOW);
        if vector["portable_accepts"] == true {
            assert!(
                now >= signed
                    .transition
                    .as_ref()
                    .expect("body")
                    .valid_from_unix_seconds
            );
            apply_transition(&state, &signed, now, limits())
                .expect("backdated body is otherwise fully valid portable history");
        }
        assert_eq!(
            apply_transition_with_timelock(&state, &signed, now, START, limits()).err(),
            Some(error(vector)),
            "{} must isolate the intended rule",
            vector["name"]
        );
    }
}

#[test]
fn retained_w0_reaches_the_published_retained_policy_error() {
    let f = fixture();
    let vector = f["verifier_negatives"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|v| v["name"] == "retained_old_guardian")
        .expect("retained W0");
    let signed: native::SignedOwnerKeyTransition = decode(vector, "recover_wire_hex");
    assert_eq!(
        apply_transition_with_timelock(&state(&f), &signed, NOW, START, limits()).err(),
        Some(Error::Invalid(
            "recovery must replace enough guardians to retire the current policy".into()
        ))
    );
}

// API-only boundary evidence: these records model both lock orderings and an
// aborted private signature. The real Weft transaction/response path must run
// the same assertions under injected signing, commit failures and concurrency.
#[test]
fn prepare_then_winning_veto_cannot_assemble_portable_recover() {
    let f = fixture();
    let p: api::CustodialRecoverProposal = decode(&f, "proposal_wire_hex");
    let request: api::SubmitCustodialRecoverRequest = decode(&f, "submit_wire_hex");
    let old = decode(&f, "old_guardian_wire_hex");
    let state = state(&f);
    // Reconstruct every piece a client can produce using its public R1 test seed.
    let mut client = p.recover.clone().expect("prepared response");
    let mut proof = request
        .recover
        .as_ref()
        .expect("request")
        .next_authority_key_proof
        .clone()
        .expect("R1");
    proof.signature = SigningKey::from_bytes(&[13; 32])
        .sign(&p.signing_digest)
        .to_bytes()
        .to_vec();
    client.next_authority_key_proof = Some(proof);
    for outcome in f["release_scenarios"]
        .as_array()
        .expect("lock/abort scenarios")
    {
        let attempt: api::RecoveryAttempt = decode(outcome, "attempt_wire_hex");
        let now = outcome["now"]
            .as_str()
            .map(|v| v.parse().expect("seconds"))
            .unwrap_or(NOW);
        if outcome["error"] == "State" {
            assert_eq!(
                custody::validate_submission(&attempt, &p, &request, &old, now),
                Err(custody::Error::State)
            );
        }
        if outcome["private_signing"] == true || outcome["committed"] == true {
            let private: native::SignedOwnerKeyTransition =
                decode(&f, "completed_recover_wire_hex");
            apply_transition(&state, &private, NOW, limits()).expect("private W0 signature exists");
            if outcome["committed"] == true {
                // Submit won: the completed result is portable; a subsequent veto
                // cannot undo it or yield a second completed transition.
                assert!(attempt.completed);
                continue;
            }
        }
        assert_eq!(
            apply_transition(
                &state,
                &to_native::<_, native::SignedOwnerKeyTransition>(&client),
                now,
                limits()
            )
            .err(),
            Some(Error::RecoveryThreshold {
                required: 1,
                actual: 0
            }),
            "{} must leave the client without portable authority even after local R1 signing",
            outcome["name"]
        );
        assert!(
            request
                .recover
                .as_ref()
                .expect("client submission")
                .authorizations
                .is_empty()
        );
    }
}

#[test]
fn published_verifier_authenticates_rotated_owner_evidence() {
    let f: Value = serde_json::from_str(contract::IMPORT_AUTHORITY_HOST_WITNESS_V1_FIXTURE_JSON)
        .expect("HYBRID fixture");
    let wire = |name: &str| {
        hex::decode(f["wire_vectors"][name]["wire_hex"].as_str().expect("wire")).expect("fixed hex")
    };
    let history = native::OwnerHistory::decode(wire("rotated_owner_history").as_slice())
        .expect("published history codec");
    let initial = verify_owner_root(history.root.as_ref().expect("original root"))
        .expect("independently selected root");
    let signed = &history.accepted_transitions[0];
    let next =
        apply_transition(&initial, signed, 1350, limits()).expect("accepted rotation history");
    assert_eq!(next.state_hash().as_slice(), history.state_hash);
    assert_ne!(next.authority_key(), initial.authority_key());
    assert_eq!(
        next.authority_key().public_key,
        hex::decode(
            f["keys"]["rotated_owner"]["public_key_hex"]
                .as_str()
                .expect("key")
        )
        .expect("hex")
    );
    let mut changed = signed.clone();
    changed.transition.as_mut().expect("transition").nonce[0] ^= 1;
    assert_eq!(
        apply_transition(&initial, &changed, 1350, limits()).err(),
        Some(Error::InvalidSignature)
    );
    apply_transition(&initial, signed, 1350, limits()).expect("unchanged passing control");
}
