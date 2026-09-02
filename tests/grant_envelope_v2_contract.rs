use heddle_api::signing::{
    GrantEnvelopeV2Payload, GrantEnvelopeV2Right, grant_envelope_v2_canonical_payload,
    parse_grant_envelope_v2_canonical_payload,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    valid: ValidVector,
    rejections: Vec<RejectionVector>,
}

#[derive(Deserialize)]
struct ValidVector {
    biscuit_authority_public_key_hex: String,
    device_proof_public_key_hex: String,
    subject: String,
    rights: Vec<RightVector>,
    issued_at: i64,
    expires_at: i64,
    canonical_payload_hex: String,
}

#[derive(Deserialize)]
struct RightVector {
    kind: String,
    path: String,
    action: String,
}

#[derive(Deserialize)]
struct RejectionVector {
    name: String,
    canonical_payload_hex: String,
    error: String,
}

#[test]
fn valid_fixture_is_byte_exact_and_round_trips() {
    let fixture = fixture();
    let expected = payload(&fixture.valid);
    let encoded = grant_envelope_v2_canonical_payload(&expected).expect("valid issuer input");
    assert_eq!(hex::encode(&encoded), fixture.valid.canonical_payload_hex);
    assert_eq!(
        parse_grant_envelope_v2_canonical_payload(&encoded).expect("valid canonical payload"),
        expected
    );
}

#[test]
fn every_rejection_fixture_is_rejected_for_the_pinned_reason() {
    for rejection in fixture().rejections {
        let encoded = hex::decode(&rejection.canonical_payload_hex).expect("fixture hex");
        let error = parse_grant_envelope_v2_canonical_payload(&encoded)
            .expect_err("rejection fixture must fail closed");
        eprintln!("rejected {}: {error}", rejection.name);
        assert_eq!(error.to_string(), rejection.error, "{}", rejection.name);
    }
}

#[test]
fn issuer_rejects_equal_role_keys() {
    let fixture = fixture();
    let mut equal = payload(&fixture.valid);
    equal.device_proof_public_key = equal.biscuit_authority_public_key;
    let error = grant_envelope_v2_canonical_payload(&equal)
        .expect_err("issuer must reject equal role keys");
    assert_eq!(
        error.to_string(),
        "biscuit authority and device proof keys must be distinct"
    );
}

fn fixture() -> Fixture {
    serde_json::from_str(heddle_api::GRANT_ENVELOPE_V2_FIXTURE_JSON).expect("valid fixture JSON")
}

fn payload(vector: &ValidVector) -> GrantEnvelopeV2Payload {
    GrantEnvelopeV2Payload {
        biscuit_authority_public_key: decode_key(&vector.biscuit_authority_public_key_hex),
        device_proof_public_key: decode_key(&vector.device_proof_public_key_hex),
        subject: vector.subject.clone(),
        rights: vector
            .rights
            .iter()
            .map(|right| GrantEnvelopeV2Right {
                kind: right.kind.clone(),
                path: right.path.clone(),
                action: right.action.clone(),
            })
            .collect(),
        issued_at: vector.issued_at,
        expires_at: vector.expires_at,
    }
}

fn decode_key(value: &str) -> [u8; 32] {
    hex::decode(value)
        .expect("fixture key hex")
        .try_into()
        .expect("32-byte fixture key")
}
