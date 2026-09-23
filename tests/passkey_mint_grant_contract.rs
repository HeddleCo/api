use heddle_api::{
    heddle::api::v1alpha2::{
        AuthenticationChallenge, CredentialMethod, SignedMintRootAttachment, SpoolCreationProof,
        ThreadControlAuthority,
    },
    mint_root_association::{
        MintRootAssociationWireError, decode_spool_creation_proof_for_verification,
        decode_thread_control_authority_for_verification, verify_mint_root_association_wire,
    },
    passkey_mint_grant::{
        PASSKEY_MINT_GRANT_DOMAIN, PasskeyMintGrantError, canonical_passkey_mint_grant,
        passkey_mint_grant_signing_digest, verify_passkey_authentication_challenge,
        verify_passkey_mint_grant_window,
    },
};
use prost::Message;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/passkey-mint-grant-v1.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("valid language-neutral grant fixture")
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().expect(field)
}

fn integer(value: &Value, field: &str) -> i64 {
    value[field].as_i64().expect(field)
}

fn decode_attachment(encoded: &str) -> SignedMintRootAttachment {
    SignedMintRootAttachment::decode(hex::decode(encoded).expect("fixture hex").as_slice())
        .expect("v2 attachment protobuf")
}

fn decode_challenge(encoded: &str) -> AuthenticationChallenge {
    AuthenticationChallenge::decode(hex::decode(encoded).expect("fixture hex").as_slice())
        .expect("authentication challenge protobuf")
}

fn in_window(value: &SignedMintRootAttachment, now: i64) -> bool {
    value.grant.as_ref().is_some_and(|grant| {
        now >= grant.not_before_unix_seconds && now < grant.expires_at_unix_seconds
    })
}

#[test]
fn rust_matches_shared_canonical_digest_and_v2_attachment_bytes() {
    let fixture = fixture();
    let positive = &fixture["positive"];
    assert_eq!(
        PASSKEY_MINT_GRANT_DOMAIN,
        text(&fixture["canonical_encoding"], "domain").as_bytes()
    );
    let encoded = text(positive, "attachment_proto_hex");
    let attachment = decode_attachment(encoded);
    let grant = attachment.grant.as_ref().expect("grant");
    assert_eq!(
        hex::encode(canonical_passkey_mint_grant(grant).expect("canonical grant")),
        text(positive, "canonical_hex")
    );
    assert_eq!(
        hex::encode(passkey_mint_grant_signing_digest(grant).expect("grant digest")),
        text(positive, "signing_digest_hex")
    );
    assert_eq!(hex::encode(attachment.encode_to_vec()), encoded);

    let fields: Vec<_> = fixture["canonical_encoding"]["field_order"]
        .as_array()
        .expect("field order")
        .iter()
        .map(|field| field.as_str().expect("field"))
        .collect();
    assert_eq!(
        fields,
        [
            "format_version:u32be",
            "mint_root_key.algorithm:u32be",
            "mint_root_key.public_key:u32be-length+bytes",
            "not_before_unix_seconds:i64be",
            "expires_at_unix_seconds:i64be",
            "nonce:u32be-length+bytes",
            "relying_party_id:u32be-length+utf8",
        ]
    );
}

#[test]
fn every_tampered_grant_field_changes_or_invalidates_the_digest() {
    let fixture = fixture();
    let expected = text(&fixture["positive"], "signing_digest_hex");
    let cases: Vec<_> = fixture["negative_cases"]
        .as_array()
        .expect("negative cases")
        .iter()
        .filter(|case| text(case, "kind") == "tampered_grant")
        .collect();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let attachment = decode_attachment(text(case, "attachment_proto_hex"));
        let grant = attachment.grant.as_ref().expect("tampered grant");
        match passkey_mint_grant_signing_digest(grant) {
            Ok(digest) => assert_ne!(hex::encode(digest), expected, "{}", text(case, "id")),
            Err(_) => assert_eq!(text(case, "field"), "format_version"),
        }
    }
}

#[test]
fn passkey_challenge_is_the_exact_grant_digest_but_other_methods_keep_their_semantics() {
    let fixture = fixture();
    let positive = decode_challenge(text(
        &fixture["positive"],
        "authentication_challenge_proto_hex",
    ));
    verify_passkey_authentication_challenge(&positive).expect("bound challenge");

    let mismatch = fixture["negative_cases"]
        .as_array()
        .expect("negative cases")
        .iter()
        .find(|case| text(case, "id") == "mismatching-authentication-challenge")
        .expect("challenge mismatch vector");
    let mismatch = decode_challenge(text(mismatch, "authentication_challenge_proto_hex"));
    assert_eq!(
        verify_passkey_authentication_challenge(&mismatch),
        Err(PasskeyMintGrantError::ChallengeBinding)
    );

    let mut password = mismatch;
    password.method = CredentialMethod::Password as i32;
    password.challenge = vec![1];
    verify_passkey_authentication_challenge(&password)
        .expect("non-passkey challenge semantics are method-specific");
}

#[test]
fn shared_grant_window_boundaries_match_the_owner_ceiling_contract() {
    let fixture = fixture();
    let attachment = decode_attachment(text(&fixture["positive"], "attachment_proto_hex"));
    let template = attachment.grant.expect("grant");
    for case in fixture["window_cases"].as_array().expect("window cases") {
        let mut grant = template.clone();
        grant.not_before_unix_seconds = integer(case, "not_before_unix_seconds");
        grant.expires_at_unix_seconds = integer(case, "expires_at_unix_seconds");
        let ceiling =
            u32::try_from(integer(case, "max_session_ttl_seconds")).expect("u32 TTL ceiling");
        let result =
            verify_passkey_mint_grant_window(&grant, ceiling, integer(case, "now_unix_seconds"));
        assert_eq!(
            result.is_ok(),
            case["accepted"].as_bool().expect("accepted flag"),
            "{}: {result:?}",
            text(case, "id")
        );
    }
}

#[test]
fn checked_decoders_reject_both_oneof_arms_before_last_wins_decoding() {
    let fixture = fixture();
    for case in fixture["ambiguous_oneof_cases"]
        .as_array()
        .expect("ambiguous oneof cases")
    {
        let bytes = hex::decode(text(case, "raw_proto_hex")).expect("raw protobuf hex");
        assert_eq!(
            verify_mint_root_association_wire(&bytes)
                .expect_err("both raw alternatives must be rejected")
                .to_string(),
            MintRootAssociationWireError::BothArms.to_string(),
            "{}",
            text(case, "id")
        );
        match text(case, "message") {
            "ThreadControlAuthority" => {
                assert!(
                    ThreadControlAuthority::decode(bytes.as_slice())
                        .expect("ordinary decoder is last-wins")
                        .mint_root_association
                        .is_some()
                );
                assert!(matches!(
                    decode_thread_control_authority_for_verification(&bytes),
                    Err(MintRootAssociationWireError::BothArms)
                ));
            }
            "SpoolCreationProof" => {
                assert!(
                    SpoolCreationProof::decode(bytes.as_slice())
                        .expect("ordinary decoder is last-wins")
                        .mint_root_association
                        .is_some()
                );
                assert!(matches!(
                    decode_spool_creation_proof_for_verification(&bytes),
                    Err(MintRootAssociationWireError::BothArms)
                ));
            }
            other => panic!("unknown fixture message {other}"),
        }
    }

    decode_thread_control_authority_for_verification(&hex::decode("08012200").unwrap())
        .expect("single owner arm");
    decode_spool_creation_proof_for_verification(&hex::decode("3200").unwrap())
        .expect("single passkey arm");
}

#[test]
fn verifier_negative_vectors_are_self_describing_and_fail_the_contract_predicates() {
    let fixture = fixture();
    let cases = fixture["negative_cases"]
        .as_array()
        .expect("negative cases");

    let wrong_rp = cases
        .iter()
        .find(|case| text(case, "id") == "wrong-relying-party-id")
        .expect("wrong RP vector");
    let wrong_rp = decode_attachment(text(wrong_rp, "attachment_proto_hex"));
    let grant = wrong_rp.grant.as_ref().expect("grant");
    let authority = wrong_rp
        .passkey_delegation
        .as_ref()
        .and_then(|proof| proof.authority.as_ref())
        .and_then(|signed| signed.authority.as_ref())
        .expect("authority");
    assert_ne!(grant.relying_party_id, authority.relying_party_id);

    let positive = decode_attachment(text(&fixture["positive"], "attachment_proto_hex"));
    for id in ["expired", "not-yet-valid"] {
        let case = cases
            .iter()
            .find(|case| text(case, "id") == id)
            .expect("time vector");
        assert!(
            !in_window(&positive, integer(case, "now_unix_seconds")),
            "{id}"
        );
    }

    let confusion = cases
        .iter()
        .find(|case| text(case, "id") == "v1-attachment-domain-confusion")
        .expect("domain confusion vector");
    assert_ne!(
        text(confusion, "presented_challenge_hex"),
        text(confusion, "expected_grant_digest_hex")
    );
    assert_eq!(
        text(confusion, "expected_grant_digest_hex"),
        text(&fixture["positive"], "signing_digest_hex")
    );
    decode_attachment(text(confusion, "attachment_proto_hex"));
}
