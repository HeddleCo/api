use heddle_api::{
    heddle::api::v1alpha2::SignedMintRootAttachment,
    passkey_mint_grant::{
        PASSKEY_MINT_GRANT_DOMAIN, canonical_passkey_mint_grant, passkey_mint_grant_signing_digest,
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
