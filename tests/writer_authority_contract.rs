use heddle_api::{heddle::api::v1alpha2 as api, hybrid_codec as codec, native_witness};
use heddle_api::{import_authority as import, writer_authority as writer};
use prost::Message;
use serde_json::Value;

fn bytes(f: &Value, field: &str) -> Vec<u8> {
    hex::decode(f["context"][field].as_str().expect("hex context")).expect("bytes")
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/writer-authority-alpha35.json"))
        .expect("fixed fixture")
}
fn wire<T: Message + Default>(f: &Value, name: &str) -> T {
    codec::strict_decode(
        &hex::decode(f["vectors"][name]["wire_hex"].as_str().expect("hex")).expect("bytes"),
        1048576,
    )
    .expect("canonical fixture")
}
fn genesis(f: &Value, name: &str) -> Result<(), codec::Reject> {
    let p: api::NativeGenesisWitnessV1 = wire(f, name);
    native_witness::verify_genesis_authority(
        p.binding.as_ref().expect("binding"),
        p.original_genesis.as_ref().expect("original"),
        &p.creator_authority_envelope,
    )
}
#[test]
fn cowriter_start_thread() {
    genesis(&fixture(), "cowriter_start_thread")
        .expect("author account is independent of Spool owner");
}
#[test]
fn account_mismatch_reject_then_pass() {
    let f = fixture();
    assert_eq!(
        genesis(&f, "account_mismatch"),
        Err(codec::Reject::GenesisBinding)
    );
    genesis(&f, "cowriter_start_thread").expect("exact passing control");
}
#[test]
fn self_signed_owner_uuid_reject_then_pass() {
    let f = fixture();
    assert_eq!(
        genesis(&f, "self_signed_owner_uuid"),
        Err(codec::Reject::Root)
    );
    genesis(&f, "cowriter_start_thread").expect("exact passing control");
}

#[test]
fn cowriter_p2_p4_transport_and_own_account() {
    let f = fixture();
    let account = bytes(&f, "account_hex");
    let identity: api::ImportIdentityV1 =
        codec::strict_decode(&bytes(&f, "identity_wire_hex"), 65536).expect("identity");
    for name in [
        "cowriter_capture_own_thread",
        "cowriter_capture_owner_thread",
        "cowriter_review",
        "cowriter_claim",
        "cowriter_land_request",
    ] {
        let s: heddle_api::heddle::api::common::SignedHostedWitnessStatementV1 =
            wire(&f, &format!("{name}_statement"));
        let statement = s.body.as_ref().expect("statement");
        // Independently chosen witness key; do not select it from the statement.
        codec::verify(
            &hex::decode(
                f["keys"]["witness"]["public_key_hex"]
                    .as_str()
                    .expect("key"),
            )
            .expect("key bytes"),
            &heddle_api::witness_trust::statement_signing_digest(statement).expect("digest"),
            &s.signature,
        )
        .expect("witness signature");
        let envelope = if name == "cowriter_land_request" {
            let p: api::HostedLandingWitnessV1 = wire(&f, name);
            import::verify_witness_payload(statement, import::WitnessPayload::Landing(&p))
                .expect("P4 commitments");
            p.authority_envelope
        } else {
            let p: api::ImportAuthorityWitnessV1 = wire(&f, name);
            import::verify_witness_payload(statement, import::WitnessPayload::Authority(&p))
                .expect("P2 commitments");
            p.authority_envelope
        };
        writer::verify_account_binding(
            &writer::decode_authority(&envelope).expect("TCA"),
            &account,
            &identity.owner_account_uuid,
            &identity.owner_id,
        )
        .expect("own actor account");
        println!("API WRITER PASS {name}");
    }
}
#[test]
fn actor_key_cuts_reject_then_pass() {
    let f = fixture();
    let a: api::ThreadControlAuthority = wire(&f, "cowriter_envelope");
    let publisher = bytes(&f, "publisher_key_id_hex");
    for key in [publisher.clone(), codec::key_id(&a.mint_root_public_key)] {
        assert_eq!(
            writer::check_writer_keys(&a, &publisher, &[key]),
            Err(codec::Reject::Revoked)
        );
        writer::check_writer_keys(&a, &publisher, &[]).expect("unrevoked control");
    }
}
#[test]
fn native_and_import_policy_cuts_reject_then_pass() {
    let f = fixture();
    let native: api::NativePublicProofBundleV1 = wire(&f, "native_actor_key_revoked");
    assert_eq!(
        native_witness::validate_public_bundle(&native),
        Err(codec::Reject::Revoked)
    );
    native_witness::validate_public_bundle(&wire(&f, "cowriter_start_bundle"))
        .expect("native control");
    let imported: api::ImportPublicProofBundleV1 = wire(&f, "import_actor_key_revoked");
    assert_eq!(
        import::validate_public_bundle(&imported),
        Err(codec::Reject::Revoked)
    );
    import::validate_public_bundle(&wire(&f, "cowriter_import_bundle")).expect("import control");
}
#[test]
fn retained_attachments_reject_then_pass() {
    let f = fixture();
    let admitted: api::SignedOwnerMintRootAttachment = wire(&f, "paired_after_rotate");
    let a = admitted.attachment.as_ref().expect("attachment");
    let inventory = [admitted.clone()];
    let mut e = writer::RetainedMintRootExpectation {
        account_uuid: &a.account_uuid,
        mint_root_public_key: &a.mint_root_key.as_ref().expect("mint").public_key,
        issuer_state_hash: &a.owner_state_hash,
        issuer_sequence: a.owner_sequence,
        issuer_public_key: &a.owner_key.as_ref().expect("issuer").public_key,
        issuer_retained_mint_authority: true,
        admitted_attachments: &inventory,
        now_unix_seconds: 1100,
    };
    writer::verify_retained_owner_mint_root_attachment(&admitted, &e)
        .expect("retained after Rotate");
    e.issuer_retained_mint_authority = false;
    assert_eq!(
        writer::verify_retained_owner_mint_root_attachment(&admitted, &e),
        Err(codec::Reject::Root)
    );
    e.issuer_retained_mint_authority = true;
    writer::verify_retained_owner_mint_root_attachment(&admitted, &e).expect("Rotate control");
    for name in ["forged_old_owner_certificate", "unknown_issuer"] {
        let value = wire(&f, name);
        assert_eq!(
            writer::verify_retained_owner_mint_root_attachment(&value, &e),
            Err(codec::Reject::Root)
        );
        writer::verify_retained_owner_mint_root_attachment(&admitted, &e).expect("exact control");
    }
    // Even an inventory member needs the original valid signature.
    let bad: api::SignedOwnerMintRootAttachment = wire(&f, "invalid_old_owner_signature");
    let bad_inventory = [bad.clone()];
    e.admitted_attachments = &bad_inventory;
    assert_eq!(
        writer::verify_retained_owner_mint_root_attachment(&bad, &e),
        Err(codec::Reject::Signature)
    );
    // Unknown issuers reject even if an authenticated payload retained the bytes.
    let unknown: api::SignedOwnerMintRootAttachment = wire(&f, "unknown_issuer");
    let unknown_inventory = [unknown.clone()];
    e.admitted_attachments = &unknown_inventory;
    assert_eq!(
        writer::verify_retained_owner_mint_root_attachment(&unknown, &e),
        Err(codec::Reject::Root)
    );
    e.admitted_attachments = &inventory;
    writer::verify_retained_owner_mint_root_attachment(&admitted, &e)
        .expect("restored exact control");
}
