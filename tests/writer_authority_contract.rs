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

fn verify_statement(
    f: &Value,
    signed: &heddle_api::heddle::api::common::SignedHostedWitnessStatementV1,
) {
    codec::verify(
        &hex::decode(
            f["keys"]["witness"]["public_key_hex"]
                .as_str()
                .expect("key"),
        )
        .expect("bytes"),
        &heddle_api::witness_trust::statement_signing_digest(
            signed.body.as_ref().expect("statement"),
        )
        .expect("digest"),
        &signed.signature,
    )
    .expect("independently selected witness signature");
}
fn verified_history(f: &Value, name: &str) -> api::OwnerHistory {
    let h: api::OwnerHistory = wire(f, name);
    // The generator also runs the published native owner-history verifier.
    // Recheck the independently selected signing keys and committed endpoints.
    let root = h.root.as_ref().expect("root");
    let key = hex::decode(
        f["keys"]["cowriter_owner"]["public_key_hex"]
            .as_str()
            .expect("key"),
    )
    .expect("bytes");
    codec::verify(
        &key,
        &bytes(f, "owner_root_signing_digest_hex"),
        &root.authority_proof.as_ref().expect("root proof").signature,
    )
    .expect("authenticated root");
    for (g, proof) in root
        .root
        .as_ref()
        .expect("body")
        .recovery_policy
        .as_ref()
        .expect("policy")
        .guardians
        .iter()
        .zip(&root.recovery_key_proofs)
    {
        codec::verify(
            &g.key.as_ref().expect("guardian").public_key,
            &bytes(f, "owner_root_signing_digest_hex"),
            &proof.signature,
        )
        .expect("root guardian proof");
    }
    let t = h.accepted_transitions[0]
        .transition
        .as_ref()
        .expect("transition");
    assert_eq!(t.previous_state_hash, bytes(f, "issuer_state_hash_hex"));
    let digest = bytes(
        f,
        if t.kind == 2 {
            "recover_signing_digest_hex"
        } else {
            "rotate_signing_digest_hex"
        },
    );
    assert_eq!(h.state_hash, digest);
    let signed = &h.accepted_transitions[0];
    codec::verify(
        &t.next_authority_key.as_ref().expect("next key").public_key,
        &digest,
        &signed
            .next_authority_key_proof
            .as_ref()
            .expect("proof")
            .signature,
    )
    .expect("next proof");
    let keys: Vec<_> = if t.kind == 2 {
        root.root
            .as_ref()
            .expect("body")
            .recovery_policy
            .as_ref()
            .expect("policy")
            .guardians
            .iter()
            .map(|g| g.key.as_ref().expect("key").public_key.clone())
            .collect()
    } else {
        vec![key]
    };
    for (key, proof) in keys.iter().zip(&signed.authorizations) {
        codec::verify(key, &digest, &proof.signature).expect("transition authorization");
    }
    h
}
fn admission(f: &Value, name: &str) -> writer::AdmittedMintRootAttachment {
    let p: api::ImportAuthorityWitnessV1 = wire(f, &format!("{name}_payload"));
    let s = wire(f, &format!("{name}_statement"));
    verify_statement(f, &s);
    writer::admitted_owner_mint_root_attachment(
        s.body.as_ref().expect("statement"),
        writer::WriterWitnessPayload::Import(import::WitnessPayload::Authority(&p)),
    )
    .expect("authenticated exact attachment")
}
#[test]
fn retained_attachments_reject_then_pass() {
    let f = fixture();
    let history = verified_history(&f, "verified_rotate_history");
    let issuer =
        writer::retained_mint_root_issuer(&history, &bytes(&f, "issuer_state_hash_hex"), 0)
            .expect("issuer derived from verified history");
    let admitted = admission(&f, "admitted_original");
    let mint = hex::decode(
        f["keys"]["cowriter_device"]["public_key_hex"]
            .as_str()
            .expect("key"),
    )
    .expect("bytes");
    let cert: api::SignedOwnerMintRootAttachment = wire(&f, "paired_after_rotate");
    let check = |c: &api::SignedOwnerMintRootAttachment, a: &writer::AdmittedMintRootAttachment| {
        writer::verify_retained_writer_attachment(&c.encode_to_vec(), &mint, &issuer, a, 1100)
    };
    check(&cert, &admitted).expect("Rotate retains issuer");
    let recovered = verified_history(&f, "verified_recover_history");
    assert!(matches!(
        writer::retained_mint_root_issuer(&recovered, &bytes(&f, "issuer_state_hash_hex"), 0),
        Err(codec::Reject::Root)
    ));
    check(&cert, &admitted).expect("Rotate control");
    for name in ["forged_old_owner_certificate", "unknown_issuer"] {
        assert_eq!(check(&wire(&f, name), &admitted), Err(codec::Reject::Root));
        check(&cert, &admitted).expect("control");
    }
    assert_eq!(
        check(
            &wire(&f, "unknown_issuer"),
            &admission(&f, "admitted_unknown")
        ),
        Err(codec::Reject::Root)
    );
    assert_eq!(
        check(
            &wire(&f, "invalid_old_owner_signature"),
            &admission(&f, "admitted_bad_signature")
        ),
        Err(codec::Reject::Signature)
    );
    let mut unknown = bytes(&f, "issuer_state_hash_hex");
    unknown[0] ^= 1;
    assert!(matches!(
        writer::retained_mint_root_issuer(&history, &unknown, 0),
        Err(codec::Reject::Root)
    ));
}
#[test]
fn retained_strict_decode_reject_then_pass() {
    let f = fixture();
    let h = verified_history(&f, "verified_rotate_history");
    let issuer = writer::retained_mint_root_issuer(&h, &bytes(&f, "issuer_state_hash_hex"), 0)
        .expect("issuer");
    let admitted = admission(&f, "admitted_original");
    let cert: api::SignedOwnerMintRootAttachment = wire(&f, "paired_after_rotate");
    let a: api::ThreadControlAuthority = wire(&f, "cowriter_envelope");
    let mut bytes = cert.encode_to_vec();
    bytes.extend_from_slice(&[0x78, 1]);
    assert_eq!(
        writer::verify_retained_writer_attachment(
            &bytes,
            &a.mint_root_public_key,
            &issuer,
            &admitted,
            1100
        ),
        Err(codec::Reject::Canonical)
    );
    writer::verify_retained_writer_attachment(
        &cert.encode_to_vec(),
        &a.mint_root_public_key,
        &issuer,
        &admitted,
        1100,
    )
    .expect("strict control");
}
#[test]
fn policy_history_reject_then_pass() {
    let f = fixture();
    for (mode, reason) in [
        ("stripped", codec::Reject::Canonical),
        ("absent", codec::Reject::Canonical),
        ("reordered", codec::Reject::Canonical),
        ("duplicated", codec::Reject::Canonical),
        ("subtracted", codec::Reject::Scope),
        ("predecessor_stripped", codec::Reject::Canonical),
    ] {
        assert_eq!(
            native_witness::validate_public_bundle(&wire(&f, &format!("native_policy_{mode}"))),
            Err(reason),
            "native {mode}"
        );
        native_witness::validate_public_bundle(&wire(&f, "native_policy_chain"))
            .expect("native chain control");
        assert_eq!(
            import::validate_public_bundle(&wire(&f, &format!("import_policy_{mode}"))),
            Err(reason),
            "import {mode}"
        );
        import::validate_public_bundle(&wire(&f, "import_policy_chain"))
            .expect("import chain control");
    }
    assert_eq!(
        native_witness::validate_public_bundle(&wire(&f, "zero_head_uncommitted_policy")),
        Err(codec::Reject::Canonical)
    );
    native_witness::validate_public_bundle(&wire(&f, "zero_head_control"))
        .expect("empty policy sentinel control");
    let mut native: api::NativePublicProofBundleV1 = wire(&f, "native_actor_key_revoked");
    native.policies[0]
        .body
        .as_mut()
        .expect("body")
        .policy
        .as_mut()
        .expect("policy")
        .revoked_key_ids
        .clear();
    assert_eq!(
        native_witness::validate_public_bundle(&native),
        Err(codec::Reject::Canonical)
    );
    native_witness::validate_public_bundle(&wire(&f, "cowriter_start_bundle"))
        .expect("unrevoked control");
    let mut imported: api::ImportPublicProofBundleV1 = wire(&f, "import_actor_key_revoked");
    imported.policies[0]
        .body
        .as_mut()
        .expect("body")
        .policy
        .as_mut()
        .expect("policy")
        .revoked_key_ids
        .clear();
    assert_eq!(
        import::validate_public_bundle(&imported),
        Err(codec::Reject::Canonical)
    );
    import::validate_public_bundle(&wire(&f, "cowriter_import_bundle"))
        .expect("unrevoked import control");
}
#[test]
fn p2_p4_owner_root_and_duplicate_histories() {
    let f = fixture();
    for kind in ["p2", "p4"] {
        assert_eq!(
            native_witness::validate_public_bundle(&wire(
                &f,
                &format!("{kind}_self_signed_owner_uuid")
            )),
            Err(codec::Reject::Root),
            "{kind}"
        );
        native_witness::validate_public_bundle(&wire(&f, &format!("{kind}_owner_bundle")))
            .expect("owner control");
        assert_eq!(
            native_witness::validate_public_bundle(&wire(
                &f,
                &format!("{kind}_duplicate_history_poisoning")
            )),
            Err(codec::Reject::Canonical)
        );
        let mut duplicate: api::NativePublicProofBundleV1 =
            wire(&f, &format!("{kind}_owner_bundle"));
        duplicate
            .owner_histories
            .push(duplicate.owner_histories[0].clone());
        assert_eq!(
            native_witness::validate_public_bundle(&duplicate),
            Err(codec::Reject::Canonical)
        );
    }
}
#[test]
fn actor_subject_binding_reject_then_pass() {
    let f = fixture();
    let id: api::ImportIdentityV1 =
        codec::strict_decode(&bytes(&f, "identity_wire_hex"), 65536).expect("identity");
    let account = bytes(&f, "account_hex");
    let p: api::ImportAuthorityWitnessV1 = wire(&f, "p2_envelope_not_op_author");
    assert_eq!(
        writer::verify_authority_actor_binding(&p, &account, &id.owner_account_uuid, &id.owner_id),
        Err(codec::Reject::GenesisBinding)
    );
    writer::verify_authority_actor_binding(
        &wire(&f, "cowriter_capture_owner_thread"),
        &account,
        &id.owner_account_uuid,
        &id.owner_id,
    )
    .expect("P2 author control");
    let p: api::HostedLandingWitnessV1 = wire(&f, "requester_not_token_subject");
    let key = p
        .request
        .as_ref()
        .expect("request")
        .signature
        .as_ref()
        .expect("signature")
        .public_key
        .clone();
    assert_eq!(
        writer::verify_landing_actor_binding(
            &p,
            &account,
            &key,
            &key,
            &id.owner_account_uuid,
            &id.owner_id
        ),
        Err(codec::Reject::GenesisBinding)
    );
    let control = wire(&f, "cowriter_land_request");
    writer::verify_landing_actor_binding(
        &control,
        &account,
        &key,
        &key,
        &id.owner_account_uuid,
        &id.owner_id,
    )
    .expect("P4 verified subject control");
    assert_eq!(
        writer::verify_landing_actor_binding(
            &control,
            &account,
            &[0x80; 32],
            &[0x80; 32],
            &id.owner_account_uuid,
            &id.owner_id
        ),
        Err(codec::Reject::KeyRole)
    );
    assert_eq!(
        writer::verify_landing_actor_binding(
            &control,
            &account,
            &[0x80; 32],
            &key,
            &id.owner_account_uuid,
            &id.owner_id
        ),
        Err(codec::Reject::KeyRole)
    );
}
#[test]
fn ownership_counterparty_revocations() {
    let f = fixture();
    for kind in [2, 3] {
        assert_eq!(
            native_witness::validate_public_bundle(&wire(
                &f,
                &format!("kind_{kind}_counterparty_revoked")
            )),
            Err(codec::Reject::Revoked)
        );
        native_witness::validate_public_bundle(&wire(&f, "ownership_counterparty_control"))
            .expect("uncut counterparty control");
    }
}
#[test]
fn landing_reviews_only() {
    let f = fixture();
    assert_eq!(
        native_witness::validate_public_bundle(&wire(&f, "p4_non_review")),
        Err(codec::Reject::Semantic)
    );
    native_witness::validate_public_bundle(&wire(&f, "p4_owner_bundle")).expect("Review control");
}
#[test]
fn attachment_payload_binding_reject_then_pass() {
    let f = fixture();
    let s = wire(&f, "admitted_original_statement");
    verify_statement(&f, &s);
    let bad: api::ImportAuthorityWitnessV1 = wire(&f, "admitted_unknown_payload");
    assert!(matches!(
        writer::admitted_owner_mint_root_attachment(
            s.body.as_ref().expect("statement"),
            writer::WriterWitnessPayload::Import(import::WitnessPayload::Authority(&bad))
        ),
        Err(codec::Reject::Scope)
    ));
    admission(&f, "admitted_original");
}
