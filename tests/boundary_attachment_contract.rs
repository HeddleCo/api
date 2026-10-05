use heddle_api::{
    heddle::api::v1alpha2 as api, hybrid_codec as codec, import_authority as import,
    native_witness as native, writer_authority as writer,
};
use prost::Message;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/boundary-attachment-alpha37.json"))
        .expect("frozen attachment vectors")
}
fn wire<T: Message + Default>(f: &Value, name: &str) -> T {
    codec::strict_decode(
        &hex::decode(f["vectors"][name]["wire_hex"].as_str().expect("hex")).expect("bytes"),
        1048576,
    )
    .expect("canonical transport")
}
#[derive(serde::Deserialize)]
struct Acceptance {
    accepting_author: Author,
}
#[derive(serde::Deserialize)]
struct Author {
    authority: Vec<u8>,
}
fn attachment(a: &api::ThreadControlAuthority) -> &api::SignedOwnerMintRootAttachment {
    match a.mint_root_association.as_ref().expect("association") {
        api::thread_control_authority::MintRootAssociation::OwnerMintRootAttachment(s) => s,
        _ => panic!("paired device"),
    }
}
fn retained(
    authority: &api::ThreadControlAuthority,
    cert: &api::SignedOwnerMintRootAttachment,
    admitted: &writer::AdmittedMintRootAttachment,
) -> Result<(), codec::Reject> {
    let a = cert.attachment.as_ref().expect("attachment");
    let h = authority.owner.as_ref().expect("verified history");
    let issuer = writer::retained_mint_root_issuer(h, &a.owner_state_hash, a.owner_sequence)?;
    writer::verify_retained_writer_attachment(
        &cert.encode_to_vec(),
        &authority.mint_root_public_key,
        &issuer,
        admitted,
        1100,
    )
}
fn check(kind: &str, purpose: i32) {
    let f = fixture();
    let name = format!("{kind}_p{purpose}_control");
    let n: api::NativePublicProofBundleV1;
    let i: api::ImportPublicProofBundleV1;
    let (statements, payload, evidence, original) = if kind == "native" {
        n = wire(&f, &name);
        native::validate_public_bundle(&n).expect("rotated native carrier");
        if purpose == 1 {
            let p = &n.genesis_witnesses[0];
            (
                &n.statements,
                writer::WriterWitnessPayload::NativeGenesis(p),
                p.boundary_acceptance.as_ref().expect("boundary"),
                &p.creator_authority_envelope,
            )
        } else {
            let p = &n.authority_witnesses[0];
            (
                &n.statements,
                writer::WriterWitnessPayload::Import(import::WitnessPayload::Authority(p)),
                &p.boundary_acceptances[0],
                &p.authority_envelope,
            )
        }
    } else {
        i = wire(&f, &name);
        import::validate_public_bundle(&i).expect("rotated import carrier");
        if purpose == 1 {
            let p = &i.genesis_witnesses[0];
            (
                &i.statements,
                writer::WriterWitnessPayload::Import(import::WitnessPayload::Genesis(p)),
                p.boundary_acceptance.as_ref().expect("boundary"),
                &p.creator_authority_envelope,
            )
        } else {
            let p = &i.authority_witnesses[0];
            (
                &i.statements,
                writer::WriterWitnessPayload::Import(import::WitnessPayload::Authority(p)),
                &p.boundary_acceptances[0],
                &p.authority_envelope,
            )
        }
    };
    let signed = statements
        .iter()
        .find(|s| {
            s.body
                .as_ref()
                .is_some_and(|s| s.basis == 2 && s.purpose == purpose)
        })
        .expect("selected statement");
    let s = signed.body.as_ref().expect("statement");
    codec::verify(
        &hex::decode(
            f["keys"]["witness"]["public_key_hex"]
                .as_str()
                .expect("key"),
        )
        .expect("hex"),
        &heddle_api::witness_trust::statement_signing_digest(s).expect("digest"),
        &signed.signature,
    )
    .expect("independently selected witness signature");
    let acceptance: Acceptance = rmp_serde::from_slice(
        &evidence
            .signed_acceptance
            .as_ref()
            .expect("acceptance")
            .canonical_record,
    )
    .expect("native acceptance");
    let a = writer::decode_authority(&acceptance.accepting_author.authority).expect("acceptor");
    let h = a.owner.as_ref().expect("history");
    assert_eq!(
        h.accepted_transitions[0]
            .transition
            .as_ref()
            .expect("Rotate")
            .kind,
        1
    );
    assert_eq!(
        attachment(&a)
            .attachment
            .as_ref()
            .expect("certificate")
            .owner_sequence,
        0
    );
    let admitted = writer::admitted_owner_mint_root_attachment(s, payload).expect("admission");
    retained(&a, attachment(&a), &admitted).expect("rotated acceptor's exact attachment admitted");
    let forged = wire::<api::SignedOwnerMintRootAttachment>(
        &f,
        &format!("{kind}_p{purpose}_forged_attachment"),
    );
    assert_eq!(retained(&a, &forged, &admitted), Err(codec::Reject::Root));
    retained(&a, attachment(&a), &admitted).expect("control after forged certificate");
    // Import P1's original envelope is delegated import authority, not a
    // native paired attachment. Preserve that distinct basis-1 contract.
    if kind != "import" || purpose != 1 {
        let original = writer::decode_authority(original).expect("original authority");
        assert_eq!(
            retained(&original, attachment(&original), &admitted),
            Err(codec::Reject::Root)
        );
        retained(&a, attachment(&a), &admitted).expect("control after original substitution");
    }
}
#[test]
fn native_p1_rotated_acceptor_attachment() {
    check("native", 1);
}
#[test]
fn native_p2_rotated_acceptor_attachment() {
    check("native", 2);
}
#[test]
fn import_p1_rotated_acceptor_attachment() {
    check("import", 1);
}
#[test]
fn import_p2_rotated_acceptor_attachment() {
    check("import", 2);
}
#[test]
fn acceptance_fixed_octets_require_integer_arrays() {
    let f = fixture();
    for kind in ["native", "import"] {
        for purpose in [1, 2] {
            for mode in ["binary_publisher", "binary_authority_digest"] {
                let name = format!("{kind}_p{purpose}_{mode}");
                let result = if kind == "native" {
                    let b: api::NativePublicProofBundleV1 = wire(&f, &name);
                    let s = b
                        .statements
                        .iter()
                        .find_map(|s| {
                            s.body
                                .as_ref()
                                .filter(|s| s.basis == 2 && s.purpose == purpose)
                        })
                        .expect("statement");
                    let payload = if purpose == 1 {
                        writer::WriterWitnessPayload::NativeGenesis(&b.genesis_witnesses[0])
                    } else {
                        writer::WriterWitnessPayload::Import(import::WitnessPayload::Authority(
                            &b.authority_witnesses[0],
                        ))
                    };
                    assert_eq!(
                        writer::admitted_owner_mint_root_attachment(s, payload).err(),
                        Some(codec::Reject::Canonical),
                        "{name} admission"
                    );
                    native::validate_public_bundle(&b)
                } else {
                    let b: api::ImportPublicProofBundleV1 = wire(&f, &name);
                    let s = b
                        .statements
                        .iter()
                        .find_map(|s| {
                            s.body
                                .as_ref()
                                .filter(|s| s.basis == 2 && s.purpose == purpose)
                        })
                        .expect("statement");
                    let payload = if purpose == 1 {
                        import::WitnessPayload::Genesis(&b.genesis_witnesses[0])
                    } else {
                        import::WitnessPayload::Authority(&b.authority_witnesses[0])
                    };
                    assert_eq!(
                        writer::admitted_owner_mint_root_attachment(
                            s,
                            writer::WriterWitnessPayload::Import(payload)
                        )
                        .err(),
                        Some(codec::Reject::Canonical),
                        "{name} admission"
                    );
                    import::validate_public_bundle(&b)
                };
                assert_eq!(result, Err(codec::Reject::Canonical), "{name}");
            }
            let control = format!("{kind}_p{purpose}_control");
            if kind == "native" {
                native::validate_public_bundle(&wire(&f, &control)).expect("passing control");
            } else {
                import::validate_public_bundle(&wire(&f, &control)).expect("passing control");
            }
        }
    }
}
