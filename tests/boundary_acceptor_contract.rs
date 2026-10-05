use heddle_api::{heddle::api::v1alpha2 as api, hybrid_codec::Reject};
use heddle_api::{hybrid_codec, import_authority as import, native_witness as native};
use prost::Message;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/boundary-acceptor-alpha36.json"))
        .expect("frozen boundary vectors")
}
fn wire<T: Message + Default>(f: &Value, name: &str) -> T {
    hybrid_codec::strict_decode(
        &hex::decode(f["vectors"][name]["wire_hex"].as_str().expect("hex")).expect("bytes"),
        1048576,
    )
    .expect("canonical bundle")
}
fn validate(kind: &str, name: &str) -> Result<(), Reject> {
    let f = fixture();
    if kind == "native" {
        native::validate_public_bundle(&wire::<api::NativePublicProofBundleV1>(&f, name))
    } else {
        let b: api::ImportPublicProofBundleV1 = wire(&f, name);
        // The import carrier validator is a portable structural boundary; verify
        // the original and acceptance signatures/commitments independently too.
        for signed in &b.statements {
            let s = signed.body.as_ref().expect("statement");
            match s.purpose {
                1 => {
                    let p = b
                        .genesis_witnesses
                        .iter()
                        .find(|p| {
                            hybrid_codec::canonical(*p).expect("payload") == s.canonical_payload
                        })
                        .expect("genesis payload");
                    import::verify_witness_payload(s, import::WitnessPayload::Genesis(p))?;
                }
                2 => {
                    let p = b
                        .authority_witnesses
                        .iter()
                        .find(|p| {
                            hybrid_codec::canonical(*p).expect("payload") == s.canonical_payload
                        })
                        .expect("authority payload");
                    import::verify_witness_payload(s, import::WitnessPayload::Authority(p))?;
                }
                _ => (),
            }
        }
        import::validate_public_bundle(&b)
    }
}
#[test]
fn boundary_original_revoked_accepts() {
    for kind in ["native", "import"] {
        for purpose in [1, 2] {
            let prefix = format!("{kind}_p{purpose}");
            validate(kind, &format!("{prefix}_control")).expect("unrevoked control");
            validate(kind, &format!("{prefix}_original_revoked"))
                .expect("current acceptor preserves revoked original provenance");
        }
    }
}
#[test]
fn boundary_acceptor_guards() {
    for kind in ["native", "import"] {
        for purpose in [1, 2] {
            let prefix = format!("{kind}_p{purpose}");
            for (mode, reason) in [
                ("acceptor_revoked", Reject::Revoked),
                ("forged_acceptor", Reject::Signature),
                ("account_mismatch", Reject::GenesisBinding),
                ("owner_impersonation", Reject::Root),
                ("ordinary_revoked", Reject::Revoked),
            ] {
                if kind == "import" && purpose == 1 && mode == "ordinary_revoked" {
                    continue; // Import P1 ordinary authority remains delegated.
                }
                assert_eq!(
                    validate(kind, &format!("{prefix}_{mode}")),
                    Err(reason),
                    "{prefix}_{mode}"
                );
                validate(kind, &format!("{prefix}_control"))
                    .expect("passing control after rejection");
            }
        }
    }
}
