//! Portable collaboration additions against the published native encoding.
use contract::heddle::api::v1alpha2 as wire;
use prost::Message;
#[test]
fn older_native_decoder_refuses_new_signed_collaboration_forms() {
    let baseline = include_str!("../../../tests/fixtures/collaboration-v2-rust.txt")
        .lines()
        .find(|line| line.starts_with("open "))
        .expect("legacy opening");
    let fields: Vec<_> = baseline.split(' ').collect();
    let legacy = wire::SignedRecord {
        format: "heddle-thread-operation-v1".into(),
        canonical_record: hex::decode(fields[2]).expect("legacy canonical"),
        signatures: vec![wire::RecordSignature {
            public_key: hex::decode(fields[1]).expect("legacy public key"),
            signature: hex::decode(fields[3]).expect("legacy signature"),
        }],
    };
    let native = thread_api::contract::SignedRecord::decode(legacy.encode_to_vec().as_slice())
        .expect("legacy record");
    thread_api::replication::decode_record(native)
        .expect("same older decoder accepts legacy opening");
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/collaboration-alpha47.json"
    ))
    .expect("fixture");
    for name in ["edit_tags", "open_tags", "principal_open"] {
        let bytes = hex::decode(
            fixture["vectors"][name]["record_wire_hex"]
                .as_str()
                .expect("wire"),
        )
        .expect("hex");
        let record = thread_api::contract::SignedRecord::decode(bytes.as_slice()).expect("record");
        assert!(
            thread_api::replication::decode_record(record).is_err(),
            "thread-api 0.28.7 must refuse {name} rather than discard signed fields"
        );
    }
}

#[test]
fn collaboration_alpha47_mentions_and_signatures() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/collaboration-alpha47.json"
    ))
    .expect("fixture");
    let mut cases = 0;
    for (_, v) in fixture["vectors"].as_object().expect("vectors") {
        let record = wire::SignedRecord::decode(
            hex::decode(v["record_wire_hex"].as_str().expect("wire"))
                .expect("hex")
                .as_slice(),
        )
        .expect("record");
        assert_eq!(
            hex::encode(&record.canonical_record),
            v["canonical_hex"].as_str().expect("canonical")
        );
        let mut input = b"heddle-thread-operation-v1\0".to_vec();
        input.extend(&record.canonical_record);
        let signature = &record.signatures[0];
        contract::hybrid_codec::verify(&signature.public_key, &input, &signature.signature)
            .expect("new signed form");
        let mut changed = input;
        changed[0] ^= 1;
        assert!(
            contract::hybrid_codec::verify(&signature.public_key, &changed, &signature.signature)
                .is_err()
        );
        for mention in v["mentions"].as_array().expect("mentions") {
            let r = wire::EntityRef::decode(
                hex::decode(mention["entity_wire_hex"].as_str().expect("wire"))
                    .expect("hex")
                    .as_slice(),
            )
            .expect("entity");
            assert_eq!(
                hex::encode(
                    contract::v2::collaboration::canonical_mention(&r).expect("bounded new case")
                ),
                mention["canonical_hex"].as_str().expect("canonical")
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 7);
}
#[test]
fn existing_mention_encodings_match_published_native() {
    let spool = Some(wire::SpoolRef {
        id: "00000000-0000-0000-0000-000000000001".into(),
    });
    use wire::entity_ref::Entity;
    let cases = vec![
        Entity::Spool(spool.clone().expect("spool")),
        Entity::Thread(wire::ThreadRef {
            spool: spool.clone(),
            id: Some(wire::ThreadId { value: vec![2; 32] }),
        }),
        Entity::Revision(wire::RevisionRef {
            spool: spool.clone(),
            revision: Some(wire::revision_ref::Revision::State(
                contract::heddle::api::common::StateId { value: vec![5; 32] },
            )),
        }),
        Entity::Revision(wire::RevisionRef {
            spool: spool.clone(),
            revision: Some(wire::revision_ref::Revision::GitCommitOid("a".repeat(40))),
        }),
        Entity::Device(wire::EndpointRef {
            kind: 2,
            public_key: vec![9; 32],
        }),
        Entity::Checkout(wire::CheckoutRef {
            spool: spool.clone(),
            device: Some(wire::EndpointRef {
                kind: 2,
                public_key: vec![9; 32],
            }),
            id: "checkout-1".into(),
        }),
        Entity::Context(wire::RecordRef {
            spool,
            id: "context-1".into(),
        }),
    ];
    for entity in cases {
        let r = wire::EntityRef {
            entity: Some(entity),
        };
        let old =
            native_api::heddle::api::v1alpha2::EntityRef::decode(r.encode_to_vec().as_slice())
                .expect("old wire");
        let native = thread_api::collaboration::mention(&old).expect("native mention");
        assert_eq!(
            contract::v2::collaboration::canonical_mention(&r).expect("canonical"),
            rmp_serde::to_vec_named(&native).expect("native canonical")
        );
    }
}

#[test]
fn discussion_tags_reuse_published_context_tag_encodings() {
    use wire::{annotation_tag::Tag, annotation_value::Value};
    let reference = wire::AnnotationSourceReference {
        source: Some(wire::SourceAnchor {
            revision: Some(wire::RevisionRef {
                spool: Some(wire::SpoolRef {
                    id: "00000000-0000-0000-0000-000000000001".into(),
                }),
                revision: Some(wire::revision_ref::Revision::GitCommitOid("a".repeat(40))),
            }),
            path: "src/main.rs".into(),
            symbol_id: "run".into(),
            start_line: Some(12),
            end_line: Some(18),
            target: Some(wire::SourceTargetReference {
                target_id: vec![9; 32],
                binding: Some(wire::source_target_reference::Binding::ViewedThread(true)),
            }),
            ..Default::default()
        }),
    };
    let mut tags = vec![
        wire::AnnotationTag {
            tag: Some(Tag::Text("decision".into())),
        },
        wire::AnnotationTag {
            tag: Some(Tag::Source(reference.clone())),
        },
        wire::AnnotationTag {
            tag: Some(Tag::Symbol(wire::AnnotationSymbolTag {
                name: "run".into(),
                target: Some(reference),
            })),
        },
    ];
    for (key, value) in [
        ("text", Value::Text("label".into())),
        ("bool", Value::Boolean(false)),
        ("integer", Value::Integer(i64::MAX)),
        (
            "decimal",
            Value::Decimal(wire::AnnotationDecimal {
                coefficient: -123,
                scale: 2,
            }),
        ),
    ] {
        tags.push(wire::AnnotationTag {
            tag: Some(Tag::Property(wire::AnnotationProperty {
                key: key.into(),
                value: Some(wire::AnnotationValue { value: Some(value) }),
            })),
        });
    }
    let old: Vec<_> = tags
        .iter()
        .map(|t| {
            native_api::heddle::api::v1alpha2::AnnotationTag::decode(t.encode_to_vec().as_slice())
                .expect("old tag")
        })
        .collect();
    let native = thread_api::collaboration::annotation_tags(&old).expect("native tags");
    assert_eq!(
        contract::v2::collaboration::canonical_annotation_tags(&tags).expect("tags"),
        rmp_serde::to_vec_named(&native).expect("native encoding")
    );
}
