use ed25519_dalek::{Signer, SigningKey};
use heddle_api::heddle::api::v1alpha2 as api;
use heddle_api::v2::collaboration::{
    canonical_annotation_tags, canonical_discussion_tag_edit, canonical_mention,
    canonical_mentions, validate_mentions,
};
use prost::Message;
#[path = "support/collaboration_alpha47.rs"]
mod support;
use support::{Value, decode, encode, hash};

fn entity(name: &str) -> api::EntityRef {
    use api::entity_ref::Entity;
    let spool = Some(api::SpoolRef {
        id: "00000000-0000-0000-0000-000000000001".into(),
    });
    let r = if name.contains("git") {
        api::revision_ref::Revision::GitCommitOid("a".repeat(40))
    } else {
        api::revision_ref::Revision::State(heddle_api::heddle::api::common::StateId {
            value: vec![5; 32],
        })
    };
    api::EntityRef {
        entity: Some(if name.contains("principal") {
            Entity::Principal(api::PrincipalRef {
                id: "00000000-0000-0000-0000-000000000006".into(),
            })
        } else {
            Entity::Source(api::SourceMention {
                revision: Some(api::RevisionRef {
                    spool: spool.clone(),
                    revision: Some(r),
                }),
                path: "src/main.rs".into(),
                symbol_id: if name.contains("state") {
                    "run".into()
                } else {
                    String::new()
                },
                start_line: name.contains("state").then_some(12),
                end_line: name.contains("state").then_some(18),
                thread: name.contains("state").then_some(api::ThreadRef {
                    spool,
                    id: Some(api::ThreadId { value: vec![2; 32] }),
                }),
            })
        }),
    }
}
fn tags() -> Vec<api::AnnotationTag> {
    vec![
        api::AnnotationTag {
            tag: Some(api::annotation_tag::Tag::Text("decision".into())),
        },
        api::AnnotationTag {
            tag: Some(api::annotation_tag::Tag::Entity(entity("principal"))),
        },
    ]
}
fn baseline(name: &str) -> Vec<u8> {
    let line = include_str!("fixtures/collaboration-v2-rust.txt")
        .lines()
        .find(|s| s.starts_with(&format!("{name} ")))
        .expect("native baseline");
    hex::decode(line.split(' ').nth(2).expect("canonical")).expect("hex")
}
fn vectors() -> serde_json::Value {
    let key = SigningKey::from_bytes(&[7; 32]);
    let names = [
        "principal_open",
        "source_state_open",
        "source_git_append",
        "context_mentions",
        "open_tags",
        "edit_tags",
        "clear_tags",
    ];
    let mut result = serde_json::Map::new();
    for name in names {
        let original = baseline(if name == "context_mentions" {
            "context"
        } else if name == "source_git_append" {
            "append"
        } else {
            "open"
        });
        let mut outer = decode(&original);
        assert_eq!(encode(&outer), original, "baseline byte identity");
        let mut inner = decode(&outer.get("body").get("canonical").bytes());
        let mentions: Vec<api::EntityRef> = match name {
            "principal_open" | "source_state_open" | "source_git_append" => vec![entity(name)],
            "context_mentions" => vec![entity("principal"), entity("source_git")],
            _ => vec![],
        };
        inner.get("metadata");
        if let Value::Map(m) = &mut inner {
            m.iter_mut()
                .find(|(k, _)| k == "metadata")
                .expect("metadata")
                .1
                .set(
                    "mentions",
                    decode(&canonical_mentions(&mentions).expect("bounded mentions")),
                );
        }
        if name == "open_tags"
            && let Value::Map(m) = &mut inner
        {
            m.iter_mut()
                .find(|(k, _)| k == "body")
                .expect("body")
                .1
                .set(
                    "tags",
                    decode(&canonical_annotation_tags(&tags()).expect("tags")),
                );
        }
        if name == "edit_tags" || name == "clear_tags" {
            let tag_list = if name == "clear_tags" { vec![] } else { tags() };
            inner.set(
                "body",
                decode(&canonical_discussion_tag_edit(&tag_list).expect("tag edit")),
            );
            let open = baseline("open");
            let open_content = decode(&open).get("body").get("canonical").bytes();
            // Reuse the existing append frontier's inner textual operation ID.
            let append = decode(&baseline("append"));
            inner.set(
                "parents",
                decode(&append.get("body").get("canonical").bytes())
                    .get("parents")
                    .clone(),
            );
            assert_eq!(hash("collaboration-operation", &open_content).len(), 32);
            outer.set(
                "parents",
                Value::Array(vec![Value::byte_array(&hash(
                    "heddle-thread-operation-v1",
                    &open,
                ))]),
            );
        }
        let canonical_content = encode(&inner);
        if let Value::Map(m) = &mut outer {
            m.iter_mut()
                .find(|(k, _)| k == "body")
                .expect("body")
                .1
                .set("canonical", Value::byte_array(&canonical_content));
        }
        let canonical = encode(&outer);
        let mut signing = b"heddle-thread-operation-v1\0".to_vec();
        signing.extend(&canonical);
        let signature = key.sign(&signing);
        key.verifying_key()
            .verify_strict(&signing, &signature)
            .expect("signature");
        let record = api::SignedRecord {
            format: "heddle-thread-operation-v1".into(),
            canonical_record: canonical.clone(),
            signatures: vec![api::RecordSignature {
                public_key: key.verifying_key().to_bytes().to_vec(),
                signature: signature.to_bytes().to_vec(),
            }],
        };
        result.insert(name.into(), serde_json::json!({ "canonical_hex": hex::encode(&canonical), "signature_hex": hex::encode(signature.to_bytes()), "operation_id_hex": hex::encode(hash("heddle-thread-operation-v1", &canonical)), "record_wire_hex": hex::encode(record.encode_to_vec()),
            "mentions": mentions.iter().map(|m| serde_json::json!({"entity_wire_hex": hex::encode(m.encode_to_vec()), "canonical_hex": hex::encode(canonical_mention(m).expect("mention"))})).collect::<Vec<_>>() }));
    }
    serde_json::json!({"format":"collaboration-alpha47", "public_key_hex":hex::encode(key.verifying_key().to_bytes()), "vectors":result})
}
#[test]
fn alpha47_signed_golden_vectors() {
    let actual = vectors();
    if std::env::var_os("UPDATE_COLLABORATION_ALPHA47").is_some() {
        std::fs::write(
            "tests/fixtures/collaboration-alpha47.json",
            format!("{}\n", serde_json::to_string_pretty(&actual).expect("json")),
        )
        .expect("write fixture");
    }
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/collaboration-alpha47.json")).expect("json");
    assert_eq!(
        actual, expected,
        "independent Rust encodings/signatures must match the frozen corpus"
    );
}
#[test]
fn alpha47_mention_bounds_and_coordinates() {
    let principal = entity("principal");
    assert!(validate_mentions(&vec![principal.clone(); 128]).is_ok());
    assert_eq!(
        validate_mentions(&vec![principal; 129]),
        Err(heddle_api::hybrid_codec::Reject::Bounds)
    );
    let valid = entity("source_state");
    for (field, bad) in [
        ("path", "x".repeat(4097)),
        ("symbol", "é".repeat(2049)),
        ("path", "../main.rs".into()),
    ] {
        let mut e = valid.clone();
        if let Some(api::entity_ref::Entity::Source(s)) = &mut e.entity {
            if field == "path" {
                s.path = bad;
            } else {
                s.symbol_id = bad;
            }
        }
        assert!(canonical_mention(&e).is_err());
    }
    for (start, end) in [
        (Some(0), Some(1)),
        (Some(2), Some(1)),
        (Some(1), None),
        (None, Some(1)),
    ] {
        let mut e = valid.clone();
        if let Some(api::entity_ref::Entity::Source(s)) = &mut e.entity {
            s.start_line = start;
            s.end_line = end;
        }
        assert!(canonical_mention(&e).is_err());
    }
    let mut cross = valid;
    if let Some(api::entity_ref::Entity::Source(s)) = &mut cross.entity {
        s.thread
            .as_mut()
            .expect("thread")
            .spool
            .as_mut()
            .expect("spool")
            .id = "00000000-0000-0000-0000-000000000007".into();
    }
    assert_eq!(
        canonical_mention(&cross),
        Err(heddle_api::hybrid_codec::Reject::Scope)
    );
}
