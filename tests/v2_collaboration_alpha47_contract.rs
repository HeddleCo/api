use ed25519_dalek::{Signer, SigningKey};
use heddle_api::heddle::api::v1alpha2 as api;
use heddle_api::v2::collaboration::{
    canonical_discussion_open_tags, canonical_discussion_tag_edit, canonical_mention,
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
                    decode(
                        &canonical_mentions(&mentions, Some(&peer())).expect("bounded mentions"),
                    ),
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
                    decode(&canonical_discussion_open_tags(&tags(), Some(&peer())).expect("tags")),
                );
        }
        if name == "edit_tags" || name == "clear_tags" {
            let tag_list = if name == "clear_tags" { vec![] } else { tags() };
            inner.set(
                "body",
                decode(&canonical_discussion_tag_edit(&tag_list, Some(&peer())).expect("tag edit")),
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
            "mentions": mentions.iter().map(|m| serde_json::json!({"entity_wire_hex": hex::encode(m.encode_to_vec()), "canonical_hex": hex::encode(canonical_mention(m, Some(&peer())).expect("mention"))})).collect::<Vec<_>>() }));
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
    assert!(validate_mentions(&vec![principal.clone(); 128], Some(&peer())).is_ok());
    assert_eq!(
        validate_mentions(&vec![principal; 129], Some(&peer())),
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
        assert!(canonical_mention(&e, Some(&peer())).is_err());
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
        assert!(canonical_mention(&e, Some(&peer())).is_err());
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
        canonical_mention(&cross, Some(&peer())),
        Err(heddle_api::hybrid_codec::Reject::Scope)
    );
}

#[test]
fn alpha47_total_mention_bytes_match_delivery_and_canonical_validation() {
    let mut source = entity("source_state");
    if let Some(api::entity_ref::Entity::Source(s)) = &mut source.entity {
        s.path = "é".repeat(2048);
        s.symbol_id = "s".repeat(4096);
    }
    assert!(
        canonical_mention(&source, Some(&peer())).is_ok(),
        "each field is within its bound"
    );
    let below = vec![source.clone(); 31];
    assert!(canonical_mentions(&below, Some(&peer())).is_ok());
    assert!(validate_mentions(&below, Some(&peer())).is_ok());
    for count in [32, 128] {
        let mentions = vec![source.clone(); count];
        assert_eq!(
            canonical_mentions(&mentions, Some(&peer())),
            Err(heddle_api::hybrid_codec::Reject::Bounds)
        );
        assert_eq!(
            validate_mentions(&mentions, Some(&peer())),
            Err(heddle_api::hybrid_codec::Reject::Bounds)
        );
    }
}

fn peer() -> heddle_api::heddle::api::common::ProtocolCompatibility {
    heddle_api::heddle::api::common::ProtocolCompatibility {
        protocol_version: 2,
        mandatory_features: vec![1, 2, 3, 4],
    }
}

#[test]
fn alpha48_variant_features_gate_before_encoding() {
    use heddle_api::heddle::api::common::MandatoryProtocolFeature as F;
    use heddle_api::hybrid_codec::Reject;
    use heddle_api::v2::protocol::{host_supports, require_feature};
    let missing = heddle_api::heddle::api::common::ProtocolCompatibility {
        protocol_version: 2,
        mandatory_features: vec![1],
    };
    for feature in [
        F::CollaborationMentionsV1,
        F::DiscussionTagsV1,
        F::ContentOutlineV1,
    ] {
        assert!(host_supports(Some(&peer()), feature));
        require_feature(Some(&peer()), feature).expect("advertised feature");
        for absent in [None, Some(&missing)] {
            assert!(!host_supports(absent, feature));
            assert_eq!(
                require_feature(absent, feature),
                Err(Reject::MissingFeature(feature))
            );
        }
    }
    for absent in [None, Some(&missing)] {
        for name in ["principal", "source_state", "source_git"] {
            let r = entity(name);
            assert_eq!(
                canonical_mention(&r, absent),
                Err(Reject::MissingFeature(F::CollaborationMentionsV1))
            );
            assert_eq!(
                validate_mentions(&[r], absent),
                Err(Reject::MissingFeature(F::CollaborationMentionsV1))
            );
        }
        assert_eq!(
            canonical_discussion_open_tags(&tags(), absent),
            Err(Reject::MissingFeature(F::DiscussionTagsV1))
        );
        for tags in [vec![], tags()] {
            assert_eq!(
                canonical_discussion_tag_edit(&tags, absent),
                Err(Reject::MissingFeature(F::DiscussionTagsV1))
            );
        }
        canonical_discussion_open_tags(&[], absent).expect("empty opening tags need no feature");
        canonical_mentions(&[], absent).expect("no mentions need no feature");
        let legacy = api::EntityRef {
            entity: Some(api::entity_ref::Entity::Spool(api::SpoolRef {
                id: "00000000-0000-0000-0000-000000000001".into(),
            })),
        };
        assert_eq!(
            canonical_mention(&legacy, absent).expect("old variant"),
            canonical_mention(&legacy, Some(&peer())).expect("old variant")
        );
        // Context annotation tags existed before discussion tags.
        heddle_api::v2::collaboration::canonical_annotation_tags(&tags()).expect("context tags");
    }
    heddle_api::import_authority::require_hybrid_peer(Some(&peer()))
        .expect("additional features do not break HYBRID");
}

#[test]
fn alpha48_feature_enum_and_method_requirements_are_stable() {
    use heddle_api::heddle::api::common::MandatoryProtocolFeature as F;
    for (feature, value) in [
        (F::Unspecified, 0),
        (F::ImportAuthorityHostWitnessV1, 1),
        (F::CollaborationMentionsV1, 2),
        (F::DiscussionTagsV1, 3),
        (F::ContentOutlineV1, 4),
    ] {
        assert_eq!(feature as i32, value);
        assert_eq!(F::try_from(value), Ok(feature));
    }
    for method in heddle_api::v2::ALL_METHODS {
        assert!(
            method
                .mandatory_features
                .iter()
                .all(|f| ![2, 3, 4].contains(&(*f as i32))),
            "variant features must not gate {}",
            method.path
        );
    }
}

#[test]
fn alpha48_delivery_gate_covers_open_reply_context_extract_tags_and_outline() {
    use heddle_api::heddle::api::common::MandatoryProtocolFeature as F;
    use heddle_api::hybrid_codec::Reject;
    use heddle_api::v2::protocol::validate_request_features as validate;
    let mention = entity("principal");
    let context = api::ContextDraft {
        mentions: vec![mention.clone()],
        ..Default::default()
    };
    let outline = api::OutlineRead {
        path: "main.rs".into(),
        ..Default::default()
    };
    let cases = [
        (
            "CollaborationService/OpenDiscussion",
            api::OpenDiscussionRequest {
                mentions: vec![mention.clone()],
                ..Default::default()
            }
            .encode_to_vec(),
            F::CollaborationMentionsV1,
        ),
        (
            "CollaborationService/AppendTurn",
            api::AppendDiscussionRequest {
                mentions: vec![mention],
                ..Default::default()
            }
            .encode_to_vec(),
            F::CollaborationMentionsV1,
        ),
        (
            "CollaborationService/PutContext",
            api::PutContextRequest {
                context: Some(context.clone()),
                ..Default::default()
            }
            .encode_to_vec(),
            F::CollaborationMentionsV1,
        ),
        (
            "CollaborationService/ResolveDiscussion",
            api::ResolveDiscussionRequest {
                resolution: Some(api::resolve_discussion_request::Resolution::ExtractContext(
                    context,
                )),
                ..Default::default()
            }
            .encode_to_vec(),
            F::CollaborationMentionsV1,
        ),
        (
            "CollaborationService/OpenDiscussion",
            api::OpenDiscussionRequest {
                tags: tags(),
                ..Default::default()
            }
            .encode_to_vec(),
            F::DiscussionTagsV1,
        ),
        (
            "CollaborationService/EditDiscussionTags",
            api::EditDiscussionTagsRequest::default().encode_to_vec(),
            F::DiscussionTagsV1,
        ),
        (
            "ContentService/ReadContent",
            api::ReadContentRequest {
                selections: vec![api::ContentRead {
                    selection: Some(api::content_read::Selection::Outline(outline)),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec(),
            F::ContentOutlineV1,
        ),
    ];
    for (method, bytes, feature) in cases {
        let path = format!("/heddle.api.v1alpha2.{method}");
        assert_eq!(
            validate(&path, &bytes, None),
            Err(Reject::MissingFeature(feature))
        );
        let supported = heddle_api::heddle::api::common::ProtocolCompatibility {
            protocol_version: 2,
            mandatory_features: vec![feature as i32],
        };
        validate(&path, &bytes, Some(&supported)).expect("only the used feature is required");
        if feature != F::DiscussionTagsV1 || !method.ends_with("EditDiscussionTags") {
            validate(&path, &[], None).expect("old empty command needs no variant feature");
        }
    }
}
