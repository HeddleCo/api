#[cfg(feature = "reflection")]
mod descriptor {
    use prost_reflect::{DescriptorPool, Kind};

    fn pool() -> DescriptorPool {
        DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("compiled descriptor")
    }

    #[test]
    fn bookmark_timestamps_are_additive_present_messages() {
        let pool = pool();
        let record = pool
            .get_message_by_name("heddle.api.v1alpha2.BookmarkRecord")
            .expect("bookmark");
        for (name, tag) in [("ref", 1), ("version", 2), ("label", 3), ("bookmarked", 4)] {
            assert_eq!(
                record.get_field_by_name(name).expect("old field").number(),
                tag
            );
        }
        for (name, tag) in [("bookmarked_at", 5), ("updated_at", 6)] {
            let field = record.get_field_by_name(name).expect("additive timestamp");
            assert_eq!(field.number(), tag);
            assert!(field.supports_presence());
            assert!(!field.is_list());
            assert_eq!(
                field.kind().as_message().expect("timestamp").full_name(),
                "google.protobuf.Timestamp"
            );
        }
    }

    #[test]
    fn source_kind_and_provenance_are_separate_additive_enums() {
        let pool = pool();
        let source = pool
            .get_message_by_name("heddle.api.v1alpha2.SourceAnchor")
            .expect("anchor");
        for (name, tag) in [
            ("revision", 1),
            ("path", 2),
            ("symbol_id", 3),
            ("start_line", 4),
            ("end_line", 5),
            ("thread", 6),
            ("target", 7),
        ] {
            assert_eq!(
                source.get_field_by_name(name).expect("old field").number(),
                tag
            );
        }
        for (name, tag, enumeration, values) in [
            (
                "path_kind",
                8,
                "SourcePathKind",
                [
                    "SOURCE_PATH_KIND_UNSPECIFIED",
                    "SOURCE_PATH_KIND_FILE",
                    "SOURCE_PATH_KIND_DIRECTORY",
                ],
            ),
            (
                "path_kind_source",
                9,
                "SourcePathKindSource",
                [
                    "SOURCE_PATH_KIND_SOURCE_UNSPECIFIED",
                    "SOURCE_PATH_KIND_SOURCE_RECORDED",
                    "SOURCE_PATH_KIND_SOURCE_DERIVED",
                ],
            ),
        ] {
            let field = source.get_field_by_name(name).expect("additive enum");
            assert_eq!(field.number(), tag);
            let Kind::Enum(kind) = field.kind() else {
                panic!("typed enum")
            };
            assert_eq!(kind.name(), enumeration);
            assert_eq!(kind.values().count(), 3);
            for (number, name) in values.into_iter().enumerate() {
                assert_eq!(
                    kind.get_value_by_name(name)
                        .expect("stable enum value")
                        .number(),
                    number as i32
                );
            }
        }
    }

    #[test]
    fn current_source_locations_mirror_kind_without_signed_provenance() {
        let pool = pool();
        let location = pool
            .get_message_by_name("heddle.api.v1alpha2.SourceLocation")
            .expect("location");
        let field = location
            .get_field_by_name("path_kind")
            .expect("additive location kind");
        assert_eq!(field.number(), 7);
        assert_eq!(
            field.kind().as_enum().expect("kind").full_name(),
            "heddle.api.v1alpha2.SourcePathKind"
        );
        assert!(location.get_field_by_name("path_kind_source").is_none());
    }
}

mod wire {
    use ed25519_dalek::{Signature, SigningKey};
    use heddle_api::heddle::api::v1alpha2 as api;
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage};
    use serde_json::Value;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("fixtures/saved-source-v1.json")).expect("shared vectors")
    }
    fn bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().expect("hex")).expect("valid bytes")
    }
    fn vector(name: &str) -> Value {
        fixture()["vectors"]
            .as_array()
            .expect("vectors")
            .iter()
            .find(|v| v["name"] == name)
            .expect("named vector")
            .clone()
    }
    fn decode<T: Message + Default>(v: &Value) -> T {
        let wire = bytes(&v["wire_hex"]);
        let value = T::decode(wire.as_slice()).expect("TS wire decodes in Rust");
        assert_eq!(value.encode_to_vec(), wire);
        value
    }

    #[test]
    fn all_shared_wire_vectors_and_frozen_original_readers_agree() {
        let fixture = fixture();
        let old = DescriptorPool::decode(
            include_bytes!("fixtures/saved-source-alpha16.binpb").as_slice(),
        )
        .expect("original descriptor");
        let vectors = fixture["vectors"].as_array().expect("vectors");
        assert_eq!(vectors.len(), 26);
        for v in vectors {
            let kind = v["type"].as_str().expect("type");
            let wire = bytes(&v["wire_hex"]);
            let legacy_wire = bytes(&v["legacy_wire_hex"]);
            let descriptor = old
                .get_message_by_name(&format!("heddle.api.v1alpha2.{kind}"))
                .expect("original type");
            let mut legacy =
                DynamicMessage::decode(descriptor, wire.as_slice()).expect("old reader");
            legacy.take_unknown_fields().for_each(drop);
            assert_eq!(legacy.encode_to_vec(), legacy_wire, "{}", v["name"]);
            match kind {
                "BookmarkRecord" => {
                    let mut current: api::BookmarkRecord = decode(v);
                    current.bookmarked_at = None;
                    current.updated_at = None;
                    assert_eq!(
                        current,
                        api::BookmarkRecord::decode(legacy_wire.as_slice()).expect("new reader")
                    );
                }
                "SourceAnchor" => {
                    let mut current: api::SourceAnchor = decode(v);
                    current.path_kind = 0;
                    current.path_kind_source = 0;
                    assert_eq!(
                        current,
                        api::SourceAnchor::decode(legacy_wire.as_slice()).expect("new reader")
                    );
                }
                "SourceLocation" => {
                    let mut current: api::SourceLocation = decode(v);
                    current.path_kind = 0;
                    assert_eq!(
                        current,
                        api::SourceLocation::decode(legacy_wire.as_slice()).expect("new reader")
                    );
                }
                other => panic!("uncovered vector: {other}"),
            }
        }
    }

    #[test]
    fn bookmark_lifecycle_preserves_presence_nanoseconds_and_save_interval() {
        let saved: api::BookmarkRecord = decode(&vector("saved"));
        assert_eq!(
            saved.bookmarked_at,
            Some(prost_types::Timestamp {
                seconds: 1_780_000_000,
                nanos: 123_456_789
            })
        );
        assert_eq!(saved.bookmarked_at, saved.updated_at);
        for (name, seconds, bookmarked) in [
            ("label-edit", 1_780_000_001, true),
            ("removed", 1_780_000_002, false),
        ] {
            let record: api::BookmarkRecord = decode(&vector(name));
            assert_eq!(record.bookmarked_at, saved.bookmarked_at);
            assert_eq!(record.updated_at.expect("last change").seconds, seconds);
            assert_eq!(record.bookmarked, bookmarked);
        }
        let resaved: api::BookmarkRecord = decode(&vector("resaved"));
        assert_eq!(
            resaved.bookmarked_at.as_ref().expect("new save").seconds,
            1_780_000_003
        );
        assert_eq!(resaved.bookmarked_at, resaved.updated_at);
        for name in ["legacy-saved", "never-saved"] {
            let record: api::BookmarkRecord = decode(&vector(name));
            assert!(record.bookmarked_at.is_none() && record.updated_at.is_none());
        }
        let edited: api::BookmarkRecord = decode(&vector("legacy-label-edit"));
        assert!(edited.bookmarked_at.is_none());
        assert_eq!(
            edited.updated_at.expect("known update").seconds,
            1_780_000_004
        );
        let epoch: api::BookmarkRecord = decode(&vector("epoch-known"));
        assert_eq!(epoch.bookmarked_at.expect("known epoch").seconds, 0);
    }

    #[test]
    fn exact_revision_kind_provenance_and_hidden_path_redaction_match() {
        for (name, kind, source) in [
            ("recorded-file", 1, 1),
            ("recorded-directory", 2, 1),
            ("derived-extensionless-file", 1, 2),
            ("derived-dotted-directory", 2, 2),
            ("authorized-missing", 0, 2),
            ("source-legacy", 0, 0),
            ("unknown-future-enums", 77, 88),
            ("missing-no-guess", 0, 2),
            ("unavailable-revision", 0, 0),
        ] {
            let anchor: api::SourceAnchor = decode(&vector(name));
            assert_eq!((anchor.path_kind, anchor.path_kind_source), (kind, source));
        }
        let historical: api::SourceAnchor = decode(&vector("historical-file"));
        let newer: api::SourceAnchor = decode(&vector("new-revision-directory"));
        assert_eq!((historical.path_kind, newer.path_kind), (1, 2));
        assert_ne!(historical.revision, newer.revision);
        for name in [
            "hidden-file",
            "hidden-directory",
            "hidden-missing",
            "hidden-recorded",
        ] {
            assert_eq!(vector(name)["wire_hex"], "");
            let anchor: api::SourceAnchor = decode(&vector(name));
            assert_eq!(anchor, api::SourceAnchor::default());
        }
        for (name, kind) in [
            ("location-file", 1),
            ("location-directory", 2),
            ("location-unknown", 0),
        ] {
            let location: api::SourceLocation = decode(&vector(name));
            assert_eq!(location.path_kind, kind);
        }
    }

    // Independent minimal MessagePack writer for these canonical source/wrapper
    // fixtures, not a production collaboration decoder or native admission test.
    fn string(value: &str) -> Vec<u8> {
        let len = u8::try_from(value.len()).expect("fixture string fits str8");
        let mut result = if len < 32 {
            vec![0xa0 | len]
        } else {
            vec![0xd9, len]
        };
        result.extend_from_slice(value.as_bytes());
        result
    }
    fn map(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
        assert!(fields.len() < 16);
        let mut result = vec![0x80 | fields.len() as u8];
        for (key, value) in fields {
            result.extend(string(key));
            result.extend(value);
        }
        result
    }
    fn byte_array(value: &[u8]) -> Vec<u8> {
        let len = value.len();
        let mut result = if len < 16 {
            vec![0x90 | len as u8]
        } else {
            let n = u16::try_from(len).expect("fixture array fits array16");
            vec![0xdc, (n >> 8) as u8, n as u8]
        };
        for byte in value {
            if *byte > 127 {
                result.push(0xcc);
            }
            result.push(*byte);
        }
        result
    }
    fn canonical_source(v: &Value) -> Vec<u8> {
        let revision = map(&[
            ("kind", string("git_commit")),
            ("oid", string(&"a".repeat(40))),
        ]);
        let mut fields = vec![
            ("revision", revision),
            ("path", string(v["path"].as_str().expect("path"))),
            ("symbol_id", string("")),
            ("start_line", vec![0xc0]),
            ("end_line", vec![0xc0]),
        ];
        if v["carrier"] == "context-target" {
            fields.push((
                "target",
                map(&[
                    ("target", byte_array(&[6; 32])),
                    ("binding", map(&[("kind", string("viewed_thread"))])),
                ]),
            ));
        }
        if let Some(kind) = v["kind"].as_str() {
            fields.push(("path_kind", string(kind)));
        }
        map(&fields)
    }

    #[test]
    fn independent_rust_canonical_source_and_outer_signature_match_ts_vectors() {
        let fixture = fixture();
        let vectors = fixture["signed"].as_array().expect("signed vectors");
        assert_eq!(vectors.len(), 12);
        let public = SigningKey::from_bytes(&[7; 32]).verifying_key();
        for v in vectors {
            let source = canonical_source(v);
            assert_eq!(source, bytes(&v["source_hex"]), "{}", v["name"]);
            let inner = bytes(&v["inner_hex"]);
            assert!(inner.windows(source.len()).any(|part| part == source));
            let carrier = if v["carrier"] == "discussion" {
                "discussion"
            } else {
                "context"
            };
            let canonical = map(&[
                ("version", vec![1]),
                ("thread", byte_array(&[2; 32])),
                ("parents", vec![0x90]),
                ("publisher", byte_array(&public.to_bytes())),
                (
                    "body",
                    map(&[("kind", string(carrier)), ("canonical", byte_array(&inner))]),
                ),
            ]);
            assert_eq!(canonical, bytes(&v["canonical_hex"]));
            assert_eq!(public.to_bytes().as_slice(), bytes(&v["public_key_hex"]));
            let signature = Signature::from_slice(&bytes(&v["signature_hex"])).expect("signature");
            let mut signed = b"heddle-thread-operation-v1\0".to_vec();
            signed.extend(&canonical);
            public
                .verify_strict(&signed, &signature)
                .expect("independent Rust verification");
            signed.pop();
            assert!(
                public.verify_strict(&signed, &signature).is_err(),
                "altered signed bytes must fail"
            );
        }
    }
}
