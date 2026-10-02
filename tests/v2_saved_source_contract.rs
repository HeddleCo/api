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
