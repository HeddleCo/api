#[cfg(feature = "reflection")]
mod descriptor {
    use prost_reflect::{DescriptorPool, Kind};

    fn pool() -> DescriptorPool {
        DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("compiled descriptor")
    }

    fn field(message: &str, name: &str, tag: u32, kind: Kind, list: bool) {
        let descriptor = pool()
            .get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
            .expect("catalog message");
        let field = descriptor
            .get_field_by_name(name)
            .expect("additive catalog field");
        assert_eq!(field.number(), tag);
        assert_eq!(field.kind(), kind);
        assert_eq!(field.is_list(), list);
    }

    fn message(name: &str) -> Kind {
        Kind::Message(
            pool()
                .get_message_by_name(name)
                .expect("typed catalog message"),
        )
    }

    #[test]
    fn filter_is_additive_and_uses_segment_prefixes() {
        field(
            "ObserveCatalogRequest",
            "filter",
            5,
            message("heddle.api.v1alpha2.CatalogFilter"),
            false,
        );
        for (name, tag) in [
            ("has_open_threads", 1),
            ("landed_within_30d", 2),
            ("require_review_to_land", 3),
        ] {
            field("CatalogFilter", name, tag, Kind::Bool, false);
        }
        field("CatalogFilter", "namespace_prefix", 4, Kind::String, true);
    }

    #[test]
    fn summary_has_counts_freshness_and_bounded_leader_shape() {
        for (name, tag) in [
            ("spool_count", 1),
            ("open_thread_count", 2),
            ("landed_30d", 3),
            ("active_7d", 4),
        ] {
            field("CatalogSummary", name, tag, Kind::Uint64, false);
        }
        for (name, tag) in [("most_open", 5), ("most_landed", 6)] {
            field(
                "CatalogSummary",
                name,
                tag,
                message("heddle.api.v1alpha2.CatalogLeader"),
                true,
            );
        }
        field(
            "CatalogSummary",
            "as_of",
            7,
            message("google.protobuf.Timestamp"),
            false,
        );
        field("CatalogSummary", "approximate", 8, Kind::Bool, false);
        field(
            "CatalogLeader",
            "ref",
            1,
            message("heddle.api.v1alpha2.SpoolRef"),
            false,
        );
        field("CatalogLeader", "name", 2, Kind::String, false);
        field("CatalogLeader", "path_segments", 3, Kind::String, true);
        field("CatalogLeader", "count", 4, Kind::Uint64, false);
    }

    #[test]
    fn summary_is_an_independent_catalog_payload() {
        field(
            "CatalogEvent",
            "summary",
            6,
            message("heddle.api.v1alpha2.CatalogSummary"),
            false,
        );
        let event = pool()
            .get_message_by_name("heddle.api.v1alpha2.CatalogEvent")
            .expect("catalog event");
        assert_eq!(
            event
                .get_field_by_name("summary")
                .expect("summary")
                .containing_oneof(),
            event
                .get_field_by_name("spool")
                .expect("row")
                .containing_oneof()
        );
        for (name, tag) in [
            ("frame", 1),
            ("spool", 2),
            ("status", 3),
            ("removal", 4),
            ("replace_section", 5),
        ] {
            assert_eq!(
                event
                    .get_field_by_name(name)
                    .expect("existing field")
                    .number(),
                tag
            );
        }
    }
}
