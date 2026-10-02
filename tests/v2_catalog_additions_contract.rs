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
        match (field.kind(), kind) {
            (Kind::Message(actual), Kind::Message(expected)) => {
                assert_eq!(actual.full_name(), expected.full_name());
                assert_eq!(field.supports_presence(), !list);
            }
            (actual, expected) => assert_eq!(actual, expected),
        }
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

mod wire {
    use heddle_api::heddle::api::v1alpha2 as api;
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage};
    use serde_json::Value;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("fixtures/catalog-additions-v1.json"))
            .expect("shared catalog vectors")
    }

    fn vector(fixture: &Value, name: &str) -> Value {
        fixture["vectors"]
            .as_array()
            .expect("vectors")
            .iter()
            .find(|v| v["name"] == name)
            .expect("named vector")
            .clone()
    }

    fn bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().expect("wire hex")).expect("valid wire hex")
    }

    fn decode<T: Message + Default>(vector: &Value) -> T {
        let wire = bytes(&vector["wire_hex"]);
        let result = T::decode(wire.as_slice()).expect("TS vector decodes in Rust");
        assert_eq!(result.encode_to_vec(), wire, "shared Rust/TS wire");
        result
    }

    fn summary(fixture: &Value, name: &str) -> api::CatalogSummary {
        let event: api::CatalogEvent = decode(&vector(fixture, name));
        let Some(api::catalog_event::Payload::Summary(summary)) = event.payload else {
            panic!("summary payload");
        };
        summary
    }

    #[test]
    fn every_shared_vector_round_trips_in_rust() {
        let fixture = fixture();
        let vectors = fixture["vectors"].as_array().expect("vectors");
        assert_eq!(vectors.len(), 18);
        for vector in vectors {
            match vector["type"].as_str().expect("type") {
                "ObserveCatalogRequest" => {
                    let _: api::ObserveCatalogRequest = decode(vector);
                }
                "CatalogEvent" => {
                    let _: api::CatalogEvent = decode(vector);
                }
                other => panic!("uncovered vector: {other}"),
            }
        }
    }

    #[test]
    fn filters_preserve_defaults_predicates_and_token_binding_inputs() {
        let fixture = fixture();
        let absent: api::ObserveCatalogRequest = decode(&vector(&fixture, "absent"));
        assert!(absent.filter.is_none());
        let empty: api::ObserveCatalogRequest = decode(&vector(&fixture, "empty"));
        assert_eq!(empty.filter, Some(api::CatalogFilter::default()));
        let prefix: api::ObserveCatalogRequest = decode(&vector(&fixture, "prefix"));
        assert_eq!(
            prefix.filter.expect("prefix").namespace_prefix,
            ["HeddleCo", "Weft"]
        );
        for (name, index) in [("open", 0), ("landed", 1), ("review", 2)] {
            let request: api::ObserveCatalogRequest = decode(&vector(&fixture, name));
            let filter = request.filter.expect("one predicate");
            let mut expected = [false; 3];
            expected[index] = true;
            assert_eq!(
                [
                    filter.has_open_threads,
                    filter.landed_within_30d,
                    filter.require_review_to_land
                ],
                expected
            );
        }
        let combined: api::ObserveCatalogRequest = decode(&vector(&fixture, "combined"));
        let filter = combined.filter.as_ref().expect("combined filter");
        assert!(
            filter.has_open_threads && filter.landed_within_30d && filter.require_review_to_land
        );
        assert_eq!(filter.namespace_prefix, ["heddleco"]);
        assert_eq!(combined.query, "HeddleCo/Weft");
        assert_eq!(combined.sort, api::CatalogSort::Path as i32);
        assert_eq!(combined.spools.as_ref().expect("page").size, 20);
        for name in ["changed-filter-same-token", "changed-query-same-token"] {
            let changed: api::ObserveCatalogRequest = decode(&vector(&fixture, name));
            assert_eq!(changed.spools, combined.spools);
            assert_ne!(
                changed, combined,
                "server must reject changed binding inputs"
            );
        }
    }

    #[test]
    fn filtered_pages_preserve_exact_counts_and_exhaustion() {
        let fixture = fixture();
        for (name, count, exhausted, token) in [
            ("filtered-more", 2, false, vec![9]),
            ("filtered-exhausted", 0, true, vec![]),
        ] {
            let event: api::CatalogEvent = decode(&vector(&fixture, name));
            let Some(api::catalog_event::Payload::Status(status)) = event.payload else {
                panic!("page status");
            };
            let page = status.page.expect("filtered page");
            assert_eq!(page.matching_count, Some(count));
            assert_eq!(page.exhausted, exhausted);
            assert_eq!(page.next_page, token);
        }
    }

    #[test]
    fn snapshots_have_linkable_leaders_empty_results_and_bounded_approximation() {
        let fixture = fixture();
        let exact = summary(&fixture, "exact");
        assert_eq!(
            [
                exact.spool_count,
                exact.open_thread_count,
                exact.landed_30d,
                exact.active_7d
            ],
            [2, 7, 9, 1]
        );
        assert!(!exact.approximate);
        assert_eq!(
            exact.as_of,
            Some(prost_types::Timestamp {
                seconds: 1_780_000_000,
                nanos: 123_456_789
            })
        );
        assert_eq!(
            exact
                .most_open
                .iter()
                .map(|l| l.r#ref.as_ref().expect("leader ID").id.as_str())
                .collect::<Vec<_>>(),
            ["spool-a", "spool-b"]
        );
        assert_eq!(exact.most_open[0].name, "spool-a");
        assert_eq!(exact.most_open[0].path_segments, ["heddleco", "spool-a"]);
        assert_eq!(
            exact
                .most_landed
                .iter()
                .map(|l| l.count)
                .collect::<Vec<_>>(),
            [7, 2]
        );
        let empty = summary(&fixture, "summary-empty");
        assert_eq!(
            [
                empty.spool_count,
                empty.open_thread_count,
                empty.landed_30d,
                empty.active_7d
            ],
            [0; 4]
        );
        assert!(empty.most_open.is_empty() && empty.most_landed.is_empty());
        assert!(empty.as_of.is_some());
        let bounded = summary(&fixture, "bounded-approximate");
        assert!(bounded.approximate);
        assert_eq!(bounded.spool_count, 10_001);
        for leaders in [&bounded.most_open, &bounded.most_landed] {
            assert_eq!(leaders.len(), 5);
            assert_eq!(
                leaders.iter().map(|l| l.count).collect::<Vec<_>>(),
                [5, 4, 3, 2, 1]
            );
            let ids: std::collections::BTreeSet<_> = leaders
                .iter()
                .map(|l| l.r#ref.as_ref().expect("leader ID").id.as_str())
                .collect();
            assert_eq!(ids.len(), leaders.len());
        }
    }

    #[test]
    fn summary_counts_preserve_uint64_precision() {
        let wide = summary(&fixture(), "wide-counters");
        assert_eq!(wide.spool_count, 9_007_199_254_740_993);
        assert_eq!(wide.open_thread_count, u64::MAX);
        assert_eq!(wide.landed_30d, 9_007_199_254_740_995);
    }

    #[test]
    fn private_spool_does_not_change_outsider_counts_or_leaders() {
        let fixture = fixture();
        let before = fixture["confidentiality"]["before"]
            .as_array()
            .expect("before projection");
        let after = fixture["confidentiality"]["after"]
            .as_array()
            .expect("after projection");
        assert_eq!(after.len(), before.len() + 1);
        let hidden = after.last().expect("private spool");
        assert_eq!(hidden["visible"], false);
        assert!(hidden["open"].as_u64().expect("open") > 7);
        assert!(hidden["landed"].as_u64().expect("landed") > 9);
        assert_eq!(
            vector(&fixture, "outsider-before-private")["wire_hex"],
            vector(&fixture, "outsider-after-private")["wire_hex"]
        );
        let projected = summary(&fixture, "outsider-after-private");
        assert_eq!(projected, summary(&fixture, "exact"));
        for leaders in [&projected.most_open, &projected.most_landed] {
            assert!(
                leaders
                    .iter()
                    .all(|l| l.r#ref.as_ref().expect("public ID").id
                        != hidden["id"].as_str().expect("hidden ID"))
            );
        }
    }

    #[test]
    fn frozen_alpha16_readers_keep_old_fields_and_skip_summary() {
        let fixture = fixture();
        let old = DescriptorPool::decode(
            include_bytes!("fixtures/catalog-additions-alpha16.binpb").as_slice(),
        )
        .expect("frozen original descriptor");
        for vector in fixture["vectors"].as_array().expect("vectors") {
            let kind = vector["type"].as_str().expect("type");
            let descriptor = old
                .get_message_by_name(&format!("heddle.api.v1alpha2.{kind}"))
                .expect("old message");
            let mut legacy =
                DynamicMessage::decode(descriptor, bytes(&vector["wire_hex"]).as_slice())
                    .expect("old reader");
            legacy.take_unknown_fields().for_each(drop);
            let legacy_wire = bytes(&vector["legacy_wire_hex"]);
            assert_eq!(
                legacy.encode_to_vec(),
                legacy_wire,
                "old fields: {}",
                vector["name"]
            );
            if kind == "ObserveCatalogRequest" {
                let mut current: api::ObserveCatalogRequest = decode(vector);
                current.filter = None;
                let reread = api::ObserveCatalogRequest::decode(legacy_wire.as_slice())
                    .expect("new request reader");
                assert_eq!(reread, current);
            } else {
                let current: api::CatalogEvent = decode(vector);
                let reread =
                    api::CatalogEvent::decode(legacy_wire.as_slice()).expect("new event reader");
                assert_eq!(reread.frame, current.frame);
                if matches!(
                    current.payload,
                    Some(api::catalog_event::Payload::Summary(_))
                ) {
                    assert!(reread.payload.is_none());
                } else {
                    assert_eq!(reread, current);
                }
            }
        }
    }
}
