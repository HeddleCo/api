#[cfg(feature = "reflection")]
mod descriptor {
    use heddle_api::FILE_DESCRIPTOR_SET;
    use prost_reflect::{DescriptorPool, Kind};

    fn pool() -> DescriptorPool {
        DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor")
    }

    fn field(message: &str, name: &str, tag: u32, kind: Kind, list: bool) {
        let message = pool()
            .get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
            .expect("contract message");
        let field = message.get_field_by_name(name).expect("cleanup field");
        assert_eq!(field.number(), tag);
        match (field.kind(), kind) {
            (Kind::Message(actual), Kind::Message(expected)) => {
                assert_eq!(actual.full_name(), expected.full_name());
            }
            (Kind::Enum(actual), Kind::Enum(expected)) => {
                assert_eq!(actual.full_name(), expected.full_name());
            }
            (actual, expected) => assert_eq!(actual, expected),
        }
        assert_eq!(field.is_list(), list);
    }

    fn message(name: &str) -> Kind {
        Kind::Message(pool().get_message_by_name(name).expect("typed message"))
    }

    #[test]
    fn c1_exact_revision_paths_have_content_read_authorization() {
        let rpc =
            heddle_api::v2::method_descriptor("/heddle.api.v1alpha2.ContentService/ListPaths")
                .expect("bounded path listing RPC");
        let read =
            heddle_api::v2::method_descriptor("/heddle.api.v1alpha2.ContentService/ReadContent")
                .expect("existing read");
        assert_eq!(rpc.authorization, read.authorization);
        assert_eq!(rpc.signing_tier, read.signing_tier);
        assert_eq!(rpc.effect, read.effect);
        assert_eq!(rpc.retry_behavior, read.retry_behavior);
        assert_eq!(rpc.streaming, read.streaming);
        for (name, tag, target) in [
            ("revision", 1, "RevisionRef"),
            ("thread", 2, "ThreadRef"),
            ("page", 4, "PageRequest"),
            ("budget", 5, "ReadBudget"),
        ] {
            field(
                "ListPathsRequest",
                name,
                tag,
                message(&format!("heddle.api.v1alpha2.{target}")),
                false,
            );
        }
        field("ListPathsRequest", "prefix", 3, Kind::String, false);
        field("ListPathsEvent", "path", 2, Kind::String, false);
        field(
            "ListPathsEvent",
            "complete",
            3,
            message("heddle.api.v1alpha2.SectionStatus"),
            false,
        );
        let event = pool()
            .get_message_by_name("heddle.api.v1alpha2.ListPathsEvent")
            .expect("event");
        assert_eq!(
            event
                .get_field_by_name("path")
                .expect("path")
                .containing_oneof(),
            event
                .get_field_by_name("complete")
                .expect("completion")
                .containing_oneof()
        );
    }

    #[test]
    fn c2_ancestors_reuse_addresses_and_parent() {
        field(
            "SpoolOverview",
            "parent",
            2,
            message("heddle.api.v1alpha2.SpoolRef"),
            false,
        );
        field(
            "SpoolOverview",
            "ancestors",
            19,
            message("heddle.api.v1alpha2.SpoolAddress"),
            true,
        );
    }

    #[test]
    fn c4_display_names_do_not_duplicate_existing_history_attribution() {
        field(
            "ContextRecord",
            "author_display_name",
            15,
            Kind::String,
            false,
        );
        field(
            "DiscussionTurn",
            "author_display_name",
            10,
            Kind::String,
            false,
        );
        field("CaptureSummary", "principal_name", 11, Kind::String, false);
        field("CaptureSummary", "principal_email", 12, Kind::String, false);
    }

    #[test]
    fn c6_provider_refs_are_opt_in_and_paged() {
        field(
            "ProviderRepository",
            "default_branch",
            8,
            Kind::String,
            false,
        );
        field(
            "ProviderRepository",
            "refs",
            9,
            message("heddle.api.v1alpha2.ProviderRef"),
            true,
        );
        field(
            "ProviderRepository",
            "refs_status",
            10,
            message("heddle.api.v1alpha2.SectionStatus"),
            false,
        );
        field(
            "ObserveIntegrationsRequest",
            "include_refs_for",
            6,
            message("heddle.api.v1alpha2.ProviderRefsRequest"),
            true,
        );
        field(
            "ProviderRefsRequest",
            "connection",
            1,
            message("heddle.api.v1alpha2.RecordRef"),
            false,
        );
        field(
            "ProviderRefsRequest",
            "provider_repository_id",
            2,
            Kind::String,
            false,
        );
        field(
            "ProviderRefsRequest",
            "page",
            3,
            message("heddle.api.v1alpha2.PageRequest"),
            false,
        );
        field("ProviderRef", "name", 1, Kind::String, false);
        field("ProviderRef", "head_oid", 2, Kind::String, false);
        let kind = pool()
            .get_enum_by_name("heddle.api.v1alpha2.ProviderRef.Kind")
            .expect("ref kind");
        assert_eq!(
            kind.values()
                .map(|v| (v.name().to_owned(), v.number()))
                .collect::<Vec<_>>(),
            [
                ("KIND_UNSPECIFIED".into(), 0),
                ("KIND_BRANCH".into(), 1),
                ("KIND_TAG".into(), 2)
            ]
        );
        field("ProviderRef", "kind", 3, Kind::Enum(kind), false);
    }

    #[test]
    fn c7_capabilities_and_refusals_have_stable_typed_codes() {
        let capability = pool()
            .get_enum_by_name("heddle.api.v1alpha2.Capability")
            .expect("stable capability enum");
        assert_eq!(
            capability
                .values()
                .map(|v| (v.name().to_owned(), v.number()))
                .collect::<Vec<_>>(),
            [
                ("CAPABILITY_UNSPECIFIED".into(), 0),
                ("CAPABILITY_RECORD_REVIEW".into(), 1),
                ("CAPABILITY_LAND".into(), 2),
                ("CAPABILITY_PUT_GRANT".into(), 3),
                ("CAPABILITY_CREATE_INVITATION".into(), 4),
                ("CAPABILITY_REVISE_SPOOL".into(), 5),
            ]
        );
        field(
            "ActionAvailability",
            "capability",
            8,
            Kind::Enum(capability),
            false,
        );
        field(
            "Blocked",
            "error",
            2,
            message("heddle.api.common.ErrorDetail"),
            false,
        );
        let failure = pool()
            .get_message_by_name("heddle.api.common.CallFailure")
            .expect("existing refusal");
        assert_eq!(
            failure
                .get_field_by_name("error")
                .expect("existing detail")
                .number(),
            4
        );
    }

    #[test]
    fn c8_search_labels_are_additive() {
        field("SearchHit", "thread_name", 10, Kind::String, false);
        field("SearchHit", "spool_path", 11, Kind::String, true);
    }

    #[test]
    fn c9_relationships_reuse_lifecycle() {
        field("ThreadRelationship", "name", 3, Kind::String, false);
        field(
            "ThreadRelationship",
            "lifecycle",
            4,
            Kind::Enum(
                pool()
                    .get_enum_by_name("heddle.api.v1alpha2.ThreadLifecycle")
                    .expect("lifecycle"),
            ),
            false,
        );
    }
}
