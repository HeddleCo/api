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

mod wire {
    use heddle_api::heddle::api::{common as shared, v1alpha2 as api};
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage};
    use serde_json::Value;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("fixtures/cleanup-lane-v1.json"))
            .expect("shared cleanup wire vectors")
    }

    fn bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().expect("wire hex")).expect("valid vector bytes")
    }

    fn decode<T: Message + Default>(vector: &Value) -> T {
        let wire = bytes(&vector["wire_hex"]);
        let value = T::decode(wire.as_slice()).expect("TS vector decodes in Rust");
        assert_eq!(value.encode_to_vec(), wire, "Rust wire matches TS vector");
        value
    }

    fn vector(fixture: &Value, kind: &str, name: &str) -> Value {
        fixture["vectors"]
            .as_array()
            .expect("vectors")
            .iter()
            .find(|v| v["type"] == kind && v["name"] == name)
            .expect("named shared vector")
            .clone()
    }

    #[test]
    fn exact_revision_paths_keep_prefix_bounds_and_terminal_pagination() {
        let fixture = fixture();
        let request: api::ListPathsRequest =
            decode(&vector(&fixture, "ListPathsRequest", "prefix-page"));
        assert_eq!(request.prefix, "src/");
        let revision = request.revision.expect("exact revision");
        assert_eq!(
            revision.revision,
            Some(api::revision_ref::Revision::GitCommitOid("a".repeat(40)))
        );
        assert_eq!(revision.spool, request.thread.expect("owning Thread").spool);
        let page = request.page.expect("page");
        assert_eq!(page.size, 4096);
        assert_eq!(page.after_page, [7, 8]);
        assert_eq!(
            request.budget.expect("finite budget").max_snapshot_bytes,
            16_777_216
        );
        let root: api::ListPathsRequest =
            decode(&vector(&fixture, "ListPathsRequest", "root-defaults"));
        assert!(root.prefix.is_empty() && root.page.is_none());
        assert!(matches!(
            root.revision.expect("native revision").revision,
            Some(api::revision_ref::Revision::State(_))
        ));
        let deep: api::ListPathsEvent = decode(&vector(&fixture, "ListPathsEvent", "deep-leaf"));
        assert_eq!(
            deep.payload,
            Some(api::list_paths_event::Payload::Path(
                "nested/".repeat(65) + "file.ts"
            ))
        );
        for (name, exhausted) in [("more", false), ("exhausted", true)] {
            let event: api::ListPathsEvent = decode(&vector(&fixture, "ListPathsEvent", name));
            let Some(api::list_paths_event::Payload::Complete(status)) = event.payload else {
                panic!("terminal status");
            };
            assert_eq!(status.section, "paths");
            assert_eq!(status.coverage, 1);
            assert_eq!(status.computed_for, Some(revision.clone()));
            let page = status.page.expect("pagination independent of coverage");
            assert_eq!(page.exhausted, exhausted);
            assert_eq!(page.next_page, if exhausted { vec![] } else { vec![8] });
            assert_eq!(page.matching_count, exhausted.then_some(0));
        }
        let unavailable: api::ListPathsEvent =
            decode(&vector(&fixture, "ListPathsEvent", "unavailable"));
        let Some(api::list_paths_event::Payload::Complete(status)) = unavailable.payload else {
            panic!("status");
        };
        assert_eq!(status.coverage, 3);
        assert!(status.page.is_none());
    }

    #[test]
    fn readable_ancestry_is_ordered_with_an_actual_parent() {
        let fixture = fixture();
        let nested: api::SpoolOverview = decode(&vector(&fixture, "SpoolOverview", "nested"));
        assert_eq!(
            nested
                .ancestors
                .iter()
                .map(|a| a.r#ref.as_ref().expect("readable ID").id.as_str())
                .collect::<Vec<_>>(),
            ["root", "parent"]
        );
        assert_eq!(nested.ancestors[0].path_segments, ["team"]);
        assert_eq!(nested.ancestors[1].path_segments, ["team", "project"]);
        assert_eq!(nested.parent, nested.ancestors[1].r#ref);
        let subsequence: api::SpoolOverview =
            decode(&vector(&fixture, "SpoolOverview", "visible-subsequence"));
        assert_eq!(subsequence.ancestors.len(), 1);
        assert_eq!(subsequence.parent, subsequence.ancestors[0].r#ref);
        let root: api::SpoolOverview = decode(&vector(&fixture, "SpoolOverview", "root"));
        assert!(root.parent.is_none() && root.ancestors.is_empty());
    }

    #[test]
    fn collaboration_names_are_live_while_history_keeps_existing_claims() {
        let fixture = fixture();
        let context: api::ContextRecord = decode(&vector(&fixture, "ContextRecord", "live-author"));
        let turn: api::DiscussionTurn = decode(&vector(&fixture, "DiscussionTurn", "live-author"));
        assert_eq!(context.author_display_name, "Renamed Author");
        assert_eq!(turn.author_display_name, context.author_display_name);
        assert_eq!(context.principal_id, "principal-a");
        assert_eq!(turn.principal_id, context.principal_id);
        assert_eq!(context.agent_id, "agent-a");
        assert_eq!(turn.agent_id, context.agent_id);
        assert_eq!(context.causal_id, [11]);
        assert_eq!(turn.causal_id, [12]);
        let imported: api::ContextRecord =
            decode(&vector(&fixture, "ContextRecord", "unresolved-import"));
        assert!(imported.author_display_name.is_empty());
        assert_eq!(imported.principal_id, "gh:luke");
        let missing: api::DiscussionTurn =
            decode(&vector(&fixture, "DiscussionTurn", "unresolved"));
        assert!(missing.author_display_name.is_empty());
        let history: api::CaptureSummary =
            decode(&vector(&fixture, "CaptureSummary", "snapshot-author"));
        assert_eq!(history.principal_name, "Original claimed name");
        assert_eq!(history.attribution_assurance, 1);
        assert!(history.principal_id.is_empty());
    }

    #[test]
    fn provider_refs_defaults_caps_and_readiness_match_shared_vectors() {
        let fixture = fixture();
        let repository: api::ProviderRepository =
            decode(&vector(&fixture, "ProviderRepository", "refs-page"));
        assert_eq!(repository.default_branch, "main");
        assert!(repository.private);
        assert_eq!(repository.linked_spools[0].id, "spool-a");
        assert_eq!(
            repository
                .refs
                .iter()
                .map(|r| (r.name.as_str(), r.kind, r.head_oid.clone()))
                .collect::<Vec<_>>(),
            [
                ("refs/heads/main", 1, "b".repeat(40)),
                ("refs/tags/v1", 2, "c".repeat(40)),
            ]
        );
        let page = repository
            .refs_status
            .expect("requested readiness")
            .page
            .expect("ref window");
        assert!(!page.exhausted);
        assert_eq!(page.next_page, [9]);
        let empty: api::ProviderRepository =
            decode(&vector(&fixture, "ProviderRepository", "known-empty"));
        assert!(empty.refs.is_empty());
        let status = empty.refs_status.expect("known empty");
        assert_eq!(status.coverage, 1);
        assert!(status.page.expect("exhaustion").exhausted);
        let unavailable: api::ProviderRepository =
            decode(&vector(&fixture, "ProviderRepository", "unavailable"));
        assert_eq!(
            unavailable
                .refs_status
                .expect("unavailable status")
                .coverage,
            3
        );
        let unrequested: api::ProviderRepository =
            decode(&vector(&fixture, "ProviderRepository", "unrequested"));
        assert!(unrequested.refs_status.is_none() && unrequested.default_branch.is_empty());
        for kind in [0, 99] {
            let reference: api::ProviderRef =
                decode(&vector(&fixture, "ProviderRef", &format!("kind-{kind}")));
            assert_eq!(reference.kind, kind);
        }
        assert!(api::provider_ref::Kind::try_from(99).is_err());
        let request: api::ObserveIntegrationsRequest = decode(&vector(
            &fixture,
            "ObserveIntegrationsRequest",
            "refs-selectors-at-cap",
        ));
        assert!(request.include_repositories);
        assert_eq!(request.include_refs_for.len(), 8);
        assert_eq!(
            request
                .include_refs_for
                .iter()
                .map(|r| r.page.as_ref().expect("bounded page").size)
                .sum::<u32>(),
            4096
        );
        let older: api::ObserveIntegrationsRequest = decode(&vector(
            &fixture,
            "ObserveIntegrationsRequest",
            "older-inventory",
        ));
        assert!(older.include_refs_for.is_empty());
    }

    #[test]
    fn capability_codes_preserve_unknown_without_a_permission_default() {
        let fixture = fixture();
        for capability in [0, 1, 2, 3, 4, 5, 99] {
            let action: api::ActionAvailability = decode(&vector(
                &fixture,
                "ActionAvailability",
                &format!("capability-{capability}"),
            ));
            assert_eq!(action.capability, capability);
            assert!(action.implemented && action.authorized);
        }
        assert_eq!(
            api::ActionAvailability::default().capability,
            api::Capability::Unspecified as i32
        );
        assert!(api::Capability::try_from(99).is_err());
    }

    #[test]
    fn typed_refusal_survives_blocked_receipts_and_existing_failure_carriers() {
        let fixture = fixture();
        for reason in [0, 202, 203, 601, 9999] {
            let blocked: api::Blocked =
                decode(&vector(&fixture, "Blocked", &format!("reason-{reason}")));
            let error = blocked.error.as_ref().expect("typed reason");
            assert_eq!(error.reason, reason);
            assert!(error.resource.is_empty() && error.context.is_none());
            assert_eq!(blocked.requirements[0].kind, 1);
            let receipt: api::MutationReceipt = decode(&vector(
                &fixture,
                "MutationReceipt",
                &format!("blocked-{reason}"),
            ));
            assert_eq!(
                receipt.outcome,
                Some(api::mutation_receipt::Outcome::Blocked(blocked))
            );
            let failure: shared::CallFailure = decode(&vector(
                &fixture,
                "CallFailure",
                &format!("refused-{reason}"),
            ));
            assert_eq!(failure.error.expect("existing call detail").reason, reason);
        }
        let older: api::Blocked = decode(&vector(&fixture, "Blocked", "older-refusal"));
        assert!(older.error.is_none());
        let hidden: shared::CallFailure =
            decode(&vector(&fixture, "CallFailure", "existence-hiding"));
        assert_eq!(hidden.code, 5);
        let error = hidden.error.expect("generic existence detail");
        assert_eq!(error.reason, 300);
        assert!(error.resource.is_empty() && error.field.is_empty() && error.context.is_none());
    }

    #[test]
    fn readable_labels_and_lifecycle_preserve_empty_and_unknown_values() {
        let fixture = fixture();
        let hit: api::SearchHit = decode(&vector(&fixture, "SearchHit", "readable-labels"));
        assert_eq!(hit.thread_name, "Feature");
        assert_eq!(hit.spool_path, ["team", "api"]);
        let omitted: api::SearchHit =
            decode(&vector(&fixture, "SearchHit", "older-or-withheld-labels"));
        assert!(omitted.thread_name.is_empty() && omitted.spool_path.is_empty());
        assert_eq!(omitted.thread, hit.thread);
        for lifecycle in [0, 2, 4, 99] {
            let relationship: api::ThreadRelationship = decode(&vector(
                &fixture,
                "ThreadRelationship",
                &format!("lifecycle-{lifecycle}"),
            ));
            assert_eq!(relationship.lifecycle, lifecycle);
            assert_eq!(
                relationship.name,
                if lifecycle == 0 { "" } else { "Target" }
            );
        }
        assert!(api::ThreadLifecycle::try_from(99).is_err());
    }

    #[test]
    fn frozen_alpha15_readers_keep_every_old_field_and_new_readers_accept_them() {
        let fixture = fixture();
        let old = DescriptorPool::decode(
            include_bytes!("fixtures/cleanup-lane-alpha15.binpb").as_slice(),
        )
        .expect("frozen alpha.15 descriptor");
        for vector in fixture["vectors"].as_array().expect("shared vectors") {
            let kind = vector["type"].as_str().expect("message type");
            macro_rules! round_trip {
                ($type:ty) => {{
                    let _: $type = decode(vector);
                }};
            }
            match kind {
                "ListPathsRequest" => round_trip!(api::ListPathsRequest),
                "ListPathsEvent" => round_trip!(api::ListPathsEvent),
                "SpoolOverview" => round_trip!(api::SpoolOverview),
                "ContextRecord" => round_trip!(api::ContextRecord),
                "DiscussionTurn" => round_trip!(api::DiscussionTurn),
                "CaptureSummary" => round_trip!(api::CaptureSummary),
                "ProviderRepository" => round_trip!(api::ProviderRepository),
                "ProviderRef" => round_trip!(api::ProviderRef),
                "ObserveIntegrationsRequest" => round_trip!(api::ObserveIntegrationsRequest),
                "ActionAvailability" => round_trip!(api::ActionAvailability),
                "Blocked" => round_trip!(api::Blocked),
                "MutationReceipt" => round_trip!(api::MutationReceipt),
                "CallFailure" => round_trip!(shared::CallFailure),
                "SearchHit" => round_trip!(api::SearchHit),
                "ThreadRelationship" => round_trip!(api::ThreadRelationship),
                _ => panic!("uncovered shared vector type: {kind}"),
            }
            let Some(legacy_hex) = vector.get("legacy_wire_hex") else {
                continue;
            };
            let package = if kind == "CallFailure" {
                "common"
            } else {
                "v1alpha2"
            };
            let descriptor = old
                .get_message_by_name(&format!("heddle.api.{package}.{kind}"))
                .expect("original message");
            let mut legacy =
                DynamicMessage::decode(descriptor, bytes(&vector["wire_hex"]).as_slice())
                    .expect("old reader");
            legacy.take_unknown_fields().for_each(drop);
            // Nested Blocked also needs its unknown field removed, exactly as
            // generated alpha.15 prost readers do at every message boundary.
            if kind == "MutationReceipt" {
                let mut blocked = legacy
                    .get_field_by_name("blocked")
                    .expect("old blocked outcome")
                    .into_owned();
                if let prost_reflect::Value::Message(ref mut message) = blocked {
                    message.take_unknown_fields().for_each(drop);
                }
                legacy.set_field_by_name("blocked", blocked);
            }
            let old_wire = bytes(legacy_hex);
            assert_eq!(
                legacy.encode_to_vec(),
                old_wire,
                "all original fields: {kind}/{}",
                vector["name"]
            );
            macro_rules! reread {
                ($type:ty) => {
                    <$type>::decode(old_wire.as_slice()).expect("new reader accepts original wire")
                };
            }
            match kind {
                "SpoolOverview" => assert!(reread!(api::SpoolOverview).ancestors.is_empty()),
                "ContextRecord" => {
                    assert!(reread!(api::ContextRecord).author_display_name.is_empty())
                }
                "DiscussionTurn" => {
                    assert!(reread!(api::DiscussionTurn).author_display_name.is_empty())
                }
                "ProviderRepository" => {
                    let v = reread!(api::ProviderRepository);
                    assert!(
                        v.default_branch.is_empty() && v.refs.is_empty() && v.refs_status.is_none()
                    );
                }
                "ObserveIntegrationsRequest" => assert!(
                    reread!(api::ObserveIntegrationsRequest)
                        .include_refs_for
                        .is_empty()
                ),
                "ActionAvailability" => assert_eq!(reread!(api::ActionAvailability).capability, 0),
                "Blocked" => assert!(reread!(api::Blocked).error.is_none()),
                "MutationReceipt" => {
                    let Some(api::mutation_receipt::Outcome::Blocked(v)) =
                        reread!(api::MutationReceipt).outcome
                    else {
                        panic!("original blocked outcome");
                    };
                    assert!(v.error.is_none());
                }
                "SearchHit" => {
                    let v = reread!(api::SearchHit);
                    assert!(v.thread_name.is_empty() && v.spool_path.is_empty());
                }
                "ThreadRelationship" => {
                    let v = reread!(api::ThreadRelationship);
                    assert!(v.name.is_empty());
                    assert_eq!(v.lifecycle, 0);
                }
                "CallFailure" => assert_eq!(
                    reread!(shared::CallFailure).error,
                    decode::<shared::CallFailure>(vector).error
                ),
                "CaptureSummary" => {
                    let _: api::CaptureSummary = reread!(api::CaptureSummary);
                }
                _ => panic!("unexpected original message: {kind}"),
            }
        }
    }
}
