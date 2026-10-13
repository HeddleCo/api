use heddle_api::heddle::api::{common, v1alpha2 as api};
use heddle_api::v2::content::{
    validate_outline_read, validate_outline_status, validate_outline_symbol,
};
use prost::Message;
#[test]
fn paged_outline_rows_preserve_revision_and_have_explicit_coverage() {
    let read = api::OutlineRead {
        path: "src/main.rs".into(),
        page: Some(api::PageRequest {
            size: 100,
            after_page: vec![],
        }),
    };
    validate_outline_read(&read, Some(&peer())).expect("bounded selection");
    let selection = api::ContentRead {
        selection_id: "outline".into(),
        selection: Some(api::content_read::Selection::Outline(read)),
    };
    assert_eq!(
        api::ContentRead::decode(selection.encode_to_vec().as_slice()).expect("decode"),
        selection
    );
    let symbol = api::OutlineSymbol {
        name: "run".into(),
        kind: common::SymbolKind::Function as i32,
        container: "App".into(),
        symbol_id: "App::run".into(),
        start_line: 12,
        end_line: 18,
    };
    validate_outline_symbol(&symbol).expect("symbol");
    let revision = api::RevisionRef {
        spool: Some(api::SpoolRef {
            id: "00000000-0000-0000-0000-000000000001".into(),
        }),
        revision: Some(api::revision_ref::Revision::GitCommitOid("a".repeat(40))),
    };
    let event = api::ContentEvent {
        selection_id: "outline".into(),
        revision: Some(revision.clone()),
        payload: Some(api::content_event::Payload::OutlineSymbol(symbol)),
    };
    assert_eq!(
        api::ContentEvent::decode(event.encode_to_vec().as_slice()).expect("decode"),
        event
    );
    for coverage in [
        api::Coverage::Complete,
        api::Coverage::Partial,
        api::Coverage::Unavailable,
    ] {
        let status = api::SectionStatus {
            section: "outline".into(),
            computed_for: Some(revision.clone()),
            coverage: coverage as i32,
            page: Some(api::PageInfo {
                exhausted: coverage == api::Coverage::Unavailable,
                next_page: if coverage == api::Coverage::Unavailable {
                    vec![]
                } else {
                    vec![1]
                },
                matching_count: None,
            }),
            reason: if coverage == api::Coverage::Complete {
                0
            } else {
                api::SectionStatusReason::CoverageIncomplete as i32
            },
            ..Default::default()
        };
        validate_outline_status(&status).expect("complete page is independent of exhaustion");
        let mut missing = status.clone();
        missing.page = None;
        assert!(validate_outline_status(&missing).is_err());
        if coverage != api::Coverage::Complete {
            let mut misleading = status;
            misleading.reason = 0;
            assert!(validate_outline_status(&misleading).is_err());
        }
    }
}
#[test]
fn outline_validation_enforces_indivisible_row_and_path_bounds() {
    for path in [
        "".into(),
        "/main.rs".into(),
        "../main.rs".into(),
        "src//main.rs".into(),
        "é".repeat(2049),
    ] {
        assert!(
            validate_outline_read(
                &api::OutlineRead {
                    path,
                    ..Default::default()
                },
                Some(&peer())
            )
            .is_err()
        );
    }
    assert!(
        validate_outline_read(
            &api::OutlineRead {
                path: "main.rs".into(),
                page: Some(api::PageRequest {
                    size: 257,
                    ..Default::default()
                })
            },
            Some(&peer())
        )
        .is_err()
    );
    let good = api::OutlineSymbol {
        name: "run".into(),
        symbol_id: "run".into(),
        kind: 1,
        start_line: 1,
        end_line: 2,
        ..Default::default()
    };
    let mut bad = good.clone();
    bad.end_line = 0;
    assert!(validate_outline_symbol(&bad).is_err());
    let mut bad = good.clone();
    bad.symbol_id = "s".repeat(4097);
    assert!(validate_outline_symbol(&bad).is_err());
    let mut max = good;
    max.name = "n".repeat(4096);
    max.container = "c".repeat(4096);
    max.symbol_id = "s".repeat(4096);
    validate_outline_symbol(&max).expect("maximum indivisible row fits");
}
#[cfg(feature = "reflection")]
#[test]
fn outline_kinds_follow_the_generated_enum() {
    let pool =
        prost_reflect::DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("descriptor");
    let kinds = pool
        .get_enum_by_name("heddle.api.common.SymbolKind")
        .expect("symbol kinds");
    let mut row = api::OutlineSymbol {
        name: "run".into(),
        symbol_id: "run".into(),
        start_line: 1,
        end_line: 2,
        ..Default::default()
    };
    for value in kinds.values() {
        row.kind = value.number();
        assert_eq!(
            validate_outline_symbol(&row).is_ok(),
            row.kind != common::SymbolKind::Unspecified as i32
        );
    }
    for kind in [-1, i32::MAX] {
        row.kind = kind;
        assert!(validate_outline_symbol(&row).is_err());
    }
}

#[cfg(feature = "reflection")]
#[test]
fn additive_tags_mentions_and_outline_are_in_the_descriptor() {
    let pool =
        prost_reflect::DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("descriptor");
    for (message, field, tag) in [
        ("EntityRef", "source", 39),
        ("OpenDiscussionRequest", "mentions", 10),
        ("OpenDiscussionRequest", "tags", 11),
        ("DiscussionRecord", "tags", 14),
        ("ContextRecord", "mentions", 16),
        ("ContextDraft", "mentions", 7),
        ("ObserveCollaborationRequest", "discussion_tags", 12),
        ("ContentRead", "outline", 7),
        ("ContentEvent", "outline_symbol", 10),
    ] {
        assert_eq!(
            pool.get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
                .expect("message")
                .get_field_by_name(field)
                .expect("field")
                .number(),
            tag
        );
    }
    let route = heddle_api::v2::method_descriptor(
        "/heddle.api.v1alpha2.CollaborationService/EditDiscussionTags",
    )
    .expect("method");
    assert_eq!(route.authorization.targets[0].path, "discussion.spool");
}

fn peer() -> heddle_api::heddle::api::common::ProtocolCompatibility {
    heddle_api::heddle::api::common::ProtocolCompatibility {
        protocol_version: 2,
        mandatory_features: vec![1, 2, 3, 4],
    }
}
