use heddle_api::heddle::api::v1alpha2::{
    ApprovalGroupRecord, ResourceRole, ReviewPolicyRecord, SuggestedPrincipal,
};
use heddle_api::v2::approval_groups::{
    ApprovalGroupViewContext, ApprovalPrincipal, approval_group_view, effective_resource_role,
    group_approval_count, validate_approval_group, validate_approval_group_view,
    validate_review_policy,
};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Principal {
    subject: String,
    handle: String,
    display_name: String,
    kind: i32,
    direct_role: i32,
    inherited_role: i32,
    is_agent: bool,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    member_role: i32,
    minimum_role: i32,
    explicit: Vec<String>,
    approvers: Vec<String>,
    overrides: BTreeMap<String, [i32; 2]>,
    extra: Vec<Principal>,
    expected: Vec<String>,
    count: usize,
    error: Option<String>,
}
#[derive(Deserialize)]
struct Fixture {
    principals: Vec<Principal>,
    cases: Vec<Case>,
    refused_policy_roles: Vec<i32>,
}

// Defaults permit the added-ID schema mutation to reach real assertions.
#[allow(clippy::needless_update)]
#[test]
fn role_members_count_live_and_demoted_removed_members_drop_out() {
    let fixture: Fixture = serde_json::from_str(include_str!("fixtures/role-approval-groups.json"))
        .expect("role vectors");
    assert_eq!(fixture.cases.len(), 13);
    for case in fixture.cases {
        let group = ApprovalGroupRecord {
            member_role: case.member_role,
            explicit_member_handles: fixture
                .principals
                .iter()
                .chain(&case.extra)
                .filter(|p| case.explicit.contains(&p.subject))
                .map(|p| p.handle.clone())
                .collect(),
            ..Default::default()
        };
        let policy = ReviewPolicyRecord {
            minimum_role: case.minimum_role,
            ..Default::default()
        };
        let current: Vec<_> = fixture
            .principals
            .iter()
            .chain(&case.extra)
            .map(|p| {
                let roles = case
                    .overrides
                    .get(&p.handle)
                    .copied()
                    .unwrap_or([p.direct_role, p.inherited_role]);
                ApprovalPrincipal {
                    subject: p.subject.clone(),
                    person: SuggestedPrincipal {
                        handle: p.handle.clone(),
                        display_name: p.display_name.clone(),
                        kind: p.kind,
                        ..Default::default()
                    },
                    effective_role: effective_resource_role(
                        &roles.map(|r| ResourceRole::try_from(r).expect("known fixture role")),
                    ),
                    is_agent: p.is_agent,
                    explicit_member: case.explicit.contains(&p.subject),
                    handle_visible: true,
                }
            })
            .collect();
        let validation = validate_approval_group(&group);
        assert_eq!(
            validation.err().map(|e| format!("{e:?}")),
            case.error,
            "{}",
            case.name
        );
        if case.error.is_some() {
            continue;
        }
        let view = approval_group_view(&group, &current, &ADMIN_VIEW).expect("resolved members");
        assert_eq!(
            view.resolved_members
                .iter()
                .map(|p| &p.handle)
                .collect::<Vec<_>>(),
            case.expected.iter().collect::<Vec<_>>(),
            "{}",
            case.name
        );
        assert_eq!(
            group_approval_count(&group, &policy, &current, &case.approvers).expect("count"),
            case.count,
            "{}",
            case.name
        );
        if case.name == "role_group_member_counts_inherited_admin" {
            assert_eq!(view.role_member_handles, ["ada", "mara"]);
        }
        validate_approval_group_view(&view, &group, &current, &ADMIN_VIEW).expect("legal view");
        let mut stale = view;
        stale.resolved_members.push(current[3].person.clone());
        assert!(
            validate_approval_group_view(&stale, &group, &current, &ADMIN_VIEW).is_err(),
            "{}",
            case.name
        );
    }
    for role in fixture.refused_policy_roles {
        let error = validate_review_policy(&ReviewPolicyRecord {
            minimum_role: role,
            ..Default::default()
        })
        .expect_err("inadmissible floor");
        assert_eq!(
            format!("{error:?}"),
            if role == 1 {
                "RoleBelowEligibilityFloor"
            } else {
                "Role"
            }
        );
    }
}

#[test]
fn reader_refused_with_typed_wire_reason() {
    use heddle_api::heddle::api::common::{CallFailureCode, ErrorDetail, ErrorReason};
    use prost::Message;
    let reason = ErrorReason::ApprovalRoleBelowEligibilityFloor;
    assert_eq!(
        reason.as_str_name(),
        "ERROR_REASON_APPROVAL_ROLE_BELOW_ELIGIBILITY_FLOOR"
    );
    assert_eq!(CallFailureCode::InvalidArgument as i32, 3);
    for field in ["group.member_role", "policy.minimum_role"] {
        let detail = ErrorDetail {
            reason: reason as i32,
            field: field.into(),
            ..Default::default()
        };
        assert_eq!(
            ErrorDetail::decode(detail.encode_to_vec().as_slice()).expect("typed detail"),
            detail
        );
    }
}

// Defaults permit the added-ID schema mutation to reach real assertions.
#[allow(clippy::needless_update)]
#[test]
fn an_existing_approval_stops_counting_when_its_role_member_is_demoted() {
    let group = ApprovalGroupRecord {
        member_role: ResourceRole::Administrator as i32,
        ..Default::default()
    };
    let policy = ReviewPolicyRecord::default();
    let mut current = [ApprovalPrincipal {
        subject: "ada-account-id".into(),
        person: SuggestedPrincipal {
            handle: "ada".into(),
            display_name: "Ada".into(),
            kind: 1,
            ..Default::default()
        },
        effective_role: effective_resource_role(&[
            ResourceRole::Unspecified,
            ResourceRole::Administrator,
        ]),
        is_agent: false,
        explicit_member: false,
        handle_visible: true,
    }];
    let approved = ["ada-account-id".into()];
    assert_eq!(
        group_approval_count(&group, &policy, &current, &approved).expect("inherited role member"),
        1
    );
    current[0].effective_role = ResourceRole::Writer;
    assert_eq!(
        group_approval_count(&group, &policy, &current, &approved).expect("demoted member"),
        0
    );
    assert!(
        approval_group_view(&group, &current, &ADMIN_VIEW)
            .expect("live view")
            .resolved_members
            .is_empty()
    );
    let mut explicit = group;
    explicit.explicit_member_handles.push("ada".into());
    current[0].explicit_member = true;
    assert_eq!(
        group_approval_count(&explicit, &policy, &current, &approved)
            .expect("explicit eligible extra"),
        1
    );
    current[0].effective_role = ResourceRole::Unspecified;
    assert_eq!(
        group_approval_count(&explicit, &policy, &current, &approved).expect("removed member"),
        0
    );
}

#[test]
fn reader_group_and_review_policy_writes_are_refused() {
    use heddle_api::v2::approval_groups::ApprovalGroupError;
    assert_eq!(
        validate_approval_group(&ApprovalGroupRecord {
            member_role: ResourceRole::Reader as i32,
            ..Default::default()
        }),
        Err(ApprovalGroupError::RoleBelowEligibilityFloor)
    );
    assert_eq!(
        validate_review_policy(&ReviewPolicyRecord {
            minimum_role: ResourceRole::Reader as i32,
            ..Default::default()
        }),
        Err(ApprovalGroupError::RoleBelowEligibilityFloor)
    );
}

const ADMIN_VIEW: ApprovalGroupViewContext = ApprovalGroupViewContext {
    can_read_members: true,
    is_administrator: true,
};

#[test]
fn explicit_member_handles_accept_gitlab_provider() {
    let group = ApprovalGroupRecord {
        explicit_member_handles: vec!["gitlab.com:Alice".into()],
        ..Default::default()
    };
    assert_eq!(validate_approval_group(&group), Ok(()));
}

#[test]
fn explicit_member_handles_accept_github_provider_host() {
    let group = ApprovalGroupRecord {
        explicit_member_handles: vec!["github.com:bob".into()],
        ..Default::default()
    };
    assert_eq!(validate_approval_group(&group), Ok(()));
}

#[test]
fn explicit_member_handles_reject_malformed_metadata() {
    use heddle_api::v2::approval_groups::ApprovalGroupError;
    for handle in [
        "",
        ":alice",
        "GitLab.COM:x",
        "gitlab:alice",
        "gitlab..com:alice",
        "-gitlab.com:alice",
        "gitlab.com.:alice",
        "alice\nsmith",
        "alice\0",
        " alice",
        "alice ",
        "12345678-1234-1234-1234-123456789abc",
    ] {
        let group = ApprovalGroupRecord {
            explicit_member_handles: vec![handle.into()],
            ..Default::default()
        };
        assert_eq!(
            validate_approval_group(&group),
            Err(ApprovalGroupError::Metadata),
            "{handle:?}"
        );
    }
}

#[test]
fn group_disclosure_vectors_require_members_read_and_admin_for_explicit_edits() {
    use heddle_api::v2::approval_groups::resolve_approval_group_members;
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/approval-group-visibility.json"))
            .expect("visibility vectors");
    let group = ApprovalGroupRecord {
        member_role: 3,
        explicit_member_handles: vec!["jun".into()],
        ..Default::default()
    };
    let current: Vec<_> = fixture["principals"]
        .as_array()
        .expect("principals")
        .iter()
        .map(|p| ApprovalPrincipal {
            subject: p["subject"].as_str().expect("subject").into(),
            person: SuggestedPrincipal {
                handle: p["handle"].as_str().expect("handle").into(),
                kind: 1,
                ..Default::default()
            },
            effective_role: ResourceRole::try_from(p["role"].as_i64().expect("role") as i32)
                .expect("role enum"),
            is_agent: false,
            explicit_member: p["explicit"].as_bool().expect("explicit"),
            handle_visible: p["visible"].as_bool().expect("visible"),
        })
        .collect();
    for v in fixture["cases"].as_array().expect("cases") {
        let context = ApprovalGroupViewContext {
            can_read_members: v["members"].as_bool().expect("members"),
            is_administrator: v["admin"].as_bool().expect("admin"),
        };
        let view = approval_group_view(&group, &current, &context).expect("view");
        let expected = |key: &str| -> Vec<String> {
            v[key]
                .as_array()
                .expect("handles")
                .iter()
                .map(|h| h.as_str().expect("handle").into())
                .collect()
        };
        assert_eq!(
            view.resolved_members
                .iter()
                .map(|p| p.handle.clone())
                .collect::<Vec<_>>(),
            expected("resolved"),
            "{}",
            v["name"]
        );
        assert_eq!(view.role_member_handles, expected("role"), "{}", v["name"]);
        assert_eq!(
            view.explicit_member_handles,
            expected("explicit"),
            "{}",
            v["name"]
        );
        assert_eq!(
            (
                view.resolved_member_count,
                view.role_member_count,
                view.explicit_member_count
            ),
            (3, 2, 3)
        );
        validate_approval_group_view(&view, &group, &current, &context).expect("legal disclosure");
        if context.is_administrator && context.can_read_members {
            let edited = ApprovalGroupRecord {
                name: "renamed".into(),
                explicit_member_handles: view.explicit_member_handles,
                ..group.clone()
            };
            assert_eq!(
                resolve_approval_group_members(&edited, true, &current, |handle| current
                    .iter()
                    .find(|p| p.person.handle == handle && p.handle_visible && !p.is_agent)
                    .map(|p| p.subject.clone()))
                .expect("server handle binding"),
                ["absent-private", "hidden-private", "jun-private"]
            );
        }
    }
    assert_eq!(
        resolve_approval_group_members(&group, false, &[], |_| panic!(
            "must authorize before lookup"
        )),
        Err(heddle_api::v2::approval_groups::ApprovalGroupError::Administrator)
    );
    assert_eq!(
        resolve_approval_group_members(&group, true, &[], |_| None),
        Err(heddle_api::v2::approval_groups::ApprovalGroupError::HandleNotFound)
    );
    let cleared_visible = ApprovalGroupRecord {
        explicit_member_handles: vec![],
        ..group.clone()
    };
    assert_eq!(
        resolve_approval_group_members(&cleared_visible, true, &current, |_| panic!(
            "no visible handles to resolve"
        ))
        .expect("clear visible extras"),
        ["absent-private", "hidden-private"]
    );
    // An updated public handle never changes the privately bound explicit subject.
    let mut renamed = current;
    renamed[1].person.handle = "jun-renamed".into();
    assert_eq!(
        approval_group_view(&group, &renamed, &ADMIN_VIEW)
            .expect("rename view")
            .explicit_member_handles,
        ["jun-renamed"]
    );
}

#[cfg(feature = "reflection")]
#[test]
fn approval_group_writes_hard_cut_ids_to_handles() {
    let pool =
        prost_reflect::DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("schema");
    let group = pool
        .get_message_by_name("heddle.api.v1alpha2.ApprovalGroupRecord")
        .expect("record");
    assert!(group.get_field_by_name("principal_ids").is_none());
    assert!(group.get_field(5).is_none());
    assert_eq!(
        group
            .get_field_by_name("explicit_member_handles")
            .expect("handles")
            .number(),
        7
    );
}
