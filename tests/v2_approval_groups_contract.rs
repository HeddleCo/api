use heddle_api::heddle::api::v1alpha2::{
    ApprovalGroupRecord, ResourceRole, ReviewPolicyRecord, SuggestedPrincipal,
};
use heddle_api::v2::approval_groups::{
    ApprovalPrincipal, approval_group_view, effective_resource_role, group_approval_count,
    validate_approval_group, validate_approval_group_view, validate_review_policy,
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

#[test]
fn role_members_count_live_and_demoted_removed_members_drop_out() {
    let fixture: Fixture = serde_json::from_str(include_str!("fixtures/role-approval-groups.json"))
        .expect("role vectors");
    assert_eq!(fixture.cases.len(), 13);
    for case in fixture.cases {
        let group = ApprovalGroupRecord {
            member_role: case.member_role,
            principal_ids: case.explicit,
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
        let view = approval_group_view(&group, &current).expect("resolved members");
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
        validate_approval_group_view(&view, &group, &current).expect("legal view");
        let mut stale = view;
        stale.resolved_members.push(current[3].person.clone());
        assert!(
            validate_approval_group_view(&stale, &group, &current).is_err(),
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
        approval_group_view(&group, &current)
            .expect("live view")
            .resolved_members
            .is_empty()
    );
    let mut explicit = group;
    explicit.principal_ids.push("ada-account-id".into());
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
