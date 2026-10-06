use heddle_api::heddle::api::common::{CallFailure, CallFailureCode, ErrorDetail, ErrorReason};
use heddle_api::heddle::api::v1alpha2::{
    Capability, EndpointRef, GrantRecord, RecordRef, ResourceRole, SpoolRef, entity_ref,
};
use heddle_api::v2::membership_floor::{
    MemberKind, MembershipAdviceContext, MembershipCandidate, MembershipChange, MembershipField,
    MembershipFloorContext, membership_floor, membership_floor_actions, membership_floor_batch,
};
use prost::Message;
use prost_types::Timestamp;
use serde::Deserialize;

#[derive(Deserialize)]
struct Time {
    seconds: i64,
    nanos: i32,
}
impl Time {
    fn timestamp(&self) -> Timestamp {
        Timestamp {
            seconds: self.seconds,
            nanos: self.nanos,
        }
    }
}
#[derive(Deserialize)]
struct Ref {
    spool: String,
    id: String,
}
impl Ref {
    fn record(&self) -> RecordRef {
        RecordRef {
            spool: Some(SpoolRef {
                id: self.spool.clone(),
            }),
            id: self.id.clone(),
        }
    }
}
#[derive(Deserialize)]
struct Candidate {
    grant: Ref,
    subject: String,
    role: i32,
    kind: String,
    personal_owner: bool,
    expires_at: Option<Time>,
}
impl Candidate {
    fn model(&self) -> MembershipCandidate {
        MembershipCandidate {
            grant: self.grant.record(),
            subject: self.subject.clone(),
            role: ResourceRole::try_from(self.role).expect("known fixture role"),
            kind: if self.kind == "human" {
                MemberKind::Human
            } else {
                MemberKind::Agent
            },
            personal_owner: self.personal_owner,
            expires_at: self.expires_at.as_ref().map(Time::timestamp),
        }
    }
}
#[derive(Deserialize)]
struct Change {
    grant: Ref,
    role: i32,
    expires_at: Option<Time>,
    field: String,
}
impl Change {
    fn model(&self) -> MembershipChange {
        MembershipChange {
            grant: self.grant.record(),
            role: ResourceRole::try_from(self.role).expect("known fixture role"),
            expires_at: self.expires_at.as_ref().map(Time::timestamp),
            field: match self.field.as_str() {
                "grant" => MembershipField::Grant,
                "grant.role" => MembershipField::Role,
                "grant.expires_at" => MembershipField::ExpiresAt,
                _ => panic!("known fixture field"),
            },
        }
    }
}
#[derive(Deserialize)]
struct Case {
    #[serde(default)]
    changes: Vec<Change>,
    name: String,
    candidates: Vec<Candidate>,
    change: Change,
    can_manage_grants: bool,
    operation_authorized: bool,
    reason: i32,
    removed_rule: Option<String>,
}
#[derive(Deserialize)]
struct Fixture {
    now: Time,
    cases: Vec<Case>,
}
fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/membership-floors.json")).expect("shared vectors")
}
fn existing() -> CallFailure {
    CallFailure {
        code: CallFailureCode::NotFound as i32,
        message: "grant unavailable".into(),
        error: Some(ErrorDetail {
            reason: ErrorReason::ResourceNotFound as i32,
            field: "grant".into(),
            ..Default::default()
        }),
    }
}

#[test]
fn shared_membership_floor_vectors() {
    let fixture = fixture();
    assert_eq!(fixture.cases.len(), 30);
    let now = fixture.now.timestamp();
    let fallback = existing();
    let removed = std::env::var("MEMBERSHIP_FLOOR_REMOVED_RULE").ok();
    let mut checked = 0;
    for case in fixture.cases {
        if removed.as_ref().is_some_and(|r| {
            r != &case
                .removed_rule
                .clone()
                .unwrap_or_else(|| case.reason.to_string())
        }) {
            continue;
        }
        checked += 1;
        let current: Vec<_> = case.candidates.iter().map(Candidate::model).collect();
        let context = MembershipFloorContext {
            now: &now,
            can_manage_grants: case.can_manage_grants,
            operation_authorized: case.operation_authorized,
            existing_refusal: &fallback,
        };
        let result = if case.changes.is_empty() {
            membership_floor(&current, &case.change.model(), &context)
        } else {
            membership_floor_batch(
                &current,
                &case.changes.iter().map(Change::model).collect::<Vec<_>>(),
                case.change.model().field,
                &context,
            )
        };
        if removed.is_some() {
            assert!(
                result.is_none(),
                "{} must pass with its rule removed: {result:?}",
                case.name
            );
            continue;
        }
        if case.reason == 0 {
            assert!(result.is_none(), "{}: {result:?}", case.name);
            continue;
        }
        let failure = result.expect(&case.name);
        if !case.can_manage_grants || !case.operation_authorized {
            assert_eq!(failure, fallback, "{}", case.name);
        } else {
            assert_eq!(
                failure.code,
                CallFailureCode::FailedPrecondition as i32,
                "{}",
                case.name
            );
            let detail = failure.error.as_ref().expect("typed refusal");
            assert_eq!(detail.reason, case.reason, "{}", case.name);
            assert_eq!(detail.field, case.change.field, "{}", case.name);
            assert!(detail.resource.is_empty() && detail.context.is_none());
        }
        assert_eq!(
            CallFailure::decode(failure.encode_to_vec().as_slice()).expect("wire refusal"),
            failure
        );
    }
    assert!(checked > 0, "mutation filter must select real vectors");
}

#[test]
fn personal_precedes_both_count_floors() {
    let fixture = fixture();
    let mut owner = fixture.cases[0].candidates[0].model();
    owner.personal_owner = true;
    let now = fixture.now.timestamp();
    let fallback = existing();
    let failure = membership_floor(
        &[owner],
        &fixture.cases[0].change.model(),
        &MembershipFloorContext {
            now: &now,
            can_manage_grants: true,
            operation_authorized: true,
            existing_refusal: &fallback,
        },
    )
    .expect("personal owner cannot leave even when last member/admin");
    assert_eq!(failure.error.expect("detail").reason, 506);
}

#[test]
fn per_visible_grant_actions_share_typed_floor_and_never_target_hidden_grants() {
    let fixture = fixture();
    let case = &fixture.cases[4];
    let current: Vec<_> = case.candidates.iter().map(Candidate::model).collect();
    let now = fixture.now.timestamp();
    let fallback = existing();
    let visible: Vec<_> = current
        .iter()
        .map(|p| GrantRecord {
            r#ref: Some(p.grant.clone()),
            role: p.role as i32,
            version: vec![1],
            ..Default::default()
        })
        .collect();
    let endpoint = EndpointRef::default();
    for authorized in [true, false] {
        let actions = membership_floor_actions(
            &visible,
            &current,
            &MembershipAdviceContext {
                floor: MembershipFloorContext {
                    now: &now,
                    can_manage_grants: authorized,
                    operation_authorized: authorized,
                    existing_refusal: &fallback,
                },
                endpoint: &endpoint,
                implemented: true,
            },
        );
        assert_eq!(actions.len(), 4);
        for (index, action) in actions.iter().enumerate() {
            assert_eq!(action.authorized, authorized);
            assert!(action.implemented);
            assert_eq!(
                action.target.as_ref().expect("target").entity,
                Some(entity_ref::Entity::Grant(
                    visible[index / 2].r#ref.clone().expect("ref")
                ))
            );
            assert_eq!(action.observed_versions[0].resource, action.target);
            assert_eq!(action.observed_versions[0].version, vec![1]);
            assert_eq!(
                action.capability,
                if index % 2 == 0 {
                    Capability::RevokeGrant
                } else {
                    Capability::PutGrant
                } as i32
            );
            if authorized && index < 2 {
                let detail = action.requirements[0]
                    .error
                    .as_ref()
                    .expect("floor requirement");
                assert_eq!(detail.reason, 508);
                assert_eq!(
                    detail.field,
                    if index == 0 { "grant" } else { "grant.role" }
                );
            } else if authorized {
                assert!(action.requirements.is_empty());
            } else {
                assert!(action.requirements.iter().all(|r| r.error.is_none()));
            }
            assert_eq!(
                heddle_api::heddle::api::v1alpha2::ActionAvailability::decode(
                    action.encode_to_vec().as_slice()
                )
                .expect("wire advice"),
                *action
            );
        }
    }
    // The undisclosed second administrator counts but never becomes a target.
    let hidden = &fixture.cases[12];
    let current: Vec<_> = hidden.candidates.iter().map(Candidate::model).collect();
    let actions = membership_floor_actions(
        &visible[..1],
        &current,
        &MembershipAdviceContext {
            floor: MembershipFloorContext {
                now: &now,
                can_manage_grants: true,
                operation_authorized: true,
                existing_refusal: &fallback,
            },
            endpoint: &endpoint,
            implemented: true,
        },
    );
    assert_eq!(actions.len(), 2);
    assert!(actions.iter().all(|a| a.requirements.is_empty()));
}
