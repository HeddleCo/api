use heddle_api::heddle::api::v1alpha2::{SpoolRef, SuggestPrincipalsRequest, SuggestedPrincipal};
use heddle_api::v2::people::{
    PeopleCandidate, PeopleContext, suggest_principals, validate_suggest_principals_response,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Candidate {
    handle: String,
    display_name: String,
    kind: i32,
    spool_ids: Vec<String>,
    is_agent: bool,
    is_public: bool,
    handle_visible: bool,
}
impl Candidate {
    // Defaults keep the schema ID-leak mutation compilable, so it must fail
    // projection assertions rather than merely fail to build.
    #[allow(clippy::needless_update)]
    fn candidate(&self) -> PeopleCandidate {
        PeopleCandidate {
            person: SuggestedPrincipal {
                handle: self.handle.clone(),
                display_name: self.display_name.clone(),
                kind: self.kind,
                ..Default::default()
            },
            spool_ids: self.spool_ids.clone(),
            is_agent: self.is_agent,
            is_public: self.is_public,
            handle_visible: self.handle_visible,
        }
    }
}
#[derive(Deserialize)]
struct Case {
    name: String,
    prefix: String,
    spool: Option<String>,
    caller_spool_ids: Vec<String>,
    members_readable_spool_ids: Vec<String>,
    rate_limit_allowed: bool,
    expected: Vec<String>,
    error: Option<String>,
    replacement_candidates: Option<Vec<Candidate>>,
}
#[derive(Deserialize)]
struct Fixture {
    candidates: Vec<Candidate>,
    cases: Vec<Case>,
}

#[test]
fn shared_people_vectors_enforce_scope_agents_exact_hit_prefix_and_bounds() {
    let fixture: Fixture = serde_json::from_str(include_str!("fixtures/people-suggestions.json"))
        .expect("people vectors");
    assert_eq!(fixture.cases.len(), 23);
    for case in fixture.cases {
        let request = SuggestPrincipalsRequest {
            prefix: case.prefix,
            spool: case.spool.map(|id| SpoolRef { id }),
        };
        let candidates: Vec<_> = case
            .replacement_candidates
            .as_ref()
            .unwrap_or(&fixture.candidates)
            .iter()
            .map(Candidate::candidate)
            .collect();
        let context = PeopleContext {
            caller_spool_ids: &case.caller_spool_ids,
            members_readable_spool_ids: &case.members_readable_spool_ids,
            rate_limit_allowed: case.rate_limit_allowed,
        };
        let result = suggest_principals(&request, &candidates, &context);
        assert_eq!(
            result.as_ref().err().map(|e| format!("{e:?}")),
            case.error,
            "{}",
            case.name
        );
        if let Ok(response) = result {
            assert_eq!(
                response
                    .principals
                    .iter()
                    .map(|p| &p.handle)
                    .collect::<Vec<_>>(),
                case.expected.iter().collect::<Vec<_>>(),
                "{}",
                case.name
            );
            validate_suggest_principals_response(&response, &request, &candidates, &context)
                .expect("legal projection");
            if case.name == "non_co_member_never_suggested" {
                let mut leaked = response.clone();
                leaked.principals.push(candidates[2].person.clone());
                assert!(
                    validate_suggest_principals_response(&leaked, &request, &candidates, &context)
                        .is_err()
                );
            }
        }
    }
}

#[cfg(feature = "reflection")]
#[test]
fn no_id_leak_in_public_people_or_group_projection() {
    use prost_reflect::{DescriptorPool, Kind};
    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("descriptor");
    let person = pool
        .get_message_by_name("heddle.api.v1alpha2.SuggestedPrincipal")
        .expect("people row");
    assert_eq!(
        person
            .fields()
            .map(|f| (f.name().to_owned(), f.number()))
            .collect::<Vec<_>>(),
        vec![
            ("handle".into(), 1),
            ("display_name".into(), 2),
            ("kind".into(), 3)
        ]
    );
    let response = pool
        .get_message_by_name("heddle.api.v1alpha2.SuggestPrincipalsResponse")
        .expect("response");
    assert_eq!(response.fields().count(), 1);
    assert_eq!(
        response
            .get_field_by_name("principals")
            .expect("rows")
            .kind(),
        Kind::Message(person.clone())
    );
    let view = pool
        .get_message_by_name("heddle.api.v1alpha2.ApprovalGroupView")
        .expect("group view");
    assert_eq!(
        view.fields()
            .map(|f| f.name().to_owned())
            .collect::<Vec<_>>(),
        [
            "ref",
            "version",
            "name",
            "description",
            "member_role",
            "resolved_members",
            "role_member_handles",
            "explicit_member_handles",
            "resolved_member_count",
            "role_member_count",
            "explicit_member_count"
        ]
    );
    assert_eq!(
        view.get_field_by_name("resolved_members")
            .expect("resolved people")
            .kind(),
        Kind::Message(person)
    );
    let event = pool
        .get_message_by_name("heddle.api.v1alpha2.SpoolEvent")
        .expect("spool projection");
    assert_eq!(
        event
            .get_field_by_name("approval_group")
            .expect("group")
            .kind(),
        Kind::Message(view)
    );
}

#[test]
fn suggestions_are_authenticated_safe_hosted_reads_with_optional_spool_guard() {
    use heddle_api::heddle::api::common::{
        AuthorizationAccess, AuthorizationExistence, AuthorizationRole, AuthorizationScopeSource,
        DeploymentTarget, RetryBehavior, RpcEffect, SigningTier,
    };
    let method =
        heddle_api::v2::method_descriptor("/heddle.api.v1alpha2.IdentityService/SuggestPrincipals")
            .expect("RPC");
    assert_eq!(method.effect, RpcEffect::ReadOnly);
    assert_eq!(method.retry_behavior, RetryBehavior::Safe);
    assert_eq!(method.signing_tier, SigningTier::ProofOfPossession);
    assert_eq!(
        method.authorization_access,
        AuthorizationAccess::AuthenticatedPrincipal
    );
    assert_eq!(method.authorization.role, AuthorizationRole::CallerBound);
    assert_eq!(
        method.authorization.scope_source,
        AuthorizationScopeSource::CallerGrants
    );
    assert_eq!(method.authorization.existence, AuthorizationExistence::Hide);
    assert_eq!(method.authorization.targets[0].path, "spool");
    assert_eq!(method.deployment_targets, &[DeploymentTarget::Weft]);
}

#[test]
fn non_co_member_never_suggested_and_agents_excluded() {
    let fixture: Fixture = serde_json::from_str(include_str!("fixtures/people-suggestions.json"))
        .expect("people vectors");
    let request = SuggestPrincipalsRequest {
        prefix: "ad".into(),
        spool: Some(SpoolRef {
            id: "shared".into(),
        }),
    };
    let candidates: Vec<_> = fixture
        .candidates
        .iter()
        .map(Candidate::candidate)
        .collect();
    let memberships = ["shared".into()];
    let context = PeopleContext {
        caller_spool_ids: &memberships,
        members_readable_spool_ids: &memberships,
        rate_limit_allowed: true,
    };
    let response = suggest_principals(&request, &candidates, &context).expect("scoped suggestions");
    assert!(
        response
            .principals
            .iter()
            .all(|p| p.handle != "adam-private" && p.handle != "adam-public"),
        "non-co-member must never be a prefix suggestion"
    );
    assert!(
        response.principals.iter().all(|p| p.handle != "ada-agent"),
        "delegations have no people rows"
    );
}
