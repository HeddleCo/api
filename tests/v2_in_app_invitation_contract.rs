#![cfg(feature = "reflection")]

use heddle_api::{FILE_DESCRIPTOR_SET, heddle::api::common as contract, v2::method_descriptor};
use prost_reflect::DescriptorPool;

#[test]
fn unresolved_handle_has_a_specific_typed_refusal() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor");
    let reasons = pool
        .get_enum_by_name("heddle.api.common.ErrorReason")
        .expect("reasons");
    assert_eq!(
        reasons
            .get_value_by_name("ERROR_REASON_INVITATION_HANDLE_NOT_FOUND")
            .expect("specific handle refusal")
            .number(),
        302
    );
    let record = pool
        .get_message_by_name("heddle.api.v1alpha2.InvitationRecord")
        .expect("record");
    assert!(
        record.get_field(3).is_none(),
        "legacy recipient tag is retired"
    );
    assert_eq!(
        record
            .oneofs()
            .find(|o| o.name() == "recipient")
            .expect("typed recipient")
            .fields()
            .map(|f| f.name().to_owned())
            .collect::<Vec<_>>(),
        ["email", "handle", "account_id"]
    );
}

#[test]
fn accept_authorization_is_caller_bound_without_a_link_secret() {
    let method = method_descriptor("/heddle.api.v1alpha2.SpoolService/AcceptInvitation")
        .expect("in-app accept RPC");
    assert_eq!(
        method.authorization_access,
        contract::AuthorizationAccess::AuthenticatedPrincipal
    );
    assert_eq!(
        method.authorization.role,
        contract::AuthorizationRole::CallerBound
    );
    assert_eq!(
        method.authorization.scope_source,
        contract::AuthorizationScopeSource::CallerSubject
    );
    assert_eq!(
        method.authorization.existence,
        contract::AuthorizationExistence::Hide
    );
    assert_eq!(
        method.signing_tier,
        contract::SigningTier::ProofOfPossession
    );
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor");
    let request = pool
        .get_message_by_name("heddle.api.v1alpha2.AcceptInvitationRequest")
        .expect("accept request");
    assert_eq!(
        request
            .fields()
            .map(|f| (f.name().to_owned(), f.number()))
            .collect::<Vec<_>>(),
        [("client_operation_id".into(), 1), ("invitation".into(), 2)]
    );
}

#[test]
fn decline_is_an_idempotent_terminal_state() {
    let method = method_descriptor("/heddle.api.v1alpha2.SpoolService/DeclineInvitation")
        .expect("decline RPC");
    assert_eq!(
        method.retry_behavior,
        contract::RetryBehavior::ClientOperationId
    );
    assert!(method.client_operation_id_required);
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor");
    let state = pool
        .get_enum_by_name("heddle.api.v1alpha2.InvitationState")
        .expect("state machine");
    assert_eq!(
        state
            .values()
            .map(|v| (v.name().to_owned(), v.number()))
            .collect::<Vec<_>>(),
        [
            ("INVITATION_STATE_UNSPECIFIED".into(), 0),
            ("INVITATION_STATE_PENDING".into(), 1),
            ("INVITATION_STATE_ACCEPTED".into(), 2),
            ("INVITATION_STATE_DECLINED".into(), 3),
            ("INVITATION_STATE_REVOKED".into(), 4),
            ("INVITATION_STATE_EXPIRED".into(), 5),
        ]
    );
}
