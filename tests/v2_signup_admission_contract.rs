#![cfg(feature = "reflection")]
use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::v1alpha1::{
        AuthorizationAccess, AuthorizationRole, AuthorizationScopeSource, SigningTier,
    },
};
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn invite_redemption_yields_registration_admission_without_a_discovery_call_or_device_root() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract");
    let service = pool
        .get_service_by_name("heddle.api.v2alpha1.IdentityService")
        .expect("identity");
    let method = service
        .methods()
        .find(|m| m.name() == "RedeemSignupInvitation")
        .expect("redemption");
    let request = method.input();
    assert!(
        request.get_field_by_name("invitation").is_none(),
        "the held secret directly selects the invitation"
    );
    assert!(
        request.get_field_by_name("principal").is_none(),
        "reservation precedes account and key establishment"
    );
    assert_eq!(
        request
            .get_field_by_name("redemption_secret")
            .expect("secret")
            .kind(),
        Kind::Bytes
    );
    let reservation = pool
        .get_message_by_name("heddle.api.v2alpha1.SignupReservation")
        .expect("typed reservation");
    assert_eq!(
        method
            .output()
            .get_field_by_name("reservation")
            .expect("admission for BeginRegistration")
            .kind(),
        Kind::Message(reservation.clone())
    );
    assert!(reservation.get_field_by_name("ref").is_some());
    assert!(reservation.get_field_by_name("expires_at").is_some());
    let route = heddle_api::v2::method_descriptor(
        "/heddle.api.v2alpha1.IdentityService/RedeemSignupInvitation",
    )
    .expect("route");
    assert_eq!(route.authorization_access, AuthorizationAccess::Public);
    assert_eq!(route.signing_tier, SigningTier::None);
    assert_eq!(route.authorization.role, AuthorizationRole::None);
    assert_eq!(
        route.authorization.scope_source,
        AuthorizationScopeSource::None
    );
    assert!(route.client_operation_id_required);
}

#[test]
fn invite_page_resolution_carries_typed_availability_and_inviter_context() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract");
    let response = pool
        .get_message_by_name("heddle.api.v2alpha1.SignupInvitationResolution")
        .expect("resolution");
    for field in [
        "status",
        "inviter_display_handle",
        "inviter_member_ordinal",
        "bound_email",
    ] {
        assert!(
            response.get_field_by_name(field).is_some(),
            "invite page needs {field} without another lookup"
        );
    }
    assert!(
        response.get_field_by_name("availability").is_none(),
        "coverage is not invitation validity"
    );
}
