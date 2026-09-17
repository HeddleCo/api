#![cfg(feature = "reflection")]

use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::v1alpha1::{
        AuthorizationAccess, AuthorizationRole, AuthorizationScopeSource, SigningTier,
    },
};
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn email_delivery_proof_is_issued_only_to_the_authenticated_signup_mailer() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract");
    let request = pool
        .get_message_by_name("heddle.api.v2alpha1.BeginEmailVerificationRequest")
        .expect("email begin");
    assert_eq!(
        request
            .get_field_by_name("handle")
            .expect("bound signup handle")
            .kind(),
        Kind::String
    );
    assert_eq!(
        request
            .get_field_by_name("invitation_code")
            .expect("optional code for a newly email-bound invite")
            .kind(),
        Kind::Bytes
    );
    assert!(
        request.get_field_by_name("invitation").is_none(),
        "a bare resource reference cannot authorize email binding"
    );
    let challenge = pool
        .get_message_by_name("heddle.api.v2alpha1.EmailVerificationChallenge")
        .expect("delivery challenge");
    assert_eq!(
        challenge
            .get_field_by_name("delivery_proof")
            .expect("mailer-only email proof")
            .kind(),
        Kind::Bytes
    );
    let route = heddle_api::v2::method_descriptor(
        "/heddle.api.v2alpha1.IdentityService/BeginEmailVerification",
    )
    .expect("delivery route");
    assert_eq!(
        route.authorization_access,
        AuthorizationAccess::AuthenticatedPrincipal
    );
    assert_eq!(
        route.signing_tier,
        SigningTier::None,
        "preserve the dedicated mailer's bearer-only credential tier"
    );
    assert!(route.client_operation_id_required);
}

#[test]
fn email_possession_yields_typed_registration_admission_without_an_account_credential() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract");
    let service = pool
        .get_service_by_name("heddle.api.v2alpha1.IdentityService")
        .expect("identity");
    let method = service
        .methods()
        .find(|m| m.name() == "CompleteEmailVerification")
        .expect("completion");
    let reservation = pool
        .get_message_by_name("heddle.api.v2alpha1.VerifiedEmailReservation")
        .expect("email admission");
    assert_eq!(
        method
            .output()
            .get_field_by_name("reservation")
            .expect("admission for BeginRegistration")
            .kind(),
        Kind::Message(reservation.clone())
    );
    for field in ["ref", "expires_at", "handle", "email"] {
        assert!(
            reservation.get_field_by_name(field).is_some(),
            "reservation needs {field}"
        );
    }
    let route = heddle_api::v2::method_descriptor(
        "/heddle.api.v2alpha1.IdentityService/CompleteEmailVerification",
    )
    .expect("proof redemption");
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
fn transactional_send_email_is_distinct_from_signup_mailbox_proof() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract");
    let request = pool
        .get_message_by_name("heddle.api.v2alpha1.SendEmailRequest")
        .expect("transactional send");
    for field in [
        "client_operation_id",
        "to",
        "from_name",
        "from_email",
        "reply_to",
        "subject",
        "html",
        "text",
        "headers",
    ] {
        assert!(
            request.get_field_by_name(field).is_some(),
            "SendEmailRequest needs {field}"
        );
    }
    assert!(
        request.get_field_by_name("invitation_code").is_none(),
        "transactional send must not carry signup admission"
    );
    let response = pool
        .get_message_by_name("heddle.api.v2alpha1.SendEmailResponse")
        .expect("send receipt");
    assert!(response.get_field_by_name("receipt").is_some());
    assert_eq!(
        response
            .get_field_by_name("message_id")
            .expect("provider message id")
            .kind(),
        Kind::String
    );
    let route =
        heddle_api::v2::method_descriptor("/heddle.api.v2alpha1.IdentityService/SendEmail")
            .expect("transactional delivery route");
    assert_eq!(
        route.authorization_access,
        AuthorizationAccess::AuthenticatedPrincipal
    );
    assert_eq!(
        route.signing_tier,
        SigningTier::ProofOfPossession,
        "browser and device callers prove possession; BeginEmailVerification stays mailer-bearer"
    );
    assert_eq!(route.authorization.role, AuthorizationRole::CallerBound);
    assert_eq!(
        route.authorization.scope_source,
        AuthorizationScopeSource::CallerSubject
    );
    assert!(route.client_operation_id_required);
}
