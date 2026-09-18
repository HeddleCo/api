use heddle_api::heddle::api::common::{AuthorizationAccess, SigningTier, StableSigningIdentity};
#[test]
fn unsubscribe_capability_works_without_account_sign_in() {
    let route = heddle_api::v2::method_descriptor(
        "/heddle.api.v1alpha2.NotificationService/UnsubscribeNotifications",
    )
    .expect("unsubscribe route");
    assert_eq!(route.authorization_access, AuthorizationAccess::Public);
    assert_eq!(
        route.signing_tier,
        SigningTier::None,
        "the disabling-only capability is the authority; signed-out users need no account key"
    );
    assert_eq!(route.signing_identity, StableSigningIdentity::None);
    assert!(
        route.client_operation_id_required,
        "safe retries remain exact"
    );
}
