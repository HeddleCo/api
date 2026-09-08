#![cfg(feature = "reflection")]
use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::v1alpha1::{AuthorizationRole, AuthorizationScopeSource, SigningTier},
};
use prost_reflect::DescriptorPool;

#[test]
fn billing_targets_the_authenticated_account_with_effective_delegated_authority() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid contract");
    let service = pool
        .get_service_by_name("heddle.api.v2alpha1.BillingService")
        .expect("billing service");
    let methods: Vec<_> = service.methods().collect();
    assert_eq!(methods.len(), 6);
    for method in methods {
        let path = format!("/{}/{}", service.full_name(), method.name());
        let descriptor = heddle_api::v2::method_descriptor(&path).expect("native method metadata");
        assert_eq!(descriptor.signing_tier, SigningTier::ProofOfPossession);
        assert_eq!(
            descriptor.authorization.role,
            AuthorizationRole::CallerBound
        );
        assert_eq!(
            descriptor.authorization.scope_source,
            AuthorizationScopeSource::CallerSubject
        );
        assert!(method.input().get_field_by_name("account_id").is_none());
        assert!(method.input().get_field_by_name("customer_id").is_none());
        assert!(
            method
                .input()
                .get_field_by_name("subscription_id")
                .is_none()
        );
        assert!(method.input().get_field_by_name("return_url").is_none());
        if method.name() != "ObserveBilling" {
            assert!(descriptor.client_operation_id_required);
        }
    }
}

#[test]
fn identity_composes_billing_and_current_credential_metadata_without_issuing_a_secret() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid contract");
    let request = pool
        .get_message_by_name("heddle.api.v2alpha1.ObserveIdentityRequest")
        .expect("identity query");
    assert!(
        request
            .get_field_by_name("include_current_credential")
            .is_some()
    );
    assert!(request.get_field_by_name("include_billing").is_some());
    let event = pool
        .get_message_by_name("heddle.api.v2alpha1.IdentityEvent")
        .expect("identity event");
    assert!(event.get_field_by_name("current_credential").is_some());
    assert!(event.get_field_by_name("billing").is_some());
    for name in ["CurrentCredentialRecord", "BillingRecord"] {
        let record = pool
            .get_message_by_name(&format!("heddle.api.v2alpha1.{name}"))
            .expect("typed projection");
        assert!(record.get_field_by_name("version").is_some());
        assert!(record.get_field_by_name("actions").is_some());
        for field in record.fields() {
            assert!(!field.name().contains("biscuit"));
            assert!(!field.name().contains("secret"));
            assert!(!field.name().contains("provider_subscription"));
        }
    }
}

#[test]
fn financial_amounts_and_optional_seats_preserve_absence_and_integer_units() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid contract");
    let money = pool
        .get_message_by_name("heddle.api.v2alpha1.Money")
        .expect("money");
    assert_eq!(
        money
            .get_field_by_name("amount_minor")
            .expect("minor units")
            .kind(),
        prost_reflect::Kind::Int64
    );
    let update = pool
        .get_message_by_name("heddle.api.v2alpha1.UpdateSubscriptionRequest")
        .expect("atomic subscription update");
    assert!(
        update
            .get_field_by_name("plan")
            .expect("optional plan")
            .supports_presence()
    );
    assert!(
        update
            .get_field_by_name("seats")
            .expect("optional seats")
            .supports_presence()
    );
    assert!(update.get_field_by_name("expected_version").is_some());
}

#[test]
fn current_credential_carries_the_original_session_independently_of_collection_pages() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid contract");
    let credential = pool
        .get_message_by_name("heddle.api.v2alpha1.CurrentCredentialRecord")
        .expect("current credential");
    let session = credential
        .get_field_by_name("session")
        .expect("current session");
    assert!(session.supports_presence());
    assert_eq!(session.number(), 16);
    assert_eq!(
        session.kind(),
        prost_reflect::Kind::Message(
            pool.get_message_by_name("heddle.api.v2alpha1.SessionRecord")
                .expect("original versioned session")
        )
    );
}

#[test]
fn observed_device_has_original_registry_identity_and_version() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid contract");
    let device = pool
        .get_message_by_name("heddle.api.v2alpha1.DeviceIdentity")
        .expect("device observation");
    assert_eq!(
        device
            .get_field_by_name("ref")
            .expect("registry identity")
            .number(),
        6
    );
    assert_eq!(
        device
            .get_field_by_name("version")
            .expect("authorization version")
            .number(),
        7
    );
}

#[test]
fn device_revocation_consumes_the_observed_registry_identity_and_version() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid contract");
    let request = pool
        .get_message_by_name("heddle.api.v2alpha1.RevokeDeviceRequest")
        .expect("device revocation");
    assert_eq!(
        request
            .get_field_by_name("device")
            .expect("device identity")
            .kind(),
        prost_reflect::Kind::Message(
            pool.get_message_by_name("heddle.api.v2alpha1.RecordRef")
                .expect("registry ref")
        )
    );
    assert_eq!(
        request
            .get_field_by_name("expected_version")
            .expect("CAS version")
            .number(),
        4
    );
    assert!(
        request.get_field_by_name("revocation").is_none(),
        "ordinary delegated revocation does not invent an owner ceremony"
    );
}
