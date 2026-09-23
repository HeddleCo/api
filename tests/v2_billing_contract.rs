#![cfg(feature = "reflection")]
use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::common::{
        AccountBillingLock, AccountBillingLockAllowedAction, AccountBillingLockReason,
        AuthorizationAccess, AuthorizationRole, AuthorizationScopeSource, ErrorDetail, ErrorReason,
        RpcEffect, SigningTier, error_detail,
    },
};
use prost::Message;
use prost_reflect::DescriptorPool;

#[test]
fn billing_targets_the_authenticated_account_with_effective_delegated_authority() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid contract");
    let service = pool
        .get_service_by_name("heddle.api.v1alpha2.BillingService")
        .expect("billing service");
    let methods: Vec<_> = service.methods().collect();
    assert_eq!(methods.len(), 6);
    for method in methods {
        let path = format!("/{}/{}", service.full_name(), method.name());
        let descriptor = heddle_api::v2::method_descriptor(&path).expect("native method metadata");
        if method.name() == "ObserveBilling" {
            assert_eq!(descriptor.signing_tier, SigningTier::ProofIfAuthenticated);
            assert_eq!(descriptor.authorization_access, AuthorizationAccess::Public);
            assert_eq!(
                method
                    .input()
                    .get_field_by_name("plans_only")
                    .expect("explicit public-only selector")
                    .number(),
                3
            );
        } else {
            assert_eq!(descriptor.signing_tier, SigningTier::ProofOfPossession);
            assert_eq!(
                descriptor.authorization.role,
                AuthorizationRole::CallerBound
            );
            assert_eq!(
                descriptor.authorization.scope_source,
                AuthorizationScopeSource::CallerSubject
            );
        }
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
        .get_message_by_name("heddle.api.v1alpha2.ObserveIdentityRequest")
        .expect("identity query");
    assert!(
        request
            .get_field_by_name("include_current_credential")
            .is_some()
    );
    assert!(request.get_field_by_name("include_billing").is_some());
    let event = pool
        .get_message_by_name("heddle.api.v1alpha2.IdentityEvent")
        .expect("identity event");
    assert!(event.get_field_by_name("current_credential").is_some());
    assert!(event.get_field_by_name("billing").is_some());
    for name in ["CurrentCredentialRecord", "BillingRecord"] {
        let record = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}"))
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
        .get_message_by_name("heddle.api.v1alpha2.Money")
        .expect("money");
    assert_eq!(
        money
            .get_field_by_name("amount_minor")
            .expect("minor units")
            .kind(),
        prost_reflect::Kind::Int64
    );
    let update = pool
        .get_message_by_name("heddle.api.v1alpha2.UpdateSubscriptionRequest")
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
        .get_message_by_name("heddle.api.v1alpha2.CurrentCredentialRecord")
        .expect("current credential");
    let session = credential
        .get_field_by_name("session")
        .expect("current session");
    assert!(session.supports_presence());
    assert_eq!(session.number(), 16);
    assert_eq!(
        session.kind(),
        prost_reflect::Kind::Message(
            pool.get_message_by_name("heddle.api.v1alpha2.SessionRecord")
                .expect("original versioned session")
        )
    );
}

#[test]
fn observed_device_has_original_registry_identity_and_version() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid contract");
    let device = pool
        .get_message_by_name("heddle.api.v1alpha2.DeviceIdentity")
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
        .get_message_by_name("heddle.api.v1alpha2.RevokeDeviceRequest")
        .expect("device revocation");
    assert_eq!(
        request
            .get_field_by_name("device")
            .expect("device identity")
            .kind(),
        prost_reflect::Kind::Message(
            pool.get_message_by_name("heddle.api.v1alpha2.RecordRef")
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

#[test]
fn public_plan_preserves_tiered_pricing_and_unknown_storage() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract");
    let plan = pool
        .get_message_by_name("heddle.api.v1alpha2.BillingPlan")
        .expect("plan");
    for name in [
        "storage_bytes",
        "storage_base_bytes",
        "storage_per_seat_bytes",
    ] {
        let field = plan
            .get_field_by_name(name)
            .expect("published storage allowance");
        assert_eq!(field.kind(), prost_reflect::Kind::Uint64);
        assert!(field.supports_presence(), "unknown storage is not zero");
    }
    let pricing = pool
        .get_message_by_name("heddle.api.v1alpha2.BillingSeatPricing")
        .expect("full seat schedule");
    assert!(
        pricing
            .get_field_by_name("tiers")
            .expect("all tiers")
            .is_list()
    );
    assert!(plan.get_field_by_name("tier").is_some());
}

#[test]
fn delete_account_is_catalogued_as_an_idempotent_owner_pop_operation() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid contract");
    let service = pool
        .get_service_by_name("heddle.api.v1alpha2.IdentityService")
        .expect("identity service");
    let method = service
        .methods()
        .find(|method| method.name() == "DeleteAccount")
        .expect("DeleteAccount descriptor");
    let descriptor =
        heddle_api::v2::method_descriptor("/heddle.api.v1alpha2.IdentityService/DeleteAccount")
            .expect("DeleteAccount route in generated method catalog");
    assert_eq!(descriptor.signing_tier, SigningTier::ProofOfPossession);
    assert_eq!(descriptor.effect, RpcEffect::DurableWrite);
    assert!(descriptor.client_operation_id_required);
    assert_eq!(
        descriptor.authorization.role,
        AuthorizationRole::CallerBound
    );
    assert_eq!(
        descriptor.authorization.scope_source,
        AuthorizationScopeSource::CallerSubject
    );
    assert_eq!(
        descriptor.authorization_access,
        AuthorizationAccess::AuthenticatedPrincipal
    );
    assert!(descriptor.authorization.targets.is_empty());

    let request = method.input();
    assert_eq!(
        request
            .get_field_by_name("client_operation_id")
            .expect("idempotency key")
            .number(),
        1
    );
    assert_eq!(
        request
            .get_field_by_name("confirmation_handle")
            .expect("explicit account confirmation")
            .number(),
        2
    );
    let response = method.output();
    for (field, number) in [
        ("receipt", 1),
        ("outcome", 2),
        ("spools_deleted", 3),
        ("subscription_canceled", 4),
        ("deletion_requested_at", 5),
        ("retained_data_delete_after", 6),
    ] {
        assert_eq!(
            response
                .get_field_by_name(field)
                .unwrap_or_else(|| panic!("DeleteAccountResponse.{field}"))
                .number(),
            number
        );
    }
}

#[test]
fn billing_lock_is_shared_by_identity_and_typed_policy_denials() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid contract");
    let lock = pool
        .get_message_by_name("heddle.api.common.AccountBillingLock")
        .expect("typed account billing lock");
    for (field, number) in [
        ("reason", 1),
        ("locked_at", 2),
        ("delete_after", 3),
        ("used_bytes", 4),
        ("cap_bytes", 5),
        ("allowed_actions", 6),
    ] {
        assert_eq!(
            lock.get_field_by_name(field)
                .unwrap_or_else(|| panic!("AccountBillingLock.{field}"))
                .number(),
            number
        );
    }
    let identity = pool
        .get_message_by_name("heddle.api.v1alpha2.GetIdentityResponse")
        .expect("identity response");
    assert_eq!(
        identity
            .get_field_by_name("billing_lock")
            .expect("proactive lock status")
            .kind(),
        prost_reflect::Kind::Message(lock.clone())
    );
    let denial = pool
        .get_message_by_name("heddle.api.common.PolicyDenial")
        .expect("policy denial");
    assert_eq!(
        denial
            .get_field_by_name("billing_lock")
            .expect("denial lock status")
            .kind(),
        prost_reflect::Kind::Message(lock)
    );
}

#[test]
fn account_billing_lock_error_detail_round_trips_every_field() {
    let lock = AccountBillingLock {
        reason: AccountBillingLockReason::OverFreeCapWithoutPaidPlan as i32,
        locked_at: Some(prost_types::Timestamp {
            seconds: 1_795_000_000,
            nanos: 123_000_000,
        }),
        delete_after: Some(prost_types::Timestamp {
            seconds: 1_805_368_000,
            nanos: 456_000_000,
        }),
        used_bytes: 6_500_000_001,
        cap_bytes: 5_000_000_000,
        allowed_actions: vec![
            AccountBillingLockAllowedAction::ManageBilling as i32,
            AccountBillingLockAllowedAction::ListSpools as i32,
            AccountBillingLockAllowedAction::DeleteSpool as i32,
            AccountBillingLockAllowedAction::DeleteAccount as i32,
            AccountBillingLockAllowedAction::ExportData as i32,
        ],
    };
    let encoded = heddle_api::encode_account_billing_lock_error_detail(
        "account/00000000-0000-0000-0000-000000000237",
        lock.clone(),
    );
    let decoded = heddle_api::decode_account_billing_lock_error_detail(&encoded)
        .expect("valid ErrorDetail")
        .expect("typed billing lock");
    assert_eq!(decoded, lock, "no typed lock field may be dropped");

    let detail = ErrorDetail::decode(encoded.as_slice()).expect("detail envelope");
    assert_eq!(detail.reason, ErrorReason::PolicyDenied as i32);
    assert_eq!(
        detail.resource,
        "account/00000000-0000-0000-0000-000000000237"
    );
    let Some(error_detail::Context::Policy(policy)) = detail.context else {
        panic!("billing lock must use the existing PolicyDenial arm");
    };
    assert_eq!(policy.policy_id, heddle_api::ACCOUNT_BILLING_LOCK_POLICY_ID);
    assert!(!policy.human_verification_can_override);
    assert_eq!(policy.billing_lock.as_deref(), Some(&lock));
}
