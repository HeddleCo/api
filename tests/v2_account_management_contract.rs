#![cfg(feature = "reflection")]

use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::common::{
        AuthorizationAccess, AuthorizationExistence, AuthorizationRole, AuthorizationScopeSource,
        CapabilityArea, RetryBehavior, RpcEffect, SigningTier, StableSigningIdentity,
    },
    v2::method_descriptor,
};
use prost_reflect::{DescriptorPool, Kind, Value};

#[test]
fn account_commands_are_signed_receipt_backed_and_caller_bound() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled contract");
    let service = pool
        .get_service_by_name("heddle.api.v1alpha2.IdentityService")
        .expect("identity service");
    let extension = pool
        .get_extension_by_name("heddle.api.common.rpc_contract")
        .expect("contract option");
    for name in [
        "RemovePasskey",
        "SetDisplayName",
        "SetPrimaryHandle",
        "RemoveHandle",
    ] {
        let method = service
            .methods()
            .find(|method| method.name() == name)
            .unwrap_or_else(|| panic!("missing identity RPC: {name}"));
        let route = method_descriptor(&format!("/heddle.api.v1alpha2.IdentityService/{name}"))
            .expect("generated route");
        assert_eq!(
            route.signing_identity,
            StableSigningIdentity::AuthenticatedPrincipal
        );
        assert_eq!(route.signing_tier, SigningTier::ProofOfPossession);
        assert_eq!(route.effect, RpcEffect::DurableWrite);
        assert_eq!(route.retry_behavior, RetryBehavior::ClientOperationId);
        assert!(route.client_operation_id_required);
        assert_eq!(route.client_operation_id_field_number, Some(1));
        assert_eq!(
            route.authorization_access,
            AuthorizationAccess::AuthenticatedPrincipal
        );
        assert_eq!(route.authorization.role, AuthorizationRole::CallerBound);
        assert_eq!(
            route.authorization.scope_source,
            AuthorizationScopeSource::CallerSubject
        );
        assert_eq!(route.authorization.existence, AuthorizationExistence::Hide);
        assert!(route.authorization.targets.is_empty());
        let options = method.options();
        let contract = options.get_extension(&extension);
        let Value::Message(contract) = contract.as_ref() else {
            panic!("contract message");
        };
        for (field, expected) in [
            ("capability", CapabilityArea::IdentityAndCredentials as i32),
            ("signing_tier", SigningTier::ProofOfPossession as i32),
            ("effect", RpcEffect::DurableWrite as i32),
            (
                "authorization_existence",
                AuthorizationExistence::Hide as i32,
            ),
        ] {
            assert_eq!(
                contract.get_field_by_name(field).expect(field).as_ref(),
                &Value::EnumNumber(expected)
            );
        }
        let receipt = method
            .output()
            .get_field_by_name("receipt")
            .expect("receipt");
        assert_eq!(receipt.number(), 1);
        assert_eq!(
            receipt.kind(),
            Kind::Message(
                pool.get_message_by_name("heddle.api.v1alpha2.MutationReceipt")
                    .expect("receipt type")
            )
        );
        assert_eq!(
            method
                .input()
                .get_field_by_name("expected_version")
                .expect("CAS")
                .number(),
            3
        );
    }
}

#[test]
fn identity_metadata_is_additive_and_session_filter_preserves_the_default() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled contract");
    for (message, fields) in [
        (
            "PasskeyRecord",
            vec![
                ("created_at", 6),
                ("last_used_at", 7),
                ("aaguid", 8),
                ("authenticator_name", 9),
            ],
        ),
        (
            "CurrentCredentialRecord",
            vec![("passkey_credential_id", 18)],
        ),
        (
            "SessionRecord",
            vec![("user_agent", 8), ("device_label", 11)],
        ),
        (
            "PrincipalRecord",
            vec![("actions", 9), ("display_name", 12)],
        ),
        (
            "ObserveIdentityRequest",
            vec![("sessions", 2), ("session_state", 10)],
        ),
    ] {
        let descriptor = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
            .expect(message);
        for (field, tag) in fields {
            assert_eq!(
                descriptor.get_field_by_name(field).expect(field).number(),
                tag
            );
        }
    }
    for (message, field) in [
        ("PasskeyRecord", "aaguid"),
        ("PasskeyRecord", "authenticator_name"),
        ("SessionRecord", "device_label"),
        ("CurrentCredentialRecord", "passkey_credential_id"),
    ] {
        assert!(
            pool.get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
                .expect(message)
                .get_field_by_name(field)
                .expect(field)
                .supports_presence()
        );
    }
    let filter = pool
        .get_enum_by_name("heddle.api.v1alpha2.SessionStateFilter")
        .expect("session filter");
    assert_eq!(
        filter
            .values()
            .map(|v| (v.name().to_owned(), v.number()))
            .collect::<Vec<_>>(),
        [
            ("SESSION_STATE_FILTER_UNSPECIFIED".into(), 0),
            ("SESSION_STATE_FILTER_ACTIVE".into(), 1),
            ("SESSION_STATE_FILTER_ENDED".into(), 2),
            ("SESSION_STATE_FILTER_ALL".into(), 3),
        ]
    );
}
