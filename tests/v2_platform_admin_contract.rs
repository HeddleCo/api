#![cfg(feature = "reflection")]

use heddle_api::{
    FILE_DESCRIPTOR_SET, StreamingShape,
    heddle::api::{
        common::{
            AuthorizationAccess, AuthorizationExistence, AuthorizationRole,
            AuthorizationScopeSource, CapabilityArea, DeploymentTarget, RetryBehavior, RpcEffect,
            ServiceMaturity, SigningTier, StableSigningIdentity,
        },
        v1alpha2::{Capability, PlatformAuthorizationRequest, PlatformAuthorizationResponse},
    },
    v2::{self, client::UnaryRpc, rpc},
};
use prost_reflect::{DescriptorPool, Kind, Value};

#[test]
fn platform_admin_descriptor_pins_all_four_authorization_checks() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    let service = pool
        .get_service_by_name("heddle.api.v1alpha2.PlatformAdminService")
        .expect("platform service");
    let service_extension = pool
        .get_extension_by_name("heddle.api.common.service_contract")
        .expect("service contract");
    let options = service.options();
    let contract = options.get_extension(&service_extension);
    let Value::Message(contract) = contract.as_ref() else {
        panic!("service contract message");
    };
    assert_eq!(
        contract
            .get_field_by_name("deployment_targets")
            .expect("deployments")
            .as_ref(),
        &Value::List(vec![Value::EnumNumber(DeploymentTarget::Weft as i32)])
    );
    assert_eq!(
        contract
            .get_field_by_name("maturity")
            .expect("maturity")
            .as_ref(),
        &Value::EnumNumber(ServiceMaturity::Planned as i32)
    );
    assert_eq!(service.methods().len(), 4);
    let extension = pool
        .get_extension_by_name("heddle.api.common.rpc_contract")
        .expect("RPC contract");
    for name in [
        "AuthorizeEmailTemplates",
        "AuthorizeEmailDelivery",
        "AuthorizeAnalytics",
        "AuthorizeInvitationDirectory",
    ] {
        let method = service
            .methods()
            .find(|method| method.name() == name)
            .expect(name);
        assert!(!method.is_client_streaming());
        assert!(!method.is_server_streaming());
        assert_eq!(
            method.input().full_name(),
            "heddle.api.v1alpha2.PlatformAuthorizationRequest"
        );
        assert_eq!(
            method.output().full_name(),
            "heddle.api.v1alpha2.PlatformAuthorizationResponse"
        );
        let options = method.options();
        assert!(
            options.has_extension(&extension),
            "{name}: required contract"
        );
        let contract = options.get_extension(&extension);
        let Value::Message(contract) = contract.as_ref() else {
            panic!("RPC contract message");
        };
        for (field, expected) in [
            (
                "signing_identity",
                StableSigningIdentity::AuthenticatedPrincipal as i32,
            ),
            ("signing_tier", SigningTier::ProofOfPossession as i32),
            ("effect", RpcEffect::ReadOnly as i32),
            ("retry_behavior", RetryBehavior::Safe as i32),
            ("capability", CapabilityArea::PlatformAdministration as i32),
            (
                "authorization_access",
                AuthorizationAccess::AuthenticatedPrincipal as i32,
            ),
            (
                "authorization_role",
                AuthorizationRole::GlobalAdministrator as i32,
            ),
            (
                "authorization_scope_source",
                AuthorizationScopeSource::CallerGrants as i32,
            ),
            (
                "authorization_existence",
                AuthorizationExistence::Hide as i32,
            ),
        ] {
            assert_eq!(
                contract.get_field_by_name(field).expect(field).as_ref(),
                &Value::EnumNumber(expected),
                "{name}: {field}"
            );
        }
        let path = format!("/heddle.api.v1alpha2.PlatformAdminService/{name}");
        let route = v2::method_descriptor(&path).expect("generated v2 route");
        assert_eq!(
            route.authorization.role,
            AuthorizationRole::GlobalAdministrator,
            "{name}: route role"
        );
        assert_eq!(
            route.authorization.existence,
            AuthorizationExistence::Hide,
            "{name}: route existence"
        );
        assert_eq!(
            route.authorization.scope_source,
            AuthorizationScopeSource::CallerGrants
        );
        assert_eq!(
            route.authorization_access,
            AuthorizationAccess::AuthenticatedPrincipal
        );
        assert_eq!(
            route.signing_identity,
            StableSigningIdentity::AuthenticatedPrincipal
        );
        assert_eq!(route.signing_tier, SigningTier::ProofOfPossession);
        assert_eq!(route.effect, RpcEffect::ReadOnly);
        assert_eq!(route.retry_behavior, RetryBehavior::Safe);
        assert_eq!(route.streaming, StreamingShape::Unary);
        assert_eq!(route.deployment_targets, &[DeploymentTarget::Weft]);
        assert_eq!(route.maturity, ServiceMaturity::Planned);
        assert!(route.authorization.targets.is_empty());
        assert!(!route.client_operation_id_required);
        assert_eq!(route.client_operation_id_field_number, None);
        let transport = heddle_api::method_descriptor(&path).expect("transport export");
        assert_eq!(transport.input, route.input);
        assert_eq!(transport.output, route.output);
        assert_eq!(transport.deployment_targets, &[DeploymentTarget::Weft]);
    }
    let request = pool
        .get_message_by_name("heddle.api.v1alpha2.PlatformAuthorizationRequest")
        .expect("request");
    assert_eq!(request.fields().len(), 0);
    let response = pool
        .get_message_by_name("heddle.api.v1alpha2.PlatformAuthorizationResponse")
        .expect("response");
    assert_eq!(response.fields().len(), 1);
    let action = response.get_field_by_name("action").expect("action");
    assert_eq!(action.number(), 1);
    assert_eq!(
        action.kind(),
        Kind::Message(
            pool.get_message_by_name("heddle.api.v1alpha2.ActionAvailability")
                .expect("availability")
        )
    );
    for (capability, number) in [
        (Capability::PlatformEmailTemplates, 6),
        (Capability::PlatformEmailDelivery, 7),
        (Capability::PlatformAnalytics, 8),
        (Capability::PlatformInvitationDirectory, 9),
    ] {
        assert_eq!(capability as i32, number);
    }
    assert_eq!(CapabilityArea::PlatformAdministration as i32, 17);
}

#[test]
fn rust_clients_expose_all_platform_checks_as_typed_unary_operations() {
    fn typed<
        M: UnaryRpc<Request = PlatformAuthorizationRequest, Response = PlatformAuthorizationResponse>,
    >() {
    }
    typed::<rpc::PlatformAdminServiceAuthorizeEmailTemplates>();
    typed::<rpc::PlatformAdminServiceAuthorizeEmailDelivery>();
    typed::<rpc::PlatformAdminServiceAuthorizeAnalytics>();
    typed::<rpc::PlatformAdminServiceAuthorizeInvitationDirectory>();
}
