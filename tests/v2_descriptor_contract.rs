//! The candidate generation must not weaken the frozen v1 contract audit.
#![cfg(feature = "reflection")]

use std::collections::BTreeSet;

use heddle_api::heddle::api::v1alpha1::{RpcEffect, ServiceMaturity};
use heddle_api::v2::ALL_METHODS;
use heddle_api::{FILE_DESCRIPTOR_SET, StreamingShape};
use prost_reflect::{DescriptorPool, DynamicMessage, Kind, MessageDescriptor, Value};

fn field_path(mut message: MessageDescriptor, path: &str) {
    let mut parts = path.split('.').peekable();
    while let Some(part) = parts.next() {
        let field = message
            .get_field_by_name(part)
            .unwrap_or_else(|| panic!("missing target {path} in {}", message.full_name()));
        if parts.peek().is_some() {
            let Kind::Message(child) = field.kind() else {
                panic!("non-message in target {path}");
            };
            message = child;
        }
    }
}

fn option_message(value: &Value) -> &DynamicMessage {
    let Value::Message(value) = value else {
        panic!("contract option must be a message");
    };
    value
}

#[test]
fn every_candidate_route_has_metadata_and_resolvable_authorization_targets() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    let service_contract = pool
        .get_extension_by_name("heddle.api.v1alpha1.service_contract")
        .expect("service contract");
    let rpc_contract = pool
        .get_extension_by_name("heddle.api.v1alpha1.rpc_contract")
        .expect("RPC contract");
    let mut declared = BTreeSet::new();
    let mut services = BTreeSet::new();
    for service in pool
        .services()
        .filter(|service| service.package_name() == "heddle.api.v2alpha1")
    {
        assert!(
            service.options().has_extension(&service_contract),
            "{}",
            service.full_name()
        );
        services.insert(service.name().to_owned());
        for method in service.methods() {
            let path = format!("/{}/{}", service.full_name(), method.name());
            assert!(declared.insert(path.clone()), "duplicate {path}");
            let options = method.options();
            assert!(
                options.has_extension(&rpc_contract),
                "missing contract for {path}"
            );
            let extension = options.get_extension(&rpc_contract);
            let contract = option_message(extension.as_ref());
            for name in [
                "effect",
                "retry_behavior",
                "signing_tier",
                "authorization_access",
                "authorization_role",
                "authorization_scope_source",
                "authorization_existence",
            ] {
                let value = contract.get_field_by_name(name).expect("contract field");
                assert!(
                    matches!(value.as_ref(), Value::EnumNumber(number) if *number > 0),
                    "{path}: unspecified {name}"
                );
            }
            let targets = contract
                .get_field_by_name("authorization_request_targets")
                .expect("targets");
            let Value::List(targets) = targets.as_ref() else {
                panic!("target list");
            };
            for target in targets {
                let target = option_message(target);
                let target_path = target.get_field_by_name("path").expect("path");
                let Value::String(target_path) = target_path.as_ref() else {
                    panic!("target path string");
                };
                assert!(!target_path.is_empty(), "{path}: empty guard path");
                field_path(method.input(), target_path);
            }
            let multi = contract
                .get_field_by_name("authorization_multi_target")
                .expect("multi-target");
            assert_eq!(
                multi.as_ref(),
                &Value::Bool(targets.len() > 1),
                "{path}: multi-target declaration"
            );
        }
    }
    for required in [
        "IdentityService",
        "SpoolService",
        "OwnerAuthorizationService",
        "ThreadService",
        "CollaborationService",
        "AnalysisService",
        "ContentService",
        "CheckoutService",
        "RunService",
        "SyncService",
        "WorkspaceService",
        "SearchService",
        "AttentionService",
        "NotificationService",
        "OperationService",
    ] {
        assert!(
            services.contains(required),
            "missing complete API domain {required}"
        );
    }
    let generated: BTreeSet<_> = ALL_METHODS
        .iter()
        .map(|method| method.path.to_owned())
        .collect();
    assert_eq!(
        declared, generated,
        "generation may not silently omit methods"
    );
    assert!(
        !declared.is_empty(),
        "metadata coverage must not pass vacuously"
    );
}

#[test]
fn observations_are_streamed_and_candidates_are_never_advertised_as_shipped() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    let mut observations = 0;
    for method in ALL_METHODS {
        assert_eq!(method.maturity, ServiceMaturity::Planned, "{}", method.path);
        assert!(!method.deployment_targets.is_empty(), "{}", method.path);
        if method
            .path
            .rsplit('/')
            .next()
            .expect("method name")
            .starts_with("Observe")
        {
            observations += 1;
            assert_eq!(
                method.streaming,
                StreamingShape::ServerStreaming,
                "{}",
                method.path
            );
            assert_eq!(method.effect, RpcEffect::ReadOnly, "{}", method.path);
            let response = pool
                .get_message_by_name(method.output)
                .expect("observation response");
            let frame = response
                .get_field_by_name("frame")
                .expect("shared frame metadata");
            let Kind::Message(frame) = frame.kind() else {
                panic!("typed stream frame");
            };
            assert_eq!(frame.full_name(), "heddle.api.v2alpha1.StreamFrame");
            assert!(response.oneofs().any(|oneof| oneof.name() == "payload"));
        }
        if method.client_operation_id_required {
            assert!(
                method.client_operation_id_field_number.is_some(),
                "{}",
                method.path
            );
        }
    }
    assert!(observations >= 10, "live coverage must span the product");
}
