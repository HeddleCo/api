#![cfg(feature = "reflection")]

use heddle_api::FILE_DESCRIPTOR_SET;
use prost_reflect::{DescriptorPool, Kind};

fn field_type(pool: &DescriptorPool, message: &str, field: &str) -> String {
    let message = pool
        .get_message_by_name(&format!("heddle.api.v2alpha1.{message}"))
        .expect("v2 request exists");
    let field = message
        .get_field_by_name(field)
        .expect("typed field exists");
    let Kind::Message(target) = field.kind() else {
        panic!("evidence must be a typed message");
    };
    target.full_name().to_owned()
}

#[test]
fn root_bootstrap_targets_a_principal_without_requiring_a_spool() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract descriptors");
    let bootstrap = pool
        .get_message_by_name("heddle.api.v2alpha1.BootstrapOwnershipRequest")
        .expect("bootstrap request");
    assert!(bootstrap.get_field_by_name("spool").is_none());
    assert_eq!(
        field_type(&pool, "BootstrapOwnershipRequest", "owner"),
        "heddle.api.v2alpha1.PrincipalRef"
    );
    assert_eq!(
        field_type(&pool, "BootstrapOwnershipRequest", "root"),
        "heddle.api.v2alpha1.SignedOwnerRoot"
    );
    assert_eq!(
        field_type(&pool, "BootstrapOwnershipRequest", "binding"),
        "heddle.api.v2alpha1.OwnerKeyBinding"
    );
}

#[test]
fn owner_transitions_keep_distinct_rotation_recovery_and_policy_intent() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract descriptors");
    let request = pool
        .get_message_by_name("heddle.api.v2alpha1.SubmitOwnerTransitionRequest")
        .expect("transition request");
    assert!(request.get_field_by_name("spool").is_none());
    assert!(request.get_field_by_name("expected_version").is_none());
    let action = request
        .oneofs()
        .find(|oneof| oneof.name() == "action")
        .expect("explicit transition action");
    let fields: Vec<_> = action
        .fields()
        .map(|field| field.name().to_owned())
        .collect();
    assert_eq!(fields, ["rotation", "recovery", "recovery_policy_change"]);
    for field in fields {
        assert_eq!(
            field_type(&pool, "SubmitOwnerTransitionRequest", &field),
            "heddle.api.v2alpha1.SignedOwnerKeyTransition"
        );
    }
    assert_eq!(
        field_type(&pool, "TransferOwnershipRequest", "transfer"),
        "heddle.api.v2alpha1.ResourceOwnershipTransfer"
    );
}
