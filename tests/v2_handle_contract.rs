#![cfg(feature = "reflection")]
use heddle_api::FILE_DESCRIPTOR_SET;
use prost_reflect::DescriptorPool;

#[test]
fn public_handle_resolution_never_exposes_stable_subject_or_hold_owner_identity() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid contract");
    for name in ["HandleResolution", "PublicHandleRecord"] {
        let record = pool
            .get_message_by_name(&format!("heddle.api.v2alpha1.{name}"))
            .expect("public handle view");
        for field in [
            "principal_id",
            "subject",
            "account_id",
            "owner_id",
            "held_for_subject",
        ] {
            assert!(
                record.get_field_by_name(field).is_none(),
                "{name}.{field} would disclose a private identity"
            );
        }
    }
    let resolution = pool
        .get_message_by_name("heddle.api.v2alpha1.HandleResolution")
        .expect("resolution");
    for field in ["public_handle", "held_for_verified_owner", "tombstoned"] {
        assert!(resolution.get_field_by_name(field).is_some());
    }
}

#[test]
fn held_name_requests_return_the_authoritative_deadline_and_claims_return_canonical_metadata() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid contract");
    let service = pool
        .get_service_by_name("heddle.api.v2alpha1.IdentityService")
        .expect("identity service");
    let held = service
        .methods()
        .find(|method| method.name() == "RequestHeldHandle")
        .expect("held name action");
    assert!(
        held.input()
            .get_field_by_name("client_operation_id")
            .is_some()
    );
    assert!(held.output().get_field_by_name("receipt").is_some());
    assert!(
        held.output()
            .get_field_by_name("right_of_first_refusal_deadline")
            .is_some()
    );
    let claim = service
        .methods()
        .find(|method| method.name() == "ClaimHandle")
        .expect("claim action");
    assert!(claim.output().get_field_by_name("public_handle").is_some());
    assert!(claim.output().get_field_by_name("receipt").is_some());
}
