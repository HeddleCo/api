#![cfg(feature = "reflection")]

use heddle_api::FILE_DESCRIPTOR_SET;
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn registration_carries_admission_device_binding_and_original_owner_proofs() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled contract");
    let message = |name: &str| {
        pool.get_message_by_name(&format!("heddle.api.v2alpha1.{name}"))
            .expect("registration message")
    };
    let begin = message("BeginRegistrationRequest");
    assert_eq!(
        begin
            .get_field_by_name("caller_public_key")
            .expect("one device key")
            .kind(),
        Kind::Bytes
    );
    let admission = begin
        .oneofs()
        .find(|o| o.name() == "signup_admission")
        .expect("exclusive signup admission");
    assert_eq!(
        admission
            .fields()
            .map(|f| f.name().to_owned())
            .collect::<Vec<_>>(),
        ["invitation_reservation", "verified_email"]
    );
    let service = pool
        .get_service_by_name("heddle.api.v2alpha1.IdentityService")
        .expect("identity service");
    assert_eq!(
        service
            .methods()
            .find(|m| m.name() == "BeginRegistration")
            .expect("begin")
            .output(),
        message("RegistrationChallenge")
    );
    for name in [
        "account_id",
        "relying_party_name",
        "owner_binding_nonce",
        "device_binding_challenge",
    ] {
        assert!(
            message("RegistrationChallenge")
                .get_field_by_name(name)
                .is_some(),
            "{name} must arrive without another RPC"
        );
    }
    let complete = message("CompleteRegistrationRequest");
    for (field, ty) in [
        ("passkey", "PasskeyRegistration"),
        ("device_binding", "PasskeyProof"),
        ("establish_owner", "OwnerRegistration"),
        ("claim_owner", "SignedOwnerKeyTransition"),
    ] {
        assert_eq!(
            complete.get_field_by_name(field).expect(field).kind(),
            Kind::Message(message(ty))
        );
    }
    assert_eq!(
        complete
            .get_field_by_name("caller_public_key")
            .expect("completion proves selected key")
            .kind(),
        Kind::Bytes
    );
    assert!(
        complete.get_field_by_name("possession_proof").is_none(),
        "exact CallContext proof is the device possession proof"
    );
    assert!(
        complete.get_field_by_name("root").is_none(),
        "a generic attachment cannot replace the signed owner ceremony"
    );
}
