#![cfg(feature = "reflection")]

use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::common::{RetryBehavior, RpcEffect, SigningTier},
    v2::method_descriptor,
};
use prost_reflect::{DescriptorPool, Value};

#[test]
fn spool_deletion_requires_per_request_human_verification_in_both_descriptors() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/unary-signing-human-alpha43.json"))
            .expect("human signing fixture");
    assert_eq!(fixture["signing_tier"], "HUMAN_VERIFICATION");
    let route = fixture["route"].as_str().expect("fixture route");
    assert_eq!(
        method_descriptor(route)
            .expect("fixture method")
            .signing_tier,
        SigningTier::HumanVerification,
    );
    let frozen: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/unary-signing-v1.json"))
            .expect("frozen signing fixture");
    for (key, value) in frozen.as_object().expect("frozen vector object") {
        assert_eq!(&fixture[key], value, "frozen field {key}");
    }
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    let extension = pool
        .get_extension_by_name("heddle.api.common.rpc_contract")
        .expect("RPC contract extension");
    let service = pool
        .get_service_by_name("heddle.api.v1alpha2.SpoolService")
        .expect("Spool service");
    for name in ["DeleteSpool", "PutGrant", "PutReviewPolicy"] {
        let path = format!("/heddle.api.v1alpha2.SpoolService/{name}");
        let generated = method_descriptor(&path).expect("generated Spool method");
        assert_eq!(
            generated.signing_tier,
            SigningTier::HumanVerification,
            "{path}"
        );
        assert_eq!(generated.effect, RpcEffect::DurableWrite);
        assert_eq!(generated.retry_behavior, RetryBehavior::ClientOperationId);
        let method = service
            .methods()
            .find(|method| method.name() == name)
            .expect("Spool RPC");
        let options = method.options();
        let contract = options.get_extension(&extension);
        let Value::Message(contract) = contract.as_ref() else {
            panic!("RPC contract message");
        };
        assert_eq!(
            contract
                .get_field_by_name("signing_tier")
                .expect("signing tier")
                .as_ref(),
            &Value::EnumNumber(SigningTier::HumanVerification as i32),
            "{path}",
        );
    }
}
