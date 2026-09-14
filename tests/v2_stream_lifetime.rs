#![cfg(feature = "reflection")]

use heddle_api::FILE_DESCRIPTOR_SET;
use prost_reflect::{DescriptorPool, Value};

#[test]
fn live_observations_and_replication_are_distinct_from_finite_resumable_transfers() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptors");
    let option = pool
        .get_extension_by_name("heddle.api.v1alpha1.rpc_contract")
        .expect("RPC contract");
    let mut live_count = 0;
    let mut finite_count = 0;
    for service in pool
        .services()
        .filter(|service| service.package_name() == "heddle.api.v2alpha1")
    {
        for method in service.methods() {
            let expected =
                method.name().starts_with("Observe") || method.name() == "ReplicateThread";
            let options = method.options();
            let contract = options.get_extension(&option);
            let Value::Message(contract) = contract.as_ref() else {
                panic!("contract message")
            };
            let live = contract
                .get_field_by_name("live_stream")
                .expect("explicit stream-lifetime vocabulary");
            assert_eq!(
                live.as_ref(),
                &Value::Bool(expected),
                "{}.{} stream lifetime",
                service.name(),
                method.name()
            );
            let path = format!("/{}/{}", service.full_name(), method.name());
            assert_eq!(
                heddle_api::v2::method_descriptor(&path)
                    .expect("generated descriptor")
                    .live_stream,
                expected,
                "generated lifetime must match the schema"
            );
            if expected {
                live_count += 1;
                assert!(
                    method.method_descriptor_proto().server_streaming(),
                    "live methods produce a response stream"
                );
            } else {
                finite_count += 1;
            }
        }
    }
    assert!(live_count > 10, "every observation family participates");
    assert!(
        finite_count > 50,
        "finite operations retain bounded progress"
    );
}
