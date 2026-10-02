#![cfg(feature = "reflection")]

use heddle_api::FILE_DESCRIPTOR_SET;
use prost_reflect::DescriptorPool;

#[test]
fn hybrid_messages_and_rpc_are_present_in_the_descriptor() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/import-authority-host-witness-v1.json"
    ))
    .expect("shared conformance fixture");
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor");
    for name in fixture["messages"].as_array().expect("message inventory") {
        let name = name.as_str().expect("message name");
        assert!(pool.get_message_by_name(name).is_some(), "missing {name}");
    }
    let service = pool
        .get_service_by_name("heddle.api.v1alpha2.IntegrationService")
        .expect("integration service");
    for name in ["PrepareImportJob", "CommitImportJob", "RenewImportJob", "CancelImportJob", "GetHostedWitnessHistoryProof"] {
        assert!(service.methods().any(|m| m.name() == name), "missing {name}");
    }
}
