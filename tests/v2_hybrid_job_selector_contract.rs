use heddle_api::heddle::api::v1alpha2::{OperationRecord, operation_subject};
use heddle_api::import_authority::{
    Reject, import_job_state_request_from_operation, validate_hybrid_import_job_selector,
};
use prost::Message;

#[test]
fn hybrid_operation_job_selector_wire_and_projection_match_shared_vectors() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/hybrid-job-selector-v1.json"))
            .expect("shared selector fixture");
    for vector in fixture["operations"].as_array().expect("operation vectors") {
        let name = vector["name"].as_str().expect("vector name");
        let wire = hex::decode(vector["wire_hex"].as_str().expect("wire hex"))
            .expect("valid operation bytes");
        let operation = OperationRecord::decode(wire.as_slice()).expect("operation decodes");
        assert_eq!(operation.encode_to_vec(), wire, "wire round trip: {name}");
        if let Some(operation_subject::Subject::Import(subject)) = operation
            .subject
            .as_ref()
            .and_then(|subject| subject.subject.as_ref())
            && let Some(selector) = subject.hybrid_job.as_ref()
        {
            let expected = if vector["expected"] == "Canonical" {
                Err(Reject::Canonical)
            } else {
                Ok(())
            };
            assert_eq!(
                validate_hybrid_import_job_selector(selector),
                expected,
                "shape: {name}"
            );
        }
        let result = import_job_state_request_from_operation(&operation);
        match vector["expected"].as_str().expect("expected result") {
            "OK" => {
                let request = result
                    .expect("valid projection")
                    .expect("available selector");
                assert_eq!(
                    hex::encode(request.encode_to_vec()),
                    vector["request_wire_hex"].as_str().expect("request bytes"),
                    "destination/job projection: {name}"
                );
            }
            "unavailable" => assert_eq!(result, Ok(None), "{name}"),
            "Canonical" => assert_eq!(result, Err(Reject::Canonical), "{name}"),
            "Scope" => assert_eq!(result, Err(Reject::Scope), "{name}"),
            expected => panic!("unknown expectation: {expected}"),
        }
    }
}

#[cfg(feature = "reflection")]
#[test]
fn hybrid_job_selector_has_typed_stable_placement() {
    use prost_reflect::{DescriptorPool, Kind};
    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("descriptor");
    let subject = pool
        .get_message_by_name("heddle.api.v1alpha2.ImportOperationSubject")
        .expect("import subject");
    let field = subject.get_field(4).expect("selector field");
    assert_eq!(field.name(), "hybrid_job");
    assert!(field.supports_presence());
    let Kind::Message(selector) = field.kind() else {
        panic!("typed selector message");
    };
    assert_eq!(
        selector.full_name(),
        "heddle.api.v1alpha2.HybridImportJobSelector"
    );
    assert_eq!(selector.fields().count(), 1);
    let id = selector.get_field(1).expect("logical job ID");
    assert_eq!(id.name(), "logical_job_id");
    assert_eq!(id.kind(), Kind::Bytes);
}
