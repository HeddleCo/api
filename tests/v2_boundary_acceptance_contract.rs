//! Transport preservation only: receipt basis and authority validation are consumer work.
#![cfg(feature = "reflection")]

use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::v2alpha1::{
        RecordSignature, ReplicationOperations, SignedRecord, ThreadGenesisRecord,
    },
};
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage};

fn evidence() -> SignedRecord {
    SignedRecord {
        format: "heddle-original-boundary-acceptance-v1".into(),
        canonical_record: vec![0, 255, 19, 72],
        signatures: vec![RecordSignature {
            public_key: vec![7; 32],
            signature: vec![9; 64],
        }],
    }
}

#[test]
fn boundary_evidence_fields_are_additive_and_preserve_populated_signed_records() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor");
    for (name, number) in [("ReplicationOperations", 3), ("ThreadGenesisRecord", 6)] {
        let descriptor = pool
            .get_message_by_name(&format!("heddle.api.v2alpha1.{name}"))
            .expect("carrier");
        let field = descriptor
            .get_field_by_name("boundary_acceptances")
            .expect("boundary evidence field");
        assert_eq!(field.number(), number);
        assert!(field.is_list());
        assert_eq!(
            field
                .kind()
                .as_message()
                .expect("signed evidence")
                .full_name(),
            "heddle.api.v2alpha1.SignedRecord"
        );
    }
    let batch = ReplicationOperations {
        operations: vec![SignedRecord {
            format: "unchanged-original".into(),
            ..evidence()
        }],
        authority_admissions: vec![SignedRecord {
            format: "unchanged-receipt".into(),
            ..evidence()
        }],
        boundary_acceptances: vec![evidence()],
    };
    let bytes = batch.encode_to_vec();
    let dynamic = DynamicMessage::decode(
        pool.get_message_by_name("heddle.api.v2alpha1.ReplicationOperations")
            .expect("batch"),
        bytes.as_slice(),
    )
    .expect("dynamic decode");
    assert_eq!(
        ReplicationOperations::decode(dynamic.encode_to_vec().as_slice())
            .expect("generated mapping"),
        batch
    );
    let wrapper = ThreadGenesisRecord {
        genesis: Some(evidence()),
        creator_authority: vec![11; 17],
        admission: Some(evidence()),
        ownership_claims: vec![evidence()],
        ownership_claim_admissions: vec![evidence()],
        boundary_acceptances: vec![evidence()],
    };
    let bytes = wrapper.encode_to_vec();
    let dynamic = DynamicMessage::decode(
        pool.get_message_by_name("heddle.api.v2alpha1.ThreadGenesisRecord")
            .expect("wrapper"),
        bytes.as_slice(),
    )
    .expect("dynamic decode");
    assert_eq!(
        ThreadGenesisRecord::decode(dynamic.encode_to_vec().as_slice()).expect("generated mapping"),
        wrapper
    );
}
