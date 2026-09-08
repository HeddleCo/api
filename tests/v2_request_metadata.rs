use heddle_api::{
    heddle::api::v2alpha1::RenameThreadRequest,
    v2::{client::Rpc, rpc::ThreadServiceRenameThread},
};
use prost::Message;

fn request(id: &str) -> Vec<u8> {
    RenameThreadRequest {
        client_operation_id: id.into(),
        ..Default::default()
    }
    .encode_to_vec()
}

#[test]
fn metadata_and_decoded_mutation_cannot_select_different_operation_ids() {
    let method = ThreadServiceRenameThread::METHOD;
    let valid = request("first");
    assert_eq!(method.client_operation_id(&valid).expect("valid metadata"), Some("first"));
    let mut ambiguous = valid.clone();
    ambiguous.extend(request("second"));
    assert_eq!(RenameThreadRequest::decode(ambiguous.as_slice()).expect("valid protobuf merge").client_operation_id, "second");
    assert!(method.client_operation_id(&ambiguous).is_err(), "reject ambiguous mutation identity before dispatch");
    let mut duplicate = valid.clone();
    duplicate.extend(valid);
    assert!(method.client_operation_id(&duplicate).is_err(), "identical duplicate fields are ambiguous too");
}

#[test]
fn metadata_validates_the_whole_envelope_and_operation_id_wire_type() {
    let method = ThreadServiceRenameThread::METHOD;
    for suffix in [&[0xff][..], &[0x00], &[0x08, 0x01], &[0x12, 0xff]] {
        let mut malformed = request("first");
        malformed.extend(suffix);
        assert!(method.client_operation_id(&malformed).is_err(), "invalid tail {suffix:?} must not be hidden by an earlier operation ID");
    }
    assert!(method.client_operation_id(&[0x08, 0x01]).is_err(), "operation ID must be length-delimited");
    assert_eq!(method.client_operation_id(&[]).expect("empty message"), None);
    let mut with_unknown = request("first");
    with_unknown.extend([0xa0, 0x06, 0x01]);
    assert_eq!(method.client_operation_id(&with_unknown).expect("valid unknown field"), Some("first"));
}
