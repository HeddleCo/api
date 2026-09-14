use ed25519_dalek::{Signer, SigningKey};
use heddle_api::{
    heddle::api::v1alpha1::{CallContext, RequestProof},
    request_proof::{RequestProofError, verify_native_request_proof},
    v2::method_descriptor,
};
use prost::Message;

#[test]
fn provider_request_proof_binds_exact_method_body_key_and_time() {
    let method = method_descriptor("/heddle.api.v2alpha1.SyncService/ReadProviderExtent")
        .expect("provider method");
    let body =
        heddle_api::heddle::api::v2alpha1::ReadProviderExtentRequest::default().encode_to_vec();
    let key = SigningKey::from_bytes(&[17; 32]);
    let public = key.verifying_key().to_bytes();
    let identity = format!("principal:device-key:{}", hex::encode(public));
    let nonce = vec![8; 16];
    let timestamp = 1_700_000_000_000_i64;
    let signature = key.sign(&heddle_api::signing::unary_bytes(
        &identity,
        method.path,
        timestamp,
        &nonce,
        &body,
    ));
    let context = CallContext {
        request_proof: Some(RequestProof {
            algorithm: "ed25519".into(),
            signing_identity: identity,
            nonce: nonce.clone(),
            timestamp_millis: timestamp,
            signature: signature.to_bytes().to_vec(),
        }),
        ..Default::default()
    };
    let verified = verify_native_request_proof(&context, method, &body, &public, timestamp)
        .expect("exact request proof");
    assert_eq!(verified.nonce, nonce);
    let mut changed = body.clone();
    changed.extend([0xa0, 0x06, 1]);
    assert!(matches!(
        verify_native_request_proof(&context, method, &changed, &public, timestamp),
        Err(RequestProofError::Signature)
    ));
    assert!(matches!(
        verify_native_request_proof(&context, method, &body, &[18; 32], timestamp),
        Err(RequestProofError::Identity)
    ));
    assert!(matches!(
        verify_native_request_proof(&context, method, &body, &public, timestamp + 60_001),
        Err(RequestProofError::InvalidProof)
    ));
}
