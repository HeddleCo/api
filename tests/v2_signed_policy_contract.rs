use heddle_api::heddle::api::common::{
    AuthorizationExistence, AuthorizationRole, DeploymentTarget, RetryBehavior, RpcEffect,
    SigningTier,
};
use heddle_api::heddle::api::v1alpha2::{
    Audience, SignedPolicyBody, SignedPolicyHead, SignedPolicyMergeSemantics, SignedSpoolPolicy,
    SignedSpoolPolicyRecord, SpoolSection, SubmitSignedPolicyRequest, spool_event,
};
use heddle_api::v2::method_descriptor;
use prost::Message;

#[test]
fn submit_signed_policy_is_owner_gated_weft_write() {
    let method = method_descriptor("/heddle.api.v1alpha2.SpoolService/SubmitSignedPolicy")
        .expect("SubmitSignedPolicy");
    assert_eq!(method.effect, RpcEffect::DurableWrite);
    assert_eq!(method.retry_behavior, RetryBehavior::ClientOperationId);
    assert_eq!(method.signing_tier, SigningTier::ProofOfPossession);
    assert_eq!(method.authorization.role, AuthorizationRole::ResourceOwner);
    assert_eq!(method.authorization.existence, AuthorizationExistence::Hide);
    assert_eq!(method.deployment_targets, &[DeploymentTarget::Weft]);
    assert!(method.client_operation_id_required);
    assert_eq!(method.client_operation_id_field_number, Some(1));
    assert_eq!(method.authorization.targets[0].path, "spool");
    let request = SubmitSignedPolicyRequest {
        client_operation_id: "op-1".into(),
        ..Default::default()
    };
    assert_eq!(
        method
            .client_operation_id(&request.encode_to_vec())
            .expect("operation id"),
        Some("op-1")
    );
}

#[test]
fn signed_policy_record_preserves_max_audience_presence() {
    let mut present = SignedSpoolPolicy::default();
    present.max_audience = Some(Audience::Private.into());
    let encoded = present.encode_to_vec();
    let decoded = SignedSpoolPolicy::decode(encoded.as_slice()).expect("present");
    assert_eq!(decoded.max_audience, Some(Audience::Private.into()));

    let absent = SignedSpoolPolicy::default();
    assert!(absent.max_audience.is_none());
    let decoded_absent =
        SignedSpoolPolicy::decode(absent.encode_to_vec().as_slice()).expect("absent");
    assert!(decoded_absent.max_audience.is_none());
}

#[test]
fn signed_policy_body_carries_transfer_sequence_and_cas_head() {
    let body = SignedPolicyBody {
        format_version: 1,
        spool_uuid: vec![0; 16],
        expected_head: Some(SignedPolicyHead {
            state_hash: vec![0; 32],
            sequence: 0,
        }),
        sequence: 1,
        owner_id: vec![1; 32],
        owner_state_hash: vec![2; 32],
        ownership_transfer_sequence: 3,
        policy_state_hash: vec![3; 32],
        ..Default::default()
    };
    let record = SignedSpoolPolicyRecord {
        body: Some(body.clone()),
        owner_signature: None,
    };
    let decoded = SignedSpoolPolicyRecord::decode(record.encode_to_vec().as_slice()).expect("body");
    let decoded_body = decoded.body.expect("body");
    assert_eq!(decoded_body.format_version, 1);
    assert_eq!(decoded_body.ownership_transfer_sequence, 3);
    assert_eq!(decoded_body.sequence, 1);
    assert_eq!(decoded_body.expected_head.expect("head").sequence, 0);
    assert_eq!(SignedPolicyMergeSemantics::GrowOnlySetUnion as i32, 2);
}

#[test]
fn observe_spool_exposes_signed_policy_section_and_payload() {
    assert_eq!(SpoolSection::SignedPolicy as i32, 11);
    let payload = spool_event::Payload::SignedPolicy(SignedSpoolPolicyRecord::default());
    match payload {
        spool_event::Payload::SignedPolicy(_) => {}
        _ => panic!("signed_policy must be a SpoolEvent payload arm"),
    }
}
