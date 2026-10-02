#![cfg(feature = "reflection")]

use heddle_api::{FILE_DESCRIPTOR_SET, heddle::api::common::*, v2};
use prost_reflect::{DescriptorPool, DynamicMessage, Kind, Value};

#[test]
fn custody_has_a_distinct_email_proof_and_typed_recover_proposal() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor");
    for (message, field, tag, target) in [
        (
            "SubmitRecoveryProofRequest",
            "custodial_email",
            5,
            "CustodialEmailProof",
        ),
        (
            "RecoveryAttempt",
            "custodial",
            8,
            "CustodialRecoveryDetails",
        ),
        (
            "CustodialRecoverProposal",
            "recover",
            3,
            "SignedOwnerKeyTransition",
        ),
        (
            "SubmitCustodialRecoverRequest",
            "recover",
            4,
            "SignedOwnerKeyTransition",
        ),
    ] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
            .expect("message");
        let field = message
            .get_field_by_name(field)
            .expect("additive custody field");
        assert_eq!(field.number(), tag);
        assert_eq!(
            field.kind(),
            Kind::Message(
                pool.get_message_by_name(&format!("heddle.api.v1alpha2.{target}"))
                    .expect("typed carrier")
            )
        );
    }
    let request = pool
        .get_message_by_name("heddle.api.v1alpha2.SubmitRecoveryProofRequest")
        .expect("proof request");
    assert_eq!(
        request
            .get_field_by_name("custodial_email")
            .expect("email")
            .containing_oneof()
            .expect("exclusive proof")
            .name(),
        "proof"
    );
}

#[test]
fn custody_rpc_metadata_requires_possession_and_idempotent_writes() {
    for method in [
        "BeginCustodialRecovery",
        "SubmitRecoveryProof",
        "GetCustodialRecoveryAttempt",
        "PrepareCustodialRecover",
        "SubmitCustodialRecover",
        "VetoCustodialRecovery",
    ] {
        let route =
            v2::method_descriptor(&format!("/heddle.api.v1alpha2.IdentityService/{method}"))
                .expect("custody route");
        assert_eq!(route.authorization_access, AuthorizationAccess::Public);
        assert_eq!(route.signing_tier, SigningTier::ProofOfPossession);
        assert_eq!(route.authorization.existence, AuthorizationExistence::Hide);
        let read = method == "GetCustodialRecoveryAttempt";
        assert_eq!(
            route.effect,
            if read {
                RpcEffect::ReadOnly
            } else {
                RpcEffect::DurableWrite
            }
        );
        assert_eq!(route.client_operation_id_required, !read);
        assert_eq!(
            route.retry_behavior,
            if read {
                RetryBehavior::Safe
            } else {
                RetryBehavior::ClientOperationId
            }
        );
    }
}

#[test]
fn custody_state_wire_vector_is_not_silently_discarded() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor");
    let descriptor = pool
        .get_message_by_name("heddle.api.v1alpha2.RecoveryAttempt")
        .expect("attempt");
    // RecoveryAttempt.custodial.state = TIME_LOCKED. Original schemas discard it.
    let record = DynamicMessage::decode(descriptor, &[0x42, 2, 0x10, 2][..]).expect("wire vector");
    let field = record
        .get_field_by_name("custodial")
        .expect("vector must survive decoding");
    let Value::Message(details) = field.as_ref() else {
        panic!("typed details")
    };
    assert_eq!(
        details.get_field_by_name("state").expect("state").as_ref(),
        &Value::EnumNumber(2)
    );
}
