#![cfg(feature = "reflection")]
use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::v1alpha1::{AuthorizationAccess, SigningTier},
};
use prost_reflect::DescriptorPool;
#[test]
fn pending_pairing_observation_requires_subject_possession_without_account() {
    let method =
        heddle_api::v2::method_descriptor("/heddle.api.v2alpha1.IdentityService/ObservePairing")
            .expect("pairing observation");
    assert_eq!(method.signing_tier, SigningTier::ProofOfPossession);
    assert_eq!(method.authorization_access, AuthorizationAccess::Public);
}
#[test]
fn approval_observations_contain_commitments_and_completion_requires_device_proof() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptors");
    let pairing = pool
        .get_message_by_name("heddle.api.v2alpha1.PairingRecord")
        .expect("pairing");
    assert!(pairing.get_field_by_name("delegated_biscuit").is_none());
    assert_eq!(
        pairing
            .get_field_by_name("approval_binding")
            .expect("public commitment")
            .kind()
            .as_message()
            .expect("typed binding")
            .full_name(),
        "heddle.api.v2alpha1.RootAttachmentBinding"
    );
    let complete = pool
        .get_message_by_name("heddle.api.v2alpha1.CompletePairingRequest")
        .expect("completion");
    assert_eq!(
        complete
            .get_field_by_name("attachment")
            .expect("dual possession proof")
            .kind()
            .as_message()
            .expect("typed attachment")
            .full_name(),
        "heddle.api.v2alpha1.RootAttachment"
    );
}

#[test]
fn browser_pairing_has_exclusive_receiver_and_proof_without_endpoint_claims() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptors");
    for message in [
        "BeginPairingRequest",
        "PairingInitiationBinding",
        "PairingRecord",
    ] {
        let descriptor = pool
            .get_message_by_name(&format!("heddle.api.v2alpha1.{message}"))
            .expect("pairing message");
        let receiver = descriptor
            .oneofs()
            .find(|field| field.name() == "receiver")
            .expect("exclusive receiver");
        assert_eq!(
            receiver
                .fields()
                .map(|field| field.name().to_owned())
                .collect::<Vec<_>>(),
            ["device", "browser"]
        );
    }
    let complete = pool
        .get_message_by_name("heddle.api.v2alpha1.CompletePairingRequest")
        .expect("completion");
    assert_eq!(
        complete
            .oneofs()
            .find(|field| field.name() == "proof")
            .expect("exclusive proof")
            .fields()
            .map(|field| field.name().to_owned())
            .collect::<Vec<_>>(),
        ["attachment", "browser_possession"]
    );
    let approval = pool
        .get_message_by_name("heddle.api.v2alpha1.BrowserPairingApprovalBinding")
        .expect("browser commitment");
    assert!(approval.get_field_by_name("device").is_none());
    assert!(approval.get_field_by_name("biscuit").is_none());
    for name in [
        "root_public_key",
        "subject_public_key",
        "account_id",
        "credential_digest",
        "pairing_challenge",
        "not_before_unix_seconds",
        "expires_at_unix_seconds",
    ] {
        assert!(
            approval.get_field_by_name(name).is_some(),
            "missing signed approval field {name}"
        );
    }
}
