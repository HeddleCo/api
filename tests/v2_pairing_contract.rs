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
