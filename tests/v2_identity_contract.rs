#![cfg(feature = "reflection")]

use heddle_api::FILE_DESCRIPTOR_SET;
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn authentication_preserves_account_tiers_and_explicit_credential_issuance() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract descriptors");
    let principal = pool
        .get_message_by_name("heddle.api.v2alpha1.PrincipalRecord")
        .expect("principal record");
    let tier = principal
        .get_field_by_name("rooting_tier")
        .expect("account rooting tier");
    let Kind::Enum(tiers) = tier.kind() else {
        panic!("rooting tiers must be typed")
    };
    let values: Vec<_> = tiers
        .values()
        .map(|value| value.name().to_owned())
        .collect();
    assert_eq!(
        values,
        [
            "ROOTING_TIER_UNSPECIFIED",
            "ROOTING_TIER_SELF_ROOTED",
            "ROOTING_TIER_SERVER_ROOTED",
            "ROOTING_TIER_AGENT_ROOTED"
        ]
    );

    let response = pool
        .get_message_by_name("heddle.api.v2alpha1.AuthenticationResponse")
        .expect("authentication response");
    let credential = response
        .get_field_by_name("credential")
        .expect("credential result");
    let Kind::Message(result) = credential.kind() else {
        panic!("credential result must be typed")
    };
    let outcome = result
        .oneofs()
        .find(|field| field.name() == "outcome")
        .expect("explicit issuance outcome");
    assert_eq!(
        outcome
            .fields()
            .map(|field| field.name().to_owned())
            .collect::<Vec<_>>(),
        ["client_authority", "issued"]
    );
    let Kind::Message(issued) = result
        .get_field_by_name("issued")
        .expect("issued credential")
        .kind()
    else {
        panic!("issued result must be typed")
    };
    for name in ["biscuit", "proof_public_key", "expires_at", "kind"] {
        assert!(issued.get_field_by_name(name).is_some(), "missing {name}");
    }

    // Account observations must not become an alternate secret retrieval path.
    for name in ["PrincipalRecord", "SessionRecord", "DelegationRecord"] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.v2alpha1.{name}"))
            .expect("account record");
        assert!(message.get_field_by_name("biscuit").is_none());
        assert!(message.get_field_by_name("credential").is_none());
    }
}
