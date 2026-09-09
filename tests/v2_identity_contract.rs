#![cfg(feature = "reflection")]

use heddle_api::FILE_DESCRIPTOR_SET;
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn passkey_sign_in_carries_browser_options_and_one_device_proof() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract descriptors");
    let proof = pool
        .get_message_by_name("heddle.api.v2alpha1.PasskeyProof")
        .expect("proof");
    assert_eq!(
        proof
            .get_field_by_name("user_handle")
            .expect("credential owner binding")
            .kind(),
        Kind::Bytes
    );
    let complete = pool
        .get_message_by_name("heddle.api.v2alpha1.CompleteAuthenticationRequest")
        .expect("completion");
    assert_eq!(
        complete
            .get_field_by_name("caller_public_key")
            .expect("same device key as challenge")
            .kind(),
        Kind::Bytes
    );
    assert!(
        complete.get_field_by_name("caller").is_none(),
        "sign-in does not enroll an attachment"
    );
    assert!(
        complete.get_field_by_name("possession_proof").is_none(),
        "CallContext carries the exact request PoP"
    );
    let challenge = pool
        .get_message_by_name("heddle.api.v2alpha1.AuthenticationChallenge")
        .expect("challenge");
    assert!(matches!(
        challenge
            .get_field_by_name("user_verification")
            .expect("browser authenticator policy")
            .kind(),
        Kind::Enum(_)
    ));
}

#[test]
fn onboarding_distinguishes_human_accounts_delegations_and_anonymous_continuity() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract descriptors");
    let identity = pool
        .get_service_by_name("heddle.api.v2alpha1.IdentityService")
        .expect("identity service");
    let provision = identity
        .methods()
        .find(|method| method.name() == "ProvisionAccount")
        .expect("agent provisioning creates an unclaimed human account");
    for name in [
        "client_operation_id",
        "invitation_secret",
        "agent_public_key",
    ] {
        assert!(
            provision.input().get_field_by_name(name).is_some(),
            "provisioning requires {name}"
        );
    }
    assert!(
        provision.input().get_field_by_name("kind").is_none(),
        "callers cannot choose a human rooting tier"
    );
    for name in ["principal", "credential", "claim_web_origin"] {
        assert!(
            provision.output().get_field_by_name(name).is_some(),
            "provisioning returns {name}"
        );
    }
    let anonymous = identity
        .methods()
        .find(|method| method.name() == "CreateAnonymousSession")
        .expect("anonymous continuity has its own ceremony");
    assert!(
        anonymous
            .input()
            .get_field_by_name("continuity_secret")
            .is_some()
    );
    assert!(
        anonymous
            .output()
            .get_field_by_name("continuity_secret")
            .is_some()
    );
    assert!(
        anonymous
            .output()
            .get_field_by_name("continuity_expires_at")
            .is_some()
    );
    let issue = identity
        .methods()
        .find(|method| method.name() == "IssueDelegationCredential")
        .expect("delegated credential issuance is explicit");
    assert!(issue.input().get_field_by_name("delegation").is_some());
    assert!(
        issue
            .input()
            .get_field_by_name("proof_public_key")
            .is_some()
    );
    assert!(issue.output().get_field_by_name("credential").is_some());
    assert!(
        identity
            .methods()
            .all(|method| method.name() != "CreatePrincipal"),
        "remove the conflated principal factory"
    );
    assert!(
        pool.get_message_by_name("heddle.api.v2alpha1.CreatePrincipalRequest")
            .is_none()
    );
}

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
        ["client_owned", "issued"]
    );
    let Kind::Message(registered) = result
        .get_field_by_name("client_owned")
        .expect("client-owned registration")
        .kind()
    else {
        panic!("typed registration")
    };
    for name in ["ref", "subject", "proof_public_key", "kind"] {
        assert!(
            registered.get_field_by_name(name).is_some(),
            "registration needs {name}"
        );
    }
    assert!(
        registered.get_field_by_name("biscuit").is_none(),
        "keyed clients mint their own bearer"
    );
    let Kind::Message(issued) = result
        .get_field_by_name("issued")
        .expect("issued credential")
        .kind()
    else {
        panic!("typed issued credential")
    };
    assert_eq!(
        issued.get_field_by_name("subject").map(|field| field.kind()),
        Some(Kind::String),
        "issued credentials must identify their exact proof subject without conflating it with the human account UUID"
    );
    assert!(
        result.get_field_by_name("session").is_some(),
        "one session result for every credential ceremony"
    );
    assert!(
        response.get_field_by_name("session").is_none(),
        "session metadata has one canonical location"
    );
    for name in ["ProvisionAccountResponse", "DelegationCredentialResponse"] {
        let response = pool
            .get_message_by_name(&format!("heddle.api.v2alpha1.{name}"))
            .expect("credential ceremony");
        assert_eq!(
            response
                .get_field_by_name("credential")
                .expect("credential result")
                .kind(),
            Kind::Message(result.clone()),
            "keyed provisioning cannot require a server-minted bearer"
        );
    }
    assert!(
        result.get_field_by_name("owner_authorization").is_some(),
        "original owner proofs accompany the credential result"
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

#[test]
fn credential_ceremonies_have_exclusive_proofs_and_explicit_lifetimes() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract descriptors");
    for name in [
        "CompleteAuthenticationRequest",
        "CompleteRegistrationRequest",
    ] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.v2alpha1.{name}"))
            .expect("existing completion entrypoint");
        let proof = message
            .oneofs()
            .find(|o| o.name() == "proof")
            .expect("one credential proof per ceremony");
        let names: Vec<_> = proof
            .fields()
            .map(|field| field.name().to_owned())
            .collect();
        assert_eq!(names, ["passkey", "password", "oauth"]);
        assert_eq!(
            message
                .get_field_by_name("passkey")
                .expect("passkey proof")
                .number(),
            3
        );
    }
    for name in ["AuthenticationChallenge", "RegistrationChallenge"] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.v2alpha1.{name}"))
            .expect("challenge");
        assert_ne!(
            message.get_field_by_name("expires_at"),
            message.get_field_by_name("credential_expires_at")
        );
        assert!(message.get_field_by_name("credential_expires_at").is_some());
        assert!(message.get_field_by_name("method").is_some());
        assert!(message.get_field_by_name("oauth_provider").is_some());
    }
    let proof = pool
        .get_message_by_name("heddle.api.v2alpha1.OAuthProof")
        .expect("provider proof");
    let fields: Vec<_> = proof
        .oneofs()
        .next()
        .expect("one provider proof")
        .fields()
        .map(|field| field.name().to_owned())
        .collect();
    assert_eq!(fields, ["id_token", "access_token"]);
    assert!(
        proof.get_field_by_name("email").is_none(),
        "provider identity is verified, never caller asserted"
    );
}
