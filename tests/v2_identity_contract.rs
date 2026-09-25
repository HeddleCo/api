#![cfg(feature = "reflection")]

use heddle_api::{
    FILE_DESCRIPTOR_SET, StreamingShape,
    heddle::api::common::{
        AuthorizationAccess, AuthorizationExistence, AuthorizationRole, AuthorizationScopeSource,
        RetryBehavior, RpcEffect, SigningTier, StableSigningIdentity,
    },
};
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn unary_identity_read_is_bounded_and_matches_observation_authorization() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract descriptors");
    let request = pool
        .get_message_by_name("heddle.api.v1alpha2.GetIdentityRequest")
        .expect("unary identity request");
    assert_eq!(
        request
            .fields()
            .map(|field| field.name().to_owned())
            .collect::<Vec<_>>(),
        ["include_current_credential"]
    );

    let response = pool
        .get_message_by_name("heddle.api.v1alpha2.GetIdentityResponse")
        .expect("unary identity response");
    assert_eq!(
        response
            .fields()
            .map(|field| (field.name().to_owned(), field.kind()))
            .collect::<Vec<_>>(),
        [
            (
                "identity".to_owned(),
                Kind::Message(
                    pool.get_message_by_name("heddle.api.v1alpha2.PrincipalRecord")
                        .expect("shared principal record")
                )
            ),
            (
                "current_credential".to_owned(),
                Kind::Message(
                    pool.get_message_by_name("heddle.api.v1alpha2.CurrentCredentialRecord")
                        .expect("shared credential record")
                )
            ),
            (
                "billing_lock".to_owned(),
                Kind::Message(
                    pool.get_message_by_name("heddle.api.common.AccountBillingLock")
                        .expect("shared billing-lock status")
                )
            )
        ]
    );

    let method =
        heddle_api::v2::method_descriptor("/heddle.api.v1alpha2.IdentityService/GetIdentity")
            .expect("GetIdentity route in generated method catalog");
    assert_eq!(method.streaming, StreamingShape::Unary);
    assert!(!method.live_stream);
    assert_eq!(method.effect, RpcEffect::ReadOnly);
    assert_eq!(method.retry_behavior, RetryBehavior::Safe);
    assert_eq!(method.signing_tier, SigningTier::ProofOfPossession);
    assert_eq!(
        method.signing_identity,
        StableSigningIdentity::AuthenticatedPrincipal
    );
    assert_eq!(
        method.authorization_access,
        AuthorizationAccess::AuthenticatedPrincipal
    );
    assert_eq!(method.authorization.role, AuthorizationRole::CallerBound);
    assert_eq!(
        method.authorization.scope_source,
        AuthorizationScopeSource::CallerGrants
    );
    assert_eq!(method.authorization.existence, AuthorizationExistence::Hide);
    assert!(method.authorization.targets.is_empty());
}

#[test]
fn passkey_sign_in_carries_browser_options_and_one_device_proof() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract descriptors");
    let proof = pool
        .get_message_by_name("heddle.api.v1alpha2.PasskeyProof")
        .expect("proof");
    assert_eq!(
        proof
            .get_field_by_name("user_handle")
            .expect("credential owner binding")
            .kind(),
        Kind::Bytes
    );
    let complete = pool
        .get_message_by_name("heddle.api.v1alpha2.CompleteAuthenticationRequest")
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
        .get_message_by_name("heddle.api.v1alpha2.AuthenticationChallenge")
        .expect("challenge");
    assert!(
        challenge
            .get_field_by_name("mint_root_attachment")
            .is_none()
    );
    let grant_field = challenge
        .get_field_by_name("passkey_mint_grant")
        .expect("account-free grant");
    assert_eq!(grant_field.number(), 10);
    assert!(challenge.get_field_by_name("passkey_authorities").is_some());
    assert!(matches!(
        challenge
            .get_field_by_name("user_verification")
            .expect("browser authenticator policy")
            .kind(),
        Kind::Enum(_)
    ));

    let grant = pool
        .get_message_by_name("heddle.api.v1alpha2.PasskeyMintGrant")
        .expect("passkey mint grant");
    assert_eq!(
        grant
            .fields()
            .map(|field| (field.name().to_owned(), field.number()))
            .collect::<Vec<_>>(),
        [
            ("format_version".into(), 1),
            ("mint_root_key".into(), 2),
            ("not_before_unix_seconds".into(), 3),
            ("expires_at_unix_seconds".into(), 4),
            ("nonce".into(), 5),
            ("relying_party_id".into(), 6),
        ]
    );
    let signed = pool
        .get_message_by_name("heddle.api.v1alpha2.SignedMintRootAttachment")
        .expect("v2 signed mint root attachment");
    assert_eq!(
        signed
            .fields()
            .map(|field| (field.name().to_owned(), field.number()))
            .collect::<Vec<_>>(),
        [("grant".into(), 1), ("passkey_delegation".into(), 2)]
    );
    assert!(complete.get_field_by_name("mint_root_attachment").is_none());
    let response = pool
        .get_message_by_name("heddle.api.v1alpha2.AuthenticationResponse")
        .expect("authentication response");
    assert_eq!(
        response
            .get_field_by_name("passkey_authority")
            .expect("resolved owner-signed authority")
            .number(),
        6
    );
    assert_eq!(
        response
            .get_field_by_name("mint_root_attachment")
            .expect("server-assembled v2 attachment")
            .number(),
        7
    );
}

#[test]
fn onboarding_distinguishes_human_accounts_delegations_and_anonymous_continuity() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract descriptors");
    let identity = pool
        .get_service_by_name("heddle.api.v1alpha2.IdentityService")
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
        pool.get_message_by_name("heddle.api.v1alpha2.CreatePrincipalRequest")
            .is_none()
    );
}

#[test]
fn authentication_preserves_account_tiers_and_explicit_credential_issuance() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract descriptors");
    let principal = pool
        .get_message_by_name("heddle.api.v1alpha2.PrincipalRecord")
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
        .get_message_by_name("heddle.api.v1alpha2.AuthenticationResponse")
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
        issued
            .get_field_by_name("subject")
            .map(|field| field.kind()),
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
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}"))
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
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}"))
            .expect("account record");
        assert!(message.get_field_by_name("biscuit").is_none());
        assert!(message.get_field_by_name("credential").is_none());
    }
}

#[test]
fn credential_ceremonies_have_exclusive_proofs_and_explicit_lifetimes() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("contract descriptors");
    for (name, expected) in [
        (
            "CompleteAuthenticationRequest",
            ["passkey", "oauth", "password_unlock"],
        ),
        (
            "CompleteRegistrationRequest",
            ["passkey", "oauth", "password_setup"],
        ),
    ] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}"))
            .expect("existing completion entrypoint");
        let proof = message
            .oneofs()
            .find(|o| o.name() == "proof")
            .expect("one credential proof per ceremony");
        let names: Vec<_> = proof
            .fields()
            .map(|field| field.name().to_owned())
            .collect();
        assert_eq!(names, expected);
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
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}"))
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
        .get_message_by_name("heddle.api.v1alpha2.OAuthProof")
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
