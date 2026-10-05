use heddle_api::{
    heddle::api::{
        common::{
            AuthorizationAccess, AuthorizationExistence, AuthorizationRole,
            AuthorizationScopeSource, DeploymentTarget, RetryBehavior, RpcEffect, SigningTier,
        },
        v1alpha2::{
            GetInvitationCodeResponse, GetSignupInvitationCodeResponse, InvitationRecord,
            SignupInvitation,
        },
    },
    v2::{
        invitation_code::{
            InvitationCodeReadContext, validate_invitation_code_response,
            validate_signup_invitation_code_response,
        },
        method_descriptor,
    },
};
use prost::Message;
use prost_types::Timestamp;
use serde::Deserialize;

#[derive(Deserialize)]
struct Time {
    seconds: String,
    nanos: i32,
}
impl Time {
    fn timestamp(&self) -> Timestamp {
        Timestamp {
            seconds: self.seconds.parse().expect("vector seconds"),
            nanos: self.nanos,
        }
    }
}
#[derive(Deserialize)]
struct Vector {
    name: String,
    caller: String,
    creator: String,
    now: Time,
    expires_at: Option<Time>,
    redeemed: bool,
    revoked: bool,
    secret_hex: String,
    error: Option<String>,
}
#[derive(Deserialize)]
struct Fixture {
    secret_wire_hex: String,
    empty_wire_hex: String,
    cases: Vec<Vector>,
}
fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/invitation-code-reads.json"))
        .expect("shared invitation code vectors")
}

fn check(vector: &Vector) {
    let secret = hex::decode(&vector.secret_hex).expect("secret bytes");
    let now = vector.now.timestamp();
    let context = InvitationCodeReadContext {
        caller_subject: &vector.caller,
        creator_subject: &vector.creator,
        now: &now,
    };
    let expires_at = vector.expires_at.as_ref().map(Time::timestamp);
    let signup = SignupInvitation {
        expires_at,
        redeemed: vector.redeemed,
        revoked: vector.revoked,
        ..Default::default()
    };
    let spool = InvitationRecord {
        expires_at,
        redeemed: vector.redeemed,
        revoked: vector.revoked,
        ..Default::default()
    };
    let signup_response = GetSignupInvitationCodeResponse {
        redemption_secret: secret.clone(),
    };
    let spool_response = GetInvitationCodeResponse {
        redemption_secret: secret,
    };
    for result in [
        validate_signup_invitation_code_response(&signup_response, &signup, &context),
        validate_invitation_code_response(&spool_response, &spool, &context),
    ] {
        assert_eq!(
            result.err().map(|error| format!("{error:?}")),
            vector.error,
            "{}",
            vector.name,
        );
    }
}

#[test]
fn non_creator_reads_are_refused_even_for_other_admins_or_empty_codes() {
    let cases = fixture().cases;
    let denied: Vec<_> = cases
        .iter()
        .filter(|v| v.error.as_deref() == Some("Creator"))
        .collect();
    assert_eq!(denied.len(), 6);
    for vector in denied {
        check(vector);
    }
}

#[test]
fn reads_after_redeem_revoke_or_expiry_must_be_empty() {
    let cases = fixture().cases;
    let terminal: Vec<_> = cases
        .iter()
        .filter(|v| {
            v.name.starts_with("redeemed_")
                || v.name.starts_with("revoked_")
                || v.name.starts_with("expired_")
        })
        .collect();
    assert_eq!(terminal.len(), 8);
    for vector in terminal {
        check(vector);
    }
}

#[test]
fn shared_vectors_cover_repeated_reads_legacy_codes_and_timestamp_validation() {
    let cases = fixture().cases;
    assert_eq!(cases.len(), 22);
    for vector in cases {
        check(&vector);
    }
}

#[test]
fn code_responses_round_trip_the_same_original_bytes_and_empty_terminal_shape() {
    let fixture = fixture();
    for wire_hex in [&fixture.secret_wire_hex, &fixture.empty_wire_hex] {
        let wire = hex::decode(wire_hex).expect("wire bytes");
        let signup = GetSignupInvitationCodeResponse::decode(wire.as_slice()).expect("signup code");
        let spool = GetInvitationCodeResponse::decode(wire.as_slice()).expect("spool code");
        assert_eq!(signup.redemption_secret, spool.redemption_secret);
        assert_eq!(signup.encode_to_vec(), wire);
        assert_eq!(spool.encode_to_vec(), wire);
    }
}

#[test]
fn creator_reads_are_authenticated_hosted_caller_bound_unary_safe_reads() {
    for path in [
        "/heddle.api.v1alpha2.IdentityService/GetSignupInvitationCode",
        "/heddle.api.v1alpha2.SpoolService/GetInvitationCode",
    ] {
        let method = method_descriptor(path).expect("creator read RPC");
        assert_eq!(method.effect, RpcEffect::ReadOnly);
        assert_eq!(method.retry_behavior, RetryBehavior::Safe);
        assert_eq!(method.signing_tier, SigningTier::ProofOfPossession);
        assert_eq!(
            method.authorization_access,
            AuthorizationAccess::AuthenticatedPrincipal
        );
        assert_eq!(method.authorization.role, AuthorizationRole::CallerBound);
        assert_eq!(
            method.authorization.scope_source,
            AuthorizationScopeSource::CallerSubject
        );
        assert_eq!(method.authorization.existence, AuthorizationExistence::Hide);
        assert_eq!(method.deployment_targets, &[DeploymentTarget::Weft]);
        assert_eq!(method.streaming, heddle_api::StreamingShape::Unary);
        assert!(!method.client_operation_id_required);
        assert!(method.authorization.targets.is_empty());
    }
}

#[cfg(feature = "reflection")]
#[test]
fn every_service_projection_excludes_invite_codes_except_top_level_create_and_creator_reads() {
    use prost_reflect::{DescriptorPool, Kind, MessageDescriptor};
    use std::collections::BTreeSet;

    fn walk(message: MessageDescriptor, root: &str, seen: &mut BTreeSet<String>) {
        if !seen.insert(message.full_name().to_owned()) {
            return;
        }
        for field in message.fields() {
            if field.name() == "redemption_secret" {
                assert_eq!(
                    message.full_name(),
                    root,
                    "code leaked into {root} through {}",
                    message.full_name()
                );
                assert!(
                    matches!(
                        message.name(),
                        "CreateInvitationResponse"
                            | "CreateSignupInvitationResponse"
                            | "GetInvitationCodeResponse"
                            | "GetSignupInvitationCodeResponse"
                    ),
                    "code leaked into {root}"
                );
            }
            if let Kind::Message(child) = field.kind() {
                walk(child, root, seen);
            }
        }
    }
    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("descriptor");
    let mut roots_with_codes = BTreeSet::new();
    let mut methods = 0;
    for service in pool.services() {
        for method in service.methods() {
            methods += 1;
            let output = method.output();
            if output.get_field_by_name("redemption_secret").is_some() {
                roots_with_codes.insert(output.name().to_owned());
            }
            walk(output.clone(), output.full_name(), &mut BTreeSet::new());
        }
    }
    assert!(methods >= 171, "non-vacuous service projection coverage");
    assert_eq!(roots_with_codes.len(), 4);
    for name in ["GetInvitationCode", "GetSignupInvitationCode"] {
        let request = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}Request"))
            .expect("request");
        let response = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}Response"))
            .expect("response");
        assert_eq!(request.fields().count(), 1);
        assert_eq!(
            request
                .get_field_by_name("invitation")
                .expect("reference")
                .number(),
            1
        );
        assert_eq!(response.fields().count(), 1);
        let code = response
            .get_field_by_name("redemption_secret")
            .expect("code");
        assert_eq!(code.number(), 1);
        assert_eq!(code.kind(), Kind::Bytes);
    }
}
