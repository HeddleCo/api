use heddle_api::{
    heddle::api::v1alpha2::{
        CreateInvitationRequest, CreateInvitationResponse, InvitationRecord,
        invitation_record::Recipient,
    },
    v2::invitation::{
        InvitationError, InvitationResponseAction, plan_invitation_response,
        resolve_invitation_recipient, validate_create_invitation,
        validate_create_invitation_response,
    },
};
use prost_types::Timestamp;
use serde_json::Value;

fn recipient(v: &Value) -> Option<Recipient> {
    let value = v["value"].as_str().expect("value").to_owned();
    match v["kind"].as_str().expect("kind") {
        "handle" => Some(Recipient::Handle(value)),
        "account_id" => Some(Recipient::AccountId(value)),
        "email" => Some(Recipient::Email(value)),
        _ => None,
    }
}
fn refusal(error: InvitationError, v: &Value) {
    let failure = error.failure();
    if v["reason"] == 302 {
        assert_eq!(failure.message, "no such user");
    }
    if v["reason"] == 300 {
        assert_eq!(failure.message, "invitation unavailable");
    }
    assert_eq!(
        failure.code as i64,
        v["code"].as_i64().expect("code"),
        "{}",
        v["name"]
    );
    let detail = failure.error.expect("typed error");
    assert_eq!(
        detail.reason as i64,
        v["reason"].as_i64().expect("reason"),
        "{}",
        v["name"]
    );
    assert_eq!(detail.field, v["field"].as_str().expect("field"));
    assert!(detail.resource.is_empty());
    assert!(detail.context.is_none());
}
fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/in-app-invitations.json")).expect("shared vectors")
}

#[test]
fn typed_recipient_wire_vectors_do_not_reuse_legacy_tags() {
    use prost::Message;
    for v in vectors()["wire"].as_array().expect("wire vectors") {
        let wire = hex::decode(v["hex"].as_str().expect("hex")).expect("bytes");
        let record = InvitationRecord {
            recipient: recipient(v),
            state: v["state"].as_i64().expect("state") as i32,
            ..Default::default()
        };
        assert_eq!(record.encode_to_vec(), wire, "{}", v["name"]);
        assert_eq!(
            InvitationRecord::decode(wire.as_slice()).expect("decode"),
            record
        );
    }
    let legacy = InvitationRecord::decode(&[0x1a, 4, b'm', b'a', b'r', b'a'][..])
        .expect("old tag is unknown");
    assert!(
        legacy.recipient.is_none(),
        "never reinterpret legacy recipient"
    );
}

#[test]
fn handle_resolution_typed_refusal_vectors() {
    for v in vectors()["recipient"].as_array().expect("recipients") {
        let record = InvitationRecord {
            recipient: recipient(v),
            ..Default::default()
        };
        let result = resolve_invitation_recipient(&record, |handle| {
            assert_eq!(
                handle,
                v["value"]
                    .as_str()
                    .expect("value")
                    .trim()
                    .to_ascii_lowercase()
            );
            v["resolved"].as_str().map(str::to_owned)
        });
        if v.get("code").is_some() {
            refusal(result.expect_err("refusal"), v);
        } else {
            assert_eq!(
                result.expect("resolved"),
                v["account"].as_str().map(str::to_owned)
            );
        }
    }
}

#[test]
fn accept_authorization_and_decline_idempotence_vectors() {
    for v in vectors()["response"].as_array().expect("responses") {
        let record = InvitationRecord {
            recipient: recipient(v),
            state: v["state"].as_i64().expect("state") as i32,
            expires_at: v["expires_seconds"].as_i64().map(|seconds| Timestamp {
                seconds,
                nanos: v["expires_nanos"].as_i64().expect("expiry nanos") as i32,
            }),
            ..Default::default()
        };
        let result = plan_invitation_response(
            &record,
            v["stored"].as_str(),
            v["caller"].as_str(),
            if v["action"] == "accept" {
                InvitationResponseAction::Accept
            } else {
                InvitationResponseAction::Decline
            },
            &Timestamp {
                seconds: v["now_seconds"].as_i64().expect("now"),
                nanos: v["now_nanos"].as_i64().expect("nanos") as i32,
            },
        );
        if v.get("code").is_some() {
            refusal(result.expect_err("refusal"), v);
        } else {
            let plan = result.expect("authorized response");
            assert_eq!(
                plan.state as i64,
                v["expected_state"].as_i64().expect("state"),
                "{}",
                v["name"]
            );
            assert_eq!(
                plan.changed,
                v["changed"].as_bool().expect("changed"),
                "{}",
                v["name"]
            );
            assert_eq!(plan.grant_role, v["grant_role"].as_bool().expect("grant"));
            assert_eq!(plan.notification_kind, v["notification"].as_str());
        }
    }
}

#[test]
fn repeated_decline_emits_one_notification_and_no_grant() {
    let mut record = InvitationRecord {
        recipient: Some(Recipient::Handle("mara".into())),
        state: 1,
        ..Default::default()
    };
    let now = Timestamp {
        seconds: 100,
        nanos: 0,
    };
    let mut notifications = 0;
    for _ in 0..2 {
        let plan = plan_invitation_response(
            &record,
            Some("11111111-1111-4111-8111-111111111111"),
            Some("11111111-1111-4111-8111-111111111111"),
            InvitationResponseAction::Decline,
            &now,
        )
        .expect("own decline");
        record.state = plan.state as i32;
        notifications += usize::from(plan.notification_kind.is_some());
        assert!(!plan.grant_role);
    }
    assert_eq!(notifications, 1);
    assert_eq!(record.state, 3);
}

#[test]
fn accept_refuses_a_different_signed_in_account_even_on_retry() {
    let now = Timestamp {
        seconds: 100,
        nanos: 0,
    };
    for state in [1, 2, 3, 4, 5] {
        let record = InvitationRecord {
            recipient: Some(Recipient::Handle("mara".into())),
            state,
            ..Default::default()
        };
        assert_eq!(
            plan_invitation_response(
                &record,
                Some("11111111-1111-4111-8111-111111111111"),
                Some("22222222-2222-4222-8222-222222222222"),
                InvitationResponseAction::Accept,
                &now
            ),
            Err(InvitationError::Unavailable)
        );
    }
}

#[test]
fn create_response_preserves_handle_and_never_returns_its_binding_or_secret() {
    use prost::Message;
    let input = InvitationRecord {
        recipient: Some(Recipient::Handle("mara".into())),
        role: 1,
        ..Default::default()
    };
    validate_create_invitation(&input).expect("typed input");
    let request = CreateInvitationRequest {
        invitation: Some(input.clone()),
        ..Default::default()
    };
    let output = InvitationRecord { state: 1, ..input };
    let response = CreateInvitationResponse {
        invitation: Some(output.clone()),
        ..Default::default()
    };
    validate_create_invitation_response(&request, &response).expect("safe handle projection");
    let id = "11111111-1111-4111-8111-111111111111";
    let wire = response.encode_to_vec();
    assert!(!wire.windows(id.len()).any(|chunk| chunk == id.as_bytes()));
    let substituted = CreateInvitationResponse {
        invitation: Some(InvitationRecord {
            recipient: Some(Recipient::AccountId(id.into())),
            ..output
        }),
        ..Default::default()
    };
    assert_eq!(
        validate_create_invitation_response(&request, &substituted),
        Err(InvitationError::InvalidRecord)
    );
    assert_eq!(
        validate_create_invitation_response(
            &request,
            &CreateInvitationResponse {
                redemption_secret: vec![1],
                ..response
            }
        ),
        Err(InvitationError::InvalidRecord)
    );
}

#[test]
fn create_input_rejects_server_fields_and_invalid_roles() {
    let input = InvitationRecord {
        recipient: Some(Recipient::Email("mara@example.org".into())),
        role: 2,
        ..Default::default()
    };
    validate_create_invitation(&input).expect("email input");
    for invalid in [
        InvitationRecord {
            state: 1,
            ..input.clone()
        },
        InvitationRecord {
            version: vec![1],
            ..input.clone()
        },
        InvitationRecord {
            spool_name: "private".into(),
            ..input.clone()
        },
        InvitationRecord { role: 99, ..input },
    ] {
        assert_eq!(
            validate_create_invitation(&invalid),
            Err(InvitationError::InvalidRecord)
        );
    }
}
