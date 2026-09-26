#![cfg(feature = "reflection")]

use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::{
        common::{
            AuthorizationAccess, AuthorizationExistence, AuthorizationRole,
            AuthorizationScopeSource, RetryBehavior, RpcEffect, SigningTier, StableSigningIdentity,
        },
        v1alpha2::{PasskeyRegistration, RenamePasskeyRequest},
    },
    v2::{
        method_descriptor,
        passkey_label::{
            DEFAULT_PASSKEY_LABEL, PasskeyLabelError, normalize_passkey_label,
            passkey_display_label,
        },
    },
};
use prost::Message;
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn passkey_label_is_additive_and_rename_has_a_version_checked_receipt() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled contract");
    let message = |name: &str| {
        pool.get_message_by_name(&format!("heddle.api.v1alpha2.{name}"))
            .expect("passkey message")
    };
    let registration = message("PasskeyRegistration");
    assert_eq!(
        registration
            .fields()
            .map(|f| (f.name().to_owned(), f.number()))
            .collect::<Vec<_>>(),
        [
            ("credential_id".into(), 1),
            ("client_data_json".into(), 2),
            ("attestation_object".into(), 3),
            ("label".into(), 4),
        ]
    );
    let label = registration.get_field_by_name("label").expect("label");
    assert_eq!(label.kind(), Kind::String);
    assert!(label.supports_presence(), "omission selects the default");

    let request = message("RenamePasskeyRequest");
    assert_eq!(
        request
            .fields()
            .map(|f| (f.name().to_owned(), f.number(), f.kind()))
            .collect::<Vec<_>>(),
        [
            ("client_operation_id".into(), 1, Kind::String),
            ("passkey".into(), 2, Kind::Message(message("RecordRef"))),
            ("expected_version".into(), 3, Kind::Bytes),
            ("label".into(), 4, Kind::String),
        ]
    );
    let response = message("RenamePasskeyResponse");
    assert_eq!(
        response
            .fields()
            .map(|f| (f.name().to_owned(), f.number(), f.kind()))
            .collect::<Vec<_>>(),
        [
            (
                "receipt".into(),
                1,
                Kind::Message(message("MutationReceipt"))
            ),
            ("passkey".into(), 2, Kind::Message(message("PasskeyRecord"))),
        ]
    );
    assert_eq!(
        message("PasskeyRecord")
            .get_field_by_name("label")
            .expect("observed label")
            .kind(),
        Kind::String
    );

    let service = pool
        .get_service_by_name("heddle.api.v1alpha2.IdentityService")
        .expect("identity service");
    let rename = service
        .methods()
        .find(|method| method.name() == "RenamePasskey")
        .expect("rename method");
    assert_eq!(rename.input(), request);
    assert_eq!(rename.output(), response);
    let route = method_descriptor("/heddle.api.v1alpha2.IdentityService/RenamePasskey")
        .expect("generated route");
    assert_eq!(
        route.signing_identity,
        StableSigningIdentity::AuthenticatedPrincipal
    );
    assert_eq!(route.signing_tier, SigningTier::ProofOfPossession);
    assert_eq!(route.effect, RpcEffect::DurableWrite);
    assert_eq!(route.retry_behavior, RetryBehavior::ClientOperationId);
    assert!(route.client_operation_id_required);
    assert_eq!(route.client_operation_id_field_number, Some(1));
    assert_eq!(
        route.authorization_access,
        AuthorizationAccess::AuthenticatedPrincipal
    );
    assert_eq!(route.authorization.role, AuthorizationRole::CallerBound);
    assert_eq!(
        route.authorization.scope_source,
        AuthorizationScopeSource::CallerSubject
    );
    assert_eq!(route.authorization.existence, AuthorizationExistence::Hide);
    assert!(route.authorization.targets.is_empty());
}

#[test]
fn passkey_labels_trim_count_utf8_bytes_reject_controls_and_default() {
    assert_eq!(
        normalize_passkey_label("  Work laptop  "),
        Ok("Work laptop")
    );
    assert_eq!(normalize_passkey_label("   "), Ok(""));
    assert_eq!(passkey_display_label(""), DEFAULT_PASSKEY_LABEL);
    assert_eq!(passkey_display_label("Work laptop"), "Work laptop");
    assert_eq!(
        normalize_passkey_label(&"é".repeat(128)),
        Ok("é".repeat(128).as_str())
    );
    assert_eq!(
        normalize_passkey_label(&"x".repeat(257)),
        Err(PasskeyLabelError::TooLong)
    );
    assert_eq!(
        normalize_passkey_label(&"é".repeat(129)),
        Err(PasskeyLabelError::TooLong)
    );
    for label in ["a\nb", "\tname", "name\u{7f}", "name\u{85}"] {
        assert_eq!(
            normalize_passkey_label(label),
            Err(PasskeyLabelError::ControlCharacter)
        );
    }

    let registration = PasskeyRegistration {
        label: Some("Work laptop".into()),
        ..Default::default()
    };
    assert_eq!(
        PasskeyRegistration::decode(registration.encode_to_vec().as_slice()).unwrap(),
        registration
    );
    let rename = RenamePasskeyRequest {
        client_operation_id: "rename-1".into(),
        expected_version: vec![1, 2, 3],
        label: "Work laptop".into(),
        ..Default::default()
    };
    assert_eq!(
        RenamePasskeyRequest::decode(rename.encode_to_vec().as_slice()).unwrap(),
        rename
    );
}
