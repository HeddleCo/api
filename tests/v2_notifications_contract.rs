use heddle_api::heddle::api::common::{CallFailureCode, ErrorReason};
use heddle_api::heddle::api::v1alpha2::{
    EffectiveDelivery, NotificationDigestOverride, NotificationPreferences, NotificationRule,
    SetNotificationPreferencesRequest, SpoolRef, UnsubscribeNotificationsRequest,
    effective_delivery::Source,
    notification_event::Payload,
    notification_rule::{Channel, Delivery},
};
use heddle_api::v2::notifications::{
    MAX_EFFECTIVE_DELIVERIES, MAX_NOTIFICATION_PREFERENCES_BYTES, NotificationValidationError,
    validate_notification_preferences_bound, validate_notification_preferences_write,
    validate_notification_rule, validate_unsubscribe_notifications,
};
use prost::Message;

#[test]
fn in_app_digest_is_rejected_with_typed_invalid_argument() {
    let rule = NotificationRule {
        kind: "mention".into(),
        actor_origin: "human".into(),
        channel: Channel::InApp as i32,
        delivery: Delivery::Digest as i32,
        ..Default::default()
    };
    let error = validate_notification_rule(&rule).expect_err("in-app cannot digest");
    assert_eq!(error, NotificationValidationError::DigestRequiresEmail);
    assert_eq!(error.code(), CallFailureCode::InvalidArgument);
    assert_eq!(error.reason(), ErrorReason::FieldInvalid);
}

#[test]
fn rust_ts_delivery_parity_including_origins_and_spool_overrides() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/notification-delivery.json"))
            .expect("shared vectors");
    assert_eq!(vectors.as_array().expect("array").len(), 150);
    for row in vectors.as_array().expect("array") {
        for origin in ["", "any", "human", "agent"] {
            for spool in [None, Some(SpoolRef::default())] {
                let rule = NotificationRule {
                    kind: row["kind"].as_str().expect("kind").into(),
                    channel: row["channel"].as_i64().expect("channel") as i32,
                    delivery: row["delivery"].as_i64().expect("delivery") as i32,
                    actor_origin: origin.into(),
                    spool,
                };
                let expected = match row["violation"].as_str() {
                    None => Ok(()),
                    Some("InvalidRule") => Err(NotificationValidationError::InvalidRule),
                    Some("DigestRequiresEmail") => {
                        Err(NotificationValidationError::DigestRequiresEmail)
                    }
                    Some("LockedEmail") => Err(NotificationValidationError::LockedEmail),
                    value => panic!("unexpected vector {value:?}"),
                };
                assert_eq!(
                    validate_notification_rule(&rule),
                    expected,
                    "{row} {origin}"
                );
                let request = SetNotificationPreferencesRequest {
                    preferences: Some(NotificationPreferences {
                        rules: vec![rule],
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                assert_eq!(validate_notification_preferences_write(&request), expected);
            }
        }
    }
}

#[test]
fn locked_email_rejects_settings_and_unsubscribe_but_allows_in_app_off() {
    for kind in ["account_security", "security_surface", "", "*"] {
        let mut rule = NotificationRule {
            kind: kind.into(),
            channel: Channel::Email as i32,
            delivery: Delivery::Disabled as i32,
            ..Default::default()
        };
        let error = validate_notification_rule(&rule).expect_err("locked email");
        assert_eq!(error, NotificationValidationError::LockedEmail);
        assert_eq!(error.code(), CallFailureCode::FailedPrecondition);
        assert_eq!(error.reason(), ErrorReason::PolicyDenied);
        let request = UnsubscribeNotificationsRequest {
            rules: vec![rule.clone()],
            ..Default::default()
        };
        assert_eq!(validate_unsubscribe_notifications(&request), Err(error));
        rule.channel = Channel::InApp as i32;
        assert_eq!(validate_notification_rule(&rule), Ok(()));
        assert_eq!(
            validate_unsubscribe_notifications(&UnsubscribeNotificationsRequest {
                rules: vec![rule],
                ..Default::default()
            }),
            Ok(())
        );
    }
    assert_eq!(
        validate_notification_preferences_write(&SetNotificationPreferencesRequest::default()),
        Err(NotificationValidationError::InvalidRule)
    );
    let request = UnsubscribeNotificationsRequest {
        rules: vec![NotificationRule {
            kind: "mention".into(),
            channel: Channel::Email as i32,
            delivery: Delivery::Immediate as i32,
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(
        validate_unsubscribe_notifications(&request),
        Err(NotificationValidationError::UnsubscribeDelivery)
    );
}

#[test]
fn effective_delivery_and_digest_timestamps_round_trip_on_the_same_read() {
    let next = prost_types::Timestamp {
        seconds: 1_800_000_000,
        nanos: 123,
    };
    let preferences = NotificationPreferences {
        effective_delivery: vec![
            EffectiveDelivery {
                kind: "account_security".into(),
                channel: Channel::Email as i32,
                delivery: Delivery::Immediate as i32,
                source: Source::Default as i32,
                locked: true,
                ..Default::default()
            },
            EffectiveDelivery {
                kind: "mention".into(),
                actor_origin: "agent".into(),
                channel: Channel::Email as i32,
                delivery: Delivery::Immediate as i32,
                source: Source::Rule as i32,
                spool: Some(SpoolRef::default()),
                locked: false,
            },
        ],
        next_digest_at: Some(next),
        digest_overrides: vec![NotificationDigestOverride {
            spool: Some(SpoolRef::default()),
            digest_interval: Some(prost_types::Duration {
                seconds: 0,
                nanos: 0,
            }),
            next_digest_at: None,
        }],
        ..Default::default()
    };
    let event = heddle_api::heddle::api::v1alpha2::NotificationEvent {
        payload: Some(Payload::Preferences(preferences.clone())),
        ..Default::default()
    };
    assert_eq!(
        heddle_api::heddle::api::v1alpha2::NotificationEvent::decode(
            event.encode_to_vec().as_slice()
        )
        .expect("decode"),
        event
    );
    let request = SetNotificationPreferencesRequest {
        preferences: Some(preferences),
        ..Default::default()
    };
    assert_eq!(
        validate_notification_preferences_write(&request),
        Ok(()),
        "read-only projections ignored on write"
    );
    let old = NotificationPreferences::decode([].as_slice()).expect("empty legacy preferences");
    assert!(old.effective_delivery.is_empty());
    assert!(old.next_digest_at.is_none());
}

#[test]
fn effective_projection_is_bounded_by_count_and_encoded_bytes() {
    let mut preferences = NotificationPreferences {
        effective_delivery: vec![EffectiveDelivery::default(); MAX_EFFECTIVE_DELIVERIES],
        ..Default::default()
    };
    assert_eq!(
        validate_notification_preferences_bound(&preferences),
        Ok(())
    );
    preferences
        .effective_delivery
        .push(EffectiveDelivery::default());
    assert_eq!(
        validate_notification_preferences_bound(&preferences),
        Err(NotificationValidationError::ProjectionTooLarge)
    );
    preferences.effective_delivery.clear();
    preferences.timezone = "x".repeat(MAX_NOTIFICATION_PREFERENCES_BYTES - 4);
    assert_eq!(
        preferences.encoded_len(),
        MAX_NOTIFICATION_PREFERENCES_BYTES
    );
    assert_eq!(
        validate_notification_preferences_bound(&preferences),
        Ok(())
    );
    preferences.timezone.push('x');
    let error = validate_notification_preferences_bound(&preferences).expect_err("byte cap");
    assert_eq!(error.code(), CallFailureCode::ResourceExhausted);
    assert_eq!(error.reason(), ErrorReason::QuotaExceeded);
}

#[cfg(feature = "reflection")]
#[test]
fn descriptor_fields_are_additive_and_sources_are_stable() {
    use prost_reflect::{DescriptorPool, Kind};
    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("descriptor");
    let preferences = pool
        .get_message_by_name("heddle.api.v1alpha2.NotificationPreferences")
        .expect("preferences");
    let effective = preferences
        .get_field_by_name("effective_delivery")
        .expect("effective");
    assert_eq!(effective.number(), 6);
    assert!(effective.is_list());
    assert_eq!(
        preferences
            .get_field_by_name("next_digest_at")
            .expect("next")
            .number(),
        7
    );
    let Kind::Message(message) = effective.kind() else {
        panic!("message")
    };
    for (name, number) in [
        ("kind", 1),
        ("spool", 2),
        ("actor_origin", 3),
        ("channel", 4),
        ("delivery", 5),
        ("source", 6),
        ("locked", 7),
    ] {
        assert_eq!(
            message.get_field_by_name(name).expect(name).number(),
            number
        );
    }
    let source = pool
        .get_enum_by_name("heddle.api.v1alpha2.EffectiveDelivery.Source")
        .expect("source");
    for (name, number) in [
        ("SOURCE_UNSPECIFIED", 0),
        ("SOURCE_RULE", 1),
        ("SOURCE_DEFAULT", 2),
    ] {
        assert_eq!(source.get_value_by_name(name).expect(name).number(), number);
    }
    let overrides = pool
        .get_message_by_name("heddle.api.v1alpha2.NotificationDigestOverride")
        .expect("override");
    assert_eq!(
        overrides
            .get_field_by_name("next_digest_at")
            .expect("next")
            .number(),
        3
    );
}

#[test]
fn locked_email_takes_precedence_over_wildcard_digest_with_typed_policy_denied() {
    for kind in ["", "*", "account_security", "security_surface"] {
        let rule = NotificationRule {
            kind: kind.into(),
            channel: Channel::Unspecified as i32,
            delivery: Delivery::Digest as i32,
            ..Default::default()
        };
        let error = validate_notification_rule(&rule).expect_err("locked email cannot digest");
        assert_eq!(error, NotificationValidationError::LockedEmail);
        assert_eq!(error.code(), CallFailureCode::FailedPrecondition);
        assert_eq!(error.reason(), ErrorReason::PolicyDenied);
    }
    for (kind, channel) in [
        ("mention", Channel::Unspecified),
        ("account_security", Channel::InApp),
        ("security_surface", Channel::InApp),
    ] {
        let rule = NotificationRule {
            kind: kind.into(),
            channel: channel as i32,
            delivery: Delivery::Digest as i32,
            ..Default::default()
        };
        let error = validate_notification_rule(&rule).expect_err("non-email digest");
        assert_eq!(error, NotificationValidationError::DigestRequiresEmail);
        assert_eq!(error.code(), CallFailureCode::InvalidArgument);
        assert_eq!(error.reason(), ErrorReason::FieldInvalid);
    }
}

#[test]
fn settings_cadence_shared_vectors_reject_invalid_account_and_override_intervals() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/notification-cadence.json"))
            .expect("shared cadence vectors");
    for row in vectors.as_array().expect("array") {
        let interval = if row["interval"].is_null() {
            None
        } else {
            Some(prost_types::Duration {
                seconds: row["interval"]["seconds"].as_i64().expect("seconds"),
                nanos: row["interval"]["nanos"].as_i64().expect("nanos") as i32,
            })
        };
        let mut preferences = NotificationPreferences::default();
        if row["scope"] == "account" {
            preferences.digest_interval = interval;
        } else {
            preferences
                .digest_overrides
                .push(NotificationDigestOverride {
                    spool: Some(SpoolRef {
                        id: "00000000-0000-4000-8000-000000000001".into(),
                    }),
                    digest_interval: interval,
                    ..Default::default()
                });
        }
        let result = validate_notification_preferences_write(&SetNotificationPreferencesRequest {
            preferences: Some(preferences),
            ..Default::default()
        });
        if let Some(violation) = row["violation"].as_str() {
            let error = result.expect_err(row["name"].as_str().expect("name"));
            assert_eq!(format!("{error:?}"), violation, "{row}");
            assert_eq!(error.code(), CallFailureCode::InvalidArgument);
            assert_eq!(error.reason(), ErrorReason::FieldInvalid);
        } else {
            assert_eq!(result, Ok(()), "{row}");
        }
    }
}
