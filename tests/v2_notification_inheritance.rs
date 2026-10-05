use heddle_api::heddle::api::v1alpha2::{
    EffectiveDelivery, NotificationPreferences, NotificationRule,
    SetNotificationPreferencesRequest, SpoolRef, notification_rule::Delivery,
};
use heddle_api::v2::notifications::{
    NotificationAncestor, NotificationValidationError, resolve_notification_delivery,
    validate_effective_delivery_source, validate_notification_preferences_write,
    validate_notification_preferences_write_for_system_root,
};
use prost::Message;
use serde_json::Value;

fn spool(value: &Value) -> Option<SpoolRef> {
    value.as_str().map(|id| SpoolRef { id: id.into() })
}

fn assert_expected(cell: &EffectiveDelivery, expected: &Value, name: &str) {
    assert_eq!(
        cell.delivery,
        expected["delivery"].as_i64().expect("delivery") as i32,
        "{name}"
    );
    assert_eq!(
        cell.source,
        expected["source"].as_i64().expect("source") as i32,
        "{name}"
    );
    assert_eq!(cell.source_spool, spool(&expected["sourceSpool"]), "{name}");
    assert_eq!(
        cell.locked,
        expected["locked"].as_bool().expect("locked"),
        "{name}"
    );
}

#[test]
fn rust_ts_shared_inheritance_resolution_removal_and_disclosure_vectors() {
    let rows: Value = serde_json::from_str(include_str!("fixtures/notification-inheritance.json"))
        .expect("shared vectors");
    for row in rows.as_array().expect("rows") {
        let name = row["name"].as_str().expect("name");
        let rules: Vec<_> = row["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .map(|r| NotificationRule {
                kind: r["kind"].as_str().expect("kind").into(),
                spool: spool(&r["spool"]),
                actor_origin: r["actorOrigin"].as_str().expect("origin").into(),
                channel: r["channel"].as_i64().expect("channel") as i32,
                delivery: r["delivery"].as_i64().expect("delivery") as i32,
            })
            .collect();
        let ancestors: Vec<_> = row["ancestors"]
            .as_array()
            .expect("ancestors")
            .iter()
            .map(|a| NotificationAncestor {
                spool: spool(&a["spool"]).expect("ancestor spool"),
                readable: a["readable"].as_bool().expect("readable"),
                system_root: a["systemRoot"].as_bool().expect("systemRoot"),
            })
            .collect();
        let c = &row["cell"];
        let cell = EffectiveDelivery {
            kind: c["kind"].as_str().expect("kind").into(),
            spool: spool(&c["spool"]),
            actor_origin: c["actorOrigin"].as_str().expect("origin").into(),
            channel: c["channel"].as_i64().expect("channel") as i32,
            ..Default::default()
        };
        let default = Delivery::try_from(row["defaultDelivery"].as_i64().expect("default") as i32)
            .expect("delivery");
        let digest = row["digestEnabled"].as_bool().expect("digest");
        if name == "system root rule invalid" {
            assert_eq!(
                validate_notification_preferences_write_for_system_root(
                    &SetNotificationPreferencesRequest {
                        preferences: Some(NotificationPreferences {
                            rules: rules.clone(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    &ancestors.last().expect("system root").spool
                ),
                Err(NotificationValidationError::InvalidRule)
            );
        }
        let result = resolve_notification_delivery(&rules, &cell, &ancestors, 128, default, digest);
        if let Some(violation) = row["violation"].as_str() {
            assert_eq!(
                format!("{:?}", result.expect_err(name)),
                violation,
                "{name}"
            );
            if violation == "InvalidRule" && name.contains("unspecified") {
                assert_eq!(
                    validate_notification_preferences_write(&SetNotificationPreferencesRequest {
                        preferences: Some(NotificationPreferences {
                            rules,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    Err(NotificationValidationError::InvalidRule),
                    "{name}"
                );
            }
            continue;
        }
        let resolved = result.expect(name);
        assert_expected(&resolved, &row["expected"], name);
        assert_eq!(resolved.spool, cell.spool, "target scope is preserved");
        assert_eq!(
            validate_effective_delivery_source(&resolved, &ancestors, 128),
            Ok(()),
            "{name}"
        );
        let encoded = resolved.encode_to_vec();
        assert_eq!(
            EffectiveDelivery::decode(encoded.as_slice()).expect("wire roundtrip"),
            resolved
        );
        if row.get("spoofSourceSpool").is_some() {
            let mut spoofed = resolved.clone();
            spoofed.source_spool = spool(&row["spoofSourceSpool"]);
            assert_eq!(
                validate_effective_delivery_source(&spoofed, &ancestors, 128),
                Err(NotificationValidationError::InvalidSource),
                "{name}"
            );
        }
        if let Some(remove) = spool(&row["removeSpool"]) {
            let remaining: Vec<_> = rules
                .into_iter()
                .filter(|r| r.spool.as_ref() != Some(&remove))
                .collect();
            let inherited =
                resolve_notification_delivery(&remaining, &cell, &ancestors, 128, default, digest)
                    .expect("after removal");
            assert_expected(&inherited, &row["after"], name);
        }
    }
}

#[test]
fn ancestry_bound_is_inclusive_and_never_falls_back_on_overflow() {
    for limit in [64, 128] {
        let mut ancestors: Vec<_> = (0..limit)
            .map(|i| NotificationAncestor {
                spool: SpoolRef {
                    id: format!("00000000-0000-4000-8000-{i:012}"),
                },
                readable: true,
                system_root: false,
            })
            .collect();
        let cell = EffectiveDelivery {
            kind: "mention".into(),
            actor_origin: "human".into(),
            channel: 2,
            spool: Some(ancestors[0].spool.clone()),
            ..Default::default()
        };
        let rule = NotificationRule {
            kind: "mention".into(),
            channel: 2,
            delivery: 3,
            spool: Some(ancestors[limit - 1].spool.clone()),
            ..Default::default()
        };
        let resolved = resolve_notification_delivery(
            &[rule],
            &cell,
            &ancestors,
            limit,
            Delivery::Immediate,
            true,
        )
        .expect("at limit");
        assert_eq!(resolved.delivery, 3);
        assert_eq!(
            resolved.source_spool,
            Some(ancestors[limit - 1].spool.clone())
        );
        ancestors.push(NotificationAncestor {
            spool: SpoolRef {
                id: "00000000-0000-4000-8000-000000000999".into(),
            },
            readable: true,
            system_root: false,
        });
        assert_eq!(
            resolve_notification_delivery(&[], &cell, &ancestors, limit, Delivery::Immediate, true),
            Err(NotificationValidationError::InvalidAncestry)
        );
    }
}
