use heddle_api::heddle::api::v1alpha2::*;
use heddle_api::v2::invitation::*;
use heddle_api::v2::notifications::*;
use prost_types::{Duration, Timestamp};
use serde_json::Value;

const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/alpha38-review-fixes.json")).expect("vectors")
}
fn spool(id: &str) -> SpoolRef {
    SpoolRef { id: id.into() }
}
fn record() -> InvitationRecord {
    InvitationRecord {
        recipient: Some(invitation_record::Recipient::Handle("mara".into())),
        role: 2,
        state: 1,
        ..Default::default()
    }
}
fn now() -> Timestamp {
    Timestamp {
        seconds: 100,
        nanos: 0,
    }
}
fn rule(id: Option<&str>) -> NotificationRule {
    NotificationRule {
        kind: "*".into(),
        spool: id.map(spool),
        channel: 1,
        delivery: 3,
        ..Default::default()
    }
}
fn cell(id: Option<&str>, kind: &str) -> EffectiveDelivery {
    EffectiveDelivery {
        kind: kind.into(),
        spool: id.map(spool),
        channel: 1,
        actor_origin: "human".into(),
        ..Default::default()
    }
}
fn ancestor(id: &str, readable: bool) -> NotificationAncestor {
    NotificationAncestor {
        spool: spool(id),
        readable,
        system_root: false,
    }
}

#[test]
fn shared_current_inviter_authority_accept_redeem_and_retry_vectors() {
    for v in vectors()["authority"].as_array().expect("authority") {
        let offered = v["offered"].as_i64().expect("role") as i32;
        let current = v["current"].as_i64().expect("role") as i32;
        let allowed = v["allowed"].as_bool().expect("allowed");
        let result = validate_inviter_authority(offered, current);
        assert_eq!(result.is_ok(), allowed, "{}", v["name"]);
        if !allowed {
            let failure = result.expect_err("authority lost").failure();
            assert_eq!(failure.code, 9);
            let detail = failure.error.expect("typed");
            assert_eq!(detail.reason, 205);
            assert!(detail.resource.is_empty());
            assert!(detail.context.is_none());
        }
        // Pending Accept and Redeem require current admin authority.
        // Accepted retries are authenticated no-ops even after demotion.
        for state in [1, 2] {
            let invitation = InvitationRecord {
                role: offered,
                state,
                ..record()
            };
            assert_eq!(
                plan_invitation_response(
                    &invitation,
                    Some(ACCOUNT),
                    Some(ACCOUNT),
                    InvitationResponseAction::Accept,
                    &now(),
                    true,
                    current
                )
                .is_ok(),
                state == 2 || allowed,
                "{}",
                v["name"]
            );
            if state == 2 {
                let plan = plan_invitation_response(
                    &invitation,
                    Some(ACCOUNT),
                    Some(ACCOUNT),
                    InvitationResponseAction::Accept,
                    &now(),
                    true,
                    current,
                )
                .expect("accepted retry");
                assert!(!plan.changed && !plan.grant_role && plan.notification_kind.is_none());
            }
        }
    }
    // Decline remains possible when inviter authority is gone.
    assert!(
        plan_invitation_response(
            &record(),
            Some(ACCOUNT),
            Some(ACCOUNT),
            InvitationResponseAction::Decline,
            &now(),
            true,
            0
        )
        .is_ok()
    );
}

#[test]
fn shared_human_session_guard_precedes_lookup_and_terminal_replay() {
    for v in vectors()["sessions"].as_array().expect("sessions") {
        for action in [
            InvitationResponseAction::Accept,
            InvitationResponseAction::Decline,
        ] {
            for state in [1, 2, 3] {
                let human = v["human"].as_bool().expect("human");
                let result = plan_invitation_response(
                    &InvitationRecord { state, ..record() },
                    Some(ACCOUNT),
                    Some(ACCOUNT),
                    action,
                    &now(),
                    human,
                    3,
                );
                if !human {
                    assert_eq!(
                        result,
                        Err(InvitationError::HumanSessionRequired),
                        "{}",
                        v["name"]
                    );
                    let failure = result.expect_err("human required").failure();
                    assert_eq!(failure.code, 7);
                    assert_eq!(failure.error.expect("reason").reason, 204);
                } else if state == 1 {
                    assert!(result.is_ok());
                }
            }
            assert_eq!(
                plan_invitation_response(&record(), None, Some(ACCOUNT), action, &now(), false, 0),
                Err(InvitationError::HumanSessionRequired)
            );
        }
    }
}

#[test]
fn large_tree_projects_only_local_scopes_and_filtered_child_provenance() {
    let count = vectors()["descendants"].as_u64().expect("count");
    let mut readable: Vec<_> = (0..count).map(|i| spool(&format!("child-{i}"))).collect();
    readable.push(spool("root"));
    let rules = vec![rule(Some("root"))];
    let request = ObserveNotificationsRequest {
        include_preferences: true,
        ..Default::default()
    };
    let scopes = notification_projection_scopes(&request, &rules, &readable).expect("scopes");
    assert_eq!(scopes, vec![None, Some(spool("root"))]);
    assert_eq!(
        notification_projection_scopes(
            &request,
            &[
                rule(Some("root")),
                rule(Some("root")),
                rule(Some("hidden")),
                rule(None)
            ],
            &readable
        )
        .expect("redacted unique scopes"),
        scopes
    );
    let mut preferences = NotificationPreferences {
        rules: rules.clone(),
        ..Default::default()
    };
    // 70 cells per scope, independent of the 1000 rule-free descendants.
    for scope in scopes {
        for i in 0..70 {
            preferences.effective_delivery.push(EffectiveDelivery {
                spool: scope.clone(),
                kind: format!("kind-{i}"),
                channel: 1,
                ..Default::default()
            });
        }
    }
    assert_eq!(preferences.effective_delivery.len(), 140);
    validate_notification_preferences_bound(&preferences).expect("bounded large tree");
    let filtered = ObserveNotificationsRequest {
        effective_delivery_spool: Some(spool("child-0")),
        ..request.clone()
    };
    assert_eq!(
        notification_projection_scopes(&filtered, &rules, &readable).expect("filtered"),
        vec![Some(spool("child-0"))]
    );
    for readable_parent in [true, false] {
        let ancestry = [ancestor("child-0", true), ancestor("root", readable_parent)];
        let resolved = resolve_notification_delivery(
            &rules,
            &cell(Some("child-0"), "mention"),
            &ancestry,
            128,
            notification_rule::Delivery::Immediate,
            true,
        )
        .expect("effective child");
        assert_eq!(resolved.source, 3);
        assert_eq!(
            resolved.source_spool,
            readable_parent.then(|| spool("root"))
        );
        validate_effective_delivery_source(&resolved, &ancestry, 128).expect("source");
    }
    for invalid in [
        ObserveNotificationsRequest {
            include_preferences: false,
            ..filtered.clone()
        },
        ObserveNotificationsRequest {
            effective_delivery_spool: Some(spool("hidden")),
            ..filtered
        },
    ] {
        assert_eq!(
            notification_projection_scopes(&invalid, &rules, &readable),
            Err(NotificationValidationError::InvalidSource)
        );
    }
}

#[test]
fn hidden_rules_and_cadence_survive_replacement_until_explicit_clear() {
    let stored = NotificationPreferences {
        rules: vec![rule(Some("hidden")), rule(Some("visible")), rule(None)],
        digest_overrides: vec![NotificationDigestOverride {
            spool: Some(spool("hidden")),
            digest_interval: Some(Duration {
                seconds: 3600,
                nanos: 0,
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    for v in vectors()["replacement"].as_array().expect("replacement") {
        let request = SetNotificationPreferencesRequest {
            preferences: Some(NotificationPreferences::default()),
            clear_unreadable_scopes: v["clear"].as_bool().expect("clear"),
            ..Default::default()
        };
        let next = replace_notification_preferences(&stored, &request, &[spool("visible")])
            .expect("replacement");
        assert_eq!(next.rules.len() as u64, v["rules"].as_u64().expect("rules"));
        assert_eq!(
            next.digest_overrides.len() as u64,
            v["overrides"].as_u64().expect("overrides")
        );
        if !request.clear_unreadable_scopes {
            assert_eq!(next.rules, vec![rule(Some("hidden"))]);
        }
    }
    let unauthorized = SetNotificationPreferencesRequest {
        preferences: Some(stored.clone()),
        ..Default::default()
    };
    assert_eq!(
        replace_notification_preferences(&stored, &unauthorized, &[spool("visible")]),
        Err(NotificationValidationError::InvalidSource)
    );
    assert_eq!(stored.rules.len(), 3, "planning cannot mutate stored state");
}

#[test]
fn decline_to_departed_inviter_routes_account_without_invalid_source() {
    let ancestry = [ancestor("departed", false), ancestor("parent", true)];
    let declined = cell(Some("departed"), SPOOL_INVITATION_DECLINED);
    let rules = [rule(None), rule(Some("parent"))];
    let resolved = resolve_invitation_notification_delivery(
        &rules,
        &declined,
        &ancestry,
        128,
        notification_rule::Delivery::Immediate,
        true,
    )
    .expect("decline remains possible");
    assert_eq!(resolved.spool, None);
    assert_eq!(resolved.source, 1);
    assert_eq!(resolved.delivery, 3);
    assert_eq!(resolved.source_spool, None);
    validate_effective_delivery_source(&resolved, &[], 128).expect("account source");
    assert_eq!(
        resolve_notification_delivery(
            &rules,
            &declined,
            &ancestry,
            128,
            notification_rule::Delivery::Immediate,
            true
        ),
        Err(NotificationValidationError::InvalidSource),
        "ordinary spool reads remain denied"
    );
}

#[test]
fn shared_projection_privacy_gate_covers_all_three_read_surfaces() {
    use invitation_record::Recipient;
    let original = Recipient::Handle("mara".into());
    for v in vectors()["projections"].as_array().expect("projections") {
        let invitation = InvitationRecord {
            recipient: Some(if v["recipient"] == "accountId" {
                Recipient::AccountId(ACCOUNT.into())
            } else {
                original.clone()
            }),
            inviter: v["inviter"].as_str().map(|handle| PublicOwner {
                handle: handle.into(),
                ..Default::default()
            }),
            inviter_via_agent_label: v["label"].as_str().expect("label").into(),
            ..record()
        };
        let event = SpoolEvent {
            payload: Some(spool_event::Payload::Invitation(invitation.clone())),
            ..Default::default()
        };
        let notification = NotificationRecord {
            invitation: Some(invitation.clone()),
            ..Default::default()
        };
        let attention = AttentionItem {
            invitation: Some(invitation.clone()),
            ..Default::default()
        };
        for result in [
            validate_invitation_record_projection(&invitation, &original),
            validate_spool_invitation_projection(&event, &original),
            validate_notification_invitation_projection(&notification, &original),
            validate_attention_invitation_projection(&attention, &original),
        ] {
            assert_eq!(
                result.is_ok(),
                v["allowed"].as_bool().expect("allowed"),
                "{}",
                v["name"]
            );
        }
    }
    for (role, state) in [(0, 1), (99, 1), (2, 0), (2, 99)] {
        assert!(
            validate_invitation_record_projection(
                &InvitationRecord {
                    role,
                    state,
                    ..record()
                },
                &original
            )
            .is_err()
        );
    }
    // The safe invitation arm survives acceptance; member/grant identity is a
    // separate ordinary authorized read, not a private binding substitution.
    validate_invitation_record_projection(
        &InvitationRecord {
            state: 2,
            ..record()
        },
        &original,
    )
    .expect("accepted projection");
}

#[test]
fn admin_loss_revokes_all_pending_offered_roles_and_preserves_terminal_records() {
    let records: Vec<_> = (1..=3)
        .flat_map(|role| {
            [1, 2, 3, 4, 5].map(|state| InvitationRecord {
                role,
                state,
                ..record()
            })
        })
        .collect();
    assert!(plan_inviter_authority_loss(&records, 3, &now()).is_empty());
    for role in [0, 1, 2, 99] {
        let revoked = plan_inviter_authority_loss(&records, role, &now());
        assert_eq!(
            revoked.iter().map(|r| r.role).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert!(
            revoked
                .iter()
                .all(|r| r.state == 4 && r.updated_at == Some(now()))
        );
    }
    assert_eq!(records.iter().filter(|r| r.state == 1).count(), 3);
}
