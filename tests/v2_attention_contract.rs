use heddle_api::heddle::api::v1alpha2::{self as api, set_attention_state_request};
use prost::Message;

fn record(id: &str) -> api::RecordRef {
    api::RecordRef {
        id: id.into(),
        ..Default::default()
    }
}

fn timestamp(fixture: &serde_json::Value) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: fixture["snoozed_until_seconds"]
            .as_i64()
            .expect("snooze seconds"),
        nanos: fixture["snoozed_until_nanos"]
            .as_i64()
            .expect("snooze nanos")
            .try_into()
            .expect("nanos fit"),
    }
}

fn version(fixture: &serde_json::Value) -> Vec<u8> {
    hex::decode(fixture["version_hex"].as_str().expect("version hex")).expect("valid version")
}

fn assert_round_trip<T>(message: &T, wire_hex: &str)
where
    T: Message + Default + PartialEq + std::fmt::Debug,
{
    let wire = hex::decode(wire_hex).expect("valid golden bytes");
    assert_eq!(T::decode(wire.as_slice()).expect("TS wire"), *message);
    assert_eq!(message.encode_to_vec(), wire, "Rust wire matches TS golden");
}

#[test]
fn attention_snooze_matches_typescript_golden_in_both_directions() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/attention-snooze.json"))
            .expect("shared golden JSON");
    let item_id = fixture["item_id"].as_str().expect("item id");
    let resolution = i32::try_from(fixture["resolution"].as_i64().expect("resolution"))
        .expect("resolution fits");
    let pinned = fixture["pinned"].as_bool().expect("pinned");
    let snoozed_until = timestamp(&fixture);
    let version = version(&fixture);

    let item = api::AttentionItem {
        r#ref: Some(record(item_id)),
        version: version.clone(),
        resolution,
        pinned,
        snoozed_until: Some(snoozed_until),
        ..Default::default()
    };
    assert!(item.snoozed_until.is_some());
    assert_round_trip(&item, fixture["item_wire_hex"].as_str().expect("item wire"));
    let legacy = api::AttentionItem {
        snoozed_until: None,
        ..item.clone()
    };
    assert!(
        api::AttentionItem::decode(legacy.encode_to_vec().as_slice())
            .expect("legacy wire")
            .snoozed_until
            .is_none()
    );

    let set_request = api::SetAttentionStateRequest {
        client_operation_id: fixture["set_client_operation_id"]
            .as_str()
            .expect("set operation")
            .into(),
        item: Some(record(item_id)),
        expected_version: version.clone(),
        resolution,
        pinned,
        snooze: Some(set_attention_state_request::Snooze::SnoozedUntil(
            snoozed_until,
        )),
    };
    assert!(matches!(
        set_request.snooze,
        Some(set_attention_state_request::Snooze::SnoozedUntil(_))
    ));
    assert_round_trip(
        &set_request,
        fixture["set_wire_hex"].as_str().expect("set wire"),
    );

    let clear_request = api::SetAttentionStateRequest {
        client_operation_id: fixture["clear_client_operation_id"]
            .as_str()
            .expect("clear operation")
            .into(),
        item: Some(record(item_id)),
        expected_version: version.clone(),
        resolution,
        pinned,
        snooze: Some(set_attention_state_request::Snooze::ClearSnooze(true)),
    };
    assert!(matches!(
        clear_request.snooze,
        Some(set_attention_state_request::Snooze::ClearSnooze(true))
    ));
    assert_round_trip(
        &clear_request,
        fixture["clear_wire_hex"].as_str().expect("clear wire"),
    );

    let unchanged = api::SetAttentionStateRequest {
        client_operation_id: fixture["unchanged_client_operation_id"]
            .as_str()
            .expect("unchanged operation")
            .into(),
        item: Some(record(item_id)),
        expected_version: version,
        resolution,
        pinned,
        snooze: None,
    };
    assert!(unchanged.snooze.is_none());
    assert_round_trip(
        &unchanged,
        fixture["unchanged_wire_hex"]
            .as_str()
            .expect("unchanged wire"),
    );
    assert_ne!(fixture["set_wire_hex"], fixture["clear_wire_hex"]);
    assert_ne!(fixture["set_wire_hex"], fixture["unchanged_wire_hex"]);
}
