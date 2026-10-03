use heddle_api::heddle::api::v1alpha2::{ReadBudget, SpoolSettings, ThreadOverview};
use heddle_api::v2::spool_settings::{SpoolSettingsPatchError, apply_spool_settings_patch};
use heddle_api::v2::{
    GUARANTEED_READ_BUDGET, ReadBudgetError, negotiate_read_budget, validate_accepted_read_budget,
};
use prost::Message;
use prost_types::FieldMask;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/v2-alpha22.json")).expect("shared parity vectors")
}

fn budget(v: &Value) -> ReadBudget {
    ReadBudget {
        max_items: v[0].as_u64().expect("items") as u32,
        max_frame_bytes: v[1].as_u64().expect("frame") as u32,
        max_snapshot_bytes: v[2].as_str().expect("snapshot").parse().expect("u64"),
    }
}

#[test]
fn read_budget_clamps_fixed_requests_and_enforces_floor() {
    let fixture = fixture();
    assert_eq!(budget(&fixture["floor"]), GUARANTEED_READ_BUDGET);
    let vectors = fixture["budgets"].as_array().expect("vectors");
    assert!(vectors.len() >= 10);
    for vector in vectors {
        let requested = budget(&vector["requested"]);
        let result = negotiate_read_budget(
            &requested,
            &budget(&vector["defaults"]),
            &budget(&vector["maximum"]),
            &budget(&vector["capacity"]),
        );
        if let Some(error) = vector["error"].as_str() {
            let expected = match error {
                "capacity" => ReadBudgetError::Capacity,
                "shape" => ReadBudgetError::Shape,
                "advertisement" => ReadBudgetError::Advertisement,
                _ => panic!("unknown error vector"),
            };
            assert_eq!(result, Err(expected), "{}", vector["name"]);
        } else {
            let accepted = result.expect("accepted fixed budget");
            assert_eq!(accepted, budget(&vector["accepted"]), "{}", vector["name"]);
            assert_eq!(
                hex::encode(accepted.encode_to_vec()),
                vector["accepted_wire_hex"].as_str().expect("wire")
            );
            validate_accepted_read_budget(&requested, Some(&accepted))
                .expect("valid mandatory echo");
        }
    }
    for echo in [
        None,
        Some(ReadBudget::default()),
        Some(ReadBudget {
            max_items: 1025,
            ..GUARANTEED_READ_BUDGET
        }),
        Some(ReadBudget {
            max_items: 1023,
            ..GUARANTEED_READ_BUDGET
        }),
    ] {
        assert_eq!(
            validate_accepted_read_budget(&GUARANTEED_READ_BUDGET, echo.as_ref()),
            Err(ReadBudgetError::Echo)
        );
    }
}

#[test]
fn clear_semantics_preserve_hidden_settings_and_authorize_explicit_clears() {
    let fixture = fixture();
    let stored = SpoolSettings::decode(
        hex::decode(fixture["settings_wire_hex"].as_str().expect("wire"))
            .expect("hex")
            .as_slice(),
    )
    .expect("settings");
    let patch = SpoolSettings {
        description: "after".into(),
        ..Default::default()
    };
    let mask = |paths: &[&str]| FieldMask {
        paths: paths.iter().map(|p| (*p).into()).collect(),
    };
    let all = FieldMask {
        paths: fixture["settings_fields"]
            .as_object()
            .expect("fields")
            .keys()
            .cloned()
            .collect(),
    };
    assert_eq!(
        apply_spool_settings_patch(&SpoolSettings::default(), Some(&stored), Some(&all), |_| {
            false
        }),
        Ok(stored.clone())
    );
    let updated =
        apply_spool_settings_patch(&stored, Some(&patch), Some(&mask(&["description"])), |_| {
            false
        })
        .expect("unrelated edit");
    assert_eq!(updated.default_thread, stored.default_thread);
    assert_eq!(updated.default_review_policy, stored.default_review_policy);
    assert_eq!(updated.description, "after");
    assert_eq!(
        apply_spool_settings_patch(&stored, Some(&patch), None, |_| false),
        Ok(stored.clone())
    );
    for field in ["default_thread", "default_review_policy"] {
        assert_eq!(
            apply_spool_settings_patch(&stored, Some(&patch), Some(&mask(&[field])), |_| false),
            Err(SpoolSettingsPatchError::ClearDenied)
        );
        let cleared =
            apply_spool_settings_patch(&stored, Some(&patch), Some(&mask(&[field])), |_| true)
                .expect("authorized clear");
        if field == "default_thread" {
            assert!(cleared.default_thread.is_none());
        } else {
            assert!(cleared.default_review_policy.is_none());
        }
    }
    for field in fixture["settings_fields"]
        .as_object()
        .expect("complete field audit")
        .keys()
    {
        assert_eq!(
            apply_spool_settings_patch(&stored, None, Some(&mask(&[field])), |_| false),
            Err(SpoolSettingsPatchError::ClearDenied)
        );
        let result = apply_spool_settings_patch(&stored, None, Some(&mask(&[field])), |_| true)
            .expect("explicit clear");
        let expected = fixture["cleared_settings_wire_hex"][field]
            .as_str()
            .expect("shared cleared wire");
        assert_eq!(hex::encode(result.encode_to_vec()), expected, "{field}");
    }
    for paths in [
        vec!["*"],
        vec!["default_thread.id"],
        vec!["settings.description"],
        vec!["unknown"],
        vec!["description", "description"],
    ] {
        assert_eq!(
            apply_spool_settings_patch(&stored, Some(&patch), Some(&mask(&paths)), |_| true),
            Err(SpoolSettingsPatchError::Mask)
        );
    }
    // Failed multi-field patches never return partially applied settings.
    assert_eq!(
        apply_spool_settings_patch(
            &stored,
            Some(&patch),
            Some(&mask(&["description", "default_thread"])),
            |_| false
        ),
        Err(SpoolSettingsPatchError::ClearDenied)
    );
    assert_eq!(stored.description, "before");
}

#[test]
fn integrated_at_is_the_landing_time_and_unset_before_landing() {
    let fixture = fixture();
    let bytes = hex::decode(fixture["thread_wire_hex"].as_str().expect("wire")).expect("hex");
    let overview = ThreadOverview::decode(bytes.as_slice()).expect("overview");
    assert_eq!(
        overview.integrated_at.as_ref().expect("landed").seconds,
        fixture["integrated_at"]
            .as_str()
            .expect("time")
            .parse::<i64>()
            .expect("i64")
    );
    assert_ne!(overview.integrated_at, overview.updated_at);
    assert_eq!(overview.encode_to_vec(), bytes);
    assert!(ThreadOverview::default().integrated_at.is_none());
}

#[cfg(feature = "reflection")]
#[test]
fn alpha22_descriptors_pin_mask_landing_and_every_budget_echo() {
    use prost_reflect::DescriptorPool;
    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("descriptors");
    let fixture = fixture();
    let settings = pool
        .get_message_by_name("heddle.api.v1alpha2.SpoolSettings")
        .expect("settings");
    assert_eq!(
        settings.fields().len(),
        fixture["settings_fields"]
            .as_object()
            .expect("fields")
            .len()
    );
    for field in settings.fields() {
        assert!(
            fixture["settings_fields"].get(field.name()).is_some(),
            "all fields audited"
        );
    }
    for (message, name, tag, target) in [
        (
            "ReviseSpoolRequest",
            "settings_mask",
            7,
            "google.protobuf.FieldMask",
        ),
        (
            "ThreadOverview",
            "integrated_at",
            30,
            "google.protobuf.Timestamp",
        ),
        (
            "StreamOpen",
            "accepted_budget",
            4,
            "heddle.api.v1alpha2.ReadBudget",
        ),
        (
            "ContentEvent",
            "accepted_budget",
            9,
            "heddle.api.v1alpha2.ReadBudget",
        ),
        (
            "ListPathsEvent",
            "accepted_budget",
            4,
            "heddle.api.v1alpha2.ReadBudget",
        ),
        (
            "ArtifactEvent",
            "accepted_budget",
            4,
            "heddle.api.v1alpha2.ReadBudget",
        ),
        (
            "SearchEvent",
            "accepted_budget",
            5,
            "heddle.api.v1alpha2.ReadBudget",
        ),
        (
            "ResolveResourcesResponse",
            "accepted_budget",
            2,
            "heddle.api.v1alpha2.ReadBudget",
        ),
        (
            "ResolveHandlesResponse",
            "accepted_budget",
            2,
            "heddle.api.v1alpha2.ReadBudget",
        ),
        (
            "GetFileSymbolsResponse",
            "accepted_budget",
            5,
            "heddle.api.v1alpha2.ReadBudget",
        ),
        (
            "GetDefinitionResponse",
            "accepted_budget",
            5,
            "heddle.api.v1alpha2.ReadBudget",
        ),
        (
            "GetSemanticRefsResponse",
            "accepted_budget",
            6,
            "heddle.api.v1alpha2.ReadBudget",
        ),
        (
            "GetSemanticImportersResponse",
            "accepted_budget",
            6,
            "heddle.api.v1alpha2.ReadBudget",
        ),
        (
            "TransferReady",
            "budget",
            9,
            "heddle.api.v1alpha2.ReadBudget",
        ),
        (
            "ReplicationReady",
            "budget",
            5,
            "heddle.api.v1alpha2.ReadBudget",
        ),
    ] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
            .expect("message");
        let field = message.get_field_by_name(name).expect("typed field");
        assert_eq!(field.number(), tag);
        assert!(field.supports_presence());
        assert_eq!(
            field.kind().as_message().expect("message kind").full_name(),
            target
        );
        if message.name().ends_with("Event") {
            assert_eq!(
                field.containing_oneof().expect("initial echo event").name(),
                "payload"
            );
        }
    }
    for (message, wire) in fixture["echoes_wire_hex"].as_object().expect("echo wires") {
        let descriptor = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
            .expect("response descriptor");
        let bytes = hex::decode(wire.as_str().expect("wire")).expect("hex");
        let response = prost_reflect::DynamicMessage::decode(descriptor, bytes.as_slice())
            .expect("response wire");
        assert!(response.has_field_by_name("accepted_budget"));
        assert_eq!(response.encode_to_vec(), bytes);
    }
    let request = heddle_api::heddle::api::v1alpha2::ReviseSpoolRequest::decode(
        hex::decode(fixture["clear_request_wire_hex"].as_str().expect("wire"))
            .expect("hex")
            .as_slice(),
    )
    .expect("clear mask wire");
    assert!(request.settings.is_none());
    assert_eq!(
        request.settings_mask.expect("explicit mask").paths,
        ["default_thread", "default_review_policy"]
    );
    // Any budget field in the API must reference the same generated wire type.
    for message in pool
        .all_messages()
        .filter(|m| m.package_name() == "heddle.api.v1alpha2")
    {
        for field in message.fields().filter(|f| f.name().ends_with("budget")) {
            assert_eq!(
                field
                    .kind()
                    .as_message()
                    .expect("shared budget")
                    .full_name(),
                "heddle.api.v1alpha2.ReadBudget"
            );
        }
    }
}

#[test]
fn replacements_authorize_stored_references_and_fail_atomically() {
    let f = fixture();
    let stored = SpoolSettings::decode(
        hex::decode(f["settings_wire_hex"].as_str().expect("wire"))
            .expect("hex")
            .as_slice(),
    )
    .expect("settings");
    for vector in f["replacement_cases"].as_array().expect("shared cases") {
        let patch = SpoolSettings::decode(
            hex::decode(vector["patch_wire_hex"].as_str().expect("wire"))
                .expect("hex")
                .as_slice(),
        )
        .expect("patch");
        let mask = FieldMask {
            paths: vector["mask"]
                .as_array()
                .expect("mask")
                .iter()
                .map(|p| p.as_str().expect("path").into())
                .collect(),
        };
        let mut calls = Vec::new();
        assert_eq!(
            apply_spool_settings_patch(&stored, Some(&patch), Some(&mask), |field| {
                calls.push(field.to_owned());
                !vector["denied"]
                    .as_array()
                    .expect("denied")
                    .iter()
                    .any(|v| v.as_str() == Some(field))
            }),
            Err(SpoolSettingsPatchError::ClearDenied),
            "{}",
            vector["field"]
        );
        assert_eq!(
            calls,
            mask.paths
                .iter()
                .filter(|p| p.as_str() != "description")
                .cloned()
                .collect::<Vec<_>>()
        );
        let mut expected = stored.clone();
        for field in &mask.paths {
            match field.as_str() {
                "default_thread" => expected.default_thread = patch.default_thread.clone(),
                "default_review_policy" => {
                    expected.default_review_policy = patch.default_review_policy.clone()
                }
                "description" => expected.description = patch.description.clone(),
                _ => panic!("unexpected shared mask"),
            }
        }
        assert_eq!(
            apply_spool_settings_patch(&stored, Some(&patch), Some(&mask), |_| true),
            Ok(expected)
        );
        assert_eq!(
            hex::encode(stored.encode_to_vec()),
            f["settings_wire_hex"].as_str().expect("stored wire")
        );
    }
    assert_eq!(
        apply_spool_settings_patch(
            &stored,
            Some(&stored.clone()),
            Some(&FieldMask {
                paths: vec!["default_thread".into(), "default_review_policy".into()]
            }),
            |_| false
        ),
        Ok(stored)
    );
}

fn isolated_floor(index: usize, dimension: &str) {
    let f = fixture();
    let name = format!("below floor {dimension} only");
    let vector = f["budgets"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|v| v["name"].as_str() == Some(&name))
        .expect("isolated floor vector");
    let defaults = budget(&vector["defaults"]);
    let maximum = budget(&vector["maximum"]);
    for i in 0..3 {
        let value = |v: &Value| {
            if i == 2 {
                v[i].as_str()
                    .expect("u64 string")
                    .parse::<u64>()
                    .expect("u64")
            } else {
                v[i].as_u64().expect("u32")
            }
        };
        assert!(value(&vector["defaults"]) <= value(&vector["maximum"]));
        assert_eq!(value(&vector["maximum"]) < value(&f["floor"]), i == index);
    }
    assert_eq!(
        negotiate_read_budget(
            &budget(&vector["requested"]),
            &defaults,
            &maximum,
            &budget(&vector["capacity"])
        ),
        Err(ReadBudgetError::Advertisement)
    );
}
#[test]
fn advertised_floor_isolates_items() {
    isolated_floor(0, "items");
}
#[test]
fn advertised_floor_isolates_frame() {
    isolated_floor(1, "frame");
}
#[test]
fn advertised_floor_isolates_snapshot() {
    isolated_floor(2, "snapshot");
}
