#![cfg(feature = "reflection")]

use heddle_api::FILE_DESCRIPTOR_SET;
use heddle_api::heddle::api::v1alpha2::{
    ObservationMode, ObserveOptions, ObserveRunsRequest, RecordRef, RunEvent, TimelineRecord,
    TimelineStart, run_event,
};
use heddle_api::v2::method_descriptor;
use prost::Message;
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn timeline_fields_and_latest_request_round_trip() {
    let timeline = TimelineRecord {
        r#ref: Some(RecordRef {
            id: "run-7:12".into(),
            ..Default::default()
        }),
        run: Some(RecordRef {
            id: "run-7".into(),
            ..Default::default()
        }),
        position: 12,
        kind: "PostToolUse".into(),
        summary: "Bash: cargo test".into(),
        recorded_at: Some(prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_000_000,
        }),
        tool_name: Some("Bash".into()),
        detail: Some("cargo test".into()),
        ..Default::default()
    };
    let event = RunEvent {
        payload: Some(run_event::Payload::Timeline(timeline.clone())),
        ..Default::default()
    };
    let decoded = RunEvent::decode(event.encode_to_vec().as_slice()).expect("timeline event");
    assert_eq!(decoded, event);
    let Some(run_event::Payload::Timeline(decoded_timeline)) = decoded.payload else {
        panic!("timeline payload was lost");
    };
    assert_eq!(decoded_timeline.recorded_at, timeline.recorded_at);
    assert_eq!(decoded_timeline.tool_name, Some("Bash".into()));
    assert_eq!(decoded_timeline.detail, Some("cargo test".into()));

    let request = ObserveRunsRequest {
        runs: vec![RecordRef {
            id: "run-7".into(),
            ..Default::default()
        }],
        include_timeline: true,
        observe: Some(ObserveOptions {
            mode: ObservationMode::Follow as i32,
            ..Default::default()
        }),
        timeline_start: TimelineStart::Latest as i32,
        timeline_limit: 32,
        ..Default::default()
    };
    let decoded = ObserveRunsRequest::decode(request.encode_to_vec().as_slice())
        .expect("latest timeline request");
    assert_eq!(decoded, request);
    assert_eq!(decoded.timeline_start, TimelineStart::Latest as i32);
    assert_eq!(decoded.timeline_limit, 32);
}

#[test]
fn observe_runs_catalog_and_descriptor_include_new_request_shape() {
    let route = method_descriptor("/heddle.api.v1alpha2.RunService/ObserveRuns")
        .expect("ObserveRuns catalog route");
    assert_eq!(route.input, "heddle.api.v1alpha2.ObserveRunsRequest");
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor set");
    let request = pool
        .get_message_by_name("heddle.api.v1alpha2.ObserveRunsRequest")
        .expect("request descriptor");
    for (name, number) in [("timeline_start", 7), ("timeline_limit", 8)] {
        assert_eq!(
            request
                .get_field_by_name(name)
                .expect("request field")
                .number(),
            number
        );
    }
    let timeline = pool
        .get_message_by_name("heddle.api.v1alpha2.TimelineRecord")
        .expect("timeline descriptor");
    for (name, number) in [("recorded_at", 9), ("tool_name", 10), ("detail", 11)] {
        assert_eq!(
            timeline
                .get_field_by_name(name)
                .expect("timeline field")
                .number(),
            number
        );
    }
    assert!(matches!(
        timeline
            .get_field_by_name("recorded_at")
            .expect("time")
            .kind(),
        Kind::Message(_)
    ));
    assert!(
        timeline
            .get_field_by_name("tool_name")
            .expect("tool")
            .supports_presence()
    );
    assert!(
        timeline
            .get_field_by_name("detail")
            .expect("detail")
            .supports_presence()
    );
}
