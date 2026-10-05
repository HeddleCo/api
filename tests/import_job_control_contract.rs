use heddle_api::{heddle::api::v1alpha2 as api, import_authority as a};
use prost::Message;
use serde_json::Value;

struct Fixture {
    new: Value,
    old: Value,
}
impl Fixture {
    fn load() -> Self {
        Self {
            new: serde_json::from_str(include_str!("fixtures/import-job-control-alpha31.json"))
                .expect("control fixture"),
            old: serde_json::from_str(heddle_api::IMPORT_AUTHORITY_HOST_WITNESS_V1_FIXTURE_JSON)
                .expect("signed fixture"),
        }
    }
    fn record<T: Message + Default>(&self, name: &str) -> T {
        let v = [
            &self.new["wire_vectors"][name],
            &self.old["wire_vectors"][name],
            &self.old["signed_vectors"][name],
        ]
        .into_iter()
        .find(|v| !v.is_null())
        .expect("vector exists");
        a::strict_decode(
            &hex::decode(v["wire_hex"].as_str().expect("hex")).expect("bytes"),
            2 * a::MAX_BUNDLE_BYTES,
        )
        .expect("fixed wire")
    }
    fn active(&self, read: &api::GetImportJobStateResponse) -> a::VerifiedImportDelegation {
        let signed = read
            .state
            .as_ref()
            .expect("state")
            .active_predecessor
            .as_ref()
            .expect("active");
        let d = signed.body.as_ref().expect("body");
        let owner = hex::decode(
            self.old["keys"]["owner"]["public_key_hex"]
                .as_str()
                .expect("key"),
        )
        .expect("owner");
        let expected = a::ImportOwnerExpectation {
            identity: d.identity.as_ref().expect("identity"),
            owner_public_key: &owner,
            owner_chain_digest: &d.owner_chain_digest,
            authority_expires_at_seconds: 2000,
            now_unix_seconds: if read.state.as_ref().expect("state").authority_epoch == 1 {
                1100
            } else {
                1250
            },
            forbidden_job_keys: &[],
            known_job_associations: &[],
        };
        let parent = a::resolve_bundle_permission(
            read.retained_proof.as_ref().expect("proof"),
            &d.parent_permission_digest,
        )
        .expect("parent selector");
        a::verify_delegation(signed, parent, &expected).expect("verified fixed authority")
    }
    fn prior(&self) -> Vec<String> {
        self.new["prior_attempt_ids"]
            .as_array()
            .expect("prior attempts")
            .iter()
            .map(|v| v.as_str().expect("ID").to_owned())
            .collect()
    }
}
fn text(v: &Value) -> &str {
    v.as_str().expect("string")
}
fn expected(s: &str) -> Result<(), a::Reject> {
    match s {
        "OK" => Ok(()),
        "SourceSelection" => Err(a::Reject::SourceSelection),
        "Scope" => Err(a::Reject::Scope),
        "StaleContext" => Err(a::Reject::StaleContext),
        "Revoked" => Err(a::Reject::Revoked),
        "Expired" => Err(a::Reject::Expired),
        "Canonical" => Err(a::Reject::Canonical),
        "Bounds" => Err(a::Reject::Bounds),
        "Semantic" => Err(a::Reject::Semantic),
        "PendingOperation" => Err(a::Reject::PendingOperation),
        other => panic!("unhandled {other}"),
    }
}
fn caller<'a>(
    read: &'a api::GetImportJobStateResponse,
    account: &'a str,
) -> a::ImportControlCaller<'a> {
    a::ImportControlCaller {
        authenticated_pop: true,
        destination_writer: true,
        caller_account: account,
        connection_owner_account: Some("owner"),
        authorized_source: read.retained_source.as_ref(),
        exact_grants_current: true,
        selected_commits_available: true,
    }
}
fn action(s: &str) -> a::ImportControlAction {
    match s {
        "Cancel" => a::ImportControlAction::Cancel,
        "Retry" => a::ImportControlAction::Retry,
        "Renew" => a::ImportControlAction::Renew,
        _ => panic!("action"),
    }
}

fn retry(f: &Fixture, change: &Value) -> Result<(), a::Reject> {
    let read: api::GetImportJobStateResponse =
        f.record(change["read"].as_str().unwrap_or("control_connected_state"));
    let mut request: api::RetryImportSourceRequest = f.record("control_retry_connected");
    let mut original: api::OperationRecord = f.record("control_original");
    let mut c = caller(&read, "owner");
    let state = read.state.as_ref().expect("state");
    let lineage = if change["lineage"].is_string() {
        vec![0xb4; 16]
    } else {
        state.retry_lineage_id.clone()
    };
    if change["operation_version"].is_string() {
        request.expected_operation_version = vec![0xb4; 32];
    }
    if let Some(epoch) = change["epoch"].as_u64() {
        request.expected_authority_epoch = epoch;
    }
    if change["active_digest"].is_string() {
        request.active_delegation_digest = vec![0xb4; 32];
    }
    if change["operation_job"].is_string() {
        let Some(api::operation_subject::Subject::Import(subject)) =
            &mut original.subject.as_mut().expect("subject").subject
        else {
            panic!("import")
        };
        subject
            .hybrid_job
            .as_mut()
            .expect("job selector")
            .logical_job_id = vec![0xb4; 16];
    }
    if let Some(s) = change["operation_state"].as_i64() {
        original.state = s as i32;
    }
    if change["superseded"] == true {
        original.superseded_by = Some(api::OperationRef {
            spool: original.r#ref.as_ref().expect("ref").spool.clone(),
            id: f.prior()[1].clone(),
        });
    }
    let public: api::GetImportJobStateResponse = f.record("control_public_state");
    if change["replacement_connection"] == true {
        c.authorized_source = public.retained_source.as_ref();
    }
    if let Some(v) = change["authenticated_pop"].as_bool() {
        c.authenticated_pop = v;
    }
    if let Some(v) = change["destination_writer"].as_bool() {
        c.destination_writer = v;
    }
    if let Some(v) = change["exact_grants_current"].as_bool() {
        c.exact_grants_current = v;
    }
    if let Some(v) = change["selected_commits_available"].as_bool() {
        c.selected_commits_available = v;
    }
    let context = a::ImportRetryAdmission {
        read: &read,
        original: &original,
        retry_lineage_id: &lineage,
        logical_job_terminal: change["terminal"].as_bool().unwrap_or(false),
        original_admitted: true,
        now_unix_seconds: change["now"].as_i64().unwrap_or(1100),
    };
    a::check_retry_admission(&request, &context, &f.active(&read), &c)
}
#[test]
fn co_writer_control_and_custody_vectors() {
    let f = Fixture::load();
    for row in f.new["control_vectors"].as_array().expect("vectors") {
        let read: api::GetImportJobStateResponse = f.record(text(&row["read"]));
        let state = read.state.as_ref().expect("state");
        let signed = state.active_predecessor.as_ref().expect("active");
        let d = signed.body.as_ref().expect("body");
        assert_eq!(row["ordinary_operation_visible"], false);
        let mut control_caller = caller(&read, text(&row["caller"]));
        if row["action"] == "Cancel" {
            control_caller.connection_owner_account = None;
            control_caller.authorized_source = None;
            control_caller.exact_grants_current = false;
            control_caller.selected_commits_available = false;
        }
        let result = a::check_import_control_caller(
            action(text(&row["action"])),
            read.retained_source.as_ref().expect("source"),
            d.scope.as_ref().expect("scope"),
            &control_caller,
        )
        .and_then(|()| match text(&row["action"]) {
            "Cancel" => a::check_cancel_request(
                &f.record("cancel_active"),
                signed,
                state.authority_epoch,
                false,
            ),
            "Retry" => {
                let request = f.record(if row["read"] == "control_public_state" {
                    "control_retry_public"
                } else {
                    "control_retry_connected"
                });
                let original = f.record(if row["read"] == "control_public_state" {
                    "control_public_original"
                } else {
                    "control_original"
                });
                a::check_retry_admission(
                    &request,
                    &a::ImportRetryAdmission {
                        read: &read,
                        original: &original,
                        retry_lineage_id: &state.retry_lineage_id,
                        logical_job_terminal: false,
                        original_admitted: true,
                        now_unix_seconds: 1100,
                    },
                    &f.active(&read),
                    &caller(&read, text(&row["caller"])),
                )
            }
            _ => Ok(()),
        });
        assert_eq!(result, expected(text(&row["expected"])), "{}", row["id"]);
        retry(&f, &Value::Null).expect("owner control after refusal");
        println!(
            "CONTROL {}: {}; owner control PASS",
            row["id"], row["expected"]
        );
    }
}
#[test]
fn retry_admission_reject_then_pass_vectors() {
    let f = Fixture::load();
    for row in f.new["retry_negatives"].as_array().expect("vectors") {
        assert_eq!(
            retry(&f, &row["change"]),
            expected(text(&row["expected"])),
            "{}",
            row["id"]
        );
        retry(&f, &Value::Null).expect("unchanged owner control");
        println!(
            "RETRY REJECT {}: {}; control PASS",
            row["id"], row["expected"]
        );
    }
}
#[test]
fn writer_retry_disclosure_reject_then_pass_vectors() {
    let f = Fixture::load();
    let request = f.record("job_state_request");
    for row in f.new["state_negatives"].as_array().expect("vectors") {
        assert_eq!(
            a::validate_retry_state_response(&request, &f.record(text(&row["read"]))),
            expected(text(&row["expected"])),
            "{}",
            row["id"]
        );
        a::validate_retry_state_response(&request, &f.record("control_connected_state"))
            .expect("unchanged disclosure control");
        println!(
            "DISCLOSURE REJECT {}: {}; control PASS",
            row["id"], row["expected"]
        );
    }
    for reason in 1..=6 {
        let read: api::GetImportJobStateResponse =
            f.record(&format!("control_unavailable_{reason}"));
        a::validate_retry_state_response(&request, &read).expect("known explicit unavailability");
        let original = f.record("control_original");
        assert_eq!(
            a::check_retry_admission(
                &f.record("control_retry_connected"),
                &a::ImportRetryAdmission {
                    read: &read,
                    original: &original,
                    retry_lineage_id: &read.state.as_ref().expect("state").retry_lineage_id,
                    logical_job_terminal: false,
                    original_admitted: true,
                    now_unix_seconds: 1100
                },
                &f.active(&read),
                &caller(&read, "owner")
            ),
            Err(a::Reject::StaleContext)
        );
    }
}
#[test]
fn control_receipt_reject_then_pass_vectors() {
    let f = Fixture::load();
    let prior = f.prior();
    for row in f.new["receipt_negatives"].as_array().expect("vectors") {
        let response = f.record(text(&row["response"]));
        let result = if row["kind"] == "Renew" {
            a::validate_renew_response(&f.record(text(&row["request"])), &response)
        } else {
            a::validate_retry_response(&f.record(text(&row["request"])), &response, &prior)
        };
        assert_eq!(result, expected(text(&row["expected"])), "{}", row["id"]);
        a::validate_renew_response(
            &f.record("renew_request_partial"),
            &f.record("control_renew_applied"),
        )
        .expect("empty applied versions");
        a::validate_retry_response(
            &f.record("control_retry_connected"),
            &f.record("control_retry_pending"),
            &prior,
        )
        .expect("fresh UUID pending control");
        println!(
            "RECEIPT REJECT {}: {}; control PASS",
            row["id"], row["expected"]
        );
    }
}
#[test]
fn frozen_control_replays_do_not_reactivate_or_allocate() {
    let f = Fixture::load();
    for row in f.new["replay_vectors"].as_array().expect("replay vectors") {
        let wire = if row["kind"] == "Retry" {
            f.record::<api::RetryImportSourceRequest>(text(&row["request"]))
                .encode_to_vec()
        } else {
            f.record::<api::RenewImportJobRequest>(text(&row["request"]))
                .encode_to_vec()
        };
        let stored: frozen::Entry = frozen::Entry {
            wire: wire.clone(),
            receipt: f
                .record::<api::MutationResponse>(text(&row["response"]))
                .encode_to_vec(),
        };
        let mut changed = wire.clone();
        *changed.last_mut().expect("nonempty wire") ^= 1;
        assert_eq!(stored.replay(&changed), Err(a::Reject::OperationIdReused));
        assert_eq!(stored.replay(&wire).expect("exact replay"), stored.receipt);
    }
}
mod frozen {
    use super::a;
    pub struct Entry {
        pub wire: Vec<u8>,
        pub receipt: Vec<u8>,
    }
    impl Entry {
        pub fn replay(&self, wire: &[u8]) -> Result<&[u8], a::Reject> {
            a::check_retry_replay(wire, &self.wire)?;
            Ok(&self.receipt)
        }
    }
}
fn sized_request(row: &Value, size: usize) -> api::CommitImportJobRequest {
    let whole = row["kind"] == "request";
    let mut request = api::CommitImportJobRequest {
        proof: Some(api::ImportPublicProofBundleV1::default()),
        ..Default::default()
    };
    if whole {
        request.client_operation_id = "x".repeat(size);
    } else {
        request
            .proof
            .as_mut()
            .expect("proof")
            .creator_authority_envelopes = vec![vec![0; size]];
    }
    for _ in 0..4 {
        let measured = if whole {
            request.encoded_len()
        } else {
            request.proof.as_ref().expect("proof").encoded_len()
        };
        if measured == size {
            return request;
        }
        if whole {
            let len = request.client_operation_id.len() + size - measured;
            request.client_operation_id = "x".repeat(len);
        } else {
            let proof = request.proof.as_mut().expect("proof");
            let len = proof.creator_authority_envelopes[0].len() + size - measured;
            proof.creator_authority_envelopes[0] = vec![0; len];
        }
    }
    panic!("boundary recipe did not converge")
}
#[test]
fn commit_decoded_request_and_proof_boundaries() {
    let f = Fixture::load();
    for row in f.new["bound_vectors"].as_array().expect("boundaries") {
        let size = row["decoded_protobuf_bytes"].as_u64().expect("size") as usize;
        let request = sized_request(row, size);
        assert_eq!(
            a::validate_commit_request_bounds(&request),
            expected(text(&row["expected"])),
            "{}",
            row["id"]
        );
        if row["expected"] == "Bounds" {
            assert_eq!(
                a::validate_commit_request(
                    &request,
                    "github",
                    &f.record("source_connected"),
                    &f.record("import_configuration")
                ),
                Err(a::Reject::Bounds)
            );
            a::validate_commit_request_bounds(&sized_request(row, size - 1))
                .expect("inclusive limit control");
        }
        println!("BOUND {}: {}", row["id"], row["expected"]);
    }
}
#[test]
fn authority_only_renew_then_explicit_retry_uses_new_id_and_active_fence() {
    let f = Fixture::load();
    let flow = &f.new["renew_retry_flow"];
    let renew: api::RenewImportJobRequest = f.record(text(&flow["renew_request"]));
    let retry: api::RetryImportSourceRequest = f.record(text(&flow["retry_request"]));
    a::validate_renew_response(&renew, &f.record(text(&flow["renew_response"])))
        .expect("authority-only acknowledgement");
    assert_ne!(renew.client_operation_id, retry.client_operation_id);
    let read: api::GetImportJobStateResponse = f.record(text(&flow["new_state"]));
    let original = f.record("control_original");
    a::check_retry_admission(
        &retry,
        &a::ImportRetryAdmission {
            read: &read,
            original: &original,
            retry_lineage_id: &read.state.as_ref().expect("state").retry_lineage_id,
            logical_job_terminal: false,
            original_admitted: true,
            now_unix_seconds: 1250,
        },
        &f.active(&read),
        &caller(&read, "owner"),
    )
    .expect("replacement authority admits explicit retry");
}
#[cfg(feature = "reflection")]
#[test]
fn retry_target_is_additive_and_typed() {
    use prost_reflect::{DescriptorPool, Kind};
    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("descriptor");
    let response = pool
        .get_message_by_name("heddle.api.v1alpha2.GetImportJobStateResponse")
        .expect("response");
    let target = response.get_field(4).expect("additive target");
    assert_eq!(target.name(), "eligible_retry_target");
    assert!(target.containing_oneof().is_some());
    let Kind::Message(target) = target.kind() else {
        panic!("typed target")
    };
    assert_eq!(
        target.full_name(),
        "heddle.api.v1alpha2.ImportEligibleRetryTargetV1"
    );
    assert_eq!(target.fields().count(), 2);
    assert_eq!(target.get_field(2).expect("CAS").kind(), Kind::Bytes);
    assert_eq!(
        response.get_field(5).expect("unavailability").name(),
        "retry_unavailable"
    );
}
#[test]
fn review_fix_retry_original_window_reject_then_pass() {
    let f = Fixture::load();
    let read: api::GetImportJobStateResponse = f.record("control_renewed_state");
    let original = f.record("control_original");
    let request = f.record("control_retry_renewed");
    let context = a::ImportRetryAdmission {
        read: &read,
        original: &original,
        retry_lineage_id: &read.state.as_ref().expect("state").retry_lineage_id,
        logical_job_terminal: false,
        original_admitted: false,
        now_unix_seconds: 1300,
    };
    assert_eq!(
        a::check_retry_admission(
            &request,
            &context,
            &f.active(&read),
            &caller(&read, "owner")
        ),
        Err(a::Reject::OriginalWindowEnded)
    );
    a::check_retry_admission(
        &request,
        &a::ImportRetryAdmission {
            original_admitted: true,
            ..context
        },
        &f.active(&read),
        &caller(&read, "owner"),
    )
    .expect("admitted control");
}
