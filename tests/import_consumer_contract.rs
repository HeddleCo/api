use heddle_api::{heddle::api::v1alpha2 as api, import_authority as a};
use prost::Message;
use serde_json::Value;

struct Fixture {
    new: Value,
    old: Value,
    control: Value,
    owner: Vec<u8>,
    root: Vec<u8>,
    replacement: Vec<u8>,
}
impl Fixture {
    fn load() -> Self {
        let old: Value =
            serde_json::from_str(heddle_api::IMPORT_AUTHORITY_HOST_WITNESS_V1_FIXTURE_JSON)
                .expect("signed fixture");
        let key = |name: &str| {
            hex::decode(old["keys"][name]["public_key_hex"].as_str().expect("hex")).expect("key")
        };
        Self {
            new: serde_json::from_str(include_str!("fixtures/import-consumer-alpha32.json"))
                .expect("consumer fixture"),
            control: serde_json::from_str(include_str!("fixtures/import-job-control-alpha31.json"))
                .expect("control fixture"),
            owner: key("owner"),
            root: key("root"),
            replacement: key("wrong_root"),
            old,
        }
    }
    fn record<T: Message + Default>(&self, name: &str) -> T {
        let r = [
            &self.new["wire_vectors"][name],
            &self.control["wire_vectors"][name],
            &self.old["wire_vectors"][name],
            &self.old["signed_vectors"][name],
        ]
        .into_iter()
        .find(|r| !r.is_null())
        .expect("vector");
        a::strict_decode(
            &hex::decode(text(&r["wire_hex"])).expect("wire"),
            2 * a::MAX_BUNDLE_BYTES,
        )
        .expect("fixed wire")
    }
    fn pin(&self, replacement: bool) -> a::ImportWitnessRootPin {
        a::ImportWitnessRootPin {
            authority: text(&self.old["context"]["authority"]).into(),
            root_id: if replacement {
                "descriptor-root-2".into()
            } else {
                text(&self.old["context"]["root_id"]).into()
            },
            public_key: if replacement {
                self.replacement.clone()
            } else {
                self.root.clone()
            },
            epoch: if replacement { 2 } else { 1 },
        }
    }
    fn verify(
        &self,
        bundle: &api::ImportPublicProofBundleV1,
        snapshot: Option<&a::ImportWitnessSnapshot>,
        now: i64,
        replacement: bool,
    ) -> Result<a::VerifiedImportBundleWitnesses, a::Reject> {
        let owners = bundle
            .delegations
            .iter()
            .map(|d| {
                let b = d.body.as_ref().expect("body");
                a::ImportBundleOwnerExpectation {
                    identity: b.identity.as_ref().expect("identity"),
                    owner_public_key: &self.owner,
                    owner_chain_digest: &b.owner_chain_digest,
                    authority_expires_at_seconds: 2000,
                    effective_from_unix_seconds: 0,
                    effective_until_unix_seconds: None,
                    forbidden_job_keys: &[],
                    known_job_associations: &[],
                }
            })
            .collect::<Vec<_>>();
        a::verify_import_bundle_witnesses(
            bundle,
            &self.pin(replacement),
            snapshot,
            now,
            |i, _| Ok(owners[i]),
            |b, _| {
                assert_eq!(b.policies, vec![self.record("signed_policy")]);
                Ok(())
            },
        )
    }
}
fn text(v: &Value) -> &str {
    v.as_str().expect("text")
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
fn context<'a>(
    read: &'a api::GetImportJobStateResponse,
    change: &Value,
) -> a::ImportControlAvailabilityContext<'a> {
    a::ImportControlAvailabilityContext {
        read,
        logical_job_terminal: change["terminal"].as_bool().unwrap_or(false),
        original_admitted: change["admitted"].as_bool().unwrap_or(true),
        now_unix_seconds: change["now"].as_i64().unwrap_or(1100),
    }
}
#[test]
fn alpha32_caller_availability_vectors() {
    let f = Fixture::load();
    for row in f.new["availability"].as_array().expect("vectors") {
        let read: api::GetImportJobStateResponse = f.record(text(&row["read"]));
        let mut c = caller(&read, text(&row["caller"]));
        let change = &row["change"];
        c.exact_grants_current = change["grants"].as_bool().unwrap_or(true);
        c.selected_commits_available = change["commits"].as_bool().unwrap_or(true);
        let public: api::GetImportJobStateResponse = f.record("control_public_state");
        if change["replacement"] == true {
            c.authorized_source = public.retained_source.as_ref();
        }
        let actual =
            a::import_job_control_availability(&context(&read, change), &c).expect("writer advice");
        assert_eq!(Some(actual), read.control_availability, "{}", row["id"]);
        let mut request: api::GetImportJobStateRequest = f.record("job_state_request");
        request.logical_job_id = read.state.as_ref().expect("state").logical_job_id.clone();
        a::validate_control_state_response(&request, &read).expect("valid current read");
    }
}
#[test]
fn alpha32_controls_reject_then_pass() {
    let f = Fixture::load();
    for row in f.new["state_negatives"].as_array().expect("negatives") {
        assert_eq!(
            a::validate_control_state_response(
                &f.record("job_state_request"),
                &f.record(text(&row["read"]))
            ),
            Err(a::Reject::Canonical),
            "{}",
            row["id"]
        );
        a::validate_control_state_response(
            &f.record("job_state_request"),
            &f.record(text(&row["control"])),
        )
        .expect("control");
    }
}
#[test]
fn alpha32_availability_requires_writer_and_never_overrides_admission() {
    let f = Fixture::load();
    let mut read: api::GetImportJobStateResponse =
        f.record("consumer_controls_connected_co_writer");
    let owner_read: api::GetImportJobStateResponse = f.record("consumer_controls_owner");
    read.control_availability = owner_read.control_availability;
    let scope = read
        .state
        .as_ref()
        .expect("state")
        .active_predecessor
        .as_ref()
        .expect("active")
        .body
        .as_ref()
        .expect("body")
        .scope
        .as_ref()
        .expect("scope");
    for action in [a::ImportControlAction::Retry, a::ImportControlAction::Renew] {
        assert_eq!(
            a::check_import_control_caller(
                action,
                read.retained_source.as_ref().expect("source"),
                scope,
                &caller(&read, "co-writer")
            ),
            Err(a::Reject::SourceSelection)
        );
        a::check_import_control_caller(
            action,
            read.retained_source.as_ref().expect("source"),
            scope,
            &caller(&read, "owner"),
        )
        .expect("owner control");
    }
    let mut c = caller(&read, "co-writer");
    c.connection_owner_account = None;
    c.authorized_source = None;
    c.exact_grants_current = false;
    c.selected_commits_available = false;
    a::check_import_control_caller(
        a::ImportControlAction::Cancel,
        read.retained_source.as_ref().expect("source"),
        scope,
        &c,
    )
    .expect("destination-only cancel");
    c.authenticated_pop = false;
    assert_eq!(
        a::import_job_control_availability(&context(&read, &Value::Null), &c),
        Err(a::Reject::Scope)
    );
    c.authenticated_pop = true;
    c.destination_writer = false;
    assert_eq!(
        a::import_job_control_availability(&context(&read, &Value::Null), &c),
        Err(a::Reject::Scope)
    );
    c.destination_writer = true;
    c.caller_account = "";
    assert_eq!(
        a::import_job_control_availability(&context(&read, &Value::Null), &c),
        Err(a::Reject::Scope)
    );
    a::import_job_control_availability(&context(&read, &Value::Null), &caller(&read, "owner"))
        .expect("writer control");
}
#[test]
fn alpha32_recovery_snapshot_vectors() {
    let f = Fixture::load();
    for row in f.new["recovery"].as_array().expect("recovery") {
        let mut initial_bundle: api::ImportPublicProofBundleV1 =
            f.record("review_scheduled_recovery");
        let initial_time = if let Some(name) = row["initial_set"].as_str() {
            initial_bundle.witness_set = Some(f.record(name));
            1_350_000
        } else {
            1_100_000
        };
        let initial = if row["input"] == true {
            Some(
                f.verify(&initial_bundle, None, initial_time, false)
                    .expect("initial set"),
            )
        } else {
            None
        };
        let input = initial.as_ref().and_then(|r| r.snapshot.as_ref());
        let before = input.cloned();
        let mut bundle: api::ImportPublicProofBundleV1 = f.record(text(&row["bundle"]));
        if row["remove_set"] == true {
            bundle.witness_set = None;
        }
        let replacement = row["replacement"] == true;
        if replacement {
            bundle.witness_set = Some(f.record("alpha31_replacement_set"));
        }
        let now = if replacement { 1_350_000 } else { 1_150_000 };
        let result = f
            .verify(&bundle, input, now, replacement)
            .expect("time-free recovery");
        assert_eq!(result.evidence, a::ImportBundleEvidence::Recovery);
        assert_eq!(
            result.snapshot_advanced,
            row["expected_advanced"] == true,
            "{}",
            row["id"]
        );
        assert_eq!(result.snapshot.is_some(), row["expected_snapshot"] == true);
        assert_eq!(result.owner_check_times_unix_seconds, vec![None]);
        assert_eq!(input, before.as_ref());
        if !result.snapshot_advanced {
            assert_eq!(result.snapshot, before, "persisted no-op");
        }
        if let Some(s) = result.snapshot {
            assert!(s.accepted_history.is_empty());
            assert!(s.job_associations.is_empty());
            if result.snapshot_advanced {
                assert_eq!(s.clock_floor_unix_millis, now);
                assert_eq!(Some(s.witness_set), bundle.witness_set);
            }
        }
    }
}
#[test]
fn alpha32_authenticated_receipts_reject_then_pass() {
    let f = Fixture::load();
    for row in f.new["receipt_negatives"].as_array().expect("negatives") {
        let initial = f
            .verify(&f.record(text(&row["bundle"])), None, 1_350_000, false)
            .expect("initial set");
        let before = initial.snapshot.clone();
        let mut b: api::ImportPublicProofBundleV1 = f.record(text(&row["bundle"]));
        match text(&row["change"]) {
            "observation" => {
                b.statements[0]
                    .body
                    .as_mut()
                    .expect("body")
                    .observed_at_unix_millis += 1000
            }
            "signature" => b.statements[0].signature[0] ^= 1,
            "remove_set" => b.witness_set = None,
            "set_signature" => b.witness_set.as_mut().expect("set").root_signature[0] ^= 1,
            _ => panic!("change"),
        }
        let reason = if row["expected"] == "Canonical" {
            a::Reject::Canonical
        } else {
            a::Reject::Signature
        };
        assert_eq!(
            f.verify(&b, initial.snapshot.as_ref(), 1_350_000, false),
            Err(reason),
            "{}",
            row["id"]
        );
        assert_eq!(initial.snapshot, before);
        f.verify(
            &f.record(text(&row["bundle"])),
            initial.snapshot.as_ref(),
            1_350_000,
            false,
        )
        .expect("control");
    }
}
#[test]
fn alpha32_owner_times_are_internal_and_receipt_ordered() {
    let f = Fixture::load();
    let mut b: api::ImportPublicProofBundleV1 = f.record("review_control");
    let first = f.verify(&b, None, 1_350_000, false).expect("first");
    assert_eq!(
        first.owner_check_times_unix_seconds,
        vec![Some(1100), Some(1250)]
    );
    b.statements.reverse();
    let reversed = f
        .verify(&b, None, 1_350_000, false)
        .expect("array order irrelevant");
    assert_eq!(
        reversed.owner_check_times_unix_seconds,
        first.owner_check_times_unix_seconds
    );
    let admitted = f
        .verify(
            &f.record("review_scheduled_admitted"),
            None,
            1_350_000,
            false,
        )
        .expect("admission");
    assert_eq!(admitted.owner_check_times_unix_seconds, vec![Some(1200)]);
    let mut recovery: api::ImportPublicProofBundleV1 = f.record("review_scheduled_recovery");
    recovery.witness_set = None;
    let owner = a::ImportBundleOwnerExpectation {
        identity: recovery.delegations[0]
            .body
            .as_ref()
            .expect("body")
            .identity
            .as_ref()
            .expect("identity"),
        owner_public_key: &f.owner,
        owner_chain_digest: &recovery.delegations[0]
            .body
            .as_ref()
            .expect("body")
            .owner_chain_digest,
        authority_expires_at_seconds: 2000,
        effective_from_unix_seconds: 0,
        effective_until_unix_seconds: None,
        forbidden_job_keys: &[],
        known_job_associations: &[],
    };
    let mut calls = 0;
    a::verify_import_bundle_witnesses(
        &recovery,
        &f.pin(false),
        None,
        1_100_000,
        |i, _| Ok([owner][i]),
        |_, statement| {
            calls += 1;
            assert!(statement.is_none());
            Ok(())
        },
    )
    .expect("time-free policy");
    assert_eq!(calls, 1);
    assert_eq!(
        a::verify_import_bundle_witnesses(
            &recovery,
            &f.pin(false),
            None,
            1_100_000,
            |i, _| Ok([owner][i]),
            |_, _| Err(a::Reject::Signature)
        ),
        Err(a::Reject::Signature)
    );
}
#[cfg(feature = "reflection")]
#[test]
fn alpha32_controls_disclose_only_availability() {
    let pool =
        prost_reflect::DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("descriptor");
    let response = pool
        .get_message_by_name("heddle.api.v1alpha2.GetImportJobStateResponse")
        .expect("response");
    assert_eq!(
        response.get_field(6).expect("controls").name(),
        "control_availability"
    );
    for (name, fields) in [
        (
            "ImportJobControlAvailabilityV1",
            vec!["retry", "renew", "cancel"],
        ),
        (
            "ImportControlAvailabilityV1",
            vec!["available", "unavailable"],
        ),
    ] {
        let d = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}"))
            .expect("message");
        assert_eq!(
            d.fields().map(|f| f.name().to_owned()).collect::<Vec<_>>(),
            fields
        );
    }
}
