use heddle_api::heddle::api::v1alpha2 as api;
use heddle_api::{hybrid_codec as codec, import_authority as import};
use prost::Message;
use serde_json::Value;
use std::collections::BTreeMap;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/import-sibling-jobs-alpha32.json"))
        .expect("frozen sibling fixture")
}
fn base() -> Value {
    serde_json::from_str(heddle_api::IMPORT_AUTHORITY_HOST_WITNESS_V1_FIXTURE_JSON)
        .expect("unchanged base fixture")
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex")).expect("frozen hex")
}
fn record<T: Message + Default>(f: &Value, name: &str) -> T {
    let v = if f["wire_vectors"][name].is_null() {
        &f["signed_vectors"][name]
    } else {
        &f["wire_vectors"][name]
    };
    codec::strict_decode(&bytes(&v["wire_hex"]), import::MAX_BUNDLE_BYTES)
        .expect("original frozen wire")
}
fn verified(f: &Value, job: &str) -> Result<import::VerifiedImportDelegation, codec::Reject> {
    let base = base();
    let identity = record(f, "identity");
    let key = bytes(&base["keys"]["owner"]["public_key_hex"]);
    let chain = bytes(&base["context"]["owner_chain_digest_hex"]);
    let forbidden: Vec<_> = ["owner", "device", "witness", "next_witness", "root"]
        .iter()
        .map(|k| bytes(&base["keys"][k]["public_key_hex"]))
        .collect();
    import::verify_commit_submission(
        &record(f, &format!("commit_{job}")),
        &record(f, &format!("prepared_{job}")),
        "github",
        &record(f, "source"),
        &record(f, "configuration"),
        &import::ImportOwnerExpectation {
            identity: &identity,
            owner_public_key: &key,
            owner_chain_digest: &chain,
            authority_expires_at_seconds: 2000,
            now_unix_seconds: 1100,
            forbidden_job_keys: &forbidden,
            known_job_associations: &[],
        },
    )
}
fn outcome(result: Result<(), codec::Reject>) -> String {
    match result {
        Ok(()) => "OK".into(),
        Err(codec::Reject::PreparationRefused(
            api::ImportPreparationRefusalReason::DestinationConflict,
        )) => "DESTINATION_CONFLICT".into(),
        Err(codec::Reject::PreparationRefused(
            api::ImportPreparationRefusalReason::InvalidScope,
        )) => "INVALID_SCOPE".into(),
        Err(codec::Reject::PreparationRefused(
            api::ImportPreparationRefusalReason::BudgetExceeded,
        )) => "BUDGET_EXCEEDED".into(),
        Err(error) => format!("{error:?}"),
    }
}

#[test]
fn alpha32_sibling_scenarios() {
    let f = fixture();
    let identity: api::ImportIdentityV1 = record(&f, "identity");
    let configuration = record(&f, "configuration");
    let current = bytes(&f["current_destination_hex"]);
    for scenario in f["scenarios"].as_array().expect("scenarios") {
        let mut inventory = BTreeMap::<String, (api::ImportJobDelegationV1, bool)>::new();
        for step in scenario["steps"].as_array().expect("steps") {
            let job = step["job"].as_str().expect("job");
            let action = step["action"].as_str().expect("action");
            let scope: api::ImportPermissionScopeV1 =
                record(&f, step["scope"].as_str().expect("scope"));
            let signed: api::SignedImportJobDelegationV1 = record(&f, &format!("delegation_{job}"));
            let d = signed.body.expect("body");
            let before = inventory.clone();
            let actual = outcome((|| {
                if action == "complete" {
                    assert!(inventory.get(job).expect("active job").1);
                    let operation = record(&f, &format!("operation_{job}"));
                    import::verify_operation(&operation, &verified(&f, job)?)?;
                    assert!(import::check_slot_replay(
                        &record(&f, &format!("manifest_{job}")),
                        &operation
                    )?);
                    inventory.remove(job);
                } else if action == "expire_prepare" {
                    assert!(!inventory.get(job).expect("prepared job").1);
                    inventory.remove(job);
                } else {
                    let held: Vec<_> = inventory
                        .values()
                        .map(|(d, _)| import::ImportSpoolReservation {
                            spool_uuid: &identity.spool_uuid,
                            logical_job_id: &d.logical_job_id,
                            branches: &d.scope.as_ref().expect("scope").branches,
                        })
                        .collect();
                    if action == "commit" {
                        import::check_import_destination_version(&scope, &current)?;
                        assert!(inventory.contains_key(job), "activation owns reservation");
                        import::check_import_spool_reservations(
                            &identity.spool_uuid,
                            &d.logical_job_id,
                            &scope,
                            &held,
                            action == "commit",
                        )?;
                        verified(&f, job)?;
                        inventory.get_mut(job).expect("reserved job").1 = true;
                    } else {
                        let selected = import::prepare_scope(&scope, &configuration, &current)?;
                        import::check_import_spool_reservations(
                            &identity.spool_uuid,
                            &d.logical_job_id,
                            &selected,
                            &held,
                            action == "commit",
                        )?;
                        if action == "prepare" {
                            import::validate_preparation_response(
                                &record(&f, &format!("prepare_{job}")),
                                &record(&f, &format!("prepared_{job}")),
                            )?;
                            inventory.insert(job.into(), (d, false));
                        }
                    }
                }
                Ok(())
            })());
            println!(
                "SIBLING {}.{action}.{job}: {actual}",
                scenario["id"].as_str().expect("id")
            );
            assert_eq!(actual, step["expected"].as_str().expect("outcome"));
            if actual != "OK" {
                assert_eq!(inventory, before, "refusal changes no reservations");
            }
        }
    }
}

#[test]
fn alpha32_sibling_gates_reject_then_pass() {
    let f = fixture();
    for v in f["gate_vectors"].as_array().expect("gates") {
        let run = |name: &str| {
            let scope = if name == "scope_256" {
                let corrected: Value =
                    serde_json::from_str(include_str!("fixtures/import-review-fixes-alpha32.json"))
                        .expect("corrected control");
                record(&corrected, "unique_scope_256")
            } else {
                record(&f, name)
            };
            let current = bytes(&f[v["current"].as_str().expect("token")]);
            if v["kind"] == "activate" {
                import::check_import_destination_version(&scope, &current)
            } else {
                import::prepare_scope(&scope, &record(&f, "configuration"), &current).map(|_| ())
            }
        };
        let actual = outcome(run(v["scope"].as_str().expect("scope")));
        assert_eq!(actual, v["expected"].as_str().expect("refusal"));
        run(v["control"].as_str().expect("control")).expect("succeeding control");
        println!("SIBLING {}: {actual} -> OK", v["id"].as_str().expect("id"));
    }
}

#[test]
fn alpha32_sibling_typed_refusal_fields_reject_then_pass() {
    let f = fixture();
    for (name, field) in [
        ("duplicate", "proposed_scope.branches.ref_name"),
        ("slot", "proposed_scope.branches.slot_id"),
        ("stale", "proposed_scope.destination_version"),
    ] {
        let response: api::PrepareImportJobResponse = record(&f, &format!("refusal_{name}"));
        assert_eq!(
            response.refusal.as_ref().expect("typed refusal").field,
            field
        );
        assert_eq!(
            outcome(import::validate_preparation_response(
                &record(&f, "prepare_b"),
                &response
            )),
            "DESTINATION_CONFLICT"
        );
        import::validate_preparation_response(&record(&f, "prepare_b"), &record(&f, "prepared_b"))
            .expect("succeeding control");
    }
}

fn signed_parity<T: codec::Canonical>(v: &Value, body: &T) {
    assert_eq!(
        codec::canonical(body).expect("canonical"),
        bytes(&v["canonical_hex"])
    );
    let input = codec::signing_digest(v["domain"].as_str().expect("domain"), body).expect("digest");
    assert_eq!(input, bytes(&v["signing_input_hex"]));
    codec::verify(
        &bytes(&v["public_key_hex"]),
        &input,
        &bytes(&v["signature_hex"]),
    )
    .expect("original signature");
}

#[test]
fn alpha32_sibling_signed_parity_and_independent_totals() {
    let f = fixture();
    for (name, v) in f["signed_vectors"].as_object().expect("signed vectors") {
        match v["body_schema"]
            .as_str()
            .expect("schema")
            .rsplit('.')
            .next()
            .expect("name")
        {
            "ImportMemberPermissionV1" => signed_parity(
                v,
                &record::<api::SignedImportMemberPermissionV1>(&f, name)
                    .body
                    .expect("body"),
            ),
            "ImportGenesisAuthorityV1" => signed_parity(
                v,
                &record::<api::SignedImportGenesisAuthorityV1>(&f, name)
                    .body
                    .expect("body"),
            ),
            "ImportJobDelegationV1" => signed_parity(
                v,
                &record::<api::SignedImportJobDelegationV1>(&f, name)
                    .body
                    .expect("body"),
            ),
            "DelegatedImportOperationV1" => signed_parity(
                v,
                &record::<api::SignedDelegatedImportOperationV1>(&f, name)
                    .body
                    .expect("body"),
            ),
            other => panic!("unexpected signed schema {other}"),
        }
    }
    for job in ["a", "b", "fresh"] {
        let d = verified(&f, job).expect("original signed Commit");
        let operation = record(&f, &format!("operation_{job}"));
        import::verify_operation(&operation, &d).expect("original signed operation");
        assert!(
            import::check_slot_replay(&record(&f, &format!("manifest_{job}")), &operation)
                .expect("manifest")
        );
    }
    let a: api::ImportPermissionScopeV1 = record(&f, "scope_a");
    let b: api::ImportPermissionScopeV1 = record(&f, "scope_b");
    let limits = record::<api::GetImportConfigurationResponse>(&f, "configuration")
        .limits
        .expect("limits");
    assert!(a.max_result_bytes + b.max_result_bytes > limits.max_result_bytes);
    assert_eq!(
        a.branches[0].slot_id, b.branches[0].slot_id,
        "disjoint refs can share slot number"
    );
    let identity: api::ImportIdentityV1 = record(&f, "identity");
    let da = record::<api::SignedImportJobDelegationV1>(&f, "delegation_a")
        .body
        .expect("a");
    let db = record::<api::SignedImportJobDelegationV1>(&f, "delegation_b")
        .body
        .expect("b");
    assert_ne!(da.job_public_key, db.job_public_key);
    let held = import::ImportSpoolReservation {
        spool_uuid: &[0xff; 16],
        logical_job_id: &da.logical_job_id,
        branches: &a.branches,
    };
    import::check_import_spool_reservations(
        &identity.spool_uuid,
        &db.logical_job_id,
        &a,
        &[held],
        false,
    )
    .expect("another spool does not conflict");
}

#[test]
fn review_fix_reservation_ownership_and_destinations_reject_then_pass() {
    let f = fixture();
    let identity: api::ImportIdentityV1 = record(&f, "identity");
    let a: api::ImportPermissionScopeV1 = record(&f, "scope_a");
    let b: api::ImportPermissionScopeV1 = record(&f, "scope_b");
    let da: api::SignedImportJobDelegationV1 = record(&f, "delegation_a");
    let db: api::SignedImportJobDelegationV1 = record(&f, "delegation_b");
    let job_a = &da.body.as_ref().expect("a").logical_job_id;
    let job_b = &db.body.as_ref().expect("b").logical_job_id;
    let conflict = Err(codec::Reject::PreparationRefused(
        api::ImportPreparationRefusalReason::DestinationConflict,
    ));
    assert_eq!(
        import::check_import_spool_reservations(&identity.spool_uuid, job_a, &a, &[], true),
        conflict
    );
    let held = import::ImportSpoolReservation {
        spool_uuid: &identity.spool_uuid,
        logical_job_id: job_a,
        branches: &a.branches,
    };
    import::check_import_spool_reservations(&identity.spool_uuid, job_a, &a, &[held], true)
        .expect("owned control");
    for genesis in [false, true] {
        let mut selected = b.clone();
        if genesis {
            selected.branches[0].genesis_digest = a.branches[0].genesis_digest.clone();
        } else {
            selected.branches[0].target_thread_id = a.branches[0].target_thread_id.clone();
        }
        let held = import::ImportSpoolReservation {
            spool_uuid: &identity.spool_uuid,
            logical_job_id: job_a,
            branches: &a.branches,
        };
        assert_eq!(
            import::check_import_spool_reservations(
                &identity.spool_uuid,
                job_b,
                &selected,
                &[held],
                false
            ),
            conflict,
            "cross-job target identity"
        );
        let held = import::ImportSpoolReservation {
            spool_uuid: &identity.spool_uuid,
            logical_job_id: job_a,
            branches: &a.branches,
        };
        import::check_import_spool_reservations(&identity.spool_uuid, job_b, &b, &[held], false)
            .expect("distinct sibling control");
        let mut combined = a.clone();
        combined.max_operations = 2;
        combined.branches.extend(selected.branches);
        combined
            .branches
            .sort_by(|a, b| a.ref_name.cmp(&b.ref_name));
        assert_eq!(
            import::validate_scope(&combined),
            Err(codec::Reject::Scope),
            "within-job target identity"
        );
        let mut good = a.clone();
        good.max_operations = 2;
        good.branches.extend(b.branches.clone());
        good.branches.sort_by(|a, b| a.ref_name.cmp(&b.ref_name));
        import::validate_scope(&good).expect("distinct within-job control");
    }
}
#[test]
fn review_fix_original_window_releases_reservations() {
    let f = fixture();
    let identity: api::ImportIdentityV1 = record(&f, "identity");
    let a: api::ImportPermissionScopeV1 = record(&f, "scope_a");
    let b: api::ImportPermissionScopeV1 = record(&f, "scope_b");
    let da: api::SignedImportJobDelegationV1 = record(&f, "delegation_a");
    let db: api::SignedImportJobDelegationV1 = record(&f, "delegation_b");
    let job_a = &da.body.as_ref().expect("a").logical_job_id;
    let job_b = &db.body.as_ref().expect("b").logical_job_id;
    let mut held = vec![
        import::ImportSpoolReservation {
            spool_uuid: &identity.spool_uuid,
            logical_job_id: job_a,
            branches: &a.branches,
        },
        import::ImportSpoolReservation {
            spool_uuid: &identity.spool_uuid,
            logical_job_id: job_b,
            branches: &b.branches,
        },
    ];
    let facts = import::ImportOriginalAdmission {
        original: &da,
        admitted: false,
        now_unix_seconds: da.body.as_ref().expect("a").expires_at_unix_seconds,
    };
    assert_eq!(
        import::check_original_import_window(&facts),
        Err(codec::Reject::OriginalWindowEnded)
    );
    assert!(
        import::check_import_spool_reservations(&identity.spool_uuid, job_b, &a, &held, false)
            .is_err()
    );
    assert!(
        import::release_ended_import_reservations(&identity.spool_uuid, job_a, &facts, &mut held)
            .expect("release")
    );
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].logical_job_id, job_b);
    // The other sibling's own reservation is unchanged; a new job can reuse a's destinations.
    let fresh: api::SignedImportJobDelegationV1 = record(&f, "delegation_fresh");
    import::check_import_spool_reservations(
        &identity.spool_uuid,
        &fresh.body.expect("fresh").logical_job_id,
        &a,
        &held,
        false,
    )
    .expect("new job admitted");
    let admitted = import::ImportOriginalAdmission {
        admitted: true,
        ..facts
    };
    import::check_original_import_window(&admitted).expect("admitted originals control");
}
