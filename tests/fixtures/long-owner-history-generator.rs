// Included in the pinned verifier's test module by the fixture generator.
#[test]
fn generate_api_long_owner_history() {
    let mut fixture = TimelineFixture::new();
    let paper = TestKey::new(2);
    let social = TestKey::new(3);
    let guardians = [
        (&paper, RecoveryGuardianKind::Paper),
        (&social, RecoveryGuardianKind::Social),
    ];
    fixture.bundle.owner_root = Some(signed_root_with_policy(
        OWNER_UUID,
        &fixture.owner,
        &guardians,
        recovery_policy(&guardians, Some(1)),
    ));
    let mut state = verify_owner_root(fixture.bundle.owner_root.as_ref().expect("root"))
        .expect("verified root and guardian possession proofs");
    let root_hash = state.state_hash();
    let mut current = TestKey::new(1);
    for seed in 30..50 {
        let next = TestKey::new(seed);
        let rotate = rotation(&state, &current, &next);
        verify_transition_timelock(&state, &rotate, NOW - 2).expect("rotation window elapsed");
        state = apply_accepted_transition(&state, &rotate, NOW, limits()).expect("rotation");
        fixture.bundle.owner_state_chain.push(rotate);
        current = next;
    }
    let recovered = TestKey::new(50);
    let recovery = recovery_transition(
        &state,
        &[&paper, &social],
        &recovered,
        state.recovery_policy().clone(),
        NOW,
    );
    verify_transition_timelock(&state, &recovery, NOW - 1).expect("recovery window elapsed");
    state = apply_accepted_transition(&state, &recovery, NOW, limits()).expect("recovery");
    fixture.bundle.owner_state_chain.push(recovery);
    fixture.capability_mut().owner_id = state.owner_id().to_vec();
    fixture.capability_mut().issuer_state_hash = state.state_hash().to_vec();
    fixture.capability_mut().not_before_unix_seconds = NOW;
    let body = {
        let capability = fixture.capability_mut();
        capability.capability_id = digest(
            OWNER_CAPABILITY_V3_DOMAIN,
            &capability_without_id(capability).expect("capability without ID"),
        )
        .to_vec();
        capability_body(capability).expect("canonical capability")
    };
    fixture.bundle.capability_chain[0].signature =
        Some(recovered.sign(OWNER_CAPABILITY_V3_DOMAIN, &body));
    fixture.bundle.subject_biscuit = timeline_subject_biscuit(
        fixture.bundle.capability_chain[0]
            .capability
            .as_ref()
            .expect("capability"),
        &fixture.subject,
    );
    let verify = |bundle: &OwnerAuthorizationBundle, hash: &[u8; 32]| {
        crate::capability::verify_timeline_bundle_for_state(bundle, hash, NOW, limits(), &[])
    };
    verify(&fixture.bundle, &state.state_hash())
        .expect("current-key bundle verifies after recovery");
    assert!(
        verify(&fixture.bundle, &root_hash).is_err(),
        "stale checkpoint rejected"
    );
    let mut altered = fixture.bundle.clone();
    altered.owner_state_chain[10].authorizations[0].signature[0] ^= 1;
    assert!(
        verify(&altered, &state.state_hash()).is_err(),
        "bad history signature rejected"
    );
    let mut altered = fixture.bundle.clone();
    altered.capability_chain[0]
        .signature
        .as_mut()
        .expect("signature")
        .signature[0] ^= 1;
    assert!(
        verify(&altered, &state.state_hash()).is_err(),
        "bad current-issuer signature rejected"
    );
    let bytes = fixture.bundle.encode_to_vec();
    assert!((4097..=65536).contains(&bytes.len()));
    let output = serde_json::json!({
        "verifier_revision": "b83f6e83c16cfb0b2f58f6f2b599c25bfe1a65be",
        "rotations": 20,
        "recoveries": 1,
        "now_unix_seconds": NOW,
        "bundle_hex": hex::encode(&bytes),
        "bundle_bytes": bytes.len(),
        "accepted_state_hash_hex": hex::encode(state.state_hash()),
        "current_owner_public_key_hex": hex::encode(recovered.wire().public_key),
        "subject_seed_hex": hex::encode(fixture.subject.seed),
        "origin_hex": hex::encode(fixture.origin.encode_to_vec()),
    });
    std::fs::write(
        std::env::var("OWNER_HISTORY_OUTPUT").expect("output path"),
        serde_json::to_string_pretty(&output).expect("fixture JSON") + "\n",
    )
    .expect("write fixture");
    println!(
        "Verified 20 rotations + recovery: {} bytes; stale state and tampered signatures rejected",
        bytes.len()
    );
}
