use heddle_api::heddle::api::v1alpha2::*;
use heddle_api::hybrid_codec::{Reject, canonical, signing_digest};
use heddle_api::import_authority::{validate_manifest, validate_ref_selection, validate_scope};
use proptest::prelude::*;

fn sley_branch(name: &str) -> bool {
    let Some(short) = name.strip_prefix("refs/heads/") else {
        return false;
    };
    // from_full validates the namespace but not a leading dash. from_branch_name
    // does; Git additionally reserves the exact short name HEAD (Sley 0.11.0
    // does not). '@' is a valid branch, although a standalone general ref is not.
    short != "HEAD"
        && sley_refs::BranchRefNameBuf::from_branch_name(short).is_ok()
        && sley_refs::check_refname_format(name, false).is_ok()
}

fn expected_sley(name: &str) -> Result<(), Reject> {
    if !sley_branch(name) {
        Err(Reject::Canonical)
    } else if name.len() > heddle_api::import_authority::MAX_REF_BYTES {
        Err(Reject::Bounds)
    } else {
        Ok(())
    }
}

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/import-branch-refs-v1.json"))
        .expect("shared ref-name vectors")
}

fn branch(ref_name: &str) -> ImportBranchLimitV1 {
    ImportBranchLimitV1 {
        ref_name: ref_name.into(),
        hash_algorithm: 1,
        ref_mode: 1,
        pinned_commit_oid: vec![1; 20],
        genesis_digest: vec![2; 32],
        target_thread_id: vec![3; 32],
        expected_frontier_digest: vec![4; 32],
        slot_id: 1,
        ref_disclosure: 0,
    }
}

fn manifest(refs: &[String]) -> ImportResultManifestV1 {
    ImportResultManifestV1 {
        format_version: 1,
        logical_job_id: vec![5; 16],
        retry_lineage_id: vec![6; 16],
        slots: refs
            .iter()
            .map(|ref_name| ImportCommittedSlotV1 {
                ref_name: ref_name.clone(),
                slot_id: 1,
                signed_operation_digest: vec![7; 32],
                resulting_frontier_digest: vec![8; 32],
                result_bytes: 1,
            })
            .collect(),
    }
}

fn scope(refs: &[String]) -> ImportPermissionScopeV1 {
    ImportPermissionScopeV1 {
        provider: "public-git".into(),
        source_url: "https://example.com/repo.git".into(),
        branches: refs
            .iter()
            .enumerate()
            .map(|(i, name)| ImportBranchLimitV1 {
                genesis_digest: vec![i as u8; 32],
                target_thread_id: vec![i as u8; 32],
                ..branch(name)
            })
            .collect(),
        destination_version: vec![9; 32],
        options_digest: vec![10; 32],
        converter_version: "1".into(),
        max_operations: refs.len() as u32,
        max_result_bytes: 100,
    }
}

#[test]
fn shared_branch_ref_vectors() {
    for v in fixture()["vectors"].as_array().expect("vectors") {
        let name = v["ref_name"].as_str().expect("name").to_owned()
            + &v["repeat"]
                .as_str()
                .unwrap_or_default()
                .repeat(v["repeat_count"].as_u64().unwrap_or_default() as usize);
        assert_eq!(name.len() as u64, v["utf8_bytes"].as_u64().expect("length"));
        let expected = match v["expected"].as_str().expect("result") {
            "PASS" => Ok(()),
            "Canonical" => Err(Reject::Canonical),
            "Bounds" => Err(Reject::Bounds),
            other => panic!("unexpected result {other}"),
        };
        assert_eq!(expected_sley(&name), expected, "sley {}", v["id"]);
        assert_eq!(
            validate_ref_selection(&branch(&name), None),
            expected,
            "{}",
            v["id"]
        );
        assert_eq!(
            validate_scope(&scope(std::slice::from_ref(&name))),
            expected,
            "scope {}",
            v["id"]
        );
        assert_eq!(
            validate_manifest(&manifest(std::slice::from_ref(&name))),
            expected,
            "manifest {}",
            v["id"]
        );
        if expected.is_ok() {
            let bytes = canonical(&branch(&name)).expect("canonical branch");
            assert_eq!(&bytes[..4], &(name.len() as u32).to_be_bytes());
            assert_eq!(&bytes[4..4 + name.len()], name.as_bytes());
            assert_eq!(
                hex::encode(
                    signing_digest("heddle-import-branch-conformance-v1", &branch(&name))
                        .expect("digest")
                ),
                v["canonical_digest_hex"].as_str().expect("frozen digest")
            );
        }
    }
}

#[test]
fn shared_vectors_match_git_branch_rules() {
    for v in fixture()["vectors"].as_array().expect("vectors") {
        let name = v["ref_name"].as_str().expect("name").to_owned()
            + &v["repeat"]
                .as_str()
                .unwrap_or_default()
                .repeat(v["repeat_count"].as_u64().unwrap_or_default() as usize);
        let short = name.strip_prefix("refs/heads/").unwrap_or(&name);
        // NUL cannot be supplied in argv. Both Git's documented byte rule and
        // Sley's validator reject it; it is covered by shared_branch_ref_vectors.
        if short.contains('\0') {
            continue;
        }
        let status = std::process::Command::new("git")
            .args(["check-ref-format", "--branch", short])
            // Outside any repository: do not expand previous-checkout syntax.
            .current_dir(std::env::temp_dir())
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env("GIT_CEILING_DIRECTORIES", std::env::temp_dir())
            .output()
            .expect("git check-ref-format reference")
            .status;
        assert_eq!(
            status.success(),
            v["git_valid"].as_bool().expect("Git result"),
            "git {}",
            v["id"]
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    #[test]
    fn random_byte_strings_match_sley(bytes in proptest::collection::vec(any::<u8>(), 0..96)) {
        // The wire is protobuf string, so invalid UTF-8 has no representable
        // ref identity. Never test a lossy decoding as though it were the input.
        if let Ok(short) = std::str::from_utf8(&bytes) {
            let name = format!("refs/heads/{short}");
            prop_assert_eq!(validate_ref_selection(&branch(&name), None), expected_sley(&name));
            prop_assert_eq!(validate_manifest(&manifest(std::slice::from_ref(&name))), expected_sley(&name));
        }
    }

    #[test]
    fn random_utf8_strings_match_sley(chars in proptest::collection::vec(any::<char>(), 0..300)) {
        let short: String = chars.into_iter().collect();
        let name = format!("refs/heads/{short}");
        prop_assert_eq!(validate_ref_selection(&branch(&name), None), expected_sley(&name));
        prop_assert_eq!(validate_manifest(&manifest(std::slice::from_ref(&name))), expected_sley(&name));
    }

    #[test]
    fn random_ascii_strings_match_sley(bytes in proptest::collection::vec(0u8..=127, 0..96)) {
        let short = String::from_utf8(bytes).expect("ASCII");
        let name = format!("refs/heads/{short}");
        prop_assert_eq!(validate_ref_selection(&branch(&name), None), expected_sley(&name));
    }
}

#[test]
fn shared_utf8_byte_order_and_manifest_digest() {
    let f = fixture();
    let refs: Vec<String> =
        serde_json::from_value(f["ordered_refs"].clone()).expect("ordered refs");
    validate_scope(&scope(&refs)).expect("UTF-8 ordered scope");
    let mut m = manifest(&refs);
    validate_manifest(&m).expect("UTF-8 ordered manifest");
    assert_eq!(
        hex::encode(heddle_api::import_authority::manifest_digest(&m).expect("manifest digest")),
        f["manifest_digest_hex"]
            .as_str()
            .expect("frozen manifest digest")
    );
    let public_key = hex::decode(f["manifest_public_key_hex"].as_str().expect("public key"))
        .expect("hex public key");
    let signature = hex::decode(f["manifest_signature_hex"].as_str().expect("signature"))
        .expect("hex signature");
    let digest = heddle_api::import_authority::manifest_digest(&m).expect("digest");
    heddle_api::hybrid_codec::verify(&public_key, &digest, &signature)
        .expect("frozen UTF-8 signature");
    let mut normalized = m.clone();
    normalized.slots[1].ref_name = "refs/heads/é".into();
    assert_eq!(
        heddle_api::hybrid_codec::verify(
            &public_key,
            &heddle_api::import_authority::manifest_digest(&normalized).expect("digest"),
            &signature
        ),
        Err(Reject::Signature)
    );
    // UTF-16 puts the supplementary character before U+E000; UTF-8 does not.
    let mut wrong = refs.clone();
    wrong.swap(3, 4);
    assert_eq!(validate_scope(&scope(&wrong)), Err(Reject::Canonical));
    m.slots.swap(3, 4);
    assert_eq!(validate_manifest(&m), Err(Reject::Canonical));
}
