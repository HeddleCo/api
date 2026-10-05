#!/bin/sh
set -eu

npm ci
buf format -d --exit-code
buf lint
python3 -B -m unittest tests/test_attention_contract.py
python3 -B -m unittest tests/test_explore_contract.py
python3 -B -m unittest tests/test_attestation_contract.py
python3 -B -m unittest tests/test_handle_contract.py
python3 -B -m unittest tests/test_account_management_contract.py
python3 -B -m unittest tests/test_owner_authorization_contract.py
python3 -B -m unittest tests/test_owner_authz_cutover_contract.py
python3 -B -m unittest tests/test_workflow_contract.py
python3 -B -m unittest tests/test_revision_thread_identity_contract.py
python3 -B -m unittest tests/test_signup_contract.py
python3 -B -m unittest tests/test_additive_bundle_contract.py
python3 -B -m unittest tests/test_spool_contract.py
python3 -B -m unittest tests/test_transport_contract.py
python3 -B -m unittest tests/test_v2_cutover_contract.py
python3 tools/audit_contract.py
cargo +nightly fmt --check
cargo test --all-features
cargo test --locked --manifest-path tests/custodial-verifier/Cargo.toml
cargo clippy --all-features --all-targets -- -D warnings
rustfmt +nightly --edition 2024 --check tools/hybrid-native/src/main.rs tools/generate-hybrid-native-biscuit.rs
cargo test --locked --manifest-path tools/hybrid-native/Cargo.toml -- --nocapture
cargo clippy --locked --manifest-path tools/hybrid-native/Cargo.toml --all-targets -- -D warnings
npm run build
npm run typecheck
node tools/verify-alpha32-vector-continuity.mjs
node tools/verify-alpha32-guards.mjs
node tools/verify-import-consumer-guards.mjs
node tools/verify-owner-authz-cutover.mjs
node tools/verify-ts-vectors.mjs
node tools/verify-treadle-conformance.mjs
npm test
