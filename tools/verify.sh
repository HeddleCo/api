#!/bin/sh
set -eu

npm ci
buf format -d --exit-code
buf lint
python3 -B -m unittest tests/test_operation_contract.py
python3 -B -m unittest tests/test_attention_contract.py
python3 -B -m unittest tests/test_explore_contract.py
python3 -B -m unittest tests/test_attestation_contract.py
python3 -B -m unittest tests/test_handle_contract.py
python3 -B -m unittest tests/test_owner_authorization_contract.py
python3 -B -m unittest tests/test_workflow_contract.py
python3 -B -m unittest tests/test_revision_thread_identity_contract.py
python3 -B -m unittest tests/test_signup_contract.py
python3 -B -m unittest tests/test_spool_contract.py
python3 -B -m unittest tests/test_transport_contract.py
python3 tools/audit_contract.py
python3 -m unittest tests/test_capability_matrix.py
python3 tools/capability_matrix.py --check
cargo +nightly fmt --check
cargo test --all-features
cargo clippy --all-features --all-targets -- -D warnings
npm run build
npm run typecheck
node tools/verify-ts-vectors.mjs
node tools/verify-treadle-conformance.mjs
