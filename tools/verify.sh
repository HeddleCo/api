#!/bin/sh
set -eu

buf format -d --exit-code
buf lint
python3 tools/audit_contract.py
python3 -m unittest tests/test_capability_matrix.py
python3 tools/capability_matrix.py --check
cargo fmt --check
cargo test --all-features
cargo clippy --all-features --all-targets -- -D warnings
npm ci
npm run build
npm run typecheck
node tools/verify-ts-vectors.mjs
