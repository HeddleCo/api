#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 PROFILE HEDDLE_REV HEDDLE_ROOT OUTPUT_ROOT" >&2
  exit 2
fi

PROFILE=$1
HEDDLE_REV=$2
HEDDLE_ROOT=$(cd "$3" && pwd)
OUTPUT_ROOT=$(mkdir -p "$4" && cd "$4" && pwd)
SOURCE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if [[ "$PROFILE" != current && "$PROFILE" != pre-fix ]]; then
  echo "unknown profile: $PROFILE" >&2
  exit 2
fi

[[ $(git -C "$HEDDLE_ROOT" rev-parse HEAD) == "$HEDDLE_REV" ]] ||
  { echo "Heddle checkout is not pinned to $HEDDLE_REV" >&2; exit 1; }

SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/owner-auth-heddle.XXXXXX")
cleanup() {
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

cp -R "$SOURCE_ROOT/heddle-verifier" "$SCRATCH/heddle-verifier"
sed -i \
  "s|heddle-client = .*|heddle-client = { path = \"$HEDDLE_ROOT/crates/client\" }|" \
  "$SCRATCH/heddle-verifier/Cargo.toml"
RUST_SYSROOT=$(rustc --print sysroot)
CARGO_HOME="${CARGO_HOME:-$SCRATCH/cargo-home}" \
  cargo update \
    --manifest-path "$SCRATCH/heddle-verifier/Cargo.toml" \
    -p heddle-client
CARGO_HOME="${CARGO_HOME:-$SCRATCH/cargo-home}" \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static \
    --remap-path-prefix=${CARGO_HOME:-$SCRATCH/cargo-home}=/cargo \
    --remap-path-prefix=$SCRATCH/heddle-verifier=/src/api/owner-authorization-conformance/heddle-verifier \
    --remap-path-prefix=$HEDDLE_ROOT=/src/heddle \
    --remap-path-prefix=$RUST_SYSROOT=/rust-toolchain" \
  cargo build \
    --locked \
    --release \
    --target x86_64-unknown-linux-gnu \
    --manifest-path "$SCRATCH/heddle-verifier/Cargo.toml" \
    --target-dir "$SCRATCH/target"
cp \
  "$SCRATCH/target/x86_64-unknown-linux-gnu/release/api-owner-authorization-heddle-verifier" \
  "$OUTPUT_ROOT/$PROFILE-heddle"
strip "$OUTPUT_ROOT/$PROFILE-heddle"
echo "BUILT_HEDDLE_VERIFIER profile=$PROFILE revision=$HEDDLE_REV"
