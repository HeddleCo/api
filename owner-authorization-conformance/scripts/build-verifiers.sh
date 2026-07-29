#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "usage: $0 PROFILE TAPESTRY_REV TAPESTRY_ROOT HEDDLE_REV HEDDLE_ROOT OUTPUT_ROOT" >&2
  exit 2
fi

PROFILE=$1
TAPESTRY_REV=$2
TAPESTRY_ROOT=$(cd "$3" && pwd)
HEDDLE_REV=$4
HEDDLE_ROOT=$(cd "$5" && pwd)
OUTPUT_ROOT=$(mkdir -p "$6" && cd "$6" && pwd)
SOURCE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if [[ "$PROFILE" != current && "$PROFILE" != pre-fix ]]; then
  echo "unknown profile: $PROFILE" >&2
  exit 2
fi

[[ $(git -C "$TAPESTRY_ROOT" rev-parse HEAD) == "$TAPESTRY_REV" ]] ||
  { echo "Tapestry checkout is not pinned to $TAPESTRY_REV" >&2; exit 1; }
[[ $(git -C "$HEDDLE_ROOT" rev-parse HEAD) == "$HEDDLE_REV" ]] ||
  { echo "Heddle checkout is not pinned to $HEDDLE_REV" >&2; exit 1; }

SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/owner-auth-artifacts.XXXXXX")
BRIDGE_PATH="$TAPESTRY_ROOT/api-owner-authorization-bridge.ts"
BRIDGE_CREATED=false
cleanup() {
  rm -rf "$SCRATCH"
  if [[ "$BRIDGE_CREATED" == true ]]; then
    rm -f "$BRIDGE_PATH"
  fi
}
trap cleanup EXIT

if [[ -e "$BRIDGE_PATH" ]]; then
  echo "refusing to replace existing $BRIDGE_PATH" >&2
  exit 1
fi
cp "$SOURCE_ROOT/artifact-source/tapestry-bridge.ts" "$BRIDGE_PATH"
BRIDGE_CREATED=true
(
  cd "$TAPESTRY_ROOT"
  mkdir -p "$SCRATCH/bun-install" "$SCRATCH/bun-cache" "$SCRATCH/bun-tmp"
  BUN_INSTALL="$SCRATCH/bun-install" \
    BUN_INSTALL_CACHE_DIR="$SCRATCH/bun-cache" \
    BUN_TMPDIR="$SCRATCH/bun-tmp" \
    TMPDIR="$SCRATCH/bun-tmp" \
    bun install --frozen-lockfile
  BUN_INSTALL="$SCRATCH/bun-install" \
    BUN_INSTALL_CACHE_DIR="$SCRATCH/bun-cache" \
    BUN_TMPDIR="$SCRATCH/bun-tmp" \
    TMPDIR="$SCRATCH/bun-tmp" \
    bun build \
    ./api-owner-authorization-bridge.ts \
    --target=bun \
    --format=esm \
    --outfile="$OUTPUT_ROOT/$PROFILE-tapestry.mjs"
)

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
echo "BUILT_VERIFIERS profile=$PROFILE tapestry=$TAPESTRY_REV heddle=$HEDDLE_REV"
