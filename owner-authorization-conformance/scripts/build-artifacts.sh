#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 PROFILE TAPESTRY_ROOT HEDDLE_ROOT OUTPUT_ROOT" >&2
  exit 2
fi

PROFILE=$1
TAPESTRY_ROOT=$(cd "$2" && pwd)
HEDDLE_ROOT=$(cd "$3" && pwd)
OUTPUT_ROOT=$(mkdir -p "$4" && cd "$4" && pwd)
SOURCE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

case "$PROFILE" in
  current)
    TAPESTRY_REV=62f93a187dff4c1e6746b2332f3dcec3f0f52c87
    HEDDLE_REV=ca8a78141c459b95229df2afa25b1c9934f5377c
    ;;
  pre-fix)
    TAPESTRY_REV=88d00a6fd5d4dc9b9a091a48992978966e40bb4f
    HEDDLE_REV=68d10ba27a72638a2f8bdd95086c7a2dff79e2e6
    ;;
  *)
    echo "unknown profile: $PROFILE" >&2
    exit 2
    ;;
esac

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
  BUN_TMPDIR="${BUN_TMPDIR:-$SCRATCH}" bun build \
    ./api-owner-authorization-bridge.ts \
    --target=bun \
    --format=esm \
    --outfile="$OUTPUT_ROOT/$PROFILE-tapestry.mjs"
)

cp -R "$SOURCE_ROOT/heddle-verifier" "$SCRATCH/heddle-verifier"
sed -i \
  "s|rev = \"[0-9a-f]*\"|rev = \"$HEDDLE_REV\"|" \
  "$SCRATCH/heddle-verifier/Cargo.toml"
RUST_SYSROOT=$(rustc --print sysroot)
CARGO_HOME="$SCRATCH/cargo-home" \
  CARGO_NET_GIT_FETCH_WITH_CLI=true \
  cargo update \
    --manifest-path "$SCRATCH/heddle-verifier/Cargo.toml" \
    -p heddle-client
CARGO_HOME="$SCRATCH/cargo-home" \
  CARGO_NET_GIT_FETCH_WITH_CLI=true \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static \
    --remap-path-prefix=$SCRATCH/cargo-home=/cargo \
    --remap-path-prefix=$SCRATCH/heddle-verifier=/src/api/owner-authorization-conformance/heddle-verifier \
    --remap-path-prefix=$RUST_SYSROOT=/rust-toolchain" \
  cargo build \
    --locked \
    --release \
    --target x86_64-unknown-linux-gnu \
    --manifest-path "$SCRATCH/heddle-verifier/Cargo.toml" \
    --target-dir "$SCRATCH/target"
cp \
  "$SCRATCH/target/x86_64-unknown-linux-gnu/release/api-owner-authorization-heddle-verifier" \
  "$OUTPUT_ROOT/$PROFILE-heddle-linux-x86_64"
strip "$OUTPUT_ROOT/$PROFILE-heddle-linux-x86_64"
sha256sum \
  "$OUTPUT_ROOT/$PROFILE-heddle-linux-x86_64" \
  "$OUTPUT_ROOT/$PROFILE-tapestry.mjs"
