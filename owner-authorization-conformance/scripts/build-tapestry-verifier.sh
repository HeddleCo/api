#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 PROFILE TAPESTRY_REV TAPESTRY_ROOT OUTPUT_ROOT" >&2
  exit 2
fi

PROFILE=$1
TAPESTRY_REV=$2
TAPESTRY_ROOT=$(cd "$3" && pwd)
OUTPUT_ROOT=$(mkdir -p "$4" && cd "$4" && pwd)
SOURCE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if [[ "$PROFILE" != current && "$PROFILE" != pre-fix ]]; then
  echo "unknown profile: $PROFILE" >&2
  exit 2
fi

[[ $(git -C "$TAPESTRY_ROOT" rev-parse HEAD) == "$TAPESTRY_REV" ]] ||
  { echo "Tapestry checkout is not pinned to $TAPESTRY_REV" >&2; exit 1; }

SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/owner-auth-tapestry.XXXXXX")
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
echo "BUILT_TAPESTRY_VERIFIER profile=$PROFILE revision=$TAPESTRY_REV"
