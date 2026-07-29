#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS="$REPO_ROOT/owner-authorization-conformance"
PROFILE="${OWNER_AUTH_PROFILE:-current}"
SCRATCH="${OWNER_AUTH_SCRATCH:-$REPO_ROOT/target/owner-authorization-conformance/corpus}"
VERIFIER_ROOT="${OWNER_AUTH_VERIFIER_ROOT:-$REPO_ROOT/target/owner-authorization-conformance/verifiers}"

if [[ "$PROFILE" != current && "$PROFILE" != pre-fix ]]; then
  echo "unknown OWNER_AUTH_PROFILE: $PROFILE" >&2
  exit 2
fi

: "${TAPESTRY_REV:?TAPESTRY_REV is required}"
: "${HEDDLE_REV:?HEDDLE_REV is required}"

echo "CLIENT_PINS profile=$PROFILE tapestry=$TAPESTRY_REV heddle=$HEDDLE_REV"

OWNER_AUTH_PROFILE="$PROFILE" \
HEDDLE_VERIFIER_BIN="$VERIFIER_ROOT/$PROFILE-heddle" \
TAPESTRY_CURRENT_VERIFIER="$VERIFIER_ROOT/current-tapestry.mjs" \
TAPESTRY_VERIFIER="$VERIFIER_ROOT/$PROFILE-tapestry.mjs" \
OWNER_AUTH_SCRATCH="$SCRATCH" \
bun run "$HARNESS/run.ts"
