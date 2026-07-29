#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS="$REPO_ROOT/owner-authorization-conformance"
ARTIFACTS="$HARNESS/artifacts"
PROFILE="${OWNER_AUTH_PROFILE:-current}"
SCRATCH="${OWNER_AUTH_SCRATCH:-$REPO_ROOT/target/owner-authorization-conformance/corpus}"

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
    echo "unknown OWNER_AUTH_PROFILE: $PROFILE" >&2
    exit 2
    ;;
esac

(cd "$ARTIFACTS" && sha256sum --check --quiet SHA256SUMS)

echo "CLIENT_PINS profile=$PROFILE tapestry=$TAPESTRY_REV heddle=$HEDDLE_REV"

OWNER_AUTH_PROFILE="$PROFILE" \
HEDDLE_VERIFIER_BIN="$ARTIFACTS/$PROFILE-heddle-linux-x86_64" \
OWNER_AUTH_SCRATCH="$SCRATCH" \
bun run "$HARNESS/run.ts"
