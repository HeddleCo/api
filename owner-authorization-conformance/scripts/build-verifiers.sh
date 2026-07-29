#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "usage: $0 PROFILE TAPESTRY_REV TAPESTRY_ROOT HEDDLE_REV HEDDLE_ROOT OUTPUT_ROOT" >&2
  exit 2
fi

PROFILE=$1
TAPESTRY_REV=$2
TAPESTRY_ROOT=$3
HEDDLE_REV=$4
HEDDLE_ROOT=$5
OUTPUT_ROOT=$6
SCRIPT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

"$SCRIPT_ROOT/build-tapestry-verifier.sh" \
  "$PROFILE" "$TAPESTRY_REV" "$TAPESTRY_ROOT" "$OUTPUT_ROOT"
"$SCRIPT_ROOT/build-heddle-verifier.sh" \
  "$PROFILE" "$HEDDLE_REV" "$HEDDLE_ROOT" "$OUTPUT_ROOT"
echo "BUILT_VERIFIERS profile=$PROFILE tapestry=$TAPESTRY_REV heddle=$HEDDLE_REV"
