#!/usr/bin/env python3
"""Prove every refusal vector becomes allowed with its rule removed, then restore."""
import os
from pathlib import Path
import subprocess
import sys

language = sys.argv[1]
directory = Path(sys.argv[2] if len(sys.argv) > 2 else f"/tmp/api-alpha40-membership-{language}")
directory.mkdir(parents=True, exist_ok=True)
if language == "rust":
    path = Path("src/v2/membership_floor.rs")
    cases = [
        ("personal", "506", "if owner_lost {", "if false {"),
        ("member", "507", "} else if members.is_empty() {", "} else if false {"),
        ("administrator", "508", "} else if !members.is_empty()", "} else if false"),
        ("privacy", None, "if !context.can_manage_grants {", "if false {"),
        ("authorization", "authorization", "if !context.operation_authorized {", "if false {"),
        ("agents", None, "if candidate.kind != MemberKind::Human {", "if false {"),
    ]
    command = ["cargo", "test", "--all-features", "--test", "v2_membership_floor_contract", "shared_membership_floor_vectors", "--", "--nocapture"]
    red_code, red_marker, green_marker = 101, "... FAILED", "... ok"
elif language == "ts":
    path = Path("packages/typescript/dist/v1alpha2/membership-floor.js")
    cases = [
        ("personal", "506", "if (ownerLost)", "if (false)"),
        ("member", "507", "else if (members.size === 0)", "else if (false)"),
        ("administrator", "508", "else if (members.size > 0", "else if (false"),
        ("privacy", None, "if (context.canManageGrants !== true)", "if (false)"),
        ("authorization", "authorization", "if (context.operationAuthorized !== true)", "if (false)"),
        ("agents", None, 'if (candidate.kind !== "human")', "if (false)"),
        ("fallback", None, 'if (!context.existingRefusal || typeof context.existingRefusal !== "object")', "if (false)"),
    ]
    command = ["node", "--test", "--test-reporter=tap", "tests/v2-membership-floor.test.mjs"]
    red_code, red_marker, green_marker = 1, "not ok ", "# fail 0"
else:
    raise SystemExit("language must be rust or ts")


def run(name, stage, removed=None):
    environment = os.environ.copy()
    environment.pop("MEMBERSHIP_FLOOR_REMOVED_RULE", None)
    if removed is not None:
        environment["MEMBERSHIP_FLOOR_REMOVED_RULE"] = removed
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, env=environment)
    (directory / f"{name}-{stage}.log").write_text(result.stdout)
    expected = red_code if stage == "red" else 0
    marker = red_marker if stage == "red" else green_marker
    if result.returncode != expected or marker not in result.stdout:
        raise RuntimeError(f"{name}: expected {stage} assertions; inspect {directory}")
    return result.returncode


for name, reason, old, new in cases:
    original = path.read_text()
    try:
        if original.count(old) != 1:
            raise RuntimeError(f"expected one mutation site for {name}")
        path.write_text(original.replace(old, new))
        red = run(name, "red")
        if reason:
            run(name, "removed-rule-allowed", reason)
        path.write_text(original)
        green = run(name, "restored")
        print(f"alpha.40 {language} {name}: removed exit {red}; "
              f"{'all refusal vectors allowed; ' if reason else ''}restored exit {green}", flush=True)
    finally:
        path.write_text(original)
