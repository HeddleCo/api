#!/usr/bin/env python3
"""Break each creator/lifecycle/projection guard, require test failure, restore/pass."""
import os
from pathlib import Path
import subprocess
import sys

language = sys.argv[1]
directory = Path(sys.argv[2] if len(sys.argv) > 2 else f"/tmp/api-alpha39-guards-{language}")
directory.mkdir(parents=True, exist_ok=True)
if language == "rust":
    path = Path("src/v2/invitation_code.rs")
    cases = [
        ("creator", "context.caller_subject != context.creator_subject", "false"),
        ("spool_state", "invitation.state != InvitationState::Pending as i32", "false"),
        ("spool_recipient", "let non_link = !matches!", "let non_link = false && !matches!"),
        ("redeemed", "redeemed || revoked || expired", "false || revoked || expired"),
        ("revoked", "redeemed || revoked || expired", "redeemed || false || expired"),
        ("expired", "redeemed || revoked || expired", "redeemed || revoked || false"),
        ("expiry_equality", ">= (expiry.seconds, expiry.nanos)", "> (expiry.seconds, expiry.nanos)"),
    ]
    command = ["cargo", "test", "--all-features", "--test", "v2_invitation_code_contract", "--", "--nocapture"]
elif language == "ts":
    path = Path("packages/typescript/dist/v1alpha2/invitation-code.js")
    cases = [
        ("creator", "context.callerSubject !== context.creatorSubject", "false"),
        ("spool_state", "invitation.state !== InvitationState.PENDING", "false"),
        ("spool_recipient", 'const nonLink = invitation.recipient.case !== "email" || invitation.recipient.value === "";', "const nonLink = false;"),
        ("subject_types", 'typeof context.callerSubject !== "string" || typeof context.creatorSubject !== "string"', "false"),
        ("timestamp_type", 'typeof time.seconds === "bigint"', "true"),
        ("redeemed", "invitation.redeemed || invitation.revoked || expired", "false || invitation.revoked || expired"),
        ("revoked", "invitation.redeemed || invitation.revoked || expired", "invitation.redeemed || false || expired"),
        ("expired", "invitation.redeemed || invitation.revoked || expired", "invitation.redeemed || invitation.revoked || false"),
        ("expiry_equality", "context.now.nanos >= expiry.nanos", "context.now.nanos > expiry.nanos"),
    ]
    command = ["node", "--test", "--test-reporter=tap", "tests/v2-invitation-code.test.mjs"]
else:
    raise SystemExit("language must be rust or ts")


def run(name, stage):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, env=os.environ.copy())
    (directory / f"{name}-{stage}.log").write_text(result.stdout)
    marker = ("... FAILED" if stage == "red" else "... ok") if language == "rust" else ("not ok " if stage == "red" else "# fail 0")
    expected = (101 if language == "rust" else 1) if stage == "red" else 0
    if result.returncode != expected or marker not in result.stdout:
        raise RuntimeError(f"{name}: expected real {stage} tests; inspect {directory}")
    return result.returncode


for name, old, new in cases:
    original = path.read_text()
    try:
        if original.count(old) != 1:
            raise RuntimeError(f"expected one mutation site for {name} in {path}")
        path.write_text(original.replace(old, new))
        red = run(name, "red")
        path.write_text(original)
        green = run(name, "green")
        print(f"alpha.39 {language} {name}: broken exit {red}; restored exit {green}", flush=True)
    finally:
        path.write_text(original)

# Introduce a code on the account-view record. Descriptor walks must catch the
# leak through its enclosing projections, rather than just round-trip bytes.
path = Path("proto/heddle/api/v1alpha2/identity.proto")
original = path.read_text()
try:
    marker = "message SignupInvitation {"
    if original.count(marker) != 1:
        raise RuntimeError("expected one SignupInvitation record")
    path.write_text(original.replace(marker, marker + "\n  bytes redemption_secret = 99;"))
    if language == "ts":
        subprocess.run(["npm", "run", "build"], check=True, stdout=subprocess.DEVNULL)
    red = run("projection", "red")
    path.write_text(original)
    if language == "ts":
        subprocess.run(["npm", "run", "build"], check=True, stdout=subprocess.DEVNULL)
    green = run("projection", "green")
    print(f"alpha.39 {language} projection: broken exit {red}; restored exit {green}", flush=True)
finally:
    path.write_text(original)
