#!/usr/bin/env python3
"""Mutation evidence for each alpha.38 review guard; restore even on failure."""
import os
from pathlib import Path
import subprocess
import sys

language = sys.argv[1]
log_dir = Path(f"/tmp/api-alpha38-guards-{language}")
log_dir.mkdir(parents=True, exist_ok=True)
if language == "rust":
    invitation = Path("src/v2/invitation.rs")
    notifications = Path("src/v2/notifications.rs")
    cases = [
        ("local_scopes", notifications, "let mut scopes = vec![None];", "let mut scopes: Vec<_> = std::iter::once(None).chain(readable.iter().cloned().map(Some)).collect();"),
        ("spool_filter", notifications, "return Ok(vec![Some(spool.clone())]);", "return Ok(vec![None]);"),
        ("filter_auth", notifications, "!request.include_preferences || spool.id.is_empty() || !readable.contains(spool)", "false"),
        ("hidden_preserve", notifications, "if !request.clear_unreadable_scopes {", "if false {"),
        ("hidden_clear", notifications, "if !request.clear_unreadable_scopes {", "if true {"),
        ("hidden_write", notifications, "return Err(NotificationValidationError::InvalidSource);\n    }\n    if !request.clear_unreadable_scopes", "// bypass\n    }\n    if !request.clear_unreadable_scopes"),
        ("decline_account", notifications, "if cell.spool.is_some() && ancestors.first().is_some_and(|level| !level.readable) {", "if false {"),
        ("human_session", invitation, "if !human_session {", "if false {"),
        ("inviter_authority", invitation, "|| inviter_role != 3", "|| inviter_role < offered_role"),
        ("accepted_retry", invitation, "if state == target {", "if state == target && inviter_role == 3 {"),
        ("auto_revoke_all_roles", invitation, ".filter(|record| record.state == InvitationState::Pending as i32)", ".filter(|record| record.state == InvitationState::Pending as i32 && record.role == 3)"),
        ("auto_revoke", invitation, "if inviter_role == 3 {", "if inviter_role >= 1 {"),
        ("accept_authority", invitation, "validate_inviter_authority(record.role, inviter_role)?;", "let _ = inviter_role;"),
        ("recipient_projection", invitation, "normalize_invitation_recipient(record)? != *original", "{ let _ = original; false }"),
        ("inviter_uuid", invitation, " || is_account_uuid(&owner.handle)", ""),
        ("spool_projection", invitation, "validate_invitation_record_projection(record, original)?;", "let _ = (record, original);"),
        ("notification_projection", invitation, "if let Some(invitation) = &record.invitation {\n        validate_invitation_record_projection(invitation, original)?;", "if let Some(invitation) = &record.invitation {\n        let _ = (invitation, original);"),
        ("attention_projection", invitation, "if let Some(invitation) = &item.invitation {\n        validate_invitation_record_projection(invitation, original)?;", "if let Some(invitation) = &item.invitation {\n        let _ = (invitation, original);"),
    ]
    command = ["cargo", "test", "--test", "v2_review_fixes", "--", "--nocapture"]
elif language == "ts":
    invitation = Path("packages/typescript/dist/v1alpha2/invitation.js")
    notifications = Path("packages/typescript/dist/v1alpha2/notifications.js")
    cases = [
        ("local_scopes", notifications, "const scopes = [undefined];", "const scopes = [undefined, ...readable];"),
        ("spool_filter", notifications, "return [spool];", "return [undefined];"),
        ("filter_auth", notifications, "!request.includePreferences || !spool.id || !readable.some(s => s.id === spool.id)", "false"),
        ("hidden_preserve", notifications, "if (!request.clearUnreadableScopes) {", "if (false) {"),
        ("hidden_clear", notifications, "if (!request.clearUnreadableScopes) {", "if (true) {"),
        ("hidden_write", notifications, "if (next.rules.some(rule => hidden(rule.spool)) || next.digestOverrides.some(item => !item.spool || hidden(item.spool)))", "if (false)"),
        ("decline_account", notifications, "if (cell.spool && ancestors[0] && !ancestors[0].readable) {", "if (false) {"),
        ("human_session", invitation, "if (!humanSession)", "if (false)"),
        ("inviter_authority", invitation, " || inviterRole !== 3", " || inviterRole < offeredRole"),
        ("accepted_retry", invitation, "if (state === target)", "if (state === target && inviterRole === 3)"),
        ("auto_revoke_all_roles", invitation, "invitations.filter(record => record.state === InvitationState.PENDING)", "invitations.filter(record => record.state === InvitationState.PENDING && record.role === 3)"),
        ("auto_revoke", invitation, "if (inviterRole === 3)", "if (inviterRole >= 1)"),
        ("accept_authority", invitation, "validateInviterAuthority(record.role, inviterRole);", "void inviterRole;"),
        ("recipient_projection", invitation, "actual.case !== original.case || actual.value !== original.value ||", "false ||"),
        ("inviter_uuid", invitation, ' || accountUuid.test(response.inviter.handle)', ""),
        ("spool_projection", invitation, "validateInvitationRecordProjection(event.payload.value, original);", "void original;"),
        ("notification_projection", invitation, "validateInvitationRecordProjection(record.invitation, original);", "void original;"),
        ("attention_projection", invitation, "validateInvitationRecordProjection(item.invitation, original);", "void original;"),
    ]
    command = ["node", "--test", "--test-reporter=tap", "tests/v2-review-fixes.test.mjs"]
else:
    raise SystemExit("language must be rust or ts")


def run(name, stage):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=os.environ.copy())
    (log_dir / f"{name}-{stage}.log").write_text(result.stdout)
    marker = ("... FAILED" if stage == "red" else "... ok") if language == "rust" else ("not ok " if stage == "red" else "# fail 0")
    expected = (101 if language == "rust" else 1) if stage == "red" else 0
    if result.returncode != expected or marker not in result.stdout:
        raise RuntimeError(f"{name}: expected real {stage} test run; inspect {log_dir}")
    return result.returncode


for name, path, old, new in cases:
    original = path.read_text()
    try:
        expected_count = 1
        if original.count(old) != expected_count:
            raise RuntimeError(f"expected {expected_count} mutation site(s) for {name}")
        path.write_text(original.replace(old, new))
        red = run(name, "red")
        path.write_text(original)
        green = run(name, "green")
        print(f"alpha.38 {language} {name}: broken exit {red}; restored exit {green}", flush=True)
    finally:
        path.write_text(original)
