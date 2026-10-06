#!/usr/bin/env python3
"""Remove privacy/live-role guards, require assertion failure, restore/pass."""
import os
from pathlib import Path
import subprocess
import sys

language = sys.argv[1]
directory = Path(sys.argv[2] if len(sys.argv) > 2 else f"/tmp/api-alpha39-people-groups-{language}")
directory.mkdir(parents=True, exist_ok=True)
if language == "rust":
    people = Path("src/v2/people.rs")
    groups = Path("src/v2/approval_groups.rs")
    cases = [
        ("co_member", people, "if shared\n", "if true\n"),
        ("members_visibility", people, "&& context.members_readable_spool_ids.contains(id)", "&& true"),
        ("hidden_handle", people, "!candidate.handle_visible", "false"),
        ("absent_handle", people, "candidate.person.handle.is_empty()", "false"),
        ("uuid_handle", people, "|| uuid_shaped_handle(&person.handle)", "|| false"),
        ("explicit_admin", groups, "if !is_administrator {", "if false {"),
        ("explicit_preservation", groups, "(!p.handle_visible || p.person.handle.is_empty())", "false"),
        ("explicit_resolution", groups, "resolve_visible_human(handle)", "Some(handle.clone())"),
        ("explicit_members_read", groups, "if context.is_administrator && context.can_read_members {", "if context.is_administrator {"),
        ("explicit_hidden", groups, ".filter(|p| p.explicit_member && !p.is_agent && !p.subject.is_empty())\n        {\n            if !principal.handle_visible", ".filter(|p| p.explicit_member && !p.is_agent && !p.subject.is_empty())\n        {\n            if false"),
        ("roster_absent", groups, "for principal in &members {\n            if !principal.handle_visible || principal.person.handle.is_empty()", "for principal in &members {\n            if !principal.handle_visible || false"),
        ("explicit_view", groups, "if context.is_administrator && context.can_read_members {", "if context.can_read_members {"),
        ("roster_visibility", groups, "if context.can_read_members {", "if true {"),
        ("roster_hidden", groups, "for principal in &members {\n            if !principal.handle_visible", "for principal in &members {\n            if false"),
        ("agents", people, "if candidate.is_agent {", "if false {"),
        ("bound", people, "members.truncate(MAX_SUGGESTED_PRINCIPALS);", "// bound removed"),
        ("prefix", people, "!(2..=64).contains(&prefix.chars().count())", "false"),
        ("rate_limit", people, "if !context.rate_limit_allowed {", "if false {"),
        ("scope", people, "spool.id.is_empty() || !context.caller_spool_ids.contains(&spool.id)", "false"),
        ("role_member_counts", groups, "group.member_role != ResourceRole::Unspecified as i32", "false"),
        ("demotion", groups, "principal.effective_role as i32 >= group.member_role", "true"),
        ("reader_refused", groups, "if role == ResourceRole::Reader {", "if false {"),
    ]
    command = ["cargo", "test", "--all-features", "--test", "v2_people_contract", "--test", "v2_approval_groups_contract", "--", "--nocapture"]
elif language == "ts":
    people = Path("packages/typescript/dist/v1alpha2/people.js")
    groups = Path("packages/typescript/dist/v1alpha2/approval-groups.js")
    cases = [
        ("co_member", people, "if (shared &&", "if (true &&"),
        ("members_visibility", people, "&& context.membersReadableSpoolIds.includes(id)", "&& true"),
        ("hidden_handle", people, "!candidate.handleVisible", "false"),
        ("absent_handle", people, "!candidate.person.handle", "false"),
        ("uuid_handle", people, "|| /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(person.handle)", "|| false"),
        ("explicit_admin", groups, "if (!isAdministrator)", "if (false)"),
        ("explicit_preservation", groups, "(!p.handleVisible || !p.person.handle)", "false"),
        ("explicit_resolution", groups, "const subject = resolveVisibleHuman(handle);", "const subject = handle;"),
        ("explicit_members_read", groups, "context.isAdministrator && context.canReadMembers", "context.isAdministrator"),
        ("roster_absent", groups, "p.handleVisible && !!p.person.handle", "p.handleVisible"),
        ("explicit_view", groups, "context.isAdministrator && context.canReadMembers", "context.canReadMembers"),
        ("roster_visibility", groups, "context.canReadMembers ? members.filter(visible) : []", "members.filter(visible)"),
        ("roster_hidden", groups, "p.handleVisible &&", "true &&"),
        ("agents", people, "if (candidate.isAgent)", "if (false)"),
        ("bound", people, ".slice(0, MAX_SUGGESTED_PRINCIPALS)", ".slice(0)"),
        ("prefix", people, "[...prefix].length < 2 || [...prefix].length > 64", "false"),
        ("rate_limit", people, "if (!context.rateLimitAllowed)", "if (false)"),
        ("scope", people, "if (request.spool &&", "if (false &&"),
        ("role_member_counts", groups, "group.memberRole !== ResourceRole.UNSPECIFIED", "false"),
        ("demotion", groups, "principal.effectiveRole >= group.memberRole", "true"),
        ("reader_refused", groups, "if (role === ResourceRole.READER)", "if (false)"),
        ("runtime_id_leak", people, "Object.keys(person).some(key => !allowed.has(key))", "false"),
    ]
    command = ["node", "--test", "--test-reporter=tap", "tests/v2-people.test.mjs", "tests/v2-approval-groups.test.mjs"]
else:
    raise SystemExit("language must be rust or ts")


def run(name, stage):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=os.environ.copy())
    (directory / f"{name}-{stage}.log").write_text(result.stdout)
    marker = ("... FAILED" if stage == "red" else "... ok") if language == "rust" else ("not ok " if stage == "red" else "# fail 0")
    expected = (101 if language == "rust" else 1) if stage == "red" else 0
    if result.returncode != expected or marker not in result.stdout:
        raise RuntimeError(f"{name}: expected real {stage} assertion results; inspect {directory}")
    return result.returncode


for name, path, old, new in cases:
    original = path.read_text()
    try:
        if original.count(old) != 1:
            raise RuntimeError(f"expected one mutation site for {name}")
        path.write_text(original.replace(old, new))
        red = run(name, "red")
        path.write_text(original)
        green = run(name, "green")
        print(f"alpha.39 {language} {name}: broken exit {red}; restored exit {green}", flush=True)
    finally:
        path.write_text(original)

# Leak a declared account identifier: both descriptor tests MUST catch it.
path = Path("proto/heddle/api/v1alpha2/identity.proto")
original = path.read_text()
try:
    marker = "message SuggestedPrincipal {"
    if original.count(marker) != 1:
        raise RuntimeError("expected one people schema")
    path.write_text(original.replace(marker, marker + "\n  string account_id = 99;"))
    if language == "ts":
        subprocess.run(["npm", "run", "build"], check=True, stdout=subprocess.DEVNULL)
    red = run("no_id_leak", "red")
    path.write_text(original)
    if language == "ts":
        subprocess.run(["npm", "run", "build"], check=True, stdout=subprocess.DEVNULL)
    green = run("no_id_leak", "green")
    print(f"alpha.39 {language} no_id_leak: broken exit {red}; restored exit {green}", flush=True)
finally:
    path.write_text(original)

# Reintroduce the removed ID write arm. Hard-cut descriptor assertions must fail.
path = Path("proto/heddle/api/v1alpha2/administration.proto")
original = path.read_text()
try:
    marker = ('message ApprovalGroupRecord {\n'
              '  RecordRef ref = 1;\n  bytes version = 2;\n'
              '  string name = 3;\n  string description = 4;\n'
              '  reserved 5;\n  reserved "principal_ids";')
    if original.count(marker) != 1:
        raise RuntimeError("expected one approval group write cutover site")
    restored_id_arm = marker.replace('  reserved 5;\n  reserved "principal_ids";',
                                    '  repeated string principal_ids = 5;')
    path.write_text(original.replace(marker, restored_id_arm))
    if language == "ts":
        subprocess.run(["npm", "run", "build"], check=True, stdout=subprocess.DEVNULL)
    red = run("handle_write_cutover", "red")
    path.write_text(original)
    if language == "ts":
        subprocess.run(["npm", "run", "build"], check=True, stdout=subprocess.DEVNULL)
    green = run("handle_write_cutover", "green")
    print(f"alpha.39 {language} handle_write_cutover: broken exit {red}; restored exit {green}", flush=True)
finally:
    path.write_text(original)
