#!/usr/bin/env python3
"""One mutation per alpha.37 behavior; require real failure, then restore/pass."""
import os
from pathlib import Path
import subprocess
import sys

language = sys.argv[1]
directory = Path(sys.argv[2] if len(sys.argv) > 2 else f"/tmp/api-alpha37-guards-{language}")
directory.mkdir(parents=True, exist_ok=True)
if language == "rust":
    path = Path("src/writer_authority.rs")
    cases = [
        ("admitted_basis", "if authenticated_statement.basis == 2", "if false"),
        ("integer_arrays", "deserializer.deserialize_any(IntegerArray)", "serde::Deserialize::deserialize(deserializer)"),
    ]
    command = ["cargo", "test", "--test", "boundary_attachment_contract", "--", "--nocapture"]
elif language == "ts":
    path = Path("packages/typescript/dist/v1alpha2/writer-authority.js")
    cases = [
        ("admitted_basis", "authenticatedStatement.basis === 2", "false"),
        ("integer_arrays", 'if (!Array.isArray(v) || v.length !== 32)\n        reject("Canonical");', ""),
    ]
    command = ["node", "--test", "--test-reporter=tap", "tests/v2-boundary-attachment.test.mjs"]
else:
    raise SystemExit("language must be rust or ts")

def run(name, stage):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=os.environ.copy())
    (directory / f"{name}-{stage}.log").write_text(result.stdout)
    marker = ("... FAILED" if stage == "red" else "... ok") if language == "rust" else ("not ok " if stage == "red" else "# fail 0")
    expected = (101 if language == "rust" else 1) if stage == "red" else 0
    if result.returncode != expected or marker not in result.stdout:
        raise RuntimeError(f"{name}: expected real {stage} test run; inspect {directory}")
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
        print(f"alpha.37 {language} {name}: broken exit {red}; restored exit {green}", flush=True)
    finally:
        path.write_text(original)
