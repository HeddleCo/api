#!/usr/bin/env python3
"""Disable each acceptance selection/check, require test failure, restore/pass."""
import os
from pathlib import Path
import subprocess
import sys

language = sys.argv[1]
directory = Path(sys.argv[2] if len(sys.argv) > 2 else f"/tmp/api-alpha36-guards-{language}")
directory.mkdir(parents=True, exist_ok=True)
writer = "src/writer_authority.rs" if language == "rust" else "packages/typescript/dist/v1alpha2/writer-authority.js"

def section(path, start, end):
    text = Path(path).read_text()
    a = text.index(start)
    return text[a:text.index(end, a) + len(end)]

if language == "rust":
    account = section(writer, "        verify_account_binding(\n            &current,", ")?;")
    native = "src/native_witness.rs"
    imp = "src/import_authority.rs"
    import_selection = section(imp, "                if s.purpose == 1 {", "                },")
    cases = [
        ("basis_selection", writer, "statement.basis == 2", "false"),
        ("acceptor_signer", writer, "signed.signatures[0].public_key != acceptance.accepting_publisher", "false"),
        ("acceptor_account_and_owner", writer, account, ""),
        ("acceptor_publisher_cut", writer, "id == publisher_key_id || ", ""),
        ("acceptor_mint_cut", writer, " || *id == key_id(&authority.mint_root_public_key)", ""),
        ("native_p1_selection", native, "p.boundary_acceptance.as_ref(),", "None,"),
        ("native_p2_selection", native, "p.boundary_acceptances\n                        .iter()\n                        .find(|e| e.binding == s.boundary_acceptance)", "None"),
        ("import_selection", imp, import_selection, "                None,"),
        ("import_p1_hook", imp, "1 if s.basis == 2 =>", "1 if false =>"),
    ]
    command = ["cargo", "test", "--test", "boundary_acceptor_contract", "--", "--nocapture"]
elif language == "ts":
    native = "packages/typescript/dist/v1alpha2/native-witness.js"
    imp = "packages/typescript/dist/v1alpha2/import-authority.js"
    cases = [
        ("basis_selection", writer, "s.basis === 2", "false"),
        ("acceptor_signer", writer, "!equal(signed.signatures[0].publicKey, publisher)", "false"),
        ("acceptor_account_and_owner", writer, "verifyWriterAccountBinding(current, acceptingOctets(actor.principal_id, 16), spoolAccount, s.ownerId);", ""),
        ("acceptor_publisher_cut", writer, "equal(id, publisherKeyId) || ", ""),
        ("acceptor_mint_cut", writer, " || equal(id, keyId(a.mintRootPublicKey))", ""),
        ("native_p1_selection", native, "[], p.boundaryAcceptance);", "[], undefined);"),
        ("native_p2_selection", native, "p.boundaryAcceptances.find(e => s.boundaryAcceptance && e.binding && equal(canonicalHybridV1(HostedWitnessBoundaryAcceptanceV1Schema, e.binding), canonicalHybridV1(HostedWitnessBoundaryAcceptanceV1Schema, s.boundaryAcceptance)))", "undefined"),
        ("import_selection", imp, "?.original?.signatures ?? [], boundary);", "?.original?.signatures ?? [], undefined);"),
        ("import_p1_hook", imp, "(s.purpose === 1 && s.basis === 2)", "false"),
    ]
    command = ["node", "--test", "--test-reporter=tap", "tests/v2-boundary-acceptor.test.mjs"]
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

for name, filename, old, new in cases:
    path = Path(filename)
    original = path.read_text()
    try:
        if old not in original:
            raise RuntimeError(f"missing mutation {name} in {filename}")
        path.write_text(original.replace(old, new))
        red = run(name, "red")
        path.write_text(original)
        green = run(name, "green")
        print(f"alpha.36 {language} {name}: broken exit {red}; restored exit {green}", flush=True)
    finally:
        path.write_text(original)
