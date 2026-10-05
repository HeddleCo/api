#!/usr/bin/env python3
"""Disable each writer guard, require a real test failure, restore and pass."""
import os
from pathlib import Path
import subprocess
import sys

language = sys.argv[1] if len(sys.argv) > 1 else "ts"
directory = Path(sys.argv[2] if len(sys.argv) > 2 else f"/tmp/api-alpha35-guards-{language}")
directory.mkdir(parents=True, exist_ok=True)
rust = "src/writer_authority.rs"
ts = "packages/typescript/dist/v1alpha2/writer-authority.js"
if language == "rust":
    cases = [
        ("spool_account_conflation", "src/native_witness.rs", "cowriter_start_thread", "&authority,\n                account,", "&authority,\n                &id.owner_account_uuid,"),
        ("root_account", rust, "account_mismatch", "root.account_uuid != actor_account", "false"),
        ("owner_identity", rust, "self_signed_owner_uuid", "actor_account == spool_account && root.owner_id != spool_owner_id", "false"),
        ("publisher_cut", rust, "actor_key_cuts", "id == publisher_key_id || ", ""),
        ("mint_cut", rust, "actor_key_cuts", " || *id == key_id(&authority.mint_root_public_key)", ""),
        ("retained_inventory", rust, "retained_attachments", "!expected.admitted_attachments.contains(signed)", "false"),
        ("recover_cut", rust, "retained_attachments", "!expected.issuer_retained_mint_authority", "false"),
        ("unknown_issuer", rust, "retained_attachments", "|| a.owner_state_hash != expected.issuer_state_hash", ""),
        ("retained_signature", rust, "retained_attachments", "verify(\n        expected.issuer_public_key,\n        &hash(&[b\"heddle-mint-root-attachment-v1\", &body]),\n        &signature.signature,\n    )", "Ok(())"),
        ("native_policy_hook", "src/native_witness.rs", "native_and_import_policy_cuts", "crate::writer_authority::check_witness_writer(\n                    s,\n                    &p.creator_authority_envelope,\n                    &b.owner_histories,\n                    &b.policies,\n                )?;", ""),
        ("import_policy_hook", "src/import_authority.rs", "native_and_import_policy_cuts", "crate::writer_authority::check_witness_writer(\n                s,\n                envelope,\n                &bundle.owner_histories,\n                &bundle.policies,\n            )?;", ""),
    ]
elif language == "ts":
    cases = [
        ("spool_account_conflation", "packages/typescript/dist/v1alpha2/native-witness.js", "cowriter StartThread", "octets(owner.account, 16), id.ownerAccountUuid", "id.ownerAccountUuid, id.ownerAccountUuid"),
        ("root_account", ts, "account_mismatch", "!equal(root.accountUuid, actorAccount)", "false"),
        ("owner_identity", ts, "self_signed_owner_uuid", "equal(actorAccount, spoolAccount) && !equal(root.ownerId, spoolOwnerId)", "false"),
        ("publisher_cut", ts, "actor key cuts", "equal(id, publisherKeyId) || ", ""),
        ("mint_cut", ts, "actor key cuts", " || equal(id, keyId(a.mintRootPublicKey))", ""),
        ("retained_inventory", ts, "retained attachments", "!e.admittedAttachments.some(a => equal(toBinary(SignedOwnerMintRootAttachmentSchema, a), bytes))", "false"),
        ("recover_cut", ts, "retained attachments", "!e.issuerRetainedMintAuthority", "false"),
        ("unknown_issuer", ts, "retained attachments", " || !equal(a.ownerStateHash, e.issuerStateHash)", ""),
        ("retained_signature", ts, "retained attachments", "await verifySignature(e.issuerPublicKey.slice(), digest, signature.signature);", ""),
        ("native_policy_hook", "packages/typescript/dist/v1alpha2/native-witness.js", "native and import policy cuts", "checkWitnessWriter(s, p.creatorAuthorityEnvelope, b.ownerHistories, b.policies);", ""),
        ("import_policy_hook", "packages/typescript/dist/v1alpha2/import-authority.js", "native and import policy cuts", 'checkWitnessWriter(s, envelope ?? reject("Scope"), b.ownerHistories, b.policies);', ""),
    ]
else:
    raise SystemExit("language must be rust or ts")

def run(name, pattern, stage):
    command = (["cargo", "test", "--test", "writer_authority_contract", pattern, "--", "--nocapture"]
               if language == "rust" else
               ["node", "--test", "--test-reporter=tap", "--test-name-pattern=" + pattern, "tests/v2-writer-authority.test.mjs"])
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=os.environ.copy())
    (directory / f"{name}-{stage}.log").write_text(result.stdout)
    if stage == "red" and not ("... FAILED" in result.stdout if language == "rust" else "not ok " in result.stdout):
        raise RuntimeError(f"{name}: no actual failing test; inspect {directory}")
    if stage == "green" and not ("... ok" in result.stdout if language == "rust" else "ok 1" in result.stdout):
        raise RuntimeError(f"{name}: no actual passing test; inspect {directory}")
    return result.returncode

for name, filename, pattern, old, new in cases:
    if len(sys.argv) > 3 and name != sys.argv[3]:
        continue
    path = Path(filename)
    original = path.read_text()
    try:
        if old not in original:
            raise RuntimeError(f"missing mutation {name} in {filename}")
        path.write_text(original.replace(old, new))
        red = run(name, pattern, "red")
        path.write_text(original)
        green = run(name, pattern, "green")
        print(f"alpha.35 {language} {name}: broken exit {red}; restored exit {green}", flush=True)
        if red != (101 if language == "rust" else 1) or green != 0:
            raise RuntimeError(f"{name}: guard not demonstrated")
    finally:
        path.write_text(original)
