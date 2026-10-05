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
imp = "src/import_authority.rs"
its = "packages/typescript/dist/v1alpha2/import-authority.js"

def call_in(path, start, end):
    content = Path(path).read_text()
    a = content.index(start)
    return content[a:content.index(end, a) + len(end)]

if language == "rust":
    native_hook = call_in("src/native_witness.rs", "crate::writer_authority::check_witness_writer(", ")?;")
    import_hook = call_in(imp, "crate::writer_authority::check_witness_writer(", ")?;")
    binding = call_in(rust, "    verify_account_binding(\n        &authority,", ")?;")
    cases = [
        ("spool_account_conflation", "src/native_witness.rs", "cowriter_start_thread", "&authority,\n                account,", "&authority,\n                &id.owner_account_uuid,"),
        ("root_account", rust, "account_mismatch", "root.account_uuid != actor_account", "false"),
        ("owner_identity", rust, "self_signed_owner_uuid", "actor_account == spool_account && root.owner_id != spool_owner_id", "false"),
        ("publisher_cut", rust, "actor_key_cuts", "id == publisher_key_id || ", ""),
        ("mint_cut", rust, "actor_key_cuts", " || *id == key_id(&authority.mint_root_public_key)", ""),
        ("retained_inventory", rust, "retained_attachments", "admitted.0 != *signed", "false"),
        ("recover_cut", rust, "retained_attachments", "t.kind == 2", "false"),
        ("unknown_issuer", rust, "retained_attachments", "|| endpoint != state_hash", ""),
        ("retained_signature", rust, "retained_attachments", 'verify(\n        &issuer.public_key,\n        &hash(&[b"heddle-mint-root-attachment-v1", &body]),\n        &signature.signature,\n    )', "Ok(())"),
        ("native_policy_hook", "src/native_witness.rs", "native_and_import_policy_cuts", native_hook, ""),
        ("import_policy_hook", imp, "native_and_import_policy_cuts", import_hook, ""),
        ("policy_hash", imp, "policy_history", "digest != policy.policy_state_hash", "false"),
        ("policy_body", imp, "policy_history", "let policy = p.policy.as_ref().ok_or(Reject::Canonical)?;", "let empty_policy = SignedSpoolPolicy::default(); let policy = p.policy.as_ref().unwrap_or(&empty_policy);"),
        ("policy_order", imp, "policy_history", "prev >= current", "prev == current"),
        ("policy_duplicate", imp, "policy_history", "prev >= current", "prev > current"),
        ("policy_cumulative", imp, "policy_history", "successor_revoked.is_some_and(|next| revoked.iter().any(|id| !next.contains(id)))", "false"),
        ("duplicate_history", rust, "p2_p4_owner_root", "histories[..i]\n            .iter()\n            .any(|h| h.state_hash == history.state_hash)", "false"),
        ("witness_account_binding", rust, "p2_p4_owner_root", binding, ""),
        ("p2_actor", rust, "actor_subject_binding", "        verified_author_or_claim_account,", "        spool_account,"),
        ("p4_subject", rust, "actor_subject_binding", "        verified_token_subject,", "        spool_account,"),
        ("p4_proof_key", rust, "actor_subject_binding", "request_key != verified_request_proof_key", "false"),
        ("p4_token_key", rust, "actor_subject_binding", "verified_token_subject_key != verified_request_proof_key", "false"),
        ("counterparty_cut", rust, "ownership_counterparty", "co_signers\n            .iter()\n            .any(|s| revoked.contains(&key_id(&s.public_key)))", "false"),
        ("reviews_only", imp, "landing_reviews_only", "native_dependencies(&p.review_evidence, &[], true)?;", "native_dependencies(&p.review_evidence, &[], false)?;"),
        ("attachment_strict", "src/hybrid_codec.rs", "retained_strict_decode", "value.encode_to_vec() != bytes", "false"),
        ("attachment_payload", rust, "attachment_payload_binding", "crate::import_authority::verify_witness_payload(authenticated_statement, p)?;", ""),
    ]
elif language == "ts":
    native_hook = call_in("packages/typescript/dist/v1alpha2/native-witness.js", "checkWitnessWriter(s, p.creatorAuthorityEnvelope,", ");")
    import_hook = call_in(its, 'checkWitnessWriter(s, envelope ?? reject("Scope"),', ");")
    binding = call_in(ts, "verifyWriterAccountBinding(a, a.owner", ");")
    cases = [
        ("spool_account_conflation", "packages/typescript/dist/v1alpha2/native-witness.js", "cowriter StartThread", "octets(owner.account, 16), id.ownerAccountUuid", "id.ownerAccountUuid, id.ownerAccountUuid"),
        ("root_account", ts, "account_mismatch", "!equal(root.accountUuid, actorAccount)", "false"),
        ("owner_identity", ts, "self_signed_owner_uuid", "equal(actorAccount, spoolAccount) && !equal(root.ownerId, spoolOwnerId)", "false"),
        ("publisher_cut", ts, "actor key cuts", "equal(id, publisherKeyId) || ", ""),
        ("mint_cut", ts, "actor key cuts", " || equal(id, keyId(a.mintRootPublicKey))", ""),
        ("retained_inventory", ts, "retained attachments", "!equal(toBinary(SignedOwnerMintRootAttachmentSchema, admitted), bytes)", "false"),
        ("recover_cut", ts, "retained attachments", "t.kind === 2", "false"),
        ("unknown_issuer", ts, "retained attachments", " || !equal(endpoint, stateHash)", ""),
        ("retained_signature", ts, "retained attachments", "await verifySignature(e.publicKey.slice(), digest, signature.signature);", ""),
        ("native_policy_hook", "packages/typescript/dist/v1alpha2/native-witness.js", "native and import policy cuts", native_hook, ""),
        ("import_policy_hook", its, "native and import policy cuts", import_hook, ""),
        ("policy_hash", its, "policy history", "!equal(digest, p.policyStateHash)", "false"),
        ("policy_body", its, "policy history", 'policy = p.policy ?? reject("Canonical")', 'policy = p.policy ?? {revokedKeyIds:[],maxAudience:undefined}'),
        ("policy_order", its, "policy history", "compare(prev.spoolUuid, p.spoolUuid) > 0 || (equal(prev.spoolUuid, p.spoolUuid) && prev.sequence >= p.sequence)", "equal(prev.spoolUuid, p.spoolUuid) && prev.sequence === p.sequence"),
        ("policy_duplicate", its, "policy history", "prev.sequence >= p.sequence", "prev.sequence > p.sequence"),
        ("policy_cumulative", its, "policy history", "successorRevoked && revoked.some(id => !successorRevoked.some(next => equal(id, next)))", "false"),
        ("duplicate_history", ts, "P2 P4 owner roots", "histories.slice(0, i).some(prev => equal(prev.stateHash, h.stateHash))", "false"),
        ("witness_account_binding", ts, "P2 P4 owner roots", binding, ""),
        ("p2_actor", ts, "actor subject binding", "decodeWriterAuthority(p.authorityEnvelope), verifiedAuthorOrClaimAccount,", "decodeWriterAuthority(p.authorityEnvelope), spoolAccount,"),
        ("p4_subject", ts, "actor subject binding", "decodeWriterAuthority(p.authorityEnvelope), verifiedTokenSubject,", "decodeWriterAuthority(p.authorityEnvelope), spoolAccount,"),
        ("p4_proof_key", ts, "actor subject binding", "!equal(key, verifiedRequestProofKey)", "false"),
        ("p4_token_key", ts, "actor subject binding", "!equal(verifiedTokenSubjectKey, verifiedRequestProofKey)", "false"),
        ("counterparty_cut", ts, "ownership counterparty", "coSigners.some(s => revoked.some(id => equal(id, keyId(s.publicKey))))", "false"),
        ("reviews_only", its, "landing Reviews only", "await dependencies(p.reviewEvidence, [], true);", "await dependencies(p.reviewEvidence, [], false);"),
        ("attachment_strict", "packages/typescript/dist/v1alpha2/_hybrid-codec.js", "retained strict decode", "!equal(toBinary(schema, value), bytes)", "false"),
        ("attachment_payload", ts, "attachment payload binding", "await verifyWitnessPayload(authenticatedStatement, payload);", ""),
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
