import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { CheckEvidenceSummary_Outcome as Outcome } from '../packages/typescript/dist/v2alpha1/activity_pb.js';
import { signCheckEvidence, projectCheckEvidence, prepareCheckAcknowledgement } from '../packages/typescript/dist/v2alpha1/evidence.js';
import { decode, encode } from '../packages/typescript/dist/v2alpha1/_collaboration-msgpack.js';
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 19)]), format: 'der', type: 'pkcs8' });
const signer = { publicKey: new Uint8Array(createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32)), sign: async bytes => new Uint8Array(sign(null, bytes, key)) };
const id = n => `00000000-0000-0000-0000-${n.toString(16).padStart(12, '0')}`;
const author = { actor: { principalId: id(4), agentId: 'test-runner' }, authorityEnvelope: new TextEncoder().encode('independently verified by receiving host'), signer };
const input = { id: id(1), spoolId: id(2), threadId: new Uint8Array(32).fill(7), revision: new Uint8Array(32).fill(3), check: 'unit-tests', outcome: Outcome.PASSED, detail: '42 passed', artifacts: [id(8)], supersedes: [id(9)], completedAtMs: 1234n };
test('all outcomes and original attribution survive signed projection', async () => {
  for (const outcome of [Outcome.PASSED, Outcome.FAILED, Outcome.ERROR, Outcome.SKIPPED]) {
    const result = await signCheckEvidence({ ...input, outcome }, author);
    assert.deepEqual(await projectCheckEvidence(result.evidence), result);
    assert.deepEqual(result.thread.id.value, input.threadId);
    assert.equal(result.thread.spool.id, input.spoolId);
    assert.equal(result.summary.outcome, outcome);
    assert.equal(result.summary.author.id, author.actor.principalId);
    assert.equal(result.summary.agentId, 'test-runner');
    assert.equal(result.summary.artifacts[0].id, id(8));
    assert.equal(result.summary.supersedes[0].id, id(9));
    assert.equal(result.summary.completedAt.seconds, 1n);
    assert.equal(result.summary.completedAt.nanos, 234000000);
  }
});
test('progress binds exact evidence, policy, actor and command without rewriting result', async () => {
  const result = await signCheckEvidence({ ...input, outcome: Outcome.FAILED }, author);
  const ack = await prepareCheckAcknowledgement(result, new Uint8Array(32).fill(5), id(6), 2001n, author);
  const raw = decode(ack.acknowledgement.canonicalRecord);
  assert.equal(ack.evidence.id, id(1)); assert.equal(ack.clientOperationId, id(6));
  assert.equal(raw.occurred_at_ms, 2001); assert.deepEqual(raw.policy_version, Array(32).fill(5));
  assert.equal(result.summary.outcome, Outcome.FAILED);
  assert.equal(raw.author.actor.agent_id, 'test-runner');
  const relabeled = structuredClone(result); relabeled.summary.outcome = Outcome.PASSED;
  await assert.rejects(prepareCheckAcknowledgement(relabeled, new Uint8Array(32).fill(5), id(6), 2001n, author), /differs from original/);
});
test('original signature, domain, canonical author binding and byte limit are mandatory', async () => {
  const result = await signCheckEvidence(input, author);
  let altered = structuredClone(result.evidence); altered.signatures[0].signature[0] ^= 1;
  await assert.rejects(projectCheckEvidence(altered), /signature/);
  altered = structuredClone(result.evidence); altered.format = 'heddle-check-acknowledgement-v1';
  await assert.rejects(projectCheckEvidence(altered), /framing/);
  altered = structuredClone(result.evidence); const raw = decode(altered.canonicalRecord); raw.author.authority_digest[0] ^= 1; altered.canonicalRecord = encode(raw);
  await assert.rejects(projectCheckEvidence(altered), /Noncanonical/);
  altered = structuredClone(result.evidence); altered.canonicalRecord = new Uint8Array(128 * 1024 + 1);
  await assert.rejects(projectCheckEvidence(altered), /framing/);
  await assert.rejects(signCheckEvidence({ ...input, supersedes: [id(1)] }, author), /itself/);
  await assert.rejects(signCheckEvidence({ ...input, artifacts: [id(9), id(8)] }, author), /sorted/);
  await assert.rejects(signCheckEvidence(input, { ...author, signer: { ...signer, publicKey: new Uint8Array(32).fill(5) } }), /signature/);
});

test('original Thread scope is signed and cannot be relabeled through an identical revision', async () => {
  const result = await signCheckEvidence(input, author);
  const relabeled = structuredClone(result);
  relabeled.thread.id.value[0] ^= 1;
  await assert.rejects(prepareCheckAcknowledgement(relabeled, new Uint8Array(32).fill(5), id(6), 2001n, author), /differs from original/);
  const altered = structuredClone(result.evidence);
  const raw = decode(altered.canonicalRecord);
  raw.thread[0] ^= 1;
  altered.canonicalRecord = encode(raw);
  await assert.rejects(projectCheckEvidence(altered), /signature/);
  await assert.rejects(signCheckEvidence({ ...input, threadId: new Uint8Array() }, author), /32 bytes/);
});

// Generated independently with the Rust object-model and crypto codecs.
test('browser evidence and progress match Rust canonical bytes and signatures', async () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/check-evidence-v2-rust.json', import.meta.url), 'utf8'));
  const result = await signCheckEvidence(input, author);
  const ack = await prepareCheckAcknowledgement(result, new Uint8Array(32).fill(5), id(6), 2001n, author);
  const hex = bytes => Buffer.from(bytes).toString('hex');
  assert.equal(hex(result.evidence.canonicalRecord), fixture.evidence_hex);
  assert.equal(hex(result.evidence.signatures[0].signature), fixture.evidence_signature);
  assert.equal(hex(ack.acknowledgement.canonicalRecord), fixture.acknowledgement_hex);
  assert.equal(hex(ack.acknowledgement.signatures[0].signature), fixture.acknowledgement_signature);
});
