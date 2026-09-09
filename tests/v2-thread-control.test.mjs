import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { create } from '@bufbuild/protobuf';
import { ThreadOverviewSchema, ThreadProperty, ThreadLifecycle, SharedFacet, ThreadIntentSchema, ThreadSharingPolicySchema, ReviewDecisionSchema, ReviewDecision_Kind } from '../packages/typescript/dist/v2alpha1/thread_pb.js';
import { EndpointKind } from '../packages/typescript/dist/v2alpha1/stream_pb.js';
import { signThreadControl, threadPropertyVersion } from '../packages/typescript/dist/v2alpha1/thread-control.js';
import { decode } from '../packages/typescript/dist/v2alpha1/_collaboration-msgpack.js';

// Produced by Rust's repository metadata test, never by the JS encoder.
const fixtures = JSON.parse(readFileSync(new URL('./fixtures/thread-control-v1-rust.json', import.meta.url), 'utf8'));
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 19)]), format: 'der', type: 'pkcs8' });
const signer = { publicKey: new Uint8Array(createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32)), sign: async bytes => new Uint8Array(sign(null, bytes, key)) };
const bytes = hex => new Uint8Array(Buffer.from(hex, 'hex'));
const ref = { spool: { id: fixtures[0].control.spool }, id: { value: new Uint8Array(32).fill(11) } };
const revision = value => ({ spool: ref.spool, revision: { case: 'state', value: { value: Uint8Array.from(value) } } });
function inputs(fixture) {
  const raw = fixture.control;
  const actor = { principalId: raw.actor.principal_id, ...(raw.actor.agent_id ? { agentId: raw.actor.agent_id } : {}) };
  const source = raw.control.value;
  const kind = raw.control.kind;
  let value = source;
  if (kind === 'intent') value = create(ThreadIntentSchema, { outcome: source.outcome, acceptanceCriteria: source.acceptance_criteria, originUrls: source.origin_urls, principalApproved: source.principal_approved, principalId: actor.principalId });
  if (kind === 'lifecycle') value = ThreadLifecycle[source.toUpperCase()];
  if (kind === 'sharing') value = create(ThreadSharingPolicySchema, { thread: ref, ongoing: source.ongoing, destinations: source.destinations.map(destination => ({ endpoint: { publicKey: Uint8Array.from(destination.endpoint), kind: EndpointKind[destination.kind.toUpperCase()] }, spool: { id: destination.spool }, facets: destination.facets.map(facet => SharedFacet[facet.toUpperCase()]) })) });
  if (kind === 'review') value = create(ReviewDecisionSchema, { ref: { id: source.id, spool: ref.spool }, thread: ref, source: revision(source.source), target: revision(source.target), policyVersion: Uint8Array.from(source.policy_version), kind: ReviewDecision_Kind[source.kind.toUpperCase()], explanation: source.explanation, principalId: actor.principalId, agentId: actor.agentId ?? '', ...(source.revokes ? { revokes: { id: source.revokes, spool: ref.spool } } : {}), ...(source.expires_at_unix_seconds ? { expiresAt: { seconds: BigInt(source.expires_at_unix_seconds) } } : {}) });
  const property = ThreadProperty[kind.toUpperCase()];
  const recordId = kind === 'review' ? source.id : '';
  return {
    overview: create(ThreadOverviewSchema, { ref, metadataFrontiers: [{ property, recordId, version: bytes(fixture.property_version), operationIds: [new Uint8Array(32).fill(12), new Uint8Array(32).fill(13)] }] }),
    command: { clientOperationId: raw.client_operation_id, occurredAtMs: BigInt(raw.occurred_at_ms), control: { kind, value } },
    author: { actor, authorityEnvelope: Uint8Array.from(raw.authority_envelope), signer },
  };
}
for (const fixture of fixtures) test(`browser ${fixture.control.control.kind} matches independent Rust control, operation, signature and both property versions`, async () => {
  const { overview, command, author } = inputs(fixture);
  const signed = await signThreadControl(overview, command, author);
  assert.equal(Buffer.from(signed.operation.canonicalRecord).toString('hex'), fixture.operation_hex);
  const inner = decode(signed.operation.canonicalRecord).body.canonical;
  assert.equal(Buffer.from(inner).toString('hex'), fixture.control_hex);
  assert.equal(Buffer.from(signed.operation.signatures[0].signature).toString('hex'), fixture.signature_hex);
  assert.equal(Buffer.from(signed.expectedVersion).toString('hex'), fixture.property_version);
  const frontier = overview.metadataFrontiers[0];
  assert.equal(Buffer.from(threadPropertyVersion(ref.id.value, frontier.property, frontier.recordId, [])).toString('hex'), fixture.empty_property_version);
});

test('frontier scope and complete candidate set are checked before calling signer', async () => {
  const { overview, command, author } = inputs(fixtures[0]);
  let calls = 0;
  author.signer = { ...signer, sign: async bytes => { calls++; return signer.sign(bytes); } };
  for (const mutate of [
    value => value.ref.id.value.fill(14),
    value => value.metadataFrontiers[0].operationIds.pop(),
    value => value.metadataFrontiers[0].operationIds.reverse(),
    value => value.metadataFrontiers[0].property = ThreadProperty.INTENT,
    value => value.metadataFrontiers = [],
  ]) {
    const changed = structuredClone(overview); mutate(changed);
    await assert.rejects(signThreadControl(changed, command, author), /frontier|version/i);
  }
  assert.equal(calls, 0);
});
test('agent intent cannot invent human approval and lifecycle cannot invent landing', async () => {
  const intent = inputs(fixtures[1]); intent.author.actor.agentId = 'agent';
  await assert.rejects(signThreadControl(intent.overview, intent.command, intent.author), /human approval/);
  const lifecycle = inputs(fixtures[2]); lifecycle.command.control.value = ThreadLifecycle.LANDED;
  await assert.rejects(signThreadControl(lifecycle.overview, lifecycle.command, lifecycle.author), /integration receipt/);
});
test('original authority is hash-bound and wrong signing key cannot produce a record', async () => {
  const first = inputs(fixtures[0]);
  const original = await signThreadControl(first.overview, first.command, first.author);
  first.author.authorityEnvelope[0] ^= 1;
  const changed = await signThreadControl(first.overview, first.command, first.author);
  assert.notDeepEqual(original.operation.canonicalRecord, changed.operation.canonicalRecord);
  first.author.signer = { ...signer, sign: async () => new Uint8Array(64) };
  await assert.rejects(signThreadControl(first.overview, first.command, first.author), /signer does not match/);
});

test('a fresh review gets its own empty CAS frontier without inventing singleton defaults', async () => {
  const review = inputs(fixtures[4]); review.overview.metadataFrontiers = [];
  const signed = await signThreadControl(review.overview, review.command, review.author);
  assert.deepEqual(decode(signed.operation.canonicalRecord).parents, []);
  assert.equal(Buffer.from(signed.expectedVersion).toString('hex'), fixtures[4].empty_property_version);
});
