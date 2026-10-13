import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { EntityRefSchema, SourceMentionSchema, SignedRecordSchema } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import { AnnotationTagSchema, OpenDiscussionRequestSchema, ContextDraftSchema } from '../packages/typescript/dist/v1alpha2/collaboration_pb.js';
import { signDiscussion, signContext, verifyCollaboration, canonicalMention, validateEntityMentions, textAnnotationTag } from '../packages/typescript/dist/v1alpha2/collaboration.js';
import { encode, decode } from '../packages/typescript/dist/v1alpha2/_collaboration-msgpack.js';
const fixture = JSON.parse(readFileSync(new URL('./fixtures/collaboration-alpha47.json', import.meta.url)));
const old = Object.fromEntries(readFileSync(new URL('./fixtures/collaboration-v2-rust.txt', import.meta.url), 'utf8').trim().split('\n').map(line => {
  const [name, key, canonical, signature] = line.split(' ');
  return [name, create(SignedRecordSchema, { format: 'heddle-thread-operation-v1', canonicalRecord: Buffer.from(canonical, 'hex'), signatures: [{ publicKey: Buffer.from(key, 'hex'), signature: Buffer.from(signature, 'hex') }] })];
}));
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]), format: 'der', type: 'pkcs8' });
const signer = { publicKey: new Uint8Array(createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32)), sign: async bytes => new Uint8Array(sign(null, bytes, key)) };
const scope = { spoolId: '00000000-0000-0000-0000-000000000001', threadId: new Uint8Array(32).fill(2) };
const shared = { scope, actor: { principalId: '00000000-0000-0000-0000-000000000003', agentId: 'agent-4' }, occurredAtMs: 100n };
const command = action => ({ ...shared, discussionId: 'disc-01980000-0000-7000-8000-000000000123', clientOperationId: 'operation-1', author: { name: 'Account' }, action });
const open = { kind: 'open', blocking: true, title: 'Review', anchor: { kind: 'repository' }, visibility: 'public', body: 'First turn' };
const principal = { kind: 'principal', principalId: '00000000-0000-0000-0000-000000000006' };
const source = state => create(SourceMentionSchema, {
  revision: { spool: { id: scope.spoolId }, revision: state ? { case: 'state', value: { value: new Uint8Array(32).fill(5) } } : { case: 'gitCommitOid', value: 'a'.repeat(40) } },
  path: 'src/main.rs', symbolId: state ? 'run' : '', startLine: state ? 12 : undefined, endLine: state ? 18 : undefined,
  thread: state ? { spool: { id: scope.spoolId }, id: { value: scope.threadId } } : undefined,
});
const tags = [textAnnotationTag('decision'), create(AnnotationTagSchema, { tag: { case: 'entity', value: { entity: { case: 'principal', value: { id: principal.principalId } } } } })];

test('seven new signed cases match independent Rust canonical bytes, signatures, IDs and wire corpus', async () => {
  const records = {
    principal_open: await signDiscussion({ ...command(open), mentions: [principal] }, [], signer),
    source_state_open: await signDiscussion({ ...command(open), mentions: [{ kind: 'source', source: source(true) }] }, [], signer),
    source_git_append: await signDiscussion({ ...command({ kind: 'append', body: 'See the reviewed state' }), mentions: [{ kind: 'source', source: source(false) }] }, [old.open], signer),
    context_mentions: await signContext({ ...shared, contextId: '00000000-0000-0000-0000-000000000009', anchor: { kind: 'repository' }, content: 'Design rationale', tags: [textAnnotationTag('decision')], mentions: [principal, { kind: 'source', source: source(false) }] }, [], signer),
    open_tags: await signDiscussion(command({ ...open, tags }), [], signer),
    edit_tags: await signDiscussion(command({ kind: 'edit_tags', tags }), [old.open], signer),
    clear_tags: await signDiscussion(command({ kind: 'edit_tags', tags: [] }), [old.open], signer),
  };
  assert.deepEqual(Object.keys(records).sort(), Object.keys(fixture.vectors).sort());
  for (const [name, record] of Object.entries(records)) {
    const v = fixture.vectors[name];
    assert.equal(Buffer.from(record.canonicalRecord).toString('hex'), v.canonical_hex, name);
    assert.equal(Buffer.from(record.signatures[0].signature).toString('hex'), v.signature_hex, name);
    assert.equal(Buffer.from(toBinary(SignedRecordSchema, record)).toString('hex'), v.record_wire_hex, name);
    assert.equal(Buffer.from((await verifyCollaboration(record)).operationId).toString('hex'), v.operation_id_hex, name);
    for (const m of v.mentions) {
      const ref = fromBinary(EntityRefSchema, Buffer.from(m.entity_wire_hex, 'hex'));
      validateEntityMentions([ref]);
      assert.equal(Buffer.from(canonicalMention(ref)).toString('hex'), m.canonical_hex);
    }
  }
});
test('opening mentions round-trip with the same entity list as context drafts and empty tags retain old signed bytes', async () => {
  const mentions = [create(EntityRefSchema, { entity: { case: 'source', value: source(true) } }), create(EntityRefSchema, { entity: { case: 'principal', value: { id: principal.principalId } } })];
  const request = create(OpenDiscussionRequestSchema, { mentions, tags });
  assert.deepEqual(fromBinary(OpenDiscussionRequestSchema, toBinary(OpenDiscussionRequestSchema, request)).mentions, mentions);
  const draft = create(ContextDraftSchema, { mentions });
  assert.deepEqual(fromBinary(ContextDraftSchema, toBinary(ContextDraftSchema, draft)).mentions, mentions);
  assert.deepEqual((await signDiscussion(command({ ...open, tags: [] }), [], signer)).canonicalRecord, new Uint8Array(old.open.canonicalRecord));
});
test('mention count, UTF-8 bounds, canonical paths, exact revisions and inclusive lines are checked before signing', async () => {
  let calls = 0;
  const counting = { ...signer, sign: async bytes => { calls++; return signer.sign(bytes); } };
  await assert.rejects(signDiscussion({ ...command(open), mentions: Array(129).fill(principal) }, [], counting));
  const valid = source(true);
  for (const patch of [{ path: 'x'.repeat(4097) }, { symbolId: 'é'.repeat(2049) }, { path: '../main.rs' }, { startLine: 0 }, { startLine: 19 }, { startLine: undefined }, { endLine: undefined }, { endLine: 4294967296 }, { revision: { ...valid.revision, revision: { case: 'gitCommitOid', value: 'main' } } }, { thread: { ...valid.thread, spool: { id: principal.principalId } } }]) {
    await assert.rejects(signDiscussion({ ...command(open), mentions: [{ kind: 'source', source: create(SourceMentionSchema, { ...valid, ...patch }) }] }, [], counting));
  }
  assert.equal(calls, 0);
  await signDiscussion({ ...command(open), mentions: Array(128).fill(principal) }, [], signer);
  const ref = create(EntityRefSchema, { entity: { case: 'source', value: create(SourceMentionSchema, { ...valid, path: 'é'.repeat(2048), symbolId: 's'.repeat(4096) }) } });
  validateEntityMentions([ref]);
  assert.throws(() => validateEntityMentions(Array(129).fill(ref)));
});
test('valid signatures cannot conceal malformed new mention or tag forms from the verifier', async () => {
  for (const [name, mutate] of [
    ['principal_open', inner => { inner.metadata.mentions[0].principal_id = new Uint8Array(16); }],
    ['source_state_open', inner => { inner.metadata.mentions[0].target.source.end_line = 1; }],
    ['source_state_open', inner => { inner.metadata.mentions[0].target.source.extra = true; }],
    ['open_tags', inner => { inner.body.tags = []; }],
    ['edit_tags', inner => { inner.body.tags = Array(129).fill(inner.body.tags[0]); }],
  ]) {
    const record = fromBinary(SignedRecordSchema, Buffer.from(fixture.vectors[name].record_wire_hex, 'hex'));
    const outer = decode(record.canonicalRecord); const inner = decode(Uint8Array.from(outer.body.canonical)); mutate(inner);
    outer.body.canonical = Array.from(encode(inner)); record.canonicalRecord = encode(outer);
    record.signatures[0].signature = await signer.sign(Buffer.concat([Buffer.from('heddle-thread-operation-v1\0'), record.canonicalRecord]));
    await assert.rejects(verifyCollaboration(record));
  }
});

test('aggregate mention bytes are bounded in delivery and before signing', async () => {
  const maximal = create(SourceMentionSchema, { ...source(true), path: 'é'.repeat(2048), symbolId: 's'.repeat(4096) });
  const ref = create(EntityRefSchema, { entity: { case: 'source', value: maximal } });
  const mention = { kind: 'source', source: maximal };
  validateEntityMentions(Array(31).fill(ref));
  await signDiscussion({ ...command(open), mentions: [mention] }, [], signer);
  let calls = 0;
  const counting = { ...signer, sign: async bytes => { calls++; return signer.sign(bytes); } };
  for (const count of [32, 128]) {
    assert.throws(() => validateEntityMentions(Array(count).fill(ref)), /mention.*byte/i);
    await assert.rejects(signDiscussion({ ...command(open), mentions: Array(count).fill(mention) }, [], counting), /mention.*byte/i);
    await assert.rejects(signContext({ ...shared, contextId: '00000000-0000-0000-0000-000000000009', anchor: { kind: 'repository' }, content: 'Design rationale', tags: [], mentions: Array(count).fill(mention) }, [], counting), /mention.*byte/i);
  }
  assert.equal(calls, 0, 'aggregate bound is checked before invoking the signer');
});
