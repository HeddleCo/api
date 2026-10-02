import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { create, createFileRegistry, fromBinary, toBinary } from '@bufbuild/protobuf';
import { FileDescriptorSetSchema } from '@bufbuild/protobuf/wkt';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import { signContext, signDiscussion, verifyCollaboration, sourceTargetReference } from '../packages/typescript/dist/v1alpha2/collaboration.js';
import { decode, encode } from '../packages/typescript/dist/v1alpha2/_collaboration-msgpack.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/saved-source-v1.json', import.meta.url)));
const old = createFileRegistry(fromBinary(FileDescriptorSetSchema, readFileSync(new URL('./fixtures/saved-source-alpha16.binpb', import.meta.url))));
const bytes = hex => new Uint8Array(Buffer.from(hex, 'hex'));
const vector = name => fixture.vectors.find(v => v.name === name);
const get = name => { const v = vector(name); return fromBinary(api[`${v.type}Schema`], bytes(v.wire_hex)); };
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]), format: 'der', type: 'pkcs8' });
const signer = { publicKey: new Uint8Array(createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32)), sign: async bytes => new Uint8Array(sign(null, bytes, key)) };
const context = { scope: { spoolId: '00000000-0000-0000-0000-000000000001', threadId: new Uint8Array(32).fill(2) }, actor: { principalId: '00000000-0000-0000-0000-000000000003' },
  occurredAtMs: 100n, contextId: '00000000-0000-0000-0000-000000000009', content: 'Source kind evidence', tags: [] };
const record = v => create(api.SignedRecordSchema, { format: 'heddle-thread-operation-v1', canonicalRecord: bytes(v.canonical_hex),
  signatures: [{ publicKey: bytes(v.public_key_hex), signature: bytes(v.signature_hex) }] });
const evidence = (v, inner) => v.carrier === 'tag' ? inner.tags[0].target.source : v.carrier === 'discussion' ? inner.body.anchor.source : inner.anchor.source;

// These expectations are independent of the generator's result table.
test('26 shared wire vectors round trip with older-reader field preservation', () => {
  assert.equal(fixture.vectors.length, 26);
  for (const v of fixture.vectors) {
    const schema = api[`${v.type}Schema`];
    assert.equal(Buffer.from(toBinary(schema, get(v.name))).toString('hex'), v.wire_hex, v.name);
    const legacy = old.getMessage(schema.typeName);
    const wire = toBinary(legacy, fromBinary(legacy, bytes(v.wire_hex), { readUnknownFields: false }), { writeUnknownFields: false });
    assert.equal(Buffer.from(wire).toString('hex'), v.legacy_wire_hex, v.name);
    const current = get(v.name), reread = fromBinary(schema, wire);
    if (v.type === 'BookmarkRecord') {
      assert.equal(reread.bookmarkedAt, undefined); assert.equal(reread.updatedAt, undefined);
      const { bookmarkedAt, updatedAt, ...existing } = current;
      assert.deepEqual(reread, existing);
    } else {
      assert.equal(reread.pathKind, 0);
      const existing = { ...current, pathKind: 0 };
      if (v.type === 'SourceAnchor') { existing.pathKindSource = 0; assert.equal(reread.pathKindSource, 0); }
      assert.deepEqual(reread, existing);
    }
  }
});

test('bookmark times preserve save identity through edits and removal, with a new re-save interval', () => {
  const saved = get('saved'), edited = get('label-edit'), removed = get('removed'), resaved = get('resaved');
  assert.deepEqual(saved.bookmarkedAt, { $typeName: 'google.protobuf.Timestamp', seconds: 1780000000n, nanos: 123456789 });
  assert.deepEqual(saved.updatedAt, saved.bookmarkedAt);
  for (const row of [edited, removed]) assert.deepEqual(row.bookmarkedAt, saved.bookmarkedAt);
  assert.equal(edited.updatedAt.seconds, 1780000001n);
  assert.equal(removed.updatedAt.seconds, 1780000002n);
  assert.equal(removed.bookmarked, false);
  assert.equal(resaved.bookmarkedAt.seconds, 1780000003n);
  assert.deepEqual(resaved.updatedAt, resaved.bookmarkedAt);
  for (const name of ['legacy-saved', 'never-saved']) {
    assert.equal(get(name).bookmarkedAt, undefined); assert.equal(get(name).updatedAt, undefined);
  }
  assert.equal(get('legacy-label-edit').bookmarkedAt, undefined);
  assert.equal(get('legacy-label-edit').updatedAt.seconds, 1780000004n);
  assert.equal(get('epoch-known').bookmarkedAt.seconds, 0n);
});

test('recorded/derived/unknown enums and current-location projections remain distinct', () => {
  for (const [name, kind, source] of [['recorded-file', 1, 1], ['recorded-directory', 2, 1], ['derived-extensionless-file', 1, 2], ['derived-dotted-directory', 2, 2], ['authorized-missing', 0, 2], ['source-legacy', 0, 0], ['unknown-future-enums', 77, 88]]) {
    assert.deepEqual([get(name).pathKind, get(name).pathKindSource], [kind, source]);
  }
  for (const [name, kind] of [['location-file', 1], ['location-directory', 2], ['location-unknown', 0]]) assert.equal(get(name).pathKind, kind);
});

test('derivation is exact-revision based and hidden file/directory/missing/recorded projections are identical', () => {
  assert.equal(get('historical-file').pathKind, 1);
  assert.equal(get('new-revision-directory').pathKind, 2);
  assert.notDeepEqual(get('historical-file').revision, get('new-revision-directory').revision);
  assert.deepEqual([get('missing-no-guess').pathKind, get('missing-no-guess').pathKindSource], [0, 2]);
  assert.deepEqual([get('unavailable-revision').pathKind, get('unavailable-revision').pathKindSource], [0, 0]);
  for (const name of ['hidden-file', 'hidden-directory', 'hidden-missing', 'hidden-recorded']) {
    assert.equal(vector(name).wire_hex, '');
    assert.equal(get(name).revision, undefined);
    assert.equal(get(name).path, '');
    assert.deepEqual([get(name).pathKind, get(name).pathKindSource], [0, 0]);
  }
});

test('all 12 signed vectors verify and encode the optional final key without provenance', async () => {
  assert.equal(fixture.signed.length, 12);
  for (const v of fixture.signed) {
    const anchor = { kind: 'source', revision: { kind: 'git_commit', oid: 'a'.repeat(40) }, path: v.path, pathKind: v.kind ?? undefined,
      ...(v.carrier === 'context-target' ? { target: create(api.SourceTargetReferenceSchema, { targetId: new Uint8Array(32).fill(6), binding: { case: 'viewedThread', value: true } }) } : {}) };
    const tags = v.carrier === 'tag' ? [create(api.AnnotationTagSchema, { tag: { case: 'source', value: { source: {
      revision: { spool: { id: context.scope.spoolId }, revision: { case: 'gitCommitOid', value: 'a'.repeat(40) } }, path: v.path,
      thread: { spool: { id: context.scope.spoolId }, id: { value: context.scope.threadId } },
      pathKind: v.kind === 'file' ? 1 : v.kind === 'directory' ? 2 : 0, pathKindSource: v.kind ? 1 : 0,
    } } } })] : [];
    const actual = v.carrier === 'discussion' ? await signDiscussion({ ...context,
      discussionId: 'disc-01980000-0000-7000-8000-000000000123', clientOperationId: 'source-kind', author: { name: 'Account' },
      action: { kind: 'open', blocking: false, title: 'Source kind', anchor, visibility: 'public', body: 'Review' } }, [], signer)
      : await signContext({ ...context, anchor: v.carrier === 'tag' ? { kind: 'repository' } : anchor, tags }, [], signer);
    assert.equal(Buffer.from(actual.canonicalRecord).toString('hex'), v.canonical_hex, v.name);
    assert.equal(Buffer.from(actual.signatures[0].signature).toString('hex'), v.signature_hex, v.name);
    const verified = await verifyCollaboration(record(v));
    assert.equal(Buffer.from(verified.canonicalContent).toString('hex'), v.inner_hex);
    const source = evidence(v, decode(verified.canonicalContent));
    assert.equal(Buffer.from(encode(source)).toString('hex'), v.source_hex);
    assert.deepEqual(Object.keys(source), ['revision', 'path', 'symbol_id', 'start_line', 'end_line', ...(v.carrier === 'context-target' ? ['target'] : []), ...(v.kind ? ['path_kind'] : [])]);
    assert.equal(source.path_kind, v.kind ?? undefined);
    assert.equal(Object.hasOwn(source, 'path_kind_source'), false);
  }
});

test('changing a recorded kind invalidates the signature; signed malformed extensions are refused', async () => {
  const v = fixture.signed.find(v => v.name === 'context-file');
  const mutate = async (change, resign) => {
    const altered = record(v), outer = decode(altered.canonicalRecord), inner = decode(Uint8Array.from(outer.body.canonical));
    change(inner.anchor.source);
    outer.body.canonical = Array.from(encode(inner)); altered.canonicalRecord = encode(outer);
    if (resign) altered.signatures[0].signature = await signer.sign(Buffer.concat([Buffer.from('heddle-thread-operation-v1\0'), altered.canonicalRecord]));
    return altered;
  };
  await assert.rejects(verifyCollaboration(await mutate(s => { s.path_kind = 'directory'; }, false)), /Invalid collaboration author signature/);
  for (const invalid of [null, 0, 'unspecified', 'symlink']) {
    await assert.rejects(verifyCollaboration(await mutate(s => { s.path_kind = invalid; }, true)), /Invalid recorded source path kind/);
  }
  await assert.rejects(verifyCollaboration(await mutate(s => { s.path_kind_source = 'derived'; }, true)), /Noncanonical/);
  await assert.rejects(verifyCollaboration(await mutate(s => { s.path_kind = 'directory'; s.start_line = 1; }, true)), /Invalid recorded source path kind coordinates/);
  await assert.rejects(verifyCollaboration(await mutate(s => { const kind = s.path_kind; delete s.path_kind; const revision = s.revision; delete s.revision; s.path_kind = kind; s.revision = revision; }, true)), /Noncanonical/);
});

test('derived annotation metadata cannot be signed and kind does not change target identity', async () => {
  let calls = 0;
  const counting = { ...signer, sign: b => { calls++; return signer.sign(b); } };
  const tag = source => create(api.AnnotationTagSchema, { tag: { case: 'source', value: { source } } });
  for (const name of ['derived-extensionless-file', 'authorized-missing', 'unknown-future-enums']) {
    await assert.rejects(signContext({ ...context, anchor: { kind: 'repository' }, tags: [tag(get(name))] }, [], counting), /Derived|Unknown/);
  }
  await assert.rejects(signContext({ ...context, anchor: { kind: 'repository' }, tags: [tag({ ...get('recorded-file'), pathKindSource: 0 })] }, [], counting), /requires provenance/);
  await assert.rejects(signContext({ ...context, anchor: { kind: 'repository' }, tags: [tag({ ...get('recorded-file'), pathKind: 0 })] }, [], counting), /must be known/);
  assert.equal(calls, 0);
  const binding = { case: 'viewedThread', value: true };
  assert.deepEqual(sourceTargetReference(get('derived-extensionless-file'), binding).targetId, sourceTargetReference(get('recorded-file'), binding).targetId);
  assert.deepEqual(sourceTargetReference(get('source-legacy'), binding).targetId, sourceTargetReference(get('recorded-file'), binding).targetId);
});

test('new primary kind inputs reject unknown values and invalid directory coordinates before signing', async () => {
  let calls = 0;
  const counting = { ...signer, sign: b => { calls++; return signer.sign(b); } };
  const base = { kind: 'source', revision: { kind: 'git_commit', oid: 'a'.repeat(40) }, path: 'Makefile' };
  for (const fields of [{ pathKind: 'unspecified' }, { pathKind: null }, { pathKind: 'directory', startLine: 1 }, { pathKind: 'directory', symbolId: 'f' }, { pathKind: 'file', path: '' }]) {
    await assert.rejects(signContext({ ...context, anchor: { ...base, ...fields } }, [], counting), /Invalid recorded/);
  }
  assert.equal(calls, 0);
});
