import { create, createFileRegistry, fromBinary, toBinary } from '@bufbuild/protobuf';
import { FileDescriptorSetSchema } from '@bufbuild/protobuf/wkt';
import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import { signContext, signDiscussion } from '../packages/typescript/dist/v1alpha2/collaboration.js';
import { decode, encode } from '../packages/typescript/dist/v1alpha2/_collaboration-msgpack.js';

const old = createFileRegistry(fromBinary(FileDescriptorSetSchema,
  readFileSync(new URL('./fixtures/saved-source-alpha16.binpb', import.meta.url))));
const hex = bytes => Buffer.from(bytes).toString('hex');
const vectors = [];
const add = (type, name, value, legacyValue) => {
  const schema = api[`${type}Schema`], legacy = old.getMessage(schema.typeName);
  vectors.push({ type, name, wire_hex: hex(toBinary(schema, create(schema, value))),
    legacy_wire_hex: hex(toBinary(legacy, create(legacy, legacyValue))) });
};
const stamp = (seconds, nanos = 0) => ({ seconds: BigInt(seconds), nanos });
const bookmark = (label = 'Saved', bookmarked = true, version = 1) => ({ ref: {
  account: { id: '00000000-0000-0000-0000-000000000003' }, target: { case: 'spool', value: { id: '00000000-0000-0000-0000-000000000001' } },
}, version: Uint8Array.of(version), label, bookmarked });
const saved = stamp(1780000000, 123456789);
for (const [name, base, times] of [
  ['legacy-saved', bookmark(), {}], ['never-saved', bookmark('', false, 0), {}],
  ['saved', bookmark(), { bookmarkedAt: saved, updatedAt: saved }],
  ['label-edit', bookmark('Renamed', true, 2), { bookmarkedAt: saved, updatedAt: stamp(1780000001) }],
  ['removed', bookmark('Renamed', false, 3), { bookmarkedAt: saved, updatedAt: stamp(1780000002) }],
  ['resaved', bookmark('Renamed', true, 4), { bookmarkedAt: stamp(1780000003), updatedAt: stamp(1780000003) }],
  ['legacy-label-edit', bookmark('Known update', true, 2), { updatedAt: stamp(1780000004) }],
  ['epoch-known', bookmark(), { bookmarkedAt: stamp(0), updatedAt: stamp(0) }],
]) add('BookmarkRecord', name, { ...base, ...times }, base);
const spoolId = '00000000-0000-0000-0000-000000000001';
const threadId = new Uint8Array(32).fill(2);
const source = (path = 'Makefile', oid = 'a'.repeat(40)) => ({ revision: { spool: { id: spoolId }, revision: { case: 'gitCommitOid', value: oid } },
  path, thread: { spool: { id: spoolId }, id: { value: threadId } } });
for (const [name, base, kind, provenance] of [
  ['source-legacy', source(), 0, 0], ['recorded-file', source(), 1, 1],
  ['recorded-directory', source('dir.with.dot'), 2, 1],
  ['derived-extensionless-file', source(), 1, 2], ['derived-dotted-directory', source('dir.with.dot'), 2, 2],
  ['authorized-missing', source('missing'), 0, 2], ['unknown-future-enums', source(), 77, 88],
]) add('SourceAnchor', name, { ...base, pathKind: kind, pathKindSource: provenance }, base);
const trees = { ['a'.repeat(40)]: { Makefile: 1, 'dir.with.dot': 2 }, ['b'.repeat(40)]: { Makefile: 2 } };
// Contract model only; actual tree lookup and content authorization are weft work.
const derive = ({ oid, path, readable, recorded = 0 }) => {
  if (!readable) return { pathKind: 0, pathKindSource: 0 };
  if (recorded) return { pathKind: recorded, pathKindSource: 1 };
  if (!trees[oid]) return { pathKind: 0, pathKindSource: 0 };
  return { pathKind: trees[oid][path] ?? 0, pathKindSource: 2 };
};
const derivation = [];
for (const [name, oid, path, readable, recorded] of [
  ['historical-file', 'a'.repeat(40), 'Makefile', true, 0],
  ['new-revision-directory', 'b'.repeat(40), 'Makefile', true, 0],
  ['missing-no-guess', 'a'.repeat(40), 'missing.rs', true, 0],
  ['unavailable-revision', 'c'.repeat(40), 'Makefile', true, 0],
  ['hidden-file', 'a'.repeat(40), 'Makefile', false, 0],
  ['hidden-directory', 'a'.repeat(40), 'dir.with.dot', false, 0],
  ['hidden-missing', 'a'.repeat(40), 'missing.rs', false, 0],
  ['hidden-recorded', 'a'.repeat(40), 'Makefile', false, 1],
]) {
  const input = { oid, path, readable, recorded }, result = derive(input);
  // Referents are redacted too, not just the classification. Identical wire
  // for hidden file, directory, missing and recorded cases is intentional.
  const base = readable ? source(path, oid) : {};
  add('SourceAnchor', name, { ...base, ...result }, base);
  derivation.push({ name, input, expected: result });
}
for (const [name, path, kind] of [['location-file', 'Makefile', 1], ['location-directory', 'dir.with.dot', 2], ['location-unknown', 'missing', 0]]) {
  const base = source(path);
  add('SourceLocation', name, { ...base, pathKind: kind }, base);
}
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]), format: 'der', type: 'pkcs8' });
const signer = { publicKey: new Uint8Array(createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32)), sign: async bytes => new Uint8Array(sign(null, bytes, key)) };
const context = { scope: { spoolId, threadId }, actor: { principalId: '00000000-0000-0000-0000-000000000003' }, occurredAtMs: 100n,
  contextId: '00000000-0000-0000-0000-000000000009', content: 'Source kind evidence', tags: [] };
const signed = [];
for (const carrier of ['context', 'discussion', 'tag', 'context-target']) for (const kind of [undefined, 'file', 'directory']) {
  const path = kind === 'directory' ? 'dir.with.dot' : 'Makefile';
  const anchor = { kind: 'source', revision: { kind: 'git_commit', oid: 'a'.repeat(40) }, path, pathKind: kind, ...(carrier === 'context-target' ? { target: create(api.SourceTargetReferenceSchema, { targetId: new Uint8Array(32).fill(6), binding: { case: 'viewedThread', value: true } }) } : {}) };
  const tags = carrier === 'tag' ? [create(api.AnnotationTagSchema, { tag: { case: 'source', value: { source: { ...source(path),
    pathKind: kind === 'file' ? 1 : kind === 'directory' ? 2 : 0, pathKindSource: kind ? 1 : 0 } } } })] : [];
  const record = carrier === 'discussion' ? await signDiscussion({ ...context, discussionId: 'disc-01980000-0000-7000-8000-000000000123', clientOperationId: 'source-kind', author: { name: 'Account' },
    action: { kind: 'open', blocking: false, title: 'Source kind', anchor, visibility: 'public', body: 'Review' } }, [], signer)
    : await signContext({ ...context, anchor: carrier === 'tag' ? { kind: 'repository' } : anchor, tags }, [], signer);
  const outer = decode(record.canonicalRecord), inner = decode(Uint8Array.from(outer.body.canonical));
  const evidence = carrier === 'tag' ? inner.tags[0].target.source : carrier === 'discussion' ? inner.body.anchor.source : inner.anchor.source;
  signed.push({ name: `${carrier}-${kind ?? 'omitted'}`, carrier, kind: kind ?? null, path,
    source_hex: hex(encode(evidence)), inner_hex: hex(Uint8Array.from(outer.body.canonical)), canonical_hex: hex(record.canonicalRecord),
    public_key_hex: hex(signer.publicKey), signature_hex: hex(record.signatures[0].signature) });
}
writeFileSync(new URL('./fixtures/saved-source-v1.json', import.meta.url), `${JSON.stringify({ baseline: 'd56cbd1c20e927ff0fb5f52a854c0074f0adf035', vectors, derivation, signed }, null, 2)}\n`);
console.log(`Saved/source vectors: ${vectors.length} wire, ${signed.length} signed`);
