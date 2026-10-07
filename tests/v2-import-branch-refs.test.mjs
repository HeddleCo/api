import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { create } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as authority from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { signingDigest } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/import-branch-refs-v1.json', import.meta.url)));
const bytes = (n, length) => new Uint8Array(length).fill(n);
const branch = refName => create(api.ImportBranchLimitV1Schema, { refName, hashAlgorithm: 1, refMode: 1,
  pinnedCommitOid: bytes(1, 20), genesisDigest: bytes(2, 32), targetThreadId: bytes(3, 32),
  expectedFrontierDigest: bytes(4, 32), slotId: 1n });
const manifest = refs => create(api.ImportResultManifestV1Schema, { formatVersion: 1,
  logicalJobId: bytes(5, 16), retryLineageId: bytes(6, 16), slots: refs.map(refName => ({ refName,
    slotId: 1n, signedOperationDigest: bytes(7, 32), resultingFrontierDigest: bytes(8, 32), resultBytes: 1n })) });
const scope = refs => create(api.ImportPermissionScopeV1Schema, { provider: 'public-git', sourceUrl: 'https://example.com/repo.git',
  branches: refs.map((ref, i) => ({ ...branch(ref), genesisDigest: bytes(i, 32), targetThreadId: bytes(i, 32) })),
  destinationVersion: bytes(9, 32), optionsDigest: bytes(10, 32), converterVersion: '1', maxOperations: refs.length, maxResultBytes: 100n });
const hex = value => Buffer.from(value).toString('hex');
const rejects = reason => error => error instanceof authority.HybridContractError && error.reason === reason;

for (const v of fixture.vectors) test(`shared Git branch ref: ${v.id}`, () => {
  const name = v.ref_name + (v.repeat ?? '').repeat(v.repeat_count ?? 0);
  assert.equal(Buffer.byteLength(name), v.utf8_bytes);
  for (const validate of [() => authority.validateImportRefSelection(branch(name)),
    () => authority.validateImportScope(scope([name])), () => authority.validateImportManifest(manifest([name]))]) {
    if (v.expected === 'PASS') validate();
    else assert.throws(validate, rejects(v.expected));
  }
  if (v.expected === 'PASS') {
    const canonical = authority.canonicalHybridV1(api.ImportBranchLimitV1Schema, branch(name));
    assert.equal(new DataView(canonical.buffer, canonical.byteOffset).getUint32(0), v.utf8_bytes);
    assert.deepEqual(Buffer.from(canonical.slice(4, 4 + v.utf8_bytes)), Buffer.from(name));
    assert.equal(hex(signingDigest('heddle-import-branch-conformance-v1', api.ImportBranchLimitV1Schema, branch(name))), v.canonical_digest_hex);
  }
});

test('shared UTF-8 byte ordering and exact manifest digest', () => {
  const refs = fixture.ordered_refs;
  authority.validateImportScope(scope(refs));
  const m = manifest(refs);
  authority.validateImportManifest(m);
  assert.equal(hex(authority.manifestDigest(m)), fixture.manifest_digest_hex);
  const wrong = [...refs];
  [wrong[3], wrong[4]] = [wrong[4], wrong[3]];
  assert.throws(() => authority.validateImportScope(scope(wrong)), rejects('Canonical'));
  assert.throws(() => authority.validateImportManifest(manifest(wrong)), rejects('Canonical'));
});

for (const name of ['refs/heads/\ud800', 'refs/heads/\udfff']) test('unpaired surrogate is refused without replacement', () => {
  assert.throws(() => authority.validateImportRefSelection(branch(name)), rejects('Canonical'));
  assert.throws(() => authority.validateImportManifest(manifest([name])), rejects('Canonical'));
  assert.throws(() => authority.canonicalHybridV1(api.ImportBranchLimitV1Schema, branch(name)), rejects('Canonical'));
});
