import assert from 'node:assert/strict';
import { test } from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { ContentReadSchema, ContentEventSchema, OutlineReadSchema, OutlineSymbolSchema } from '../packages/typescript/dist/v1alpha2/content_pb.js';
import { Coverage, SectionStatusReason, SectionStatusSchema } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import { validateOutlineRead, validateOutlineSymbol, validateOutlineStatus } from '../packages/typescript/dist/v1alpha2/content.js';
import { SymbolKind, SymbolKindSchema } from '../packages/typescript/dist/common/repository_pb.js';
const revision = { spool: { id: '00000000-0000-0000-0000-000000000001' }, revision: { case: 'gitCommitOid', value: 'a'.repeat(40) } };
test('exact-revision paged outline selections and symbol rows round trip', () => {
  const read = create(OutlineReadSchema, { path: 'src/main.rs', page: { size: 100 } }); validateOutlineRead(read);
  const selection = create(ContentReadSchema, { selectionId: 'file-outline', selection: { case: 'outline', value: read } });
  assert.deepEqual(fromBinary(ContentReadSchema, toBinary(ContentReadSchema, selection)), selection);
  const symbol = create(OutlineSymbolSchema, { name: 'run', kind: 1, container: 'App', symbolId: 'App::run', startLine: 12, endLine: 18 }); validateOutlineSymbol(symbol);
  const row = create(ContentEventSchema, { selectionId: selection.selectionId, revision, payload: { case: 'outlineSymbol', value: symbol } });
  assert.deepEqual(fromBinary(ContentEventSchema, toBinary(ContentEventSchema, row)), row);
  for (const [coverage, reason] of [[Coverage.COMPLETE, SectionStatusReason.UNSPECIFIED], [Coverage.PARTIAL, SectionStatusReason.COVERAGE_INCOMPLETE], [Coverage.UNAVAILABLE, SectionStatusReason.COVERAGE_INCOMPLETE]]) {
    const status = create(SectionStatusSchema, { section: 'outline', computedFor: revision, coverage, reason, page: { exhausted: coverage === Coverage.UNAVAILABLE, nextPage: coverage === Coverage.UNAVAILABLE ? new Uint8Array() : new Uint8Array([1]) } }); validateOutlineStatus(status);
  }
});
test('outline bounds and coverage cannot claim an unavailable index is a complete empty file', () => {
  for (const path of ['', '/main.rs', '../main.rs', 'src//main.rs', 'é'.repeat(2049)]) assert.throws(() => validateOutlineRead(create(OutlineReadSchema, { path })));
  assert.throws(() => validateOutlineRead(create(OutlineReadSchema, { path: 'main.rs', page: { size: 257 } })));
  const symbol = create(OutlineSymbolSchema, { name: 'run', kind: 1, symbolId: 'run', startLine: 1, endLine: 2 });
  for (const patch of [{ startLine: 0 }, { endLine: 0 }, { symbolId: '' }, { symbolId: 's'.repeat(4097) }, { name: 'é'.repeat(2049) }, { kind: 0 }]) assert.throws(() => validateOutlineSymbol(create(OutlineSymbolSchema, { ...symbol, ...patch })));
  for (const patch of [{ coverage: Coverage.UNAVAILABLE }, { reason: SectionStatusReason.COVERAGE_INCOMPLETE }, { computedFor: undefined }, { page: { exhausted: true, nextPage: new Uint8Array([1]) } }]) {
    assert.throws(() => validateOutlineStatus(create(SectionStatusSchema, { section: 'outline', computedFor: revision, coverage: Coverage.COMPLETE, page: { exhausted: true }, ...patch })));
  }
});

test('outline kinds follow the generated enum and reject unspecified or unknown numbers', () => {
  const symbol = { name: 'run', symbolId: 'run', startLine: 1, endLine: 2 };
  for (const value of SymbolKindSchema.values) {
    const row = create(OutlineSymbolSchema, { ...symbol, kind: value.number });
    if (value.number === SymbolKind.UNSPECIFIED) assert.throws(() => validateOutlineSymbol(row));
    else validateOutlineSymbol(row);
  }
  for (const kind of [-1, 1.5, 2147483647]) assert.throws(() => validateOutlineSymbol(create(OutlineSymbolSchema, { ...symbol, kind })));
});
