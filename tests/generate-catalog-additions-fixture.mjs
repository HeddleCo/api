import { create, createFileRegistry, fromBinary, toBinary } from '@bufbuild/protobuf';
import { FileDescriptorSetSchema } from '@bufbuild/protobuf/wkt';
import { readFileSync, writeFileSync } from 'node:fs';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';

const old = createFileRegistry(fromBinary(FileDescriptorSetSchema,
  readFileSync(new URL('./fixtures/catalog-additions-alpha16.binpb', import.meta.url))));
const hex = bytes => Buffer.from(bytes).toString('hex');
const vectors = [];
const add = (type, name, value, legacyValue) => {
  const wire = toBinary(api[`${type}Schema`], create(api[`${type}Schema`], value));
  const legacy = old.getMessage(`heddle.api.v1alpha2.${type}`);
  vectors.push({ type, name, wire_hex: hex(wire), ...(legacy ? {
    // Build independently from the old schema and old fields, not by stripping new wire.
    legacy_wire_hex: hex(toBinary(legacy, create(legacy, legacyValue))),
  } : {}) });
};
const base = { query: 'HeddleCo/Weft', spools: { size: 20, afterPage: new Uint8Array([1, 2, 3]) }, sort: 2 };
for (const [name, filter] of [
  ['absent', undefined], ['empty', {}], ['open', { hasOpenThreads: true }],
  ['landed', { landedWithin30d: true }], ['review', { requireReviewToLand: true }],
  ['prefix', { namespacePrefix: ['HeddleCo', 'Weft'] }],
  ['combined', { hasOpenThreads: true, landedWithin30d: true, requireReviewToLand: true, namespacePrefix: ['heddleco'] }],
  ['changed-filter-same-token', { namespacePrefix: ['another'] }],
]) add('ObserveCatalogRequest', name, { ...base, filter }, base);
add('ObserveCatalogRequest', 'changed-query-same-token', { ...base, query: 'another' }, { ...base, query: 'another' });
const frame = { sequence: 1n };
for (const [name, page] of [
  ['filtered-more', { matchingCount: 2n, nextPage: new Uint8Array([9]) }],
  ['filtered-exhausted', { matchingCount: 0n, exhausted: true }],
]) {
  const value = { frame, payload: { case: 'status', value: { section: 'spools', coverage: 1, page } } };
  add('CatalogEvent', name, value, value);
}
const leader = (id, count) => ({ ref: { id }, name: id, pathSegments: ['heddleco', id], count: BigInt(count) });
const asOf = { seconds: 1780000000n, nanos: 123456789 };
const exact = { spoolCount: 2n, openThreadCount: 7n, landed30d: 9n, active7d: 1n,
  mostOpen: [leader('spool-a', 4), leader('spool-b', 3)],
  mostLanded: [leader('spool-b', 7), leader('spool-a', 2)], asOf };
const event = (name, summary) => add('CatalogEvent', name, { frame, payload: { case: 'summary', value: summary } }, { frame });
event('exact', exact);
event('summary-empty', { asOf });
event('bounded-approximate', { spoolCount: 10001n, openThreadCount: 10000n, landed30d: 10000n, active7d: 10000n,
  mostOpen: [5, 4, 3, 2, 1].map(n => leader(`spool-${n}`, n)),
  mostLanded: [5, 4, 3, 2, 1].map(n => leader(`spool-${n}`, n)), asOf, approximate: true });
event('wide-counters', { spoolCount: 9007199254740993n, openThreadCount: 18446744073709551615n,
  landed30d: 9007199254740995n, active7d: 10000n, asOf, approximate: true });

// Explicit projection inputs: hidden activity outranks every public candidate
// if visibility is mistakenly applied after the aggregate or top-N selection.
const publicSpools = [
  { id: 'spool-a', visible: true, open: 4, landed: 2, last_activity_seconds: 1780000000 },
  { id: 'spool-b', visible: true, open: 3, landed: 7, last_activity_seconds: 1779000000 },
];
const privateSpool = { id: 'private-spool', visible: false, open: 999999, landed: 999999, last_activity_seconds: 1780000000 };
const project = rows => {
  const visible = rows.filter(row => row.visible);
  const top = key => visible.filter(row => row[key] > 0)
    .sort((a, b) => b[key] - a[key] || a.id.localeCompare(b.id)).slice(0, 5)
    .map(row => leader(row.id, row[key]));
  return { spoolCount: BigInt(visible.length), openThreadCount: BigInt(visible.reduce((n, row) => n + row.open, 0)),
    landed30d: BigInt(visible.reduce((n, row) => n + row.landed, 0)),
    active7d: BigInt(visible.filter(row => row.last_activity_seconds > Number(asOf.seconds) - 7 * 86400
      && row.last_activity_seconds <= Number(asOf.seconds)).length),
    mostOpen: top('open'), mostLanded: top('landed'), asOf };
};
event('outsider-before-private', project(publicSpools));
event('outsider-after-private', project([...publicSpools, privateSpool]));
const row = { frame, payload: { case: 'spool', value: { ref: { id: 'spool-a' }, name: 'Weft',
  pathSegments: ['heddleco', 'weft'], publicOwner: { handle: 'heddleco', displayName: 'HeddleCo' },
  catalogActivity: { openThreadCount: 4n, landed30d: 2n }, lastActivityAt: asOf } } };
add('CatalogEvent', 'existing-public-row', row, row);
writeFileSync(new URL('./fixtures/catalog-additions-v1.json', import.meta.url), JSON.stringify({
  baseline: '2858ab54ae00f827e290cc66579d1f4e42ab9b02',
  confidentiality: { before: publicSpools, after: [...publicSpools, privateSpool] }, vectors,
}, null, 2) + '\n');
