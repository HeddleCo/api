import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createFileRegistry, fromBinary, toBinary } from '@bufbuild/protobuf';
import { FileDescriptorSetSchema } from '@bufbuild/protobuf/wkt';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/catalog-additions-v1.json', import.meta.url)));
const old = createFileRegistry(fromBinary(FileDescriptorSetSchema,
  readFileSync(new URL('./fixtures/catalog-additions-alpha16.binpb', import.meta.url))));
const bytes = hex => new Uint8Array(Buffer.from(hex, 'hex'));
const vector = name => fixture.vectors.find(v => v.name === name);
const decode = v => fromBinary(api[`${v.type}Schema`], bytes(v.wire_hex));
const get = name => decode(vector(name));
const summary = name => {
  const value = get(name);
  assert.equal(value.payload.case, 'summary');
  return value.payload.value;
};

test('shared catalog wire vectors round trip byte-for-byte', () => {
  assert.equal(fixture.vectors.length, 18);
  for (const v of fixture.vectors) {
    assert.equal(Buffer.from(toBinary(api[`${v.type}Schema`], decode(v))).toString('hex'), v.wire_hex, v.name);
  }
});

test('filters preserve defaults, every predicate and ordered address prefix', () => {
  assert.equal(get('absent').filter, undefined);
  const empty = get('empty').filter;
  assert.equal(empty.hasOpenThreads, false);
  assert.equal(empty.landedWithin30d, false);
  assert.equal(empty.requireReviewToLand, false);
  assert.deepEqual(empty.namespacePrefix, []);
  assert.equal(get('open').filter.hasOpenThreads, true);
  assert.equal(get('landed').filter.landedWithin30d, true);
  assert.equal(get('review').filter.requireReviewToLand, true);
  assert.deepEqual(get('prefix').filter.namespacePrefix, ['HeddleCo', 'Weft']);
  const combined = get('combined');
  assert.equal(combined.filter.hasOpenThreads && combined.filter.landedWithin30d && combined.filter.requireReviewToLand, true);
  assert.equal(combined.query, 'HeddleCo/Weft');
  assert.equal(combined.sort, api.CatalogSort.PATH);
  assert.equal(combined.spools.size, 20);
  // These distinct binding inputs intentionally carry the same opaque token;
  // the server must reject reuse, rather than ignoring the changed predicate.
  for (const name of ['changed-filter-same-token', 'changed-query-same-token']) {
    assert.deepEqual(get(name).spools.afterPage, combined.spools.afterPage);
    assert.notDeepEqual(get(name), combined);
  }
});

test('filtered page metadata preserves exact counts and exhaustion separately', () => {
  const more = get('filtered-more').payload.value.page;
  assert.equal(more.matchingCount, 2n);
  assert.equal(more.exhausted, false);
  assert.deepEqual(more.nextPage, bytes('09'));
  const end = get('filtered-exhausted').payload.value.page;
  assert.equal(end.matchingCount, 0n);
  assert.equal(end.exhausted, true);
  assert.equal(end.nextPage.length, 0);
});

test('summary snapshots carry linkable leaders, empty results and bounded approximation', () => {
  const exact = summary('exact');
  assert.deepEqual([exact.spoolCount, exact.openThreadCount, exact.landed30d, exact.active7d], [2n, 7n, 9n, 1n]);
  assert.equal(exact.approximate, false);
  assert.equal(exact.asOf.seconds, 1780000000n);
  assert.equal(exact.asOf.nanos, 123456789);
  assert.deepEqual(exact.mostOpen.map(l => l.ref.id), ['spool-a', 'spool-b']);
  assert.deepEqual(exact.mostLanded.map(l => l.count), [7n, 2n]);
  assert.deepEqual(exact.mostOpen[0].pathSegments, ['heddleco', 'spool-a']);
  assert.equal(exact.mostOpen[0].name, 'spool-a');
  const empty = summary('summary-empty');
  assert.equal(empty.spoolCount, 0n);
  assert.deepEqual(empty.mostOpen, []);
  assert.deepEqual(empty.mostLanded, []);
  assert.ok(empty.asOf);
  const bounded = summary('bounded-approximate');
  assert.equal(bounded.approximate, true);
  assert.equal(bounded.spoolCount, 10001n);
  for (const list of [bounded.mostOpen, bounded.mostLanded]) {
    assert.equal(list.length, 5);
    assert.equal(new Set(list.map(l => l.ref.id)).size, list.length);
    assert.deepEqual(list.map(l => l.count), [5n, 4n, 3n, 2n, 1n]);
  }
});

test('summary counters retain uint64 precision', () => {
  const wide = summary('wide-counters');
  assert.equal(wide.spoolCount, 9007199254740993n);
  assert.equal(wide.openThreadCount, 18446744073709551615n);
  assert.equal(wide.landed30d, 9007199254740995n);
});

test('adding a high-activity private spool leaves the outsider summary identical', () => {
  assert.equal(fixture.confidentiality.after.length, fixture.confidentiality.before.length + 1);
  const hidden = fixture.confidentiality.after.at(-1);
  assert.equal(hidden.visible, false);
  assert.ok(hidden.open > 7 && hidden.landed > 9);
  assert.equal(vector('outsider-before-private').wire_hex, vector('outsider-after-private').wire_hex);
  const result = summary('outsider-after-private');
  assert.deepEqual(result, summary('exact'));
  assert.equal(result.spoolCount, 2n);
  for (const list of [result.mostOpen, result.mostLanded]) {
    assert.ok(list.every(l => l.ref.id !== hidden.id));
  }
});

test('frozen alpha.16 readers keep old fields and skip the new summary payload', () => {
  for (const v of fixture.vectors) {
    const current = api[`${v.type}Schema`];
    const legacy = old.getMessage(current.typeName);
    const value = fromBinary(legacy, bytes(v.wire_hex), { readUnknownFields: false });
    const wire = toBinary(legacy, value, { writeUnknownFields: false });
    assert.equal(Buffer.from(wire).toString('hex'), v.legacy_wire_hex, v.name);
    const reread = fromBinary(current, wire);
    if (v.type === 'ObserveCatalogRequest') {
      assert.equal(reread.filter, undefined);
      const { filter, ...existing } = decode(v);
      assert.deepEqual(reread, existing);
    } else {
      assert.deepEqual(reread.frame, decode(v).frame);
      if (decode(v).payload.case === 'summary') assert.equal(reread.payload.case, undefined);
      else assert.deepEqual(reread, decode(v));
    }
  }
});
