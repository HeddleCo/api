import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { SectionStatusSchema, SectionStatusReason } from '../packages/typescript/dist/v1alpha2/index.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/section-status-reasons.json', import.meta.url)));

test('section status reasons match the shared Rust/TypeScript wire contract', () => {
  assert.deepEqual(
    Object.values(SectionStatusReason).filter(value => typeof value === 'number'),
    [0, 1, 2, 3, 4],
  );
  for (const vector of fixture.vectors) {
    const wire = Buffer.from(vector.wire_hex, 'hex');
    const status = create(SectionStatusSchema, {
      section: 'review', coverage: vector.coverage, reason: vector.reason,
    });
    assert.deepEqual(fromBinary(SectionStatusSchema, wire), status, vector.name);
    assert.equal(Buffer.from(toBinary(SectionStatusSchema, status)).toString('hex'), vector.wire_hex, vector.name);
    if (vector.reason_name) {
      const name = vector.reason_name.replace('SECTION_STATUS_REASON_', '');
      assert.equal(SectionStatusReason[name], vector.reason, vector.name);
    }
  }
});

test('older server statuses default to unspecified without changing coverage', () => {
  for (const coverage of [3, 6]) {
    const wire = Buffer.from(`0a0672657669657710${coverage.toString(16).padStart(2, '0')}`, 'hex');
    const status = fromBinary(SectionStatusSchema, wire);
    assert.equal(status.coverage, coverage);
    assert.equal(status.reason, SectionStatusReason.UNSPECIFIED);
    assert.deepEqual(Buffer.from(toBinary(SectionStatusSchema, status)), wire);
  }
  assert.equal(create(SectionStatusSchema).reason, SectionStatusReason.UNSPECIFIED);
});
