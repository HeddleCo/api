import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { TimestampSchema } from '@bufbuild/protobuf/wkt';
import {
  AttentionItemSchema,
  SetAttentionStateRequestSchema,
} from '../packages/typescript/dist/v1alpha2/activity_pb.js';

function assertWire(schema, message, wireHex) {
  const wire = Buffer.from(wireHex, 'hex');
  assert.equal(Buffer.from(toBinary(schema, message)).toString('hex'), wireHex);
  const decoded = fromBinary(schema, wire);
  assert.equal(Buffer.from(toBinary(schema, decoded)).toString('hex'), wireHex);
  return decoded;
}

test('attention snooze matches the Rust/TypeScript golden in both directions', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/attention-snooze.json', import.meta.url)));
  const version = Uint8Array.from(Buffer.from(fixture.version_hex, 'hex'));
  const snoozedUntil = create(TimestampSchema, {
    seconds: BigInt(fixture.snoozed_until_seconds),
    nanos: fixture.snoozed_until_nanos,
  });
  const item = create(AttentionItemSchema, {
    ref: { id: fixture.item_id },
    version,
    resolution: fixture.resolution,
    pinned: fixture.pinned,
    snoozedUntil,
  });
  const decodedItem = assertWire(AttentionItemSchema, item, fixture.item_wire_hex);
  assert.equal(decodedItem.ref.id, fixture.item_id);
  assert.equal(Buffer.from(decodedItem.version).toString('hex'), fixture.version_hex);
  assert.equal(decodedItem.resolution, fixture.resolution);
  assert.equal(decodedItem.pinned, fixture.pinned);
  assert.equal(decodedItem.snoozedUntil.seconds, snoozedUntil.seconds);
  assert.equal(decodedItem.snoozedUntil.nanos, snoozedUntil.nanos);
  const legacy = create(AttentionItemSchema, {
    ref: { id: fixture.item_id },
    version,
    resolution: fixture.resolution,
    pinned: fixture.pinned,
  });
  assert.equal(legacy.snoozedUntil, undefined);
  assert.equal(fromBinary(AttentionItemSchema, toBinary(AttentionItemSchema, legacy)).snoozedUntil, undefined);

  const setRequest = create(SetAttentionStateRequestSchema, {
    clientOperationId: fixture.set_client_operation_id,
    item: { id: fixture.item_id },
    expectedVersion: version,
    resolution: fixture.resolution,
    pinned: fixture.pinned,
    snooze: { case: 'snoozedUntil', value: snoozedUntil },
  });
  const decodedSet = assertWire(SetAttentionStateRequestSchema, setRequest, fixture.set_wire_hex);
  assert.equal(decodedSet.snooze.case, 'snoozedUntil');
  assert.equal(decodedSet.snooze.value.seconds, snoozedUntil.seconds);
  assert.equal(decodedSet.snooze.value.nanos, snoozedUntil.nanos);
  assert.equal(decodedSet.clientOperationId, fixture.set_client_operation_id);
  assert.equal(decodedSet.pinned, fixture.pinned);

  const clearRequest = create(SetAttentionStateRequestSchema, {
    clientOperationId: fixture.clear_client_operation_id,
    item: { id: fixture.item_id },
    expectedVersion: version,
    resolution: fixture.resolution,
    pinned: fixture.pinned,
    snooze: { case: 'clearSnooze', value: true },
  });
  const decodedClear = assertWire(SetAttentionStateRequestSchema, clearRequest, fixture.clear_wire_hex);
  assert.equal(decodedClear.snooze.case, 'clearSnooze');
  assert.equal(decodedClear.snooze.value, true);
  assert.equal(decodedClear.pinned, fixture.pinned);

  const unchanged = create(SetAttentionStateRequestSchema, {
    clientOperationId: fixture.unchanged_client_operation_id,
    item: { id: fixture.item_id },
    expectedVersion: version,
    resolution: fixture.resolution,
    pinned: fixture.pinned,
  });
  const decodedUnchanged = assertWire(SetAttentionStateRequestSchema, unchanged, fixture.unchanged_wire_hex);
  assert.equal(unchanged.snooze.case, undefined);
  assert.equal(decodedUnchanged.snooze.case, undefined);
  assert.equal(decodedUnchanged.resolution, fixture.resolution);
  assert.equal(decodedUnchanged.pinned, fixture.pinned);
  assert.notEqual(fixture.set_wire_hex, fixture.clear_wire_hex);
  assert.notEqual(fixture.set_wire_hex, fixture.unchanged_wire_hex);
});
