// Run after npm run build to regenerate the shared Rust/TypeScript golden.
import { create, toBinary } from '@bufbuild/protobuf';
import { TimestampSchema } from '@bufbuild/protobuf/wkt';
import {
  AttentionItemSchema,
  SetAttentionStateRequestSchema,
} from '../packages/typescript/dist/v1alpha2/activity_pb.js';

const snoozedUntil = create(TimestampSchema, {
  seconds: 1_800_000_000n,
  nanos: 123_000_000,
});
const version = new Uint8Array([1, 2, 3]);
const item = create(AttentionItemSchema, {
  ref: { id: 'attn-1' },
  version,
  resolution: 1,
  pinned: true,
  snoozedUntil,
});
const setRequest = create(SetAttentionStateRequestSchema, {
  clientOperationId: 'op-snooze',
  item: { id: 'attn-1' },
  expectedVersion: version,
  resolution: 1,
  pinned: true,
  snooze: { case: 'snoozedUntil', value: snoozedUntil },
});
const clearRequest = create(SetAttentionStateRequestSchema, {
  clientOperationId: 'op-clear',
  item: { id: 'attn-1' },
  expectedVersion: version,
  resolution: 1,
  pinned: true,
  snooze: { case: 'clearSnooze', value: true },
});
const unchangedRequest = create(SetAttentionStateRequestSchema, {
  clientOperationId: 'op-pin',
  item: { id: 'attn-1' },
  expectedVersion: version,
  resolution: 1,
  pinned: true,
});

function wireHex(schema, message) {
  return Buffer.from(toBinary(schema, message)).toString('hex');
}

console.log(JSON.stringify({
  generated_by: 'node tests/generate-attention-snooze-fixture.mjs',
  item_id: 'attn-1',
  version_hex: '010203',
  resolution: 1,
  pinned: true,
  snoozed_until_seconds: 1800000000,
  snoozed_until_nanos: 123000000,
  set_client_operation_id: 'op-snooze',
  clear_client_operation_id: 'op-clear',
  unchanged_client_operation_id: 'op-pin',
  item_wire_hex: wireHex(AttentionItemSchema, item),
  set_wire_hex: wireHex(SetAttentionStateRequestSchema, setRequest),
  clear_wire_hex: wireHex(SetAttentionStateRequestSchema, clearRequest),
  unchanged_wire_hex: wireHex(SetAttentionStateRequestSchema, unchangedRequest),
}, null, 2));
