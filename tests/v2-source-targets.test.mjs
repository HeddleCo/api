import assert from 'node:assert/strict';
import { test } from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { SourceTargetResolutionKeySchema, SourceTargetResolutionEventSchema, SourceTargetResolution_Status as Status, CollaborationEventSchema } from '../packages/typescript/dist/v2alpha1/collaboration_pb.js';
import { ThreadEventSchema, SpoolEventSchema } from '../packages/typescript/dist/v2alpha1/views_pb.js';
import { StreamDataKind } from '../packages/typescript/dist/v2alpha1/stream_pb.js';
import { sourceTargetResolutionKey, applySourceTargetResolution } from '../packages/typescript/dist/v2alpha1/source-targets.js';

const spool = { id: '00000000-0000-0000-0000-000000000001' };
const thread = byte => ({ spool, id: { value: new Uint8Array(32).fill(byte) } });
const revision = byte => ({ spool, revision: { case: 'state', value: { value: new Uint8Array(32).fill(byte) } } });
const key = (binding = { case: 'viewedThread', value: true }, viewedThread = binding.case === 'viewedThread' ? thread(2) : undefined) => create(SourceTargetResolutionKeySchema, {
  reference: { targetId: new Uint8Array(32).fill(3), binding }, viewedThread,
});
const upsert = (overrides = {}) => create(SourceTargetResolutionEventSchema, { change: { case: 'upsert', value: {
  key: key(), computedFor: revision(4), status: Status.RESOLVED,
  location: { thread: thread(2), revision: revision(4), path: 'src/renamed.rs', startLine: 8, endLine: 10 }, ...overrides,
} } });

test('one shared target moves atomically while fork and binding identities stay distinct', () => {
  const map = new Map();
  const first = upsert();
  applySourceTargetResolution(map, first, StreamDataKind.SNAPSHOT);
  const id = sourceTargetResolutionKey(first.change.value.key);
  const moved = upsert({ computedFor: revision(5), location: { thread: thread(2), revision: revision(5), path: 'lib/moved.rs' } });
  applySourceTargetResolution(map, moved, StreamDataKind.UPSERT);
  assert.equal(map.size, 1);
  assert.equal(map.get(id).location.path, 'lib/moved.rs');
  assert.equal(first.change.value.location.path, 'src/renamed.rs', 'updates do not mutate authored or prior views');
  moved.change.value.location.path = 'mutated-input.rs';
  assert.equal(map.get(id).location.path, 'lib/moved.rs', 'map owns its staged value');
  assert.notEqual(id, sourceTargetResolutionKey(key({ case: 'viewedThread', value: true }, thread(9))));
  assert.notEqual(id, sourceTargetResolutionKey(key({ case: 'namedThread', value: thread(2) }, undefined)));
  const pinned = byte => key({ case: 'pinnedRevision', value: { thread: thread(2), revision: revision(byte) } }, undefined);
  assert.notEqual(sourceTargetResolutionKey(pinned(4)), sourceTargetResolutionKey(pinned(5)));
  const remove = create(SourceTargetResolutionEventSchema, { change: { case: 'remove', value: first.change.value.key } });
  assert.throws(() => applySourceTargetResolution(map, remove, StreamDataKind.UPSERT));
  assert.equal(map.size, 1);
  applySourceTargetResolution(map, remove, StreamDataKind.REMOVE);
  assert.equal(map.size, 0);
});

test('inaccessible source coordinates and malformed current bindings never enter the map', () => {
  const map = new Map();
  applySourceTargetResolution(map, upsert(), StreamDataKind.SNAPSHOT);
  const original = structuredClone(map);
  const cases = [
    upsert({ status: Status.UNAVAILABLE }),
    upsert({ status: Status.DELETED }),
    upsert({ status: Status.UNSPECIFIED, location: undefined }),
    upsert({ computedFor: revision(8) }),
    upsert({ location: { thread: thread(9), revision: revision(4), path: 'src/a.rs' } }),
    upsert({ location: { thread: thread(2), revision: revision(4), path: '../a.rs' } }),
    upsert({ location: { thread: thread(2), revision: revision(4), path: 'a.rs', startLine: 0, endLine: 2 } }),
    upsert({ key: key({ case: 'namedThread', value: thread(2) }, thread(2)) }),
    upsert({ key: key({ case: 'viewedThread', value: false }) }),
  ];
  for (const event of cases) {
    assert.throws(() => applySourceTargetResolution(map, event, StreamDataKind.UPSERT));
    assert.deepEqual(map, original, 'invalid event cannot partly mutate committed data');
  }
  const missing = upsert({ status: Status.UNAVAILABLE, computedFor: undefined, location: undefined });
  applySourceTargetResolution(map, missing, StreamDataKind.UPSERT);
  assert.equal(map.values().next().value.location, undefined);
  for (const status of [Status.AMBIGUOUS, Status.DELETED]) {
    applySourceTargetResolution(map, upsert({ status, location: undefined }), StreamDataKind.UPSERT);
    assert.equal(map.values().next().value.status, status);
  }
});

test('Thread, Spool and collaboration streams carry the same shared target event losslessly', () => {
  for (const schema of [ThreadEventSchema, SpoolEventSchema, CollaborationEventSchema]) {
    for (const event of [upsert(), create(SourceTargetResolutionEventSchema, { change: { case: 'remove', value: key() } })]) {
      const value = create(schema, { payload: { case: 'sourceTarget', value: event } });
      assert.deepEqual(fromBinary(schema, toBinary(schema, value)), value);
    }
  }
});
