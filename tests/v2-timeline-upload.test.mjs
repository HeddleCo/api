import assert from 'node:assert/strict';
import { test } from 'node:test';
import { create } from '@bufbuild/protobuf';
import { OperationRecord_State, RecordRefSchema, SpoolRefSchema, ThreadIdSchema, ThreadRefSchema } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import {
  TimelineAdmissionAcceptanceSchema, TimelineOriginCredentialClass, TimelineOriginEndorsementSchema, UploadRunSummarySchema,
  UploadScrubbedTimelineRequestSchema, UploadTimelineEventKind, UploadTimelineEventSchema,
  UploadTimelineTool,
} from '../packages/typescript/dist/v1alpha2/timeline_upload_pb.js';
import {
  MAX_TIMELINE_EVENT_BYTES, MAX_TIMELINE_REQUEST_BYTES, MAX_TIMELINE_SNAPSHOT_BYTES,
  timelineAcceptanceSigningBytes, timelineLogicalRequestDigest, timelineOriginDigest, timelineOriginSigningBytes,
  validAgentLabel, validCanonicalUuid, validRunId, validVerifiedAgentId,
  validateTimelineRawSize, validateTimelineUpload, validateUploadEvent, validateUploadSummary,
} from '../packages/typescript/dist/v1alpha2/timeline-upload.js';

const uuid = '123e4567-e89b-12d3-a456-426614174000';
const filled = (n, size = 32) => new Uint8Array(size).fill(n);
const now = 1_700_000_000_000_000n;
const spool = create(SpoolRefSchema, { id: uuid });
const thread = create(ThreadRefSchema, { spool, id: create(ThreadIdSchema, { value: filled(2) }) });
const run = create(RecordRefSchema, { spool, id: 'run_7' });
function fixture() {
  const origin = create(TimelineOriginEndorsementSchema, {
    deploymentPublicKey: filled(1), spoolId: uuid, threadId: filled(2), runId: 'run_7',
    principalId: uuid, credentialClass: TimelineOriginCredentialClass.AGENT,
    effectivePopKeySha256: filled(3), originCredentialId: filled(4, 16),
    uploaderDevicePublicKey: filled(5), signature: filled(6, 64),
  });
  const snapshot = create(UploadRunSummarySchema, { state: OperationRecord_State.RUNNING, harness: 'codex' });
  const event = create(UploadTimelineEventSchema, {
    position: 0n, kind: UploadTimelineEventKind.TOOL_STARTED,
    recordedAt: { seconds: 1_700_000_000n, nanos: 123_000_000 }, toolName: UploadTimelineTool.BASH,
  });
  return create(UploadScrubbedTimelineRequestSchema, {
    clientOperationId: uuid, thread, run, canonicalizationVersion: 1, runRevision: 1n,
    snapshot, events: [event], origin, firstPosition: 0n,
  });
}

test('timeline identifiers, closed enums and timestamp rules reject invalid input', () => {
  assert.equal(validCanonicalUuid(uuid), true);
  assert.equal(validCanonicalUuid(uuid.toUpperCase()), false);
  assert.equal(validCanonicalUuid(`${uuid}\n`), false);
  assert.equal(validRunId('a-Z_09'), true);
  assert.equal(validRunId('a/b'), false);
  assert.equal(validRunId('run\n'), false);
  assert.equal(validRunId('x'.repeat(129)), false);
  assert.equal(validAgentLabel('agent.b:1-2'), true);
  assert.equal(validAgentLabel('bad label'), false);
  assert.equal(validAgentLabel('agent\n'), false);
  assert.equal(validAgentLabel('x'.repeat(65)), false);
  assert.equal(validVerifiedAgentId('agent', false), false);
  assert.equal(validVerifiedAgentId('', false), true);
  const value = fixture();
  validateTimelineUpload(value, now);
  validateTimelineUpload({ ...value, events: [] }, now);
  assert.throws(() => validateTimelineUpload({ ...value, events: [], snapshot: undefined }, now), /run-only snapshot/);
  assert.throws(() => validateUploadSummary({ ...value.snapshot, state: OperationRecord_State.UNSPECIFIED }), /state/);
  assert.throws(() => validateUploadSummary({ ...value.snapshot, state: 99 }), /state/);
  assert.throws(() => validateUploadSummary({ ...value.snapshot, harness: 'custom' }), /harness/);
  assert.throws(() => validateUploadEvent({ ...value.events[0], kind: 99 }, now), /kind/);
  assert.throws(() => validateUploadEvent({ ...value.events[0], toolName: 99 }, now), /tool_name/);
  assert.throws(() => validateUploadEvent({ ...value.events[0], recordedAt: { seconds: 1_700_000_000n, nanos: 123_000_001 } }, now), /recorded_at/);
  assert.throws(() => validateUploadEvent({ ...value.events[0], recordedAt: { seconds: 1_700_000_301n, nanos: 0 } }, now), /recorded_at/);
  assert.throws(() => validateTimelineUpload({ ...value, events: [{ ...value.events[0], position: 1n }] }, now), /sequence/);
  assert.throws(() => validateTimelineUpload({ ...value, events: Array(65).fill(value.events[0]) }, now), /event count/);
});

test('timeline wire bounds and domain transcripts are stable', () => {
  const value = fixture();
  assert.throws(() => validateTimelineRawSize(filled(0, MAX_TIMELINE_REQUEST_BYTES + 1), 'request'), /request size/);
  assert.throws(() => validateTimelineRawSize(filled(0, MAX_TIMELINE_EVENT_BYTES + 1), 'event'), /event size/);
  assert.throws(() => validateTimelineRawSize(filled(0, MAX_TIMELINE_SNAPSHOT_BYTES + 1), 'snapshot'), /snapshot size/);
  assert.throws(() => validateUploadSummary({ ...value.snapshot, harness: 'x'.repeat(MAX_TIMELINE_SNAPSHOT_BYTES + 1) }), /snapshot size/);
  assert.throws(() => validateTimelineUpload({ ...value, origin: { ...value.origin, signature: filled(0, MAX_TIMELINE_REQUEST_BYTES) } }, now), /request size/);
  assert.equal(new TextDecoder().decode(timelineOriginSigningBytes(value.origin).subarray(0, 30)), 'heddle-timeline-run-origin-v1\0');
  assert.deepEqual(timelineOriginSigningBytes({ ...value.origin, signature: new Uint8Array() }), timelineOriginSigningBytes(value.origin));
  const unsignedAcceptance = {
    originSha256: filled(1), uploaderDevicePublicKey: filled(2), deploymentPublicKey: filled(3),
    requestSha256: filled(4), firstPosition: 0n, eventCount: 1,
    authority: { case: 'principalCredentialId', value: filled(5, 1) }, signature: new Uint8Array(),
  };
  assert.equal(new TextDecoder().decode(timelineAcceptanceSigningBytes(unsignedAcceptance).subarray(0, 34)), 'heddle-timeline-run-acceptance-v1\0');
  assert.notDeepEqual(timelineAcceptanceSigningBytes(unsignedAcceptance),
    timelineAcceptanceSigningBytes({ ...unsignedAcceptance, authority: { case: 'principalCredentialId', value: filled(6, 1) } }));
  assert.notDeepEqual(timelineOriginDigest(value.origin), timelineOriginDigest({ ...value.origin, signature: filled(7, 64) }));
  assert.equal(timelineLogicalRequestDigest(value, now).length, 32);
  assert.equal(Buffer.from(timelineLogicalRequestDigest(value, now)).toString('hex'),
    '5b46eb711c38a7aa9c0587ee5c579872892afcf7327602fb31e9ae01fd404fd5');
  assert.notDeepEqual(timelineLogicalRequestDigest(value, now), timelineLogicalRequestDigest({ ...value, runRevision: 2n }, now));
});

test('acceptance binds one original and exact request range', () => {
  const value = fixture();
  const acceptance = create(TimelineAdmissionAcceptanceSchema, {
    originSha256: timelineOriginDigest(value.origin),
    uploaderDevicePublicKey: value.origin.uploaderDevicePublicKey,
    deploymentPublicKey: value.origin.deploymentPublicKey,
    requestSha256: timelineLogicalRequestDigest(value, now),
    firstPosition: 0n, eventCount: 1,
    authority: { case: 'principalCredentialId', value: filled(5, 1) }, signature: filled(6, 64),
  });
  validateTimelineUpload({ ...value, acceptance }, now);
  assert.throws(() => validateTimelineUpload({ ...value, acceptance: { ...acceptance, eventCount: 2 } }, now), /acceptance range/);
  assert.throws(() => validateTimelineUpload({ ...value, acceptance: { ...acceptance, requestSha256: filled(0) } }, now), /acceptance request digest/);
});
