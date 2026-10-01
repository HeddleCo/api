import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import {
  OperationRecordSchema, LandingAssessmentStatusSchema, LandingAssessmentStatus_State as State,
  ThreadOverviewSchema, ThreadAlternativeSchema, SpoolSettingsSchema, SpoolOverviewSchema,
  ReviseSpoolRequestSchema,
} from '../packages/typescript/dist/v1alpha2/index.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/observation-additions-v1.json', import.meta.url)));
const bytes = hex => new Uint8Array(Buffer.from(hex, 'hex'));
const roundTrip = (schema, hex) => {
  const value = fromBinary(schema, bytes(hex));
  assert.equal(Buffer.from(toBinary(schema, value)).toString('hex'), hex);
  return value;
};

test('operation subjects, timestamp presence, and direct retry chain match shared vectors', () => {
  const [a, b, c, canceled, legacy] = fixture.operations.map(vector => roundTrip(OperationRecordSchema, vector.wire_hex));
  assert.equal(a.subject.subject.case, 'import');
  assert.equal(a.subject.subject.value.sourceUrl, 'https://github.com/sharkdp/hexyl.git');
  assert.equal(a.subject.subject.value.provider, 'github');
  assert.equal(a.subject.subject.value.providerRepositoryId, 'repo-42');
  assert.deepEqual(a.subject, b.subject);
  assert.deepEqual(b.subject, c.subject);
  assert.equal(a.state, 4, 'supersession preserves historical failure state');
  assert.equal(b.state, 4);
  assert.equal(a.failure.code, 14);
  assert.equal(a.failure.message, 'Source fetch failed');
  assert.deepEqual(a.failure, b.failure);
  assert.equal(c.state, 1);
  assert.equal(a.createdAt.seconds, 1780000000n);
  assert.equal(a.createdAt.nanos, 123456789);
  assert.equal(a.finishedAt.nanos, 42);
  assert.equal(a.startedAt.seconds, 1780000001n);
  assert.equal(a.retryOf, undefined);
  for (const [link, ref] of [[a.supersededBy, b.ref], [b.retryOf, a.ref], [b.supersededBy, c.ref], [c.retryOf, b.ref]]) {
    assert.equal(link.$typeName, 'heddle.api.v1alpha2.OperationRef');
    assert.equal(link.id, ref.id);
    assert.deepEqual(link.spool, ref.spool);
  }
  assert.equal(c.supersededBy, undefined);
  assert.equal(c.startedAt, undefined);
  assert.equal(c.finishedAt, undefined);
  assert.equal(canceled.state, 5);
  assert.equal(canceled.startedAt, undefined);
  assert.ok(canceled.createdAt && canceled.finishedAt);
  assert.equal(canceled.subject.subject.value.provider, '');
  for (const field of ['subject', 'createdAt', 'startedAt', 'finishedAt', 'retryOf', 'supersededBy']) {
    assert.equal(legacy[field], undefined, `older/filtered ${field} remains unknown`);
    assert.equal(create(OperationRecordSchema)[field], undefined);
  }
});

test('landing gap states preserve typed reasons, zero, and unknown enum codes', () => {
  assert.deepEqual([State.UNSPECIFIED, State.PENDING, State.FAILED, State.NOT_ELIGIBLE, State.NO_PUBLISHED_HEAD,
    State.BASE_UNREADABLE, State.UNAVAILABLE, State.MULTIPLE_HEADS], [0, 1, 2, 3, 4, 5, 6, 7]);
  for (const vector of fixture.statuses) {
    const status = roundTrip(LandingAssessmentStatusSchema, vector.wire_hex);
    assert.equal(status.state, vector.state);
    if (vector.state > 0 && vector.state <= 7) {
      assert.ok(status.reason.kind > 0);
      assert.ok(status.reason.explanation.length > 0);
      assert.equal(status.reason.subject, undefined, 'generic reasons expose no hidden reference');
      assert.equal(status.reason.policy, undefined);
    } else {
      assert.equal(status.reason, undefined, 'unknown is neither pending nor permission');
    }
  }
});

test('overview and alternatives explain missing results and clear gaps when assessed', () => {
  for (const vector of fixture.overviews) {
    const overview = roundTrip(ThreadOverviewSchema, vector.wire_hex);
    if (vector.name.startsWith('gap-')) {
      const state = Number(vector.name.slice(4));
      assert.equal(overview.landingAssessmentStatus.state, state);
      assert.equal(overview.landingAssessment, undefined);
      assert.equal(overview.landingAssessments.length, 0);
      assert.equal(overview.alternatives.length, state === State.NO_PUBLISHED_HEAD ? 0 : 1);
      for (const alternative of overview.alternatives) {
        assert.equal(alternative.assessment, undefined);
        assert.deepEqual(alternative.assessmentStatus, overview.landingAssessmentStatus);
        assert.deepEqual(alternative.head, overview.sourceHeads[0]);
      }
    } else if (vector.name === 'assessed' || vector.name === 'multiple-heads') {
      assert.equal(overview.landingAssessmentStatus?.state, vector.name === 'multiple-heads' ? State.MULTIPLE_HEADS : undefined);
      assert.equal(overview.landingAssessment === undefined, vector.name === 'multiple-heads');
      for (const [index, alternative] of overview.alternatives.entries()) {
        assert.equal(alternative.assessmentStatus, undefined);
        assert.deepEqual(alternative.assessment, overview.landingAssessments[index]);
        assert.deepEqual(alternative.assessment.source, alternative.head);
      }
    } else {
      assert.equal(overview.landingAssessmentStatus, undefined, 'older or no-target overview is unknown');
      assert.equal(overview.alternatives[0].assessmentStatus, undefined);
    }
  }
  assert.equal(create(ThreadAlternativeSchema).assessmentStatus, undefined);
});

test('default Thread passes through delegated settings, spool CAS, and spool observation', () => {
  const settings = roundTrip(SpoolSettingsSchema, fixture.settings_wire_hex);
  const revise = roundTrip(ReviseSpoolRequestSchema, fixture.revise_wire_hex);
  const spool = roundTrip(SpoolOverviewSchema, fixture.spool_wire_hex);
  assert.deepEqual(revise.settings, settings);
  assert.deepEqual(spool.settings, settings);
  assert.deepEqual(settings.defaultThread.spool, spool.ref);
  assert.deepEqual(settings.defaultThread.id.value, new Uint8Array(32).fill(3));
  assert.deepEqual(revise.expectedVersion, spool.version);
  assert.deepEqual(spool.version, new Uint8Array([5]));
  assert.equal(revise.clientOperationId, 'set-default');
  assert.equal(roundTrip(SpoolSettingsSchema, fixture.omitted_settings_wire_hex).defaultThread, undefined,
    'unset/deleted/unreadable projections omit the selection');
  assert.equal(create(SpoolSettingsSchema).defaultThread, undefined, 'older settings have no default');
});
