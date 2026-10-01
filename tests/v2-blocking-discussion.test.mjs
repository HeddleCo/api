import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import {
  BlockingDiscussionResolveRule as Rule, SpoolSettingsSchema,
  DiscussionRecordSchema, DiscussionActionKind as Action,
  LandingRecordSchema, DiscussionResolutionRecordSchema,
} from '../packages/typescript/dist/v1alpha2/index.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/blocking-discussion-v1.json', import.meta.url)));
const bytes = hex => new Uint8Array(Buffer.from(hex, 'hex'));

test('blocking rules preserve inheritance, explicit ANY_WRITER, and unknown values on the wire', () => {
  assert.deepEqual([Rule.UNSPECIFIED, Rule.ANY_WRITER, Rule.OPENER_OR_ADMIN, Rule.OPENER_ONLY], [0, 1, 2, 3]);
  assert.equal(create(SpoolSettingsSchema).blockingDiscussionResolveRule, Rule.UNSPECIFIED);
  for (const vector of fixture.settings) {
    const settings = fromBinary(SpoolSettingsSchema, bytes(vector.wire_hex));
    assert.equal(settings.blockingDiscussionResolveRule, vector.rule);
    assert.equal(Buffer.from(toBinary(SpoolSettingsSchema, settings)).toString('hex'), vector.wire_hex);
  }
});

test('discussion actions preserve denied reasons, unsupported changes, and admitted overrides', () => {
  const discussion = fromBinary(DiscussionRecordSchema, bytes(fixture.discussion_wire_hex));
  assert.deepEqual(discussion.actions.map(action => action.action),
    [Action.RESOLVE, Action.REOPEN, Action.CHANGE_BLOCKING]);
  assert.equal(discussion.actions[0].authorized, false);
  assert.match(discussion.actions[0].requirements[0].explanation, /opener or an administrator/);
  assert.deepEqual(discussion.actions[0].observedVersions[0].version, new Uint8Array([2]));
  assert.equal(discussion.actions[1].authorized, true);
  assert.equal(discussion.actions[2].implemented, false);
  const resolution = discussion.resolutions[0];
  assert.equal(resolution.administratorOverride, true);
  assert.equal(resolution.rule, Rule.OPENER_OR_ADMIN);
  assert.equal(resolution.principalId, 'administrator-person');
  assert.equal(resolution.agentId, 'review-agent');
  assert.deepEqual(resolution.causalId, new Uint8Array(32).fill(7));
  assert.equal(Buffer.from(toBinary(DiscussionRecordSchema, discussion)).toString('hex'), fixture.discussion_wire_hex);
  assert.equal(create(DiscussionRecordSchema).resolutions.length, 0, 'older servers supply no override evidence');
  assert.equal(create(DiscussionResolutionRecordSchema).administratorOverride, false);
});

test('landing metadata refers to the same resolution without altering signed operation bytes', () => {
  const discussion = fromBinary(DiscussionRecordSchema, bytes(fixture.discussion_wire_hex));
  const landing = fromBinary(LandingRecordSchema, bytes(fixture.landing_wire_hex));
  assert.deepEqual(landing.blockingDiscussionResolutions, discussion.resolutions);
  assert.deepEqual(landing.rawSignedOperation, new Uint8Array([1, 2, 3]));
  assert.equal(Buffer.from(toBinary(LandingRecordSchema, landing)).toString('hex'), fixture.landing_wire_hex);
});
