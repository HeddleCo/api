import { create, toBinary } from '@bufbuild/protobuf';
import { writeFileSync } from 'node:fs';
import {
  BlockingDiscussionResolveRule as Rule, SpoolSettingsSchema,
  DiscussionRecordSchema, DiscussionResolutionRecordSchema,
  DiscussionActionKind as Action, LandingRecordSchema, RequirementKind,
} from '../packages/typescript/dist/v1alpha2/index.js';

const wire = (schema, value) => Buffer.from(toBinary(schema, value)).toString('hex');
const settings = [Rule.UNSPECIFIED, Rule.ANY_WRITER, Rule.OPENER_OR_ADMIN, Rule.OPENER_ONLY, 99]
  .map(rule => ({ rule, wire_hex: wire(SpoolSettingsSchema,
    create(SpoolSettingsSchema, { blockingDiscussionResolveRule: rule })) }));
const resolution = create(DiscussionResolutionRecordSchema, {
  discussion: { id: 'discussion-a' },
  causalId: new Uint8Array(32).fill(7),
  principalId: 'administrator-person',
  agentId: 'review-agent',
  rule: Rule.OPENER_OR_ADMIN,
  administratorOverride: true,
});
const discussion = create(DiscussionRecordSchema, {
  ref: resolution.discussion,
  version: new Uint8Array([2]),
  status: 2, blocking: true,
  actions: [
    { action: Action.RESOLVE, implemented: true, authorized: false,
      requirements: [{ kind: RequirementKind.POLICY,
        explanation: 'Only the opener or an administrator can resolve this blocking discussion' }],
      observedVersions: [{ version: new Uint8Array([2]) }] },
    { action: Action.REOPEN, implemented: true, authorized: true },
    { action: Action.CHANGE_BLOCKING, implemented: false, authorized: false,
      requirements: [{ kind: RequirementKind.POLICY,
        explanation: 'Changing blocking is unavailable at this endpoint' }] },
  ],
  resolutions: [resolution],
});
const landing = create(LandingRecordSchema, {
  rawSignedOperation: new Uint8Array([1, 2, 3]),
  blockingDiscussionResolutions: [resolution],
});
writeFileSync(new URL('./fixtures/blocking-discussion-v1.json', import.meta.url),
  JSON.stringify({ settings, discussion_wire_hex: wire(DiscussionRecordSchema, discussion),
    landing_wire_hex: wire(LandingRecordSchema, landing) }, null, 2) + '\n');
