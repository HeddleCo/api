import { create, toBinary } from '@bufbuild/protobuf';
import { writeFileSync } from 'node:fs';
import {
  OperationRecordSchema, LandingAssessmentStatusSchema, ThreadOverviewSchema,
  SpoolSettingsSchema, SpoolOverviewSchema, ReviseSpoolRequestSchema,
} from '../packages/typescript/dist/v1alpha2/index.js';

const wire = (schema, value) => Buffer.from(toBinary(schema, create(schema, value))).toString('hex');
const spool = { id: 'spool-a' };
const operation = id => ({ spool, id });
const thread = { spool, id: { value: new Uint8Array(32).fill(3) } };
const source = { spool, revision: { case: 'gitCommitOid', value: 'a'.repeat(40) } };
const source2 = { spool, revision: { case: 'gitCommitOid', value: 'b'.repeat(40) } };
const subject = { subject: { case: 'import', value: {
  sourceUrl: 'https://github.com/sharkdp/hexyl.git', provider: 'github', providerRepositoryId: 'repo-42',
} } };
const timestamp = (seconds, nanos = 0) => ({ seconds: BigInt(seconds), nanos });
const operations = [
  { name: 'original-failed', value: { ref: operation('a'), clientOperationId: 'import-a', version: new Uint8Array([1]), state: 4, failure: { code: 14, message: 'Source fetch failed' },
    subject, createdAt: timestamp(1780000000, 123456789), startedAt: timestamp(1780000001), finishedAt: timestamp(1780000002, 42), supersededBy: operation('b') } },
  { name: 'retry-failed', value: { ref: operation('b'), version: new Uint8Array([2]), state: 4, failure: { code: 14, message: 'Source fetch failed' },
    subject, createdAt: timestamp(1780000003), startedAt: timestamp(1780000004), finishedAt: timestamp(1780000005), retryOf: operation('a'), supersededBy: operation('c') } },
  { name: 'retry-queued', value: { ref: operation('c'), version: new Uint8Array([3]), state: 1,
    subject, createdAt: timestamp(1780000006), retryOf: operation('b') } },
  { name: 'canceled-before-start', value: { ref: operation('d'), state: 5,
    subject: { subject: { case: 'import', value: { sourceUrl: 'https://example.com/repo.git' } } },
    createdAt: timestamp(1780000007), finishedAt: timestamp(1780000008) } },
  { name: 'older-or-filtered', value: { ref: operation('legacy'), state: 4 } },
].map(({ name, value }) => ({ name, wire_hex: wire(OperationRecordSchema, value) }));
const explanations = [null, 'Assessment is pending', 'Assessment evaluation failed', 'Source is not eligible for assessment',
  'No visible published source head', 'Known comparison base cannot be read', 'Required material is unavailable', 'Several visible published source heads'];
const kinds = [0, 10, 8, 11, 9, 1, 1, 5];
const statuses = [...Array(8).keys(), 99].map(state => {
  const value = { state, ...(explanations[state] ? { reason: { kind: kinds[state], explanation: explanations[state] } } : {}) };
  return { state, wire_hex: wire(LandingAssessmentStatusSchema, value), value };
});
const assessment = revision => ({ target: thread, source: revision, readiness: 4, policyVersion: new Uint8Array([9]) });
const overviews = statuses.filter(item => item.state >= 1 && item.state <= 6).map(({ state, value }) => ({
  name: `gap-${state}`, wire_hex: wire(ThreadOverviewSchema, {
    ref: thread, version: new Uint8Array([4]), landingAssessmentStatus: value,
    ...(state === 4 ? {} : { sourceHeads: [source], alternatives: [{ head: source, assessmentStatus: value }] }),
  }),
}));
overviews.push({ name: 'assessed', wire_hex: wire(ThreadOverviewSchema, { ref: thread,
  sourceHeads: [source], landingAssessment: assessment(source), landingAssessments: [assessment(source)],
  alternatives: [{ head: source, assessment: assessment(source) }] }) });
overviews.push({ name: 'multiple-heads', wire_hex: wire(ThreadOverviewSchema, { ref: thread,
  sourceHeads: [source, source2], landingAssessmentStatus: statuses[7].value,
  landingAssessments: [assessment(source), assessment(source2)],
  alternatives: [{ head: source, assessment: assessment(source) }, { head: source2, assessment: assessment(source2) }] }) });
overviews.push({ name: 'older-or-no-target', wire_hex: wire(ThreadOverviewSchema, { ref: thread, sourceHeads: [source], alternatives: [{ head: source }] }) });
const settings = { description: 'Imported repository', defaultThread: thread };
const fixture = {
  operations, statuses: statuses.map(({ value, ...vector }) => vector), overviews,
  settings_wire_hex: wire(SpoolSettingsSchema, settings),
  revise_wire_hex: wire(ReviseSpoolRequestSchema, { clientOperationId: 'set-default', spool,
    expectedVersion: new Uint8Array([5]), name: 'hexyl', settings, settingsMask: { paths: ['description', 'default_thread'] } }),
  spool_wire_hex: wire(SpoolOverviewSchema, { ref: spool, version: new Uint8Array([5]), settings }),
  // Unset, deleted, and unreadable selections have identical caller projections.
  omitted_settings_wire_hex: wire(SpoolSettingsSchema, { description: settings.description }),
};
writeFileSync(new URL('./fixtures/observation-additions-v1.json', import.meta.url), JSON.stringify(fixture, null, 2) + '\n');
