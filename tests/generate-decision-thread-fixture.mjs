// Regenerate after `npm run build`; the committed binary is shared by Rust and TS.
// Opaque landing bytes are preservation sentinels, not a cryptographic test receipt.
import { writeFileSync } from 'node:fs';
import { create, toBinary } from '@bufbuild/protobuf';
import { LandingRequirementKind, RequirementKind } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import {
  CaptureSummary_AttributionAssurance, EvidenceCurrency, ReviewDecision_Kind, ReviewReadiness,
  SatisfiedPolicyRequirement_Kind, SatisfiedPolicyRequirement_RuleSource, ThreadOverviewSchema,
} from '../packages/typescript/dist/v1alpha2/thread_pb.js';

const bytes = (value) => new Uint8Array(32).fill(value);
const spool = { id: '123e4567-e89b-12d3-a456-426614174000' };
const thread = { spool, id: { value: bytes(1) } };
const target = { spool, id: { value: bytes(2) } };
const revision = (value) => ({ spool, revision: { case: 'state', value: { value: bytes(value) } } });
const record = (id) => ({ spool, id });
const policyVersion = bytes(5);
const review = (id, source, kind) => ({
  decision: { ref: record(id), thread, source, target: revision(4), policyVersion,
    principalId: 'reviewer', kind },
});
const check = (name, source, currency, recordedRevision, id, principalId, agentId) => ({
  check: name, source, currency,
  ...(id ? { evidence: record(id), recordedRevision, principalId, agentId } : {}),
});
const producer = (head, principalName, principalEmail, agentProvider, agentModel) => ({
  revision: head, thread, principalName, principalEmail, agentProvider, agentModel,
  attributionAssurance: CaptureSummary_AttributionAssurance.CLAIMED,
});
const a = revision(17);
const b = revision(34);
const old = revision(51);
const aCheck = check('unit', a, EvidenceCurrency.STALE, old, 'evidence-old', 'alice', 'agent-a');
const aCurrent = check('lint', a, EvidenceCurrency.CURRENT, a, 'evidence-lint-a', 'alice', 'agent-a');
const bCheck = check('unit', b, EvidenceCurrency.MISSING);
const bFailed = check('lint', b, EvidenceCurrency.FAILED, b, 'evidence-lint-b', 'bob', 'agent-b');
const aAssessment = {
  target, source: a, expectedTarget: revision(4), policyVersion,
  readiness: ReviewReadiness.BLOCKED,
  requirements: [{ kind: RequirementKind.EVIDENCE,
    landingKind: LandingRequirementKind.EVIDENCE_STALE,
    explanation: 'unit passed on an older revision' },
    { kind: RequirementKind.CONFLICT_RESOLUTION,
      landingKind: LandingRequirementKind.CONFLICT_MULTIPLE_HEADS,
      explanation: 'choose or merge a published head' }],
  satisfiedBy: { policyVersion, requirements: [
    { kind: SatisfiedPolicyRequirement_Kind.REVIEW_APPROVALS,
      ruleSource: SatisfiedPolicyRequirement_RuleSource.SPOOL_SETTINGS_REQUIRE_REVIEW_TO_LAND,
      approvals: [record('approval-a')] },
    { kind: SatisfiedPolicyRequirement_Kind.REVIEW_APPROVALS,
      ruleSource: SatisfiedPolicyRequirement_RuleSource.REVIEW_POLICY,
      reviewPolicy: record('policy-b'), approvals: [record('approval-a')] },
    { kind: SatisfiedPolicyRequirement_Kind.REQUIRED_CHECK,
      ruleSource: SatisfiedPolicyRequirement_RuleSource.REVIEW_POLICY,
      reviewPolicy: record('policy-a'), ruleIndex: 1,
      check: 'lint', evidence: [record('evidence-lint-a')] },
  ] },
  checks: [aCheck, aCurrent],
};
const bAssessment = {
  target, source: b, expectedTarget: revision(4), policyVersion,
  readiness: ReviewReadiness.BLOCKED,
  requirements: [{ kind: RequirementKind.REVIEW,
    landingKind: LandingRequirementKind.REVIEW_REJECTED,
    explanation: 'rejected for this head' },
    { kind: RequirementKind.CONFLICT_RESOLUTION,
      landingKind: LandingRequirementKind.CONFLICT_MULTIPLE_HEADS,
      explanation: 'choose or merge a published head' }],
  checks: [bCheck, bFailed],
};
const overview = create(ThreadOverviewSchema, {
  ref: thread, name: 'two candidates', sourceHeads: [a, b],
  landingAssessments: [aAssessment, bAssessment],
  alternatives: [
    { head: a, producer: producer(a, 'Alice', 'alice@example.test', 'openai', 'model-a'),
      diff: { source: a, base: revision(4), policyVersion }, reviews: [review('approval-a', a, ReviewDecision_Kind.APPROVAL)],
      assessment: aAssessment, checks: [aCheck, aCurrent] },
    { head: b, producer: producer(b, 'Bob', 'bob@example.test', 'anthropic', 'model-b'),
      diff: { source: b, base: revision(4), policyVersion }, reviews: [review('review-b', b, ReviewDecision_Kind.REJECTION)],
      assessment: bAssessment, checks: [bCheck, bFailed] },
  ],
  // An earlier landing remains visible after later competing captures.
  landingRecord: {
    sourceThread: thread, sourceRevision: revision(3), targetThread: target,
    resultRevision: revision(3), sourceOperationDigest: bytes(6),
    expectedTargetFrontier: [bytes(7)], policyVersion,
    reviewEvidenceDigests: [bytes(8), bytes(9)], initiatingRequestProofDigest: bytes(10),
    executorKey: bytes(11), executorTrustAnchorDigest: bytes(12), executedAt: { seconds: 1_800_000_000n },
    rawSignedOperation: bytes(13), initiatingPrincipalId: 'alice', initiatingAgentId: 'agent-a',
  },
});

writeFileSync(new URL('./fixtures/decision-thread-v1.json', import.meta.url),
  `${JSON.stringify({ description: 'Synthetic projection: two heads, current/stale/failed/missing checks, prior landing fields',
    wire_hex: Buffer.from(toBinary(ThreadOverviewSchema, overview)).toString('hex') }, null, 2)}\n`);
