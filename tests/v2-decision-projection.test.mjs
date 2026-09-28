import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { LandingRequirementKind, MutationReceiptSchema, RequirementKind } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import {
  CaptureSummary_AttributionAssurance, EvidenceCurrency, ReviewDecision_Kind,
  SatisfiedPolicyRequirement_RuleSource, ThreadOverviewSchema,
} from '../packages/typescript/dist/v1alpha2/thread_pb.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/decision-thread-v1.json', import.meta.url), 'utf8'));

test('golden Thread keeps two attributed heads, evidence currency and landing fields in TS', () => {
  const bytes = Buffer.from(fixture.wire_hex, 'hex');
  const thread = fromBinary(ThreadOverviewSchema, bytes);
  assert.equal(Buffer.from(toBinary(ThreadOverviewSchema, thread)).toString('hex'), fixture.wire_hex);
  assert.equal(thread.sourceHeads.length, 2);
  assert.equal(thread.landingAssessments.length, 2);
  assert.equal(thread.alternatives.length, 2);
  for (const [index, alternative] of thread.alternatives.entries()) {
    assert.deepEqual(alternative.head, thread.sourceHeads[index]);
    assert.deepEqual(alternative.assessment?.source, alternative.head);
    assert.deepEqual(alternative.producer?.revision, alternative.head);
    assert.equal(alternative.producer?.attributionAssurance, CaptureSummary_AttributionAssurance.CLAIMED);
    assert.equal(alternative.reviews.length, 1);
    assert.deepEqual(alternative.assessment, thread.landingAssessments[index]);
    assert.deepEqual(alternative.checks, alternative.assessment.checks);
    assert.equal(new Set(alternative.checks.map(check => check.check)).size, alternative.checks.length);
    if (alternative.assessment.requirements.some(requirement => requirement.landingKind === LandingRequirementKind.REVIEW_REJECTED)) {
      assert.ok(alternative.reviews.some(review => review.decision?.kind === ReviewDecision_Kind.REJECTION));
    }
  }
  assert.equal(thread.alternatives[0].producer.agentProvider, 'openai');
  assert.equal(thread.alternatives[0].producer.agentModel, 'model-a');
  assert.equal(thread.alternatives[0].producer.principalName, 'Alice');
  assert.equal(thread.alternatives[0].producer.principalEmail, 'alice@example.test');
  assert.equal(thread.alternatives[0].producer.principalId, '');
  assert.equal(thread.alternatives[0].checks[0].currency, EvidenceCurrency.STALE);
  assert.notDeepEqual(thread.alternatives[0].checks[0].recordedRevision, thread.alternatives[0].head);
  assert.equal(thread.alternatives[0].checks[0].agentId, 'agent-a');
  assert.equal(thread.alternatives[0].checks[1].currency, EvidenceCurrency.CURRENT);
  assert.deepEqual(thread.alternatives[0].checks[1].recordedRevision, thread.alternatives[0].head);
  assert.equal(thread.alternatives[0].assessment.requirements[0].landingKind, LandingRequirementKind.EVIDENCE_STALE);
  assert.equal(thread.alternatives[0].assessment.requirements[1].landingKind, LandingRequirementKind.CONFLICT_MULTIPLE_HEADS);
  assert.equal(thread.alternatives[0].assessment.satisfiedBy.requirements[0].approvals[0].id, 'approval-a');
  assert.equal(thread.alternatives[0].assessment.satisfiedBy.requirements[2].evidence[0].id, 'evidence-lint-a');
  assert.equal(thread.alternatives[0].assessment.satisfiedBy.requirements[0].ruleSource, SatisfiedPolicyRequirement_RuleSource.SPOOL_SETTINGS_REQUIRE_REVIEW_TO_LAND);
  assert.equal(thread.alternatives[0].assessment.satisfiedBy.requirements[1].ruleSource, SatisfiedPolicyRequirement_RuleSource.REVIEW_POLICY);
  assert.equal(thread.alternatives[0].assessment.satisfiedBy.requirements[1].reviewPolicy.id, 'policy-b');
  assert.equal(thread.alternatives[0].assessment.satisfiedBy.requirements[2].reviewPolicy.id, 'policy-a');
  assert.equal(thread.alternatives[0].assessment.satisfiedBy.requirements[2].ruleIndex, 1);
  assert.equal(thread.alternatives[1].checks[0].currency, EvidenceCurrency.MISSING);
  assert.equal(thread.alternatives[1].checks[1].currency, EvidenceCurrency.FAILED);
  assert.deepEqual(thread.alternatives[1].checks[1].recordedRevision, thread.alternatives[1].head);
  assert.equal(thread.alternatives[1].assessment.requirements[0].landingKind, LandingRequirementKind.REVIEW_REJECTED);
  assert.equal(thread.alternatives[1].assessment.requirements[1].landingKind, LandingRequirementKind.CONFLICT_MULTIPLE_HEADS);
  assert.equal(thread.landingRecord.reviewEvidenceDigests.length, 2);
  assert.equal(Buffer.from(thread.landingRecord.executorKey).toString('hex'), '0b'.repeat(32));
  assert.equal(Buffer.from(thread.landingRecord.rawSignedOperation).toString('hex'), '0d'.repeat(32));
  assert.equal(thread.landingRecord.initiatingPrincipalId, 'alice');
  assert.equal(thread.landingRecord.initiatingAgentId, 'agent-a');
});

test('blocked landing receipt preserves typed conflict cause', () => {
  const receipt = create(MutationReceiptSchema, {
    outcome: { case: 'blocked', value: { requirements: [{
      kind: RequirementKind.CONFLICT_RESOLUTION,
      landingKind: LandingRequirementKind.CONFLICT_MULTIPLE_HEADS,
    }] } },
  });
  const decoded = fromBinary(MutationReceiptSchema, toBinary(MutationReceiptSchema, receipt));
  assert.equal(decoded.outcome.case, 'blocked');
  assert.equal(decoded.outcome.value.requirements[0].kind, RequirementKind.CONFLICT_RESOLUTION);
  assert.equal(decoded.outcome.value.requirements[0].landingKind, LandingRequirementKind.CONFLICT_MULTIPLE_HEADS);
});
