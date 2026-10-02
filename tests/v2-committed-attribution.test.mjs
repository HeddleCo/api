import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import {
  StateAttributionSchema, AttributionEvidenceV1Schema, AttributionBasis,
  AttributionSource, HarnessVersionScope, AttributionOperationResolution, AttributionCollectionMethod,
} from '../packages/typescript/dist/common/state_attribution_pb.js';
import { DescribeEndpointResponseSchema } from '../packages/typescript/dist/v1alpha2/endpoint_pb.js';
import { STATE_V6_ATTRIBUTION_V1, requireNativeSourceFormats } from '../packages/typescript/dist/v1alpha2/source-format.js';

test('native source additions require explicit independent support', () => {
  const v6 = STATE_V6_ATTRIBUTION_V1;
  requireNativeSourceFormats([], []);
  assert.throws(() => requireNativeSourceFormats([v6], []), /does not support/);
  assert.throws(() => requireNativeSourceFormats([v6], [99]), /does not support/);
  requireNativeSourceFormats([v6], [99, v6]);
  for (const unknown of [0, -1, 99]) {
    assert.throws(() => requireNativeSourceFormats([unknown], [unknown]), /Invalid or unsupported/);
  }
  assert.throws(() => requireNativeSourceFormats([v6, v6], [v6]), /Duplicate/);
  const endpoint = create(DescribeEndpointResponseSchema, { understoodSignedRecordFormats: ['heddle-thread-operation-v1'] });
  assert.throws(() => requireNativeSourceFormats([v6], endpoint.understoodNativeSourceFormats), /does not support/);
});

test('selected and response claims share the Rust/TypeScript wire fixture', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/state-attribution-v1.json', import.meta.url)));
  const wire = Buffer.from(fixture.wire_hex, 'hex');
  const attribution = fromBinary(StateAttributionSchema, wire);
  assert.deepEqual(Buffer.from(attribution.evidenceHash), Buffer.alloc(32, 42));
  const evidence = attribution.evidence;
  assert.equal(evidence.formatVersion, 1);
  assert.equal(evidence.harness.value, 'codex');
  assert.equal(evidence.harnessVersionScope, HarnessVersionScope.SESSION_CREATION);
  assert.equal(evidence.selected.model.value, 'custom/request-alias');
  assert.equal(evidence.selected.model.basis, AttributionBasis.REQUEST_REPORTED);
  assert.equal(evidence.response.model.value, 'custom/response-model');
  assert.equal(evidence.response.model.basis, AttributionBasis.RESPONSE_REPORTED);
  assert.equal(evidence.selected.version, undefined);
  assert.equal(evidence.response.version, undefined);
  assert.equal(evidence.scope.actorId, 'child-A');
  assert.equal(evidence.scope.parentActorId, 'root');
  assert.equal(evidence.scope.attemptId, 'retry-2');
  assert.equal(Buffer.from(toBinary(StateAttributionSchema, attribution)).toString('hex'), fixture.wire_hex);
});

test('unknown model and unavailable evidence do not erase known attribution', () => {
  const pending = create(StateAttributionSchema, { evidenceHash: new Uint8Array(32).fill(7) });
  assert.deepEqual(fromBinary(StateAttributionSchema, toBinary(StateAttributionSchema, pending)), pending);
  assert.equal(pending.evidence, undefined);
  const evidence = create(AttributionEvidenceV1Schema, {
    formatVersion: 1,
    harness: { value: 'custom-harness', basis: AttributionBasis.OBSERVED, source: AttributionSource.PROCESS },
  });
  const decoded = fromBinary(AttributionEvidenceV1Schema, toBinary(AttributionEvidenceV1Schema, evidence));
  assert.equal(decoded.harness.value, 'custom-harness');
  assert.equal(decoded.selected, undefined);
  assert.equal(decoded.response, undefined);
});

test('contributor fixture preserves individual identity, typed hashes and unresolved evidence', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/state-attribution-operations-v1.json', import.meta.url)));
  const wire = Buffer.from(fixture.wire_hex, 'hex');
  const attribution = fromBinary(StateAttributionSchema, wire);
  const evidence = attribution.evidence;
  assert.equal(evidence.harness.value, 'capture-harness');
  assert.equal(evidence.selected.model.value, 'capture-model');
  assert.equal(evidence.scope.actorId, 'capture-caller');
  assert.equal(evidence.operationsIncomplete, true);
  assert.equal(evidence.operations.length, 2);
  const [bound, unresolved] = evidence.operations;
  assert.equal(bound.resolution, AttributionOperationResolution.CONTENT_BOUND);
  assert.deepEqual(bound.identity.collectionMethods, [AttributionCollectionMethod.HOOK, AttributionCollectionMethod.TRANSCRIPT]);
  assert.equal(bound.identity.harness.value, 'codex');
  assert.equal(bound.identity.harnessVersion.value, '1.2.3');
  assert.equal(bound.identity.harnessVersionScope, HarnessVersionScope.CURRENT_INVOCATION);
  assert.equal(bound.identity.selected.provider.value, 'router-a');
  assert.equal(bound.identity.selected.model.value, 'selected-a');
  assert.equal(bound.identity.response.provider, undefined);
  assert.equal(bound.identity.response.model.value, 'reported-a');
  assert.equal(bound.identity.response.model.basis, AttributionBasis.RESPONSE_REPORTED);
  assert.equal(bound.identity.response.model.source, AttributionSource.RESPONSE);
  assert.equal(bound.identity.response.model.observationId, 'response-a');
  assert.equal(bound.identity.scope.actorId, 'actor-a');
  assert.equal(bound.identity.scope.harnessSessionId, 'session-a');
  assert.equal(bound.identity.scope.requestId, 'request-a');
  assert.equal(bound.identity.scope.responseId, 'response-a');
  assert.equal(bound.identity.scope.attemptId, 'attempt-a');
  assert.equal(bound.identity.scope.messageId, 'message-a');
  assert.equal(bound.identity.scope.rootTurnId, 'root-turn');
  assert.equal(bound.identity.scope.toolCallId, 'tool-a');
  assert.equal(bound.changes.length, 3);
  assert.equal(bound.changes[0].path, 'src/modified.rs');
  assert.deepEqual(Buffer.from(bound.changes[0].before.value), Buffer.alloc(32, 11));
  assert.deepEqual(Buffer.from(bound.changes[0].after.value), Buffer.alloc(32, 12));
  assert.equal(bound.changes[1].before, undefined);
  assert.deepEqual(Buffer.from(bound.changes[1].after.value), Buffer.alloc(32, 13));
  assert.deepEqual(Buffer.from(bound.changes[2].before.value), Buffer.alloc(32, 14));
  assert.equal(bound.changes[2].after, undefined);
  assert.equal(unresolved.resolution, AttributionOperationResolution.UNRESOLVED);
  assert.deepEqual(unresolved.identity.collectionMethods, [AttributionCollectionMethod.TRANSCRIPT]);
  assert.equal(unresolved.identity.harness.value, 'custom-harness');
  assert.equal(unresolved.identity.selected, undefined);
  assert.equal(unresolved.identity.response, undefined);
  assert.equal(unresolved.identity.scope.actorId, 'actor-b');
  assert.equal(unresolved.identity.scope.attemptId, 'attempt-b');
  assert.equal(Buffer.from(toBinary(StateAttributionSchema, attribution)).toString('hex'), fixture.wire_hex);
});

test('older evidence decodes without manufacturing operation contributors', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/state-attribution-v1.json', import.meta.url)));
  const wire = Buffer.from(fixture.wire_hex, 'hex');
  const attribution = fromBinary(StateAttributionSchema, wire);
  assert.deepEqual(attribution.evidence.operations, []);
  assert.equal(attribution.evidence.operationsIncomplete, false);
  assert.equal(Buffer.from(toBinary(StateAttributionSchema, attribution)).toString('hex'), fixture.wire_hex);
});
