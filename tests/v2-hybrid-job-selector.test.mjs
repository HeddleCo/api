import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fromBinary, toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as authority from '../packages/typescript/dist/v1alpha2/import-authority.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/hybrid-job-selector-v1.json', import.meta.url)));
const bytes = value => new Uint8Array(Buffer.from(value, 'hex'));

test('HYBRID operation job selector wire and projection match shared vectors', () => {
  for (const vector of fixture.operations) {
    const operation = fromBinary(api.OperationRecordSchema, bytes(vector.wire_hex));
    assert.deepEqual(toBinary(api.OperationRecordSchema, operation), bytes(vector.wire_hex), vector.name);
    if (vector.expected === 'OK') {
      const request = authority.importJobStateRequestFromOperation(operation);
      assert.ok(request, vector.name);
      assert.deepEqual(toBinary(api.GetImportJobStateRequestSchema, request), bytes(vector.request_wire_hex), vector.name);
      authority.validateHybridImportJobSelector(operation.subject.subject.value.hybridJob);
      // Mutating the request must not mutate the observed operation.
      request.logicalJobId.fill(0);
      request.destination.id = '';
      assert.ok(authority.importJobStateRequestFromOperation(operation), 'projection owns its bytes and destination');
    } else if (vector.expected === 'unavailable') {
      assert.equal(authority.importJobStateRequestFromOperation(operation), undefined, vector.name);
    } else {
      assert.throws(() => authority.importJobStateRequestFromOperation(operation),
        error => error instanceof authority.HybridContractError && error.reason === vector.expected, vector.name);
    }
  }
});

test('HYBRID job selector has typed stable placement', () => {
  const field = api.ImportOperationSubjectSchema.fields.find(field => field.number === 4);
  assert.equal(field.name, 'hybrid_job');
  assert.equal(field.message, api.HybridImportJobSelectorSchema);
  assert.equal(api.HybridImportJobSelectorSchema.fields.length, 1);
  assert.equal(api.HybridImportJobSelectorSchema.fields[0].name, 'logical_job_id');
  assert.equal(api.HybridImportJobSelectorSchema.fields[0].number, 1);
});
