import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { BeginPairingRequestSchema } from '../packages/typescript/dist/v1alpha2/identity_pb.js';

test('pairing web origin matches the Rust/TypeScript golden in both directions', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/pairing-web-origin.json', import.meta.url)));
  const wire = Buffer.from(fixture.wire_hex, 'hex');
  const request = create(BeginPairingRequestSchema, {
    clientOperationId: fixture.client_operation_id,
    webOrigin: fixture.web_origin,
  });
  assert.equal(request.webOrigin, 'https://preview.example.com');
  assert.deepEqual(fromBinary(BeginPairingRequestSchema, wire), request);
  assert.equal(Buffer.from(toBinary(BeginPairingRequestSchema, request)).toString('hex'), fixture.wire_hex);
  request.webOrigin = '';
  assert.equal(fromBinary(BeginPairingRequestSchema, toBinary(BeginPairingRequestSchema, request)).webOrigin, '');
});
