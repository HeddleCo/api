import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { ProviderRepositorySchema } from '../packages/typescript/dist/v1alpha2/integration_pb.js';

test('linked spools match the Rust/TypeScript golden in both directions', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/provider-repository-linked-spools.json', import.meta.url)));
  const wire = Buffer.from(fixture.wire_hex, 'hex');
  const repository = create(ProviderRepositorySchema, {
    providerRepositoryId: fixture.provider_repository_id,
    cloneUrl: fixture.clone_url,
    linkedSpools: fixture.linked_spool_ids.map(id => ({ id })),
  });
  assert.equal(repository.linkedSpools.length, 2);
  assert.deepEqual(fromBinary(ProviderRepositorySchema, wire), repository);
  assert.equal(Buffer.from(toBinary(ProviderRepositorySchema, repository)).toString('hex'), fixture.wire_hex);
  repository.linkedSpools = [];
  assert.deepEqual(fromBinary(ProviderRepositorySchema, toBinary(ProviderRepositorySchema, repository)).linkedSpools, []);
});
