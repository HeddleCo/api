// Run after npm run build to regenerate the shared Rust/TypeScript golden.
import { create, toBinary } from '@bufbuild/protobuf';
import { ProviderRepositorySchema } from '../packages/typescript/dist/v1alpha2/integration_pb.js';
const repository = create(ProviderRepositorySchema, {
  providerRepositoryId: '123',
  cloneUrl: 'https://github.com/example/repo.git',
  linkedSpools: [
    { id: '11111111-1111-4111-8111-111111111111' },
    { id: '22222222-2222-4222-8222-222222222222' },
  ],
});
console.log(JSON.stringify({
  generated_by: 'node tests/generate-linked-spools-fixture.mjs',
  provider_repository_id: repository.providerRepositoryId,
  clone_url: repository.cloneUrl,
  linked_spool_ids: repository.linkedSpools.map(spool => spool.id),
  wire_hex: Buffer.from(toBinary(ProviderRepositorySchema, repository)).toString('hex'),
}, null, 2));
