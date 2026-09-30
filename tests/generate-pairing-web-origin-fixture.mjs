// Run after npm run build to regenerate the shared Rust/TypeScript golden.
import { create, toBinary } from '@bufbuild/protobuf';
import { BeginPairingRequestSchema } from '../packages/typescript/dist/v1alpha2/identity_pb.js';
const request = create(BeginPairingRequestSchema, {
  clientOperationId: 'pair-1',
  webOrigin: 'https://preview.example.com',
});
console.log(JSON.stringify({
  generated_by: 'node tests/generate-pairing-web-origin-fixture.mjs',
  client_operation_id: request.clientOperationId,
  web_origin: request.webOrigin,
  wire_hex: Buffer.from(toBinary(BeginPairingRequestSchema, request)).toString('hex'),
}, null, 2));
