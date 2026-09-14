import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { create } from '@bufbuild/protobuf';
import { ThreadOverviewSchema } from '../packages/typescript/dist/v2alpha1/thread_pb.js';
import { signThreadOwnershipAcceptance } from '../packages/typescript/dist/v2alpha1/thread-ownership.js';

const key = seed => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)]), format: 'der', type: 'pkcs8' });
const publicKey = seed => new Uint8Array(createPublicKey(key(seed)).export({ format: 'der', type: 'spki' }).subarray(-32));
const signer = { publicKey: publicKey(32), sign: async bytes => new Uint8Array(sign(null, bytes, key(32))) };
function inputs() {
  return { overview: create(ThreadOverviewSchema, {
    ref: { spool: { id: '00000000-0000-0000-0000-000000000022' }, id: { value: new Uint8Array(32).fill(33) } },
    ownership: { owner: { case: 'localKey', value: publicKey(31) } },
    sourceFrontier: { operationIds: [new Uint8Array(32).fill(37)], complete: true },
  }), author: { actor: { principalId: '00000000-0000-0000-0000-000000000023', agentId: 'delegated-agent' }, authorityEnvelope: new Uint8Array(32).fill(36), signer } };
}
test('browser ownership acceptance matches independent Rust canonical bytes and signature', async () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/thread-ownership-v1-rust.json', import.meta.url), 'utf8'));
  const { overview, author } = inputs();
  const record = await signThreadOwnershipAcceptance(overview, author);
  assert.equal(record.format, 'heddle-thread-ownership-claim-v1');
  assert.equal(Buffer.from(record.canonicalRecord).toString('hex'), fixture.canonical_hex);
  assert.equal(Buffer.from(record.signatures[0].signature).toString('hex'), fixture.acceptance_signature_hex);
  assert.equal(record.signatures.length, 1);
});
test('ownership requires observed local owner and complete bounded unique source operation frontier', async () => {
  for (const mutate of [
    overview => { overview.ownership = undefined; },
    overview => { overview.ownership.owner = { case: 'account', value: { id: '00000000-0000-0000-0000-000000000023' } }; },
    overview => { overview.sourceFrontier = undefined; },
    overview => { overview.sourceFrontier.complete = false; },
    overview => { overview.sourceFrontier.operationIds.push(overview.sourceFrontier.operationIds[0]); },
    overview => { overview.sourceFrontier.operationIds = Array.from({ length: 129 }, (_, index) => new Uint8Array(32).fill(index)); },
  ]) {
    const { overview, author } = inputs(); mutate(overview);
    await assert.rejects(signThreadOwnershipAcceptance(overview, author));
  }
});
test('ownership validates acceptor key and original authority budget before consent', async () => {
  const { overview, author } = inputs();
  await assert.rejects(signThreadOwnershipAcceptance(overview, { ...author, signer: { ...signer, publicKey: publicKey(31) } }), /acceptor does not match/);
  await assert.rejects(signThreadOwnershipAcceptance(overview, { ...author, authorityEnvelope: new Uint8Array(65537) }), /envelope exceeds/);
});
