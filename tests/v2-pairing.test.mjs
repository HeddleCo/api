import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createPrivateKey, sign } from 'node:crypto';
import { fromBinary, toBinary } from '@bufbuild/protobuf';
import { BeginPairingRequestSchema, CompletePairingRequestSchema, BrowserPairingCompletionBindingSchema } from '../packages/typescript/dist/v2alpha1/identity_pb.js';
import { signBrowserPairingInitiation, signBrowserPairingCompletion, verifyBrowserPairingCompletion } from '../packages/typescript/dist/v2alpha1/pairing.js';
const fixture = Object.fromEntries(readFileSync(new URL('./fixtures/browser-pairing-v1-rust.txt', import.meta.url), 'utf8').trim().split('\n').map(line => line.split('=')));
const bytes = value => new Uint8Array(Buffer.from(value, 'hex'));
const initiation = fromBinary(BeginPairingRequestSchema, bytes(fixture.initiation));
const completion = fromBinary(CompletePairingRequestSchema, bytes(fixture.completion));
const binding = fromBinary(BrowserPairingCompletionBindingSchema, completion.proof.value.canonicalRecord);
const now = 1800000000n;
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 41)]), format: 'der', type: 'pkcs8' });
const signer = { publicKey: initiation.subjectPublicKey, sign: async data => new Uint8Array(sign(null, data, privateKey)) };
test('browser receiver initiation matches independent Rust signed record', async () => {
  const start = await signBrowserPairingInitiation(binding.host, 'browser-start', now, signer);
  assert.equal(start.receiver.case, 'browser');
  assert.deepEqual(start.subjectPossession, initiation.subjectPossession);
});
test('browser receiver completion matches independent Rust signed record', async () => {
  const finish = await signBrowserPairingCompletion(binding.host, 'browser-complete', completion.pairing, binding.approval, now, signer);
  assert.deepEqual(finish.proof, completion.proof);
  assert.deepEqual(toBinary(CompletePairingRequestSchema, finish), bytes(fixture.completion));
  await verifyBrowserPairingCompletion(completion, binding.host, binding.approval, now);
});
test('completion must match independently observed account, root, subject, challenge, digest and host', async () => {
  for (const field of ['rootPublicKey', 'subjectPublicKey', 'credentialDigest', 'pairingChallenge']) {
    const changed = structuredClone(binding.approval); changed[field][0] ^= 1;
    await assert.rejects(verifyBrowserPairingCompletion(completion, binding.host, changed, now), /current approval/);
  }
  await assert.rejects(verifyBrowserPairingCompletion(completion, binding.host, { ...binding.approval, accountId: '00000000-0000-0000-0000-000000000099' }, now), /current approval/);
  const host = structuredClone(binding.host); host.publicKey[0] ^= 1;
  await assert.rejects(verifyBrowserPairingCompletion(completion, host, binding.approval, now), /current approval/);
  for (const changed of [{ ...completion, clientOperationId: 'other' }, { ...completion, pairing: { ...completion.pairing, id: '00000000-0000-0000-0000-000000000098' } }]) {
    await assert.rejects(verifyBrowserPairingCompletion(changed, binding.host, binding.approval, now), /current approval/);
  }
});
test('expiry, invalid signatures and mismatched subject keys cannot complete pairing', async () => {
  for (const time of [binding.approval.notBeforeUnixSeconds - 1n, binding.approval.expiresAtUnixSeconds]) {
    await assert.rejects(verifyBrowserPairingCompletion(completion, binding.host, binding.approval, time), /lifetime/);
  }
  const changed = structuredClone(completion); changed.proof.value.signatures[0].signature[0] ^= 1;
  await assert.rejects(verifyBrowserPairingCompletion(changed, binding.host, binding.approval, now), /signature/);
  await assert.rejects(signBrowserPairingInitiation(binding.host, 'start', now, { ...signer, sign: async () => new Uint8Array(64) }), /signature/);
  await assert.rejects(signBrowserPairingCompletion(binding.host, 'finish', completion.pairing, binding.approval, now, { ...signer, publicKey: new Uint8Array(32) }), /key or lifetime/);
});
test('async signer cannot change the operation reference or current approval after signing starts', async () => {
  const ref = structuredClone(completion.pairing);
  const approval = structuredClone(binding.approval);
  const finish = await signBrowserPairingCompletion(binding.host, 'browser-complete', ref, approval, now, { ...signer, sign: async data => {
    ref.id = '00000000-0000-0000-0000-000000000099';
    approval.accountId = '00000000-0000-0000-0000-000000000098';
    return signer.sign(data);
  } });
  assert.deepEqual(toBinary(CompletePairingRequestSchema, finish), bytes(fixture.completion));
});
