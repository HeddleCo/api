import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createPrivateKey, sign } from 'node:crypto';
import { fromBinary, toBinary } from '@bufbuild/protobuf';
import { SignedMintRootAttachmentSchema } from '../packages/typescript/dist/v2alpha1/owner_records_pb.js';
import { canonicalMintRootAttachment, mintRootAttachmentSigningDigest, signMintRootAttachment, verifyMintRootAttachment } from '../packages/typescript/dist/v2alpha1/owner-certificates.js';
const fixture = JSON.parse(readFileSync(new URL('./fixtures/mint-root-attachment-v1-rust.json', import.meta.url), 'utf8'));
const hex = value => new Uint8Array(Buffer.from(value, 'hex'));
const signed = fromBinary(SignedMintRootAttachmentSchema, hex(fixture.record_hex));
const expected = { accountUuid: hex(fixture.account_uuid_hex), ownerStateHash: hex(fixture.owner_state_hash_hex), ownerSequence: BigInt(fixture.owner_sequence), ownerPublicKey: hex(fixture.owner_public_key_hex), mintRootPublicKey: hex(fixture.mint_root_public_key_hex), nowUnixSeconds: 1000000n };
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 71)]), format: 'der', type: 'pkcs8' });
const signer = { publicKey: expected.ownerPublicKey, sign: async digest => new Uint8Array(sign(null, digest, privateKey)) };
test('mint-root certificate matches independent Rust canonical bytes, digest, signature and protobuf container', async () => {
  assert.deepEqual(canonicalMintRootAttachment(signed.attachment), hex(fixture.canonical_hex));
  assert.deepEqual(mintRootAttachmentSigningDigest(signed.attachment), hex(fixture.signing_digest_hex));
  await verifyMintRootAttachment(signed, expected);
  const actual = await signMintRootAttachment(signed.attachment, signer);
  assert.deepEqual(actual.ownerSignature.signature, hex(fixture.signature_hex));
  assert.deepEqual(toBinary(SignedMintRootAttachmentSchema, actual), hex(fixture.record_hex));
});
test('certificate cannot select its own trusted account, owner state, mint root or lifetime', async () => {
  for (const field of ['accountUuid', 'ownerStateHash', 'ownerPublicKey', 'mintRootPublicKey']) {
    const altered = structuredClone(expected); altered[field][0] ^= 1;
    await assert.rejects(verifyMintRootAttachment(signed, altered), /independently verified/);
  }
  await assert.rejects(verifyMintRootAttachment(signed, { ...expected, ownerSequence: 1n }), /independently verified/);
  await assert.rejects(verifyMintRootAttachment(signed, { ...expected, nowUnixSeconds: 999998n }), /currently valid/);
  await assert.rejects(verifyMintRootAttachment(signed, { ...expected, nowUnixSeconds: 1000050n }), /currently valid/);
});
test('owner signature and signer identity are verified, including a signer returning invalid bytes', async () => {
  const altered = structuredClone(signed); altered.ownerSignature.signature[0] ^= 1;
  await assert.rejects(verifyMintRootAttachment(altered, expected), /owner signature/);
  const wrongId = structuredClone(signed); wrongId.ownerSignature.signerKeyId[0] ^= 1;
  await assert.rejects(verifyMintRootAttachment(wrongId, expected), /signer identity/);
  await assert.rejects(signMintRootAttachment(signed.attachment, { ...signer, sign: async () => new Uint8Array(64) }), /owner signature/);
});
test('malformed version, keys, UUID and integer intervals fail before signing', async () => {
  let calls = 0; const count = { ...signer, sign: async data => { calls++; return signer.sign(data); } };
  for (const change of [{ formatVersion: 2 }, { accountUuid: new Uint8Array(16) }, { nonce: new Uint8Array(31) }, { ownerSequence: 1n << 64n }, { expiresAtUnixSeconds: -1n }, { ownerKey: { algorithm: 0, publicKey: expected.ownerPublicKey } }]) {
    await assert.rejects(signMintRootAttachment({ ...signed.attachment, ...change }, count));
  }
  assert.equal(calls, 0);
});
