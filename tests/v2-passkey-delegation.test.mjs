import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign, createHash } from 'node:crypto';
import { clone, fromBinary } from '@bufbuild/protobuf';
import { SignedMintRootAttachmentSchema } from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import { canonicalPasskeyAuthority, passkeyAuthoritySigningDigest, mintRootAttachmentSigningDigest,
  signPasskeyAuthority, verifyMintRootAttachment } from '../packages/typescript/dist/v1alpha2/owner-certificates.js';

const vectors = JSON.parse(readFileSync(new URL('./fixtures/passkey-mint-delegation-v1-rust.json', import.meta.url), 'utf8'));
const key = seed => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)]), format: 'der', type: 'pkcs8' });
const publicKey = seed => new Uint8Array(createPublicKey(key(seed)).export({ format: 'der', type: 'spki' }).subarray(-32));
const owner = { publicKey: publicKey(81), sign: async digest => new Uint8Array(sign(null, digest, key(81))) };
const hex = bytes => Buffer.from(bytes).toString('hex');
// Use browser Uint8Array semantics: Buffer.slice() is a view and would make
// protobuf clones alias the fixture across independent negative cases.
const decode = vector => fromBinary(SignedMintRootAttachmentSchema, new Uint8Array(Buffer.from(vector.attachment_proto_hex, 'hex')));
function expectation(value, now) {
  return { accountUuid: new Uint8Array(16).fill(0x11), ownerStateHash: value.attachment.ownerStateHash.slice(),
    ownerSequence: 0n, ownerPublicKey: publicKey(81), mintRootPublicKey: publicKey(83), nowUnixSeconds: BigInt(now) };
}
function resignAssertion(value) {
  const proof = value.passkeyDelegation;
  proof.signature = new Uint8Array(sign(null, Buffer.concat([proof.authenticatorData,
    createHash('sha256').update(proof.clientDataJson).digest()]), key(82)));
}

assert.deepEqual(vectors.map(vector => vector.name), ['ed25519', 'es256'], 'both independently generated algorithms must be exercised');
for (const vector of vectors) {
  test(`native ${vector.name} passkey delegation verifies in browser and owner canonical bytes match`, async () => {
    const value = decode(vector);
    const authority = value.passkeyDelegation.authority.authority;
    assert.equal(hex(canonicalPasskeyAuthority(authority)), vector.authority_canonical_hex);
    assert.equal(hex(passkeyAuthoritySigningDigest(authority)), vector.authority_digest_hex);
    const signed = await signPasskeyAuthority(authority, owner);
    assert.equal(hex(signed.ownerSignature.signature), hex(value.passkeyDelegation.authority.ownerSignature.signature));
    await verifyMintRootAttachment(value, expectation(value, vector.now));
  });
}

test('a cryptographically valid assertion still requires exact challenge, origin, RP and user verification', async () => {
  const original = decode(vectors[0]);
  const expected = expectation(original, vectors[0].now);
  await verifyMintRootAttachment(original, expected);
  for (const [label, mutate] of [
    ['challenge', value => { value.attachment.nonce[0] ^= 1; }],
    ['RP', value => { value.passkeyDelegation.authenticatorData[0] ^= 1; }],
    ['UV', value => { value.passkeyDelegation.authenticatorData[32] = 1; }],
    ['origin', value => {
      const client = JSON.parse(new TextDecoder().decode(value.passkeyDelegation.clientDataJson));
      client.origin = 'https://other.heddle.test';
      value.passkeyDelegation.clientDataJson = new TextEncoder().encode(JSON.stringify(client));
    }],
    ['cross-origin', value => {
      const client = JSON.parse(new TextDecoder().decode(value.passkeyDelegation.clientDataJson));
      client.crossOrigin = true;
      value.passkeyDelegation.clientDataJson = new TextEncoder().encode(JSON.stringify(client));
    }],
  ]) {
    const changed = clone(SignedMintRootAttachmentSchema, original);
    mutate(changed);
    resignAssertion(changed);
    await assert.rejects(verifyMintRootAttachment(changed, expected), undefined, label);
  }
});

test('owner certificate bounds temporary mint lifetime even when the passkey signs a longer request', async () => {
  const value = decode(vectors[0]);
  const expected = expectation(value, vectors[0].now);
  value.attachment.expiresAtUnixSeconds = value.attachment.notBeforeUnixSeconds + 43201n;
  const client = JSON.parse(new TextDecoder().decode(value.passkeyDelegation.clientDataJson));
  client.challenge = Buffer.from(mintRootAttachmentSigningDigest(value.attachment)).toString('base64url');
  value.passkeyDelegation.clientDataJson = new TextEncoder().encode(JSON.stringify(client));
  resignAssertion(value);
  await assert.rejects(verifyMintRootAttachment(value, expected), /bounds/);
});

test('untrusted certificate cannot choose the account owner or mix two authorization forms', async () => {
  const value = decode(vectors[0]);
  const expected = expectation(value, vectors[0].now);
  const changed = clone(SignedMintRootAttachmentSchema, value);
  changed.passkeyDelegation.authority.authority.ownerKey.publicKey = publicKey(82);
  await assert.rejects(verifyMintRootAttachment(changed, expected), /current owner/);
  value.ownerSignature = value.passkeyDelegation.authority.ownerSignature;
  await assert.rejects(verifyMintRootAttachment(value, expected), /ambiguous/);
});
