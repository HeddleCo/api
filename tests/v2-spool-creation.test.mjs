import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { create, fromBinary } from '@bufbuild/protobuf';
import { createPrivateKey, sign } from 'node:crypto';
import { AuthorizationKeyAlgorithm, OwnerHistorySchema, SignedMintRootAttachmentSchema, SignedOwnerRootSchema, SpoolCreationStatementSchema } from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import { canonicalSpoolCreation, signDelegatedSpoolCreation, spoolCreationSigningDigest, spoolGenesisDigest } from '../packages/typescript/dist/v1alpha2/spool-creation.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/spool-creation-v1-rust.json', import.meta.url), 'utf8'));
const passkeyFixture = JSON.parse(readFileSync(new URL('./fixtures/passkey-mint-grant-v1.json', import.meta.url), 'utf8'));
const hex = value => new Uint8Array(Buffer.from(value, 'hex'));
const genesis = { spoolUuid: hex(fixture.spool_uuid_hex), ownerPublicKey: { algorithm: AuthorizationKeyAlgorithm.ED25519, publicKey: hex(fixture.owner_public_key_hex) } };
const statement = create(SpoolCreationStatementSchema, { formatVersion: 1, genesisDigest: hex(fixture.spool_genesis_digest_hex), accountUuid: hex(fixture.account_uuid_hex), ownerStateHash: hex(fixture.owner_state_hash_hex), ownerSequence: BigInt(fixture.owner_sequence), creatorKey: { algorithm: AuthorizationKeyAlgorithm.ED25519, publicKey: hex(fixture.creator_public_key_hex) }, parentSpoolUuid: hex(fixture.parent_spool_uuid_hex), parentPathSegments: fixture.parent_path_segments, name: fixture.name, createdAtUnixSeconds: BigInt(fixture.created_at_unix_seconds) });
test('delegated Spool creation matches independent Rust canonical bytes and digests', () => {
  assert.deepEqual(spoolGenesisDigest(genesis), hex(fixture.spool_genesis_digest_hex));
  assert.deepEqual(canonicalSpoolCreation(statement), hex(fixture.canonical_spool_creation_hex));
  assert.deepEqual(spoolCreationSigningDigest(statement), hex(fixture.spool_creation_signing_digest_hex));
});
test('creation binds exact parent path and owner state', () => {
  assert.notDeepEqual(spoolCreationSigningDigest({ ...statement, parentPathSegments: ['other'] }), spoolCreationSigningDigest(statement));
  assert.notDeepEqual(spoolCreationSigningDigest({ ...statement, ownerStateHash: new Uint8Array(32) }), spoolCreationSigningDigest(statement));
  assert.throws(() => canonicalSpoolCreation({ ...statement, parentSpoolUuid: new Uint8Array() }), /parent UUID/);
});
test('delegated signature freezes the exact statement and proof before deferred signing', async () => {
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 72)]), format: 'der', type: 'pkcs8' });
  let release;
  const held = new Promise(resolve => { release = resolve; });
  const input = { spoolUuid: genesis.spoolUuid.slice(), accountUuid: statement.accountUuid.slice(), ownerStateHash: statement.ownerStateHash.slice(), ownerSequence: 0n,
    ownerPublicKey: genesis.ownerPublicKey.publicKey.slice(), creatorPublicKey: statement.creatorKey.publicKey.slice(), parentSpoolUuid: statement.parentSpoolUuid.slice(),
    parentPathSegments: [...statement.parentPathSegments], name: statement.name, createdAtUnixSeconds: statement.createdAtUnixSeconds,
    sealedBiscuit: new Uint8Array([1, 2]), ownerHistory: create(OwnerHistorySchema, { root: create(SignedOwnerRootSchema), stateHash: statement.ownerStateHash.slice() }),
    passkeyMintRootAttachment: fromBinary(SignedMintRootAttachmentSchema, hex(passkeyFixture.positive.attachment_proto_hex)),
    sign: async digest => { await held; return new Uint8Array(sign(null, digest, privateKey)); } };
  const pending = signDelegatedSpoolCreation(input);
  input.spoolUuid[0] ^= 1; input.parentPathSegments[0] = 'changed'; input.sealedBiscuit[0] = 9; input.ownerHistory.stateHash[0] ^= 1;
  input.passkeyMintRootAttachment.grant.nonce[0] ^= 1;
  release();
  const result = await pending;
  assert.deepEqual(result.delegatedCreation.statement.parentPathSegments, ['acme']);
  assert.deepEqual(result.delegatedCreation.sealedBiscuit, new Uint8Array([1, 2]));
  assert.deepEqual(result.genesis.spoolUuid, genesis.spoolUuid);
  assert.equal(result.delegatedCreation.mintRootAssociation.case, 'passkeyMintRootAttachment');
  assert.deepEqual(result.delegatedCreation.mintRootAssociation.value.grant.nonce, new Uint8Array(32).fill(9));
  await assert.rejects(signDelegatedSpoolCreation({ ...input, ownerHistory: create(OwnerHistorySchema, { root: create(SignedOwnerRootSchema), stateHash: statement.ownerStateHash }), sign: async () => new Uint8Array(64) }), /Invalid creator signature/);
});
