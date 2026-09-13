import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { create } from '@bufbuild/protobuf';
import { AuthorizationKeyAlgorithm, SpoolCreationStatementSchema } from '../packages/typescript/dist/v2alpha1/owner_records_pb.js';
import { canonicalSpoolCreation, spoolCreationSigningDigest, spoolGenesisDigest } from '../packages/typescript/dist/v2alpha1/spool-creation.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/spool-creation-v1-rust.json', import.meta.url), 'utf8'));
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
