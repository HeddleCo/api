import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { clone, fromBinary, toBinary } from '@bufbuild/protobuf';
import { AuthenticationChallengeSchema, CredentialMethod, ThreadControlAuthoritySchema } from '../packages/typescript/dist/v1alpha2/identity_pb.js';
import { SignedMintRootAttachmentSchema, SpoolCreationProofSchema } from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import {
  PASSKEY_MINT_GRANT_DOMAIN,
  canonicalPasskeyMintGrant,
  passkeyMintGrantSigningDigest,
  verifyPasskeyAuthenticationChallenge,
  verifyPasskeyMintGrantWindow,
  verifyMintRootAttachment,
} from '../packages/typescript/dist/v1alpha2/owner-certificates.js';
import {
  decodeSpoolCreationProofForVerification,
  decodeThreadControlAuthorityForVerification,
  verifyMintRootAssociationWire,
} from '../packages/typescript/dist/v1alpha2/mint-root-association.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/passkey-mint-grant-v1.json', import.meta.url), 'utf8'));
const fromHex = value => new Uint8Array(Buffer.from(value, 'hex'));
const hex = value => Buffer.from(value).toString('hex');
const decode = value => fromBinary(SignedMintRootAttachmentSchema, fromHex(value));
const decodeChallenge = value => fromBinary(AuthenticationChallengeSchema, fromHex(value));
const positive = decode(fixture.positive.attachment_proto_hex);
const passkey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 82)]), format: 'der', type: 'pkcs8' });

function resignAssertion(value) {
  const proof = value.passkeyDelegation;
  proof.signature = new Uint8Array(sign(null, Buffer.concat([
    proof.authenticatorData,
    createHash('sha256').update(proof.clientDataJson).digest(),
  ]), passkey));
}

function expectation(now = fixture.positive.now_unix_seconds) {
  return {
    accountUuid: fromHex(fixture.positive.expected_owner.account_uuid_hex),
    ownerStateHash: fromHex(fixture.positive.expected_owner.owner_state_hash_hex),
    ownerSequence: BigInt(fixture.positive.expected_owner.owner_sequence),
    ownerPublicKey: fromHex(fixture.positive.expected_owner.owner_public_key_hex),
    mintRootPublicKey: fromHex(fixture.positive.grant.mint_root_public_key_hex),
    relyingPartyId: fixture.positive.grant.relying_party_id,
    nowUnixSeconds: BigInt(now),
  };
}

test('shared v2 grant digest and SignedMintRootAttachment bytes match the language-neutral golden vector', async () => {
  assert.equal(PASSKEY_MINT_GRANT_DOMAIN, fixture.canonical_encoding.domain);
  assert.equal(hex(canonicalPasskeyMintGrant(positive.grant)), fixture.positive.canonical_hex);
  assert.equal(hex(passkeyMintGrantSigningDigest(positive.grant)), fixture.positive.signing_digest_hex);
  assert.equal(hex(toBinary(SignedMintRootAttachmentSchema, positive)), fixture.positive.attachment_proto_hex);
  await verifyMintRootAttachment(positive, expectation());
});

test('every grant field is challenge-bound and tampering is rejected', async t => {
  const cases = fixture.negative_cases.filter(value => value.kind === 'tampered_grant');
  assert.deepEqual(cases.map(value => value.field), [
    'format_version',
    'mint_root_key',
    'not_before_unix_seconds',
    'expires_at_unix_seconds',
    'nonce',
    'relying_party_id',
  ]);
  for (const vector of cases) {
    await t.test(vector.id, async () => {
      await assert.rejects(verifyMintRootAttachment(decode(vector.attachment_proto_hex), expectation()));
    });
  }
});

test('the separate passkey challenge exactly binds the grant while other methods remain method-specific', () => {
  const positiveChallenge = decodeChallenge(fixture.positive.authentication_challenge_proto_hex);
  assert.doesNotThrow(() => verifyPasskeyAuthenticationChallenge(positiveChallenge));
  const vector = fixture.negative_cases.find(value => value.id === 'mismatching-authentication-challenge');
  const mismatch = decodeChallenge(vector.authentication_challenge_proto_hex);
  assert.throws(() => verifyPasskeyAuthenticationChallenge(mismatch), /does not bind/);

  mismatch.method = CredentialMethod.PASSWORD;
  mismatch.challenge = new Uint8Array([1]);
  assert.doesNotThrow(() => verifyPasskeyAuthenticationChallenge(mismatch));
});

test('shared grant-window vectors enforce the authority ceiling and exact half-open time', () => {
  for (const vector of fixture.window_cases) {
    const grant = clone(SignedMintRootAttachmentSchema, positive).grant;
    grant.notBeforeUnixSeconds = BigInt(vector.not_before_unix_seconds);
    grant.expiresAtUnixSeconds = BigInt(vector.expires_at_unix_seconds);
    const verify = () => verifyPasskeyMintGrantWindow(
      grant,
      vector.max_session_ttl_seconds,
      BigInt(vector.now_unix_seconds),
    );
    if (vector.accepted) assert.doesNotThrow(verify, vector.id);
    else assert.throws(verify, undefined, vector.id);
  }
});

test('checked raw decoders reject both oneof arms before protobuf last-wins decoding', () => {
  for (const vector of fixture.ambiguous_oneof_cases) {
    const raw = fromHex(vector.raw_proto_hex);
    assert.throws(() => verifyMintRootAssociationWire(raw), /both owner-v1 and passkey-v2/, vector.id);
    if (vector.message === 'ThreadControlAuthority') {
      assert.equal(fromBinary(ThreadControlAuthoritySchema, raw).mintRootAssociation.case, 'passkeyMintRootAttachment');
      assert.throws(() => decodeThreadControlAuthorityForVerification(raw), /both owner-v1 and passkey-v2/);
    } else {
      assert.equal(fromBinary(SpoolCreationProofSchema, raw).mintRootAssociation.case, 'passkeyMintRootAttachment');
      assert.throws(() => decodeSpoolCreationProofForVerification(raw), /both owner-v1 and passkey-v2/);
    }
  }
  assert.doesNotThrow(() => decodeThreadControlAuthorityForVerification(fromHex('08012200')));
  assert.doesNotThrow(() => decodeSpoolCreationProofForVerification(fromHex('3200')));
});

test('a fully re-signed assertion for a different relying party is rejected by the authority binding', async () => {
  const vector = fixture.negative_cases.find(value => value.id === 'wrong-relying-party-id');
  await assert.rejects(
    verifyMintRootAttachment(decode(vector.attachment_proto_hex), expectation(vector.now_unix_seconds)),
    /relying-party ID|bounds/,
  );
});

test('grant validity is half-open and rejects expired and not-yet-valid assertions', async t => {
  for (const id of ['expired', 'not-yet-valid']) {
    const vector = fixture.negative_cases.find(value => value.id === id);
    await t.test(id, async () => {
      await assert.rejects(
        verifyMintRootAttachment(positive, expectation(vector.now_unix_seconds)),
        /not currently valid/,
      );
    });
  }
});

test('a v1 account-bound attachment digest cannot substitute for the grant digest', async () => {
  const vector = fixture.negative_cases.find(value => value.id === 'v1-attachment-domain-confusion');
  assert.notEqual(vector.presented_challenge_hex, vector.expected_grant_digest_hex);
  assert.equal(vector.expected_grant_digest_hex, fixture.positive.signing_digest_hex);
  await assert.rejects(
    verifyMintRootAttachment(decode(vector.attachment_proto_hex), expectation(vector.now_unix_seconds)),
    /challenge or origin mismatch/,
  );
});

test('origin, authenticator RP, user verification, and same-origin context remain mandatory', async t => {
  for (const [id, mutate] of [
    ['authenticator-rp', value => { value.passkeyDelegation.authenticatorData[0] ^= 1; }],
    ['user-verification', value => { value.passkeyDelegation.authenticatorData[32] = 1; }],
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
    await t.test(id, async () => {
      const changed = clone(SignedMintRootAttachmentSchema, positive);
      mutate(changed);
      resignAssertion(changed);
      await assert.rejects(verifyMintRootAttachment(changed, expectation()));
    });
  }
});

test('the owner authority bounds TTL and cannot choose a different current owner', async () => {
  const excessive = clone(SignedMintRootAttachmentSchema, positive);
  excessive.grant.expiresAtUnixSeconds = excessive.grant.notBeforeUnixSeconds + 43201n;
  const client = JSON.parse(new TextDecoder().decode(excessive.passkeyDelegation.clientDataJson));
  client.challenge = Buffer.from(passkeyMintGrantSigningDigest(excessive.grant)).toString('base64url');
  excessive.passkeyDelegation.clientDataJson = new TextEncoder().encode(JSON.stringify(client));
  resignAssertion(excessive);
  await assert.rejects(verifyMintRootAttachment(excessive, expectation()), /ceiling/);

  const foreignOwner = clone(SignedMintRootAttachmentSchema, positive);
  foreignOwner.passkeyDelegation.authority.authority.ownerKey.publicKey[0] ^= 1;
  await assert.rejects(verifyMintRootAttachment(foreignOwner, expectation()), /current owner/);
});
