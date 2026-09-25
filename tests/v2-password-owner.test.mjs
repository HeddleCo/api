import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { create, toBinary } from '@bufbuild/protobuf';
import { AuthenticationChallengeSchema, PasswordChallengeMetadataSchema, PasswordOwnerEnvelopeV1Schema, PasswordOwnerSetupSchema } from '../packages/typescript/dist/v1alpha2/identity_pb.js';
import { RecordRefSchema } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import {
  decodePasswordOwnerEnvelopeCanonical, decodePasswordOwnerSetupCanonical, passwordChallengeSigningDigest,
  passwordDeviceAdmissionDigest, passwordOwnerSetupAuthorizationDigest, passwordOwnerSetupDigest,
  passwordOwnerWrapAad, passwordRegistrationVerifierPossessionDigest, validatePasswordChallengeMetadata,
  validatePasswordOwnerEnvelope, validatePasswordOwnerSetup,
  validatePasswordOwnerSetupBinding, nextPasswordEnvelopeRevision, verifyPasswordAuthVerifierPossession,
  verifyPasswordAuthVerifierRegistrationPossession,
  verifyPasswordChallengeSignature,
  validatePasswordCompletionBindings, passwordMintAttachmentNonce,
  validatePasswordOwnerSetupAuthorizationExpiry,
} from '../packages/typescript/dist/v1alpha2/password-owner.js';

const key = (seed) => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)]), format: 'der', type: 'pkcs8' });
const publicKey = (privateKey) => new Uint8Array(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32));
const ownerKey = key(12);
const verifierKey = key(11);

const envelope = create(PasswordOwnerEnvelopeV1Schema, {
  formatVersion: 1, accountUuid: new Uint8Array(16).fill(1), ownerPublicKey: publicKey(ownerKey),
  ownerId: new Uint8Array(32).fill(3), kdfId: 1, memoryKib: 65536, iterations: 3, parallelism: 4,
  wrapSalt: new Uint8Array(16).fill(4), nonce: new Uint8Array(12).fill(5), ciphertextAndTag: new Uint8Array(48).fill(6),
});
const setup = create(PasswordOwnerSetupSchema, {
  envelope, authSalt: new Uint8Array(16).fill(7), authVerifierPublicKey: publicKey(verifierKey),
  authMemoryKib: 65536, authIterations: 3, authParallelism: 4, authKdfId: 1, formatVersion: 1,
  authVerifierPossessionSignature: new Uint8Array(sign(null, Buffer.alloc(32), verifierKey)),
});
setup.authVerifierPossessionSignature = new Uint8Array(sign(null, Buffer.alloc(32, 42), verifierKey));

test('password envelope and setup validate costs, salts, roots and canonical stored bytes', async () => {
  validatePasswordOwnerEnvelope(envelope);
  validatePasswordOwnerSetup(setup);
  assert.equal(passwordOwnerWrapAad(envelope).length, 141);
  assert.deepEqual(decodePasswordOwnerEnvelopeCanonical(toBinary(PasswordOwnerEnvelopeV1Schema, envelope)), envelope);
  assert.deepEqual(decodePasswordOwnerSetupCanonical(toBinary(PasswordOwnerSetupSchema, setup)), setup);
  assert.throws(() => validatePasswordOwnerEnvelope({ ...envelope, formatVersion: 2 }), /version/);
  assert.throws(() => validatePasswordOwnerEnvelope({ ...envelope, memoryKib: 1 }), /costs/);
  assert.throws(() => validatePasswordOwnerEnvelope({ ...envelope, ownerPublicKey: new Uint8Array(32) }), /Small-order/);
  assert.throws(() => validatePasswordOwnerEnvelope({ ...envelope, ownerPublicKey: new Uint8Array(32).fill(255) }), /Noncanonical/);
  assert.throws(() => validatePasswordOwnerEnvelope({ ...envelope, ownerPublicKey: new Uint8Array(32).fill(2) }), /Undecompressible/);
  assert.throws(() => validatePasswordOwnerSetup({ ...setup, authSalt: envelope.wrapSalt }), /independent/);
  const wire = Uint8Array.from([...toBinary(PasswordOwnerEnvelopeV1Schema, envelope), 0x60, 0x01]);
  assert.deepEqual(decodePasswordOwnerEnvelopeCanonical(wire), envelope);
  const setupWire = Uint8Array.from([...toBinary(PasswordOwnerSetupSchema, setup), 0x50, 0x01]);
  assert.deepEqual(decodePasswordOwnerSetupCanonical(setupWire), setup);
  validatePasswordOwnerSetupBinding(setup, envelope.accountUuid, envelope.ownerPublicKey, envelope.ownerId);
  assert.throws(() => validatePasswordOwnerSetupBinding(setup, envelope.accountUuid, envelope.ownerPublicKey, new Uint8Array(32)), /binding/);
  await verifyPasswordAuthVerifierPossession(setup, new Uint8Array(32).fill(42));
  assert.throws(() => validatePasswordOwnerSetup({ ...setup, authVerifierPublicKey: new Uint8Array(32) }), /Small-order/);
});

test('password and owner signatures have different bound transcripts', () => {
  const challenge = { authSalt: setup.authSalt,
    authMemoryKib: 65536, authIterations: 3, authParallelism: 4, authKdfId: 1, formatVersion: 1,
    challengeId: new Uint8Array(32).fill(9), nonce: new Uint8Array(32).fill(10) };
  const proof = { challengeId: challenge.challengeId, signature: new Uint8Array(),
    callerDevicePublicKey: new Uint8Array(32).fill(11) };
  const proofDigest = passwordChallengeSigningDigest(challenge, proof, 'prove-1', 1700000000n);
  const admission = { formatVersion: 1, accountUuid: envelope.accountUuid, challengeId: challenge.challengeId,
    continuationId: new Uint8Array(32).fill(12), callerDevicePublicKey: proof.callerDevicePublicKey,
    ownerStateHash: new Uint8Array(32).fill(13), ownerSequence: 1n, clientOperationId: 'complete-1' };
  const ownerDigest = passwordDeviceAdmissionDigest(admission);
  assert.notDeepEqual(proofDigest, ownerDigest);
  assert.notDeepEqual(passwordChallengeSigningDigest(challenge, proof, 'prove-2', 1700000000n), proofDigest);
  assert.notDeepEqual(passwordDeviceAdmissionDigest({ ...admission, continuationId: new Uint8Array(32).fill(14) }), ownerDigest);
  assert.equal(passwordOwnerSetupDigest(setup).length, 32);
  assert.deepEqual(passwordOwnerSetupDigest({ ...setup, authVerifierPossessionSignature: new Uint8Array() }), passwordOwnerSetupDigest(setup));
  assert.throws(() => validatePasswordOwnerSetup({ ...setup, authVerifierPossessionSignature: new Uint8Array() }), /signature/);
  const authorization = { formatVersion: 1, action: 1, accountUuid: envelope.accountUuid,
    ownerStateHash: admission.ownerStateHash, expectedRevision: 3n, setupSha256: passwordOwnerSetupDigest(setup),
    clientOperationId: 'change-1', expiresAt: { seconds: 1700000600n, nanos: 0 } };
  const changeDigest = passwordOwnerSetupAuthorizationDigest(authorization, setup);
  validatePasswordOwnerSetupAuthorizationExpiry(authorization, 1700000000n);
  assert.throws(() => validatePasswordOwnerSetupAuthorizationExpiry(authorization, 1700000600n), /expiry/);
  assert.notDeepEqual(passwordOwnerSetupAuthorizationDigest({ ...authorization, expectedRevision: 4n }, setup), changeDigest);
  assert.throws(() => passwordOwnerSetupAuthorizationDigest(authorization,
    { ...setup, envelope: { ...envelope, ciphertextAndTag: new Uint8Array(48).fill(0) } }), /digest differs/);
});

test('inactive password metadata has the same fields, shape and ranges as active metadata', () => {
  const active = create(PasswordChallengeMetadataSchema, { authSalt: new Uint8Array(16).fill(7),
    authMemoryKib: 65536, authIterations: 3, authParallelism: 4, authKdfId: 1, formatVersion: 1,
    challengeId: new Uint8Array(32).fill(9), nonce: new Uint8Array(32).fill(10) });
  const inactive = create(PasswordChallengeMetadataSchema, { ...active, authSalt: new Uint8Array(16).fill(21),
    challengeId: new Uint8Array(32).fill(22), nonce: new Uint8Array(32).fill(23) });
  assert.deepEqual(Object.keys(active), Object.keys(inactive));
  assert.deepEqual(Object.keys(active).filter(name => name !== '$typeName'),
    ['authSalt', 'authMemoryKib', 'authIterations', 'authParallelism', 'challengeId', 'nonce', 'authKdfId', 'formatVersion']);
  for (const value of [active, inactive]) {
    validatePasswordChallengeMetadata(value);
    assert.deepEqual([value.authSalt.length, value.challengeId.length, value.nonce.length], [16, 32, 32]);
    assert.deepEqual([value.authMemoryKib, value.authIterations, value.authParallelism, value.authKdfId, value.formatVersion],
      [65536, 3, 4, 1, 1]);
  }
  assert.equal(toBinary(PasswordChallengeMetadataSchema, active).length, toBinary(PasswordChallengeMetadataSchema, inactive).length);
  const credentialExpiresAt = { seconds: 1700001000n, nanos: 0 };
  const makeChallenge = (metadata, id) => create(AuthenticationChallengeSchema, {
    ref: create(RecordRefSchema, { id }), challenge: metadata.nonce,
    expiresAt: { seconds: 1700000000n, nanos: 0 }, method: 2,
    credentialExpiresAt, passwordChallenge: metadata,
  });
  const activeChallenge = makeChallenge(active, '8db685d0a2234ad89bb11d924b80d331');
  const inactiveChallenge = makeChallenge(inactive, 'f6c36765f468434fa07bb1a67f6a1fd4');
  assert.deepEqual(Object.keys(activeChallenge), Object.keys(inactiveChallenge));
  assert.deepEqual(Object.keys(activeChallenge).filter(name => name !== '$typeName'),
    ['ref', 'challenge', 'relyingPartyId', 'expiresAt', 'allowedCredentialIds', 'userVerification',
      'method', 'oauthProvider', 'credentialExpiresAt', 'passkeyAuthorities', 'passwordChallenge']);
  for (const value of [activeChallenge, inactiveChallenge]) {
    assert.equal(value.ref.spool, undefined);
    assert.ok(value.ref.id.length > 0);
    assert.equal(value.method, 2);
    assert.deepEqual(value.challenge, value.passwordChallenge.nonce);
    assert.deepEqual([value.credentialExpiresAt.seconds, value.credentialExpiresAt.nanos],
      [credentialExpiresAt.seconds, credentialExpiresAt.nanos]);
    assert.equal(value.passkeyMintGrant, undefined);
    assert.deepEqual(value.allowedCredentialIds, []);
    assert.deepEqual(value.passkeyAuthorities, []);
  }
  assert.notEqual(activeChallenge.ref.id, inactiveChallenge.ref.id);
  assert.equal(toBinary(AuthenticationChallengeSchema, activeChallenge).length,
    toBinary(AuthenticationChallengeSchema, inactiveChallenge).length);
  assert.throws(() => validatePasswordChallengeMetadata({ ...active, authKdfId: 0 }), /version or KDF/);
  assert.throws(() => validatePasswordChallengeMetadata({ ...active, formatVersion: 2 }), /version or KDF/);
});

test('lifetime revision retains a tombstone and rejects old expected revisions', () => {
  const first = nextPasswordEnvelopeRevision(undefined, 0n);
  const replaced = nextPasswordEnvelopeRevision(first, first);
  const tombstone = nextPasswordEnvelopeRevision(replaced, replaced);
  const recreated = nextPasswordEnvelopeRevision(tombstone, tombstone);
  assert.equal(recreated, 4n);
  assert.throws(() => nextPasswordEnvelopeRevision(recreated, 1n), /revision differs/);
  assert.throws(() => nextPasswordEnvelopeRevision(tombstone, 0n), /revision differs/);
});

test('shared password-owner v1 hex vectors and strict Ed25519 edge signature', async () => {
  const vector = JSON.parse(readFileSync(new URL('./fixtures/password-owner-v1.json', import.meta.url), 'utf8'));
  const bytes = (name) => new Uint8Array(Buffer.from(vector[name], 'hex'));
  const check = (actual, name) => assert.equal(Buffer.from(actual).toString('hex'), vector[name]);
  const sampleEnvelope = create(PasswordOwnerEnvelopeV1Schema, { ...envelope, ownerPublicKey: bytes('owner_public_key_hex') });
  const sampleSetup = create(PasswordOwnerSetupSchema, { ...setup, envelope: sampleEnvelope,
    authVerifierPublicKey: bytes('verifier_public_key_hex'),
    authVerifierPossessionSignature: bytes('verifier_possession_signature_hex') });
  check(passwordOwnerWrapAad(sampleEnvelope), 'aad_hex');
  check(passwordOwnerSetupDigest(sampleSetup), 'setup_digest_hex');
  const challenge = { authSalt: sampleSetup.authSalt, authMemoryKib: 65536, authIterations: 3,
    authParallelism: 4, authKdfId: 1, formatVersion: 1, challengeId: new Uint8Array(32).fill(9), nonce: new Uint8Array(32).fill(10) };
  const proof = { challengeId: challenge.challengeId, signature: new Uint8Array(64),
    callerDevicePublicKey: bytes('device_public_key_hex') };
  check(passwordChallengeSigningDigest(challenge, proof, vector.operation_id, 1700000000n), 'proof_digest_hex');
  const admission = { formatVersion: 1, accountUuid: sampleEnvelope.accountUuid,
    challengeId: challenge.challengeId, continuationId: new Uint8Array(32).fill(12),
    callerDevicePublicKey: proof.callerDevicePublicKey, ownerStateHash: new Uint8Array(32).fill(13),
    ownerSequence: 7n, clientOperationId: vector.operation_id };
  check(passwordDeviceAdmissionDigest(admission), 'admission_digest_hex');
  const authorization = { formatVersion: 1, action: 1, accountUuid: sampleEnvelope.accountUuid,
    ownerStateHash: admission.ownerStateHash, expectedRevision: 3n, setupSha256: passwordOwnerSetupDigest(sampleSetup),
    clientOperationId: vector.operation_id, expiresAt: { seconds: 1700000600n, nanos: 0 } };
  check(passwordOwnerSetupAuthorizationDigest(authorization, sampleSetup), 'setup_authorization_digest_hex');
  await verifyPasswordAuthVerifierPossession(sampleSetup, passwordOwnerSetupAuthorizationDigest(authorization, sampleSetup));
  const registrationChallenge = new Uint8Array(32).fill(42);
  check(passwordRegistrationVerifierPossessionDigest(registrationChallenge), 'registration_challenge_digest_hex');
  const registrationSetup = { ...sampleSetup, authVerifierPossessionSignature: bytes('registration_verifier_possession_signature_hex') };
  await verifyPasswordAuthVerifierRegistrationPossession(registrationSetup, registrationChallenge);
  await assert.rejects(() => verifyPasswordAuthVerifierPossession(registrationSetup, registrationChallenge), /Invalid verifier possession signature/);
  await assert.rejects(() => verifyPasswordChallengeSignature(challenge,
    { ...proof, signature: bytes('edge_signature_hex') }, vector.operation_id, 1700000000n,
    sampleSetup.authVerifierPublicKey), /Noncanonical signature S/);
});

test('password completion binds the challenge, device, attachment nonce and expiry', () => {
  const ref = create(RecordRefSchema, { id: 'password-challenge' });
  const metadata = { authSalt: new Uint8Array(16).fill(7), authMemoryKib: 65536, authIterations: 3,
    authParallelism: 4, authKdfId: 1, formatVersion: 1, challengeId: new Uint8Array(32).fill(9), nonce: new Uint8Array(32).fill(10) };
  const challenge = { ref, method: 2, passwordChallenge: metadata,
    credentialExpiresAt: { seconds: 1700001000n, nanos: 0 } };
  const continuation = { envelope, continuationId: new Uint8Array(32).fill(12), envelopeRevision: 3n };
  const deviceKey = publicKey(key(13));
  const admission = { formatVersion: 1, accountUuid: envelope.accountUuid, challengeId: metadata.challengeId,
    continuationId: continuation.continuationId, callerDevicePublicKey: deviceKey,
    ownerStateHash: new Uint8Array(32).fill(13), ownerSequence: 7n, clientOperationId: 'complete' };
  const attachment = { accountUuid: admission.accountUuid, ownerStateHash: admission.ownerStateHash,
    ownerSequence: 7n, mintRootKey: { algorithm: 1, publicKey: deviceKey },
    nonce: passwordMintAttachmentNonce(metadata.nonce, continuation.continuationId),
    expiresAtUnixSeconds: 1700001000n };
  const completion = { continuationId: continuation.continuationId, ownerAdmission: { admission },
    mintRootAttachment: { attachment } };
  const request = { clientOperationId: 'complete', challenge: ref, proof: { case: 'passwordUnlock', value: completion },
    callerPublicKey: deviceKey, enrollDevice: true, ephemeralPublicKey: new Uint8Array() };
  validatePasswordCompletionBindings(request, challenge, continuation, deviceKey);
  assert.throws(() => validatePasswordCompletionBindings({ ...request, challenge: undefined },
    { ...challenge, ref: undefined }, continuation, deviceKey), /binding differs/);
  assert.throws(() => validatePasswordCompletionBindings({ ...request, challenge: create(RecordRefSchema, { id: 'other' }) },
    challenge, continuation, deviceKey), /binding differs/);
  assert.throws(() => validatePasswordCompletionBindings({ ...request, proof: { case: 'passwordUnlock',
    value: { ...completion, mintRootAttachment: { attachment: { ...attachment, nonce: new Uint8Array(32) } } } } },
  challenge, continuation, deviceKey), /binding differs/);
});
