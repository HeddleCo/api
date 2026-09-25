import assert from 'node:assert/strict';
import { test } from 'node:test';
import { create, toBinary } from '@bufbuild/protobuf';
import { PasswordOwnerEnvelopeV1Schema, PasswordOwnerSetupSchema } from '../packages/typescript/dist/v1alpha2/identity_pb.js';
import {
  decodePasswordOwnerEnvelopeCanonical, decodePasswordOwnerSetupCanonical, passwordChallengeSigningDigest,
  passwordDeviceAdmissionDigest, passwordOwnerSetupAuthorizationDigest, passwordOwnerSetupDigest,
  passwordOwnerWrapAad, validatePasswordOwnerEnvelope,
  validatePasswordOwnerSetup,
} from '../packages/typescript/dist/v1alpha2/password-owner.js';

const envelope = create(PasswordOwnerEnvelopeV1Schema, {
  formatVersion: 1, accountUuid: new Uint8Array(16).fill(1), ownerPublicKey: new Uint8Array(32).fill(2),
  ownerId: new Uint8Array(32).fill(3), kdfId: 1, memoryKib: 65536, iterations: 3, parallelism: 4,
  wrapSalt: new Uint8Array(16).fill(4), nonce: new Uint8Array(12).fill(5), ciphertextAndTag: new Uint8Array(48).fill(6),
});
const setup = create(PasswordOwnerSetupSchema, {
  envelope, authSalt: new Uint8Array(16).fill(7), authVerifierPublicKey: new Uint8Array(32).fill(8),
  authMemoryKib: 65536, authIterations: 3, authParallelism: 4,
});

test('password envelope and setup reject unsupported versions, costs, salts, and noncanonical bytes', () => {
  validatePasswordOwnerEnvelope(envelope);
  validatePasswordOwnerSetup(setup);
  assert.equal(passwordOwnerWrapAad(envelope).length, 141);
  assert.deepEqual(decodePasswordOwnerEnvelopeCanonical(toBinary(PasswordOwnerEnvelopeV1Schema, envelope)), envelope);
  assert.deepEqual(decodePasswordOwnerSetupCanonical(toBinary(PasswordOwnerSetupSchema, setup)), setup);
  assert.throws(() => validatePasswordOwnerEnvelope({ ...envelope, formatVersion: 2 }), /version/);
  assert.throws(() => validatePasswordOwnerEnvelope({ ...envelope, memoryKib: 1 }), /costs/);
  assert.throws(() => validatePasswordOwnerSetup({ ...setup, authSalt: envelope.wrapSalt }), /independent/);
  const wire = Uint8Array.from([...toBinary(PasswordOwnerEnvelopeV1Schema, envelope), 0x60, 0x01]);
  assert.throws(() => decodePasswordOwnerEnvelopeCanonical(wire), /Noncanonical/);
  const setupWire = Uint8Array.from([...toBinary(PasswordOwnerSetupSchema, setup), 0x38, 0x01]);
  assert.throws(() => decodePasswordOwnerSetupCanonical(setupWire), /Noncanonical/);
});

test('password and owner signatures have different bound transcripts', () => {
  const challenge = { accountUuid: envelope.accountUuid, authSalt: setup.authSalt,
    authMemoryKib: 65536, authIterations: 3, authParallelism: 4, envelopeRevision: 1n,
    challengeId: new Uint8Array(32).fill(9), nonce: new Uint8Array(32).fill(10) };
  const proof = { challengeId: challenge.challengeId, signature: new Uint8Array(), envelopeRevision: 1n,
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
  const authorization = { formatVersion: 1, action: 1, accountUuid: envelope.accountUuid,
    ownerStateHash: admission.ownerStateHash, expectedRevision: 3n, setupSha256: passwordOwnerSetupDigest(setup),
    clientOperationId: 'change-1' };
  const changeDigest = passwordOwnerSetupAuthorizationDigest(authorization, setup);
  assert.notDeepEqual(passwordOwnerSetupAuthorizationDigest({ ...authorization, expectedRevision: 4n }, setup), changeDigest);
  assert.throws(() => passwordOwnerSetupAuthorizationDigest(authorization,
    { ...setup, envelope: { ...envelope, ciphertextAndTag: new Uint8Array(48).fill(0) } }), /digest differs/);
});
