import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createPublicKey, verify } from 'node:crypto';
import { fromBinary, toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/identity_pb.js';
import { AuthorizationVerificationKeySchema, SignedOwnerKeyTransitionSchema } from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import { canonicalCustodialEmailBinding, custodialEmailSecretHash, validateCustodialEmailProof,
  canonicalCustodialRecover, custodialProposalSigningDigest, validateCustodialSubmission, decodeCustodialRecoveryProof } from '../packages/typescript/dist/v1alpha2/custodial-recovery.js';

const f = JSON.parse(readFileSync(new URL('./fixtures/custodial-recovery-v1.json', import.meta.url)));
const bytes = hex => new Uint8Array(Buffer.from(hex, 'hex'));
const decode = (schema, hex) => fromBinary(schema, bytes(hex));
const attempt = () => decode(api.RecoveryAttemptSchema, f.attempt_wire_hex);
const proposal = () => decode(api.CustodialRecoverProposalSchema, f.proposal_wire_hex);
const submit = () => decode(api.SubmitCustodialRecoverRequestSchema, f.submit_wire_hex);
const old = decode(AuthorizationVerificationKeySchema, f.old_guardian_wire_hex);
const publicKey = raw => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw)]), format: 'der', type: 'spki' });

test('custody wire vectors retain typed email proof and proposals in both directions', () => {
  for (const [schema, field] of [
    [api.BeginCustodialRecoveryRequestSchema, 'begin_wire_hex'], [api.CustodialEmailProofSchema, 'email_proof_wire_hex'],
    [api.SubmitRecoveryProofRequestSchema, 'proof_request_wire_hex'], [api.RecoveryAttemptSchema, 'attempt_wire_hex'],
    [api.CustodialRecoverProposalSchema, 'proposal_wire_hex'], [api.SubmitCustodialRecoverRequestSchema, 'submit_wire_hex'],
    [api.VetoCustodialRecoveryRequestSchema, 'veto_wire_hex'],
  ]) assert.deepEqual(toBinary(schema, decode(schema, f[field])), bytes(f[field]));
  assert.equal(decode(api.SubmitRecoveryProofRequestSchema, f.proof_request_wire_hex).proof.case, 'custodialEmail');
  assert.equal(proposal().recover.nextAuthorityKeyProof, undefined);
});

test('canonical email proof binds account, attempt, proposed root and challenge', () => {
  const proof = decode(api.CustodialEmailProofSchema, f.email_proof_wire_hex);
  assert.deepEqual(canonicalCustodialEmailBinding(proof.binding), bytes(f.email_canonical_hex));
  assert.deepEqual(custodialEmailSecretHash(proof), bytes(f.email_secret_hash_hex));
  validateCustodialEmailProof(proof, proof.binding, 1700000000n);
  assert.throws(() => validateCustodialEmailProof(proof, proof.binding, proof.binding.expiresAtUnixSeconds), /Expired/);
  for (const field of ['accountUuid', 'attemptUuid', 'proposedRootPublicKey', 'challenge']) {
    const changed = decode(api.CustodialEmailProofSchema, f.email_proof_wire_hex).binding;
    changed[field][0] ^= 1;
    assert.throws(() => validateCustodialEmailProof(proof, changed, 1700000000n), /Binding/);
  }
});

test('Recover recomputes canonical bytes and verifies old guardian, fresh guardian and new root signatures', () => {
  const p = proposal(), request = submit(), signed = decode(SignedOwnerKeyTransitionSchema, f.completed_recover_wire_hex), body = signed.transition;
  assert.deepEqual(canonicalCustodialRecover(body), bytes(f.canonical_transition_hex));
  const digest = custodialProposalSigningDigest(p);
  assert.deepEqual(digest, bytes(f.signing_digest_hex));
  for (const [key, signature] of [[old, signed.authorizations[0]], [body.nextAuthorityKey, signed.nextAuthorityKeyProof],
    [body.nextRecoveryPolicy.guardians[0].key, signed.nextRecoveryKeyProofs[0]]])
    assert.equal(verify(null, digest, publicKey(key.publicKey), signature.signature), true);
  validateCustodialSubmission(attempt(), p, request, old, 1700604800n);
  p.signingDigest[0] ^= 1;
  assert.throws(() => custodialProposalSigningDigest(p), /Proposal/);
  const changed = proposal(); changed.canonicalTransition[0] ^= 1;
  assert.throws(() => custodialProposalSigningDigest(changed), /Proposal/);
  body.nextRecoveryPolicy.windowSecs = undefined;
  assert.deepEqual(canonicalCustodialRecover(body), bytes(f.canonical_transition_hex));
});

test('veto retains current root signature in its distinct domain', () => {
  const veto = decode(api.VetoCustodialRecoveryRequestSchema, f.veto_wire_hex).veto;
  assert.equal(veto.format, 'heddle.custodial-recovery-veto.v1');
  assert.deepEqual(veto.signatures[0].publicKey, proposal().ownership.root.root.authorityKey.publicKey);
  assert.equal(verify(null, bytes(f.veto_signing_hex), publicKey(veto.signatures[0].publicKey), veto.signatures[0].signature), true);
});

for (const vector of f.negatives) test(vector.name, () => {
  if (vector.email_proof_wire_hex) {
    assert.throws(() => validateCustodialEmailProof(decode(api.CustodialEmailProofSchema, vector.email_proof_wire_hex),
      attempt().custodial.binding, 1700000000n), new RegExp(vector.error));
  } else {
    assert.throws(() => validateCustodialSubmission(
      vector.attempt_wire_hex ? decode(api.RecoveryAttemptSchema, vector.attempt_wire_hex) : attempt(),
      vector.proposal_wire_hex ? decode(api.CustodialRecoverProposalSchema, vector.proposal_wire_hex) : proposal(),
      vector.submit_wire_hex ? decode(api.SubmitCustodialRecoverRequestSchema, vector.submit_wire_hex) : submit(), old,
      BigInt(vector.now ?? '1700604800')), new RegExp(vector.error));
  }
});

test('absent custody and missing next guardian proof cannot submit', () => {
  const absent = attempt(); absent.custodial = undefined;
  assert.throws(() => validateCustodialSubmission(absent, proposal(), submit(), old, 1700604800n), /Binding/);
  const missing = submit(); missing.recover.nextRecoveryKeyProofs = [];
  assert.throws(() => validateCustodialSubmission(attempt(), proposal(), missing, old, 1700604800n), /FreshKey/);
});

test('prepare and client submission never contain W0 authorization', () => {
  assert.equal(proposal().recover.authorizations.length, 0);
  assert.equal(submit().recover.authorizations.length, 0);
  assert.equal(decode(SignedOwnerKeyTransitionSchema, f.completed_recover_wire_hex).authorizations.length, 1);
});

test('raw duplicate proof tags reject before last-wins in both orders', () => {
  const cases = { 3: 'signedTransition', 4: 'paperUnlock', 5: 'custodialEmail' };
  for (const vector of f.ambiguous_proofs) {
    assert.equal(decode(api.SubmitRecoveryProofRequestSchema, vector.raw_wire_hex).proof.case, cases[vector.last_tag]);
    assert.throws(() => decodeCustodialRecoveryProof(bytes(vector.raw_wire_hex)), /Binding/, vector.name);
  }
  const proof = bytes(f.proof_request_wire_hex);
  assert.deepEqual(toBinary(api.SubmitRecoveryProofRequestSchema, decodeCustodialRecoveryProof(proof)), proof);
  const atLimit = new Uint8Array(8192), length = 8192 - proof.length - 4;
  atLimit.set(proof); atLimit.set([0xa2, 0x06, (length & 0x7f) | 0x80, length >> 7], proof.length);
  assert.doesNotThrow(() => decodeCustodialRecoveryProof(atLimit));
  assert.throws(() => decodeCustodialRecoveryProof(new Uint8Array(8193)), /Binding/);
  for (const malformed of [[0x28, 0], [0x2a, 0xff], [0]])
    assert.throws(() => decodeCustodialRecoveryProof(new Uint8Array(malformed)), /Binding/);
});
