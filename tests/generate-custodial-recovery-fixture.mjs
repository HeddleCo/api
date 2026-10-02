// Deterministic public test keys only; run after npm run build.
import { createPrivateKey, createPublicKey, createHash, sign } from 'node:crypto';
import { create, toBinary, fromBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/identity_pb.js';
import * as owner from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import { OwnerStateSchema } from '../packages/typescript/dist/v1alpha2/owner_views_pb.js';
import { RecordRefSchema, SignedRecordSchema } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import { canonicalCustodialEmailBinding, custodialEmailSecretHash, CUSTODIAL_VETO } from '../packages/typescript/dist/v1alpha2/custodial-recovery.js';
import { canonicalOwnerAction } from '../packages/typescript/dist/v1alpha2/owner-actions.js';

const b = (size, value) => new Uint8Array(size).fill(value);
const hex = value => Buffer.from(value).toString('hex');
const hash = (...parts) => new Uint8Array(createHash('sha256').update(Buffer.concat(parts.map(p => Buffer.from(p)))).digest());
const int = (value, width) => { const out = Buffer.alloc(width); width === 4 ? out.writeUInt32BE(Number(value)) : out.writeBigUInt64BE(BigInt(value)); return out; };
const counted = value => Buffer.concat([int(value.length, 4), Buffer.from(value)]);
const key = seed => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)]), format: 'der', type: 'pkcs8' });
const keys = [11, 12, 13, 14].map(key);
const verificationKeys = keys.map(k => create(owner.AuthorizationVerificationKeySchema, {
  algorithm: 1, publicKey: new Uint8Array(createPublicKey(k).export({ format: 'der', type: 'spki' }).subarray(-32)),
}));
const [oldRoot, oldGuardian, newRoot, freshGuardian] = verificationKeys;
const kid = k => hash(Buffer.from('heddle-key-v1'), int(k.algorithm, 4), k.publicKey);
const signature = (index, digest) => create(owner.AuthorizationSignatureSchema, {
  signerKeyId: kid(verificationKeys[index]), signature: new Uint8Array(sign(null, digest, keys[index])),
});
const keyBody = k => Buffer.concat([int(k.algorithm, 4), counted(k.publicKey)]);
const policy = k => create(owner.RecoveryPolicySchema, { threshold: 1,
  guardians: [{ kind: 3, key: k }], windowSecs: 604800n });
const policyBody = p => Buffer.concat([int(p.threshold, 4), int(p.guardians.length, 4),
  ...p.guardians.map(g => Buffer.concat([int(g.kind, 4), keyBody(g.key)])), int(p.windowSecs ?? 604800n, 8)]);
const account = b(16, 1), accountId = '01010101-0101-0101-0101-010101010101';
const attemptId = '02020202-0202-0202-0202-020202020202';
const root = create(owner.OwnerRootSchema, { formatVersion: 1, accountUuid: account,
  authorityKey: oldRoot, recoveryPolicy: policy(oldGuardian), nonce: b(32, 5) });
const withoutId = Buffer.concat([int(1, 4), counted(account), keyBody(oldRoot), policyBody(root.recoveryPolicy),
  Buffer.from([0]), counted(root.nonce), int(0, 8)]);
root.ownerId = hash(Buffer.from('heddle-owner-root-v1'), withoutId);
const rootBody = Buffer.concat([int(1, 4), counted(root.ownerId), withoutId.subarray(4)]);
const rootDigest = hash(Buffer.from('heddle-owner-root-v1'), rootBody);
const signedRoot = create(owner.SignedOwnerRootSchema, { root, authorityProof: signature(0, rootDigest),
  recoveryKeyProofs: [signature(1, rootDigest)] });
const binding = create(api.CustodialEmailBindingSchema, { formatVersion: 1, accountUuid: account,
  attemptUuid: b(16, 2), proposedRootPublicKey: newRoot.publicKey, challenge: b(32, 4),
  expiresAtUnixSeconds: 1700000600n });
const proof = create(api.CustodialEmailProofSchema, { binding, emailSecret: b(32, 6) });
const reference = create(RecordRefSchema, { id: attemptId });
const attempt = create(api.RecoveryAttemptSchema, { ref: reference, version: b(32, 3), challenge: binding.challenge,
  eligibleAt: { seconds: 1700604800n }, custodial: { binding, state: 4,
    startedAt: { seconds: 1700000000n }, expiresAt: { seconds: 1700691200n },
    ownerStateHash: rootDigest, effectiveWindowSecs: 604800n } });
const body = create(owner.OwnerKeyTransitionSchema, { formatVersion: 1, ownerId: root.ownerId,
  previousStateHash: rootDigest, sequence: 1n, kind: 2, nextAuthorityKey: newRoot,
  nextRecoveryPolicy: policy(freshGuardian), validFromUnixSeconds: attempt.eligibleAt.seconds, nonce: b(32, 7) });
const transitionBody = body => Buffer.concat([int(body.formatVersion, 4), counted(body.ownerId), counted(body.previousStateHash),
  int(body.sequence, 8), int(body.kind, 4), keyBody(body.nextAuthorityKey), policyBody(body.nextRecoveryPolicy),
  int(body.validFromUnixSeconds, 8), int(body.previousKeyValidUntilUnixSeconds, 8), counted(body.nonce)]);
const canonical = transitionBody(body);
const digest = hash(Buffer.from('heddle-owner-key-transition-v1'), canonical);
// Preparation releases only W1 possession, never W0 authorization.
const prepared = create(owner.SignedOwnerKeyTransitionSchema, { transition: body,
  nextRecoveryKeyProofs: [signature(3, digest)] });
const ownership = create(OwnerStateSchema, { owner: { id: accountId }, version: rootDigest, root: signedRoot });
const proposal = create(api.CustodialRecoverProposalSchema, { recovery: attempt, ownership, recover: prepared,
  canonicalTransition: canonical, signingDigest: digest });
const submit = create(api.SubmitCustodialRecoverRequestSchema, { clientOperationId: 'submit-1',
  recovery: reference, expectedVersion: attempt.version, recover: { ...prepared, nextAuthorityKeyProof: signature(2, digest) } });
const proofRequest = create(api.SubmitRecoveryProofRequestSchema, { clientOperationId: 'prove-1',
  recovery: reference, proof: { case: 'custodialEmail', value: proof } });
const vetoCanonical = canonicalOwnerAction(accountId, 'veto-1', reference, attempt.version, newRoot.publicKey);
const vetoSigning = Buffer.concat([Buffer.from(CUSTODIAL_VETO), Buffer.from([0]), Buffer.from(vetoCanonical)]);
const veto = create(api.VetoCustodialRecoveryRequestSchema, { clientOperationId: 'veto-1', recovery: reference,
  expectedVersion: attempt.version, veto: create(SignedRecordSchema, { format: CUSTODIAL_VETO,
    canonicalRecord: vetoCanonical, signatures: [{ publicKey: oldRoot.publicKey,
      signature: new Uint8Array(sign(null, vetoSigning, keys[0])) }] }) });
const wire = (schema, value) => hex(toBinary(schema, value));
const changedSubmit = change => {
  const value = fromBinary(api.SubmitCustodialRecoverRequestSchema, toBinary(api.SubmitCustodialRecoverRequestSchema, submit));
  change(value); return wire(api.SubmitCustodialRecoverRequestSchema, value);
};
const clone = (schema, value) => fromBinary(schema, toBinary(schema, value));
const completed = create(owner.SignedOwnerKeyTransitionSchema, {
  ...submit.recover, authorizations: [signature(1, digest)],
});
// Re-sign every role after body mutation. These are public deterministic test
// keys, not another verifier. The released verifier checks their acceptance.
const signedMutation = (change, guardianIndex = 3) => {
  const signed = clone(owner.SignedOwnerKeyTransitionSchema, completed);
  change(signed.transition);
  const canonical = transitionBody(signed.transition);
  const digest = hash(Buffer.from('heddle-owner-key-transition-v1'), canonical);
  signed.authorizations = [signature(1, digest)];
  signed.nextAuthorityKeyProof = signature(2, digest);
  signed.nextRecoveryKeyProofs = [signature(guardianIndex, digest)];
  return { signed, canonical, digest };
};
const pendingMutation = mutation => {
  const p = clone(api.CustodialRecoverProposalSchema, proposal);
  p.recover = clone(owner.SignedOwnerKeyTransitionSchema, mutation.signed);
  p.recover.authorizations = []; p.recover.nextAuthorityKeyProof = undefined;
  p.canonicalTransition = mutation.canonical; p.signingDigest = mutation.digest;
  const r = clone(api.SubmitCustodialRecoverRequestSchema, submit);
  r.recover = clone(owner.SignedOwnerKeyTransitionSchema, mutation.signed);
  r.recover.authorizations = [];
  return { proposal_wire_hex: wire(api.CustodialRecoverProposalSchema, p),
    submit_wire_hex: wire(api.SubmitCustodialRecoverRequestSchema, r) };
};
const retained = signedMutation(body => { body.nextRecoveryPolicy = policy(oldGuardian); }, 1);
const backdated = signedMutation(body => { body.validFromUnixSeconds -= 1n; });
const otherProof = create(api.CustodialEmailProofSchema, { ...proof, binding: { ...binding, attemptUuid: b(16, 9) } });
const changedAttempt = change => {
  const value = clone(api.RecoveryAttemptSchema, attempt); change(value);
  return wire(api.RecoveryAttemptSchema, value);
};
const vetoedHex = changedAttempt(v => { v.vetoed = true; v.custodial.state = 5; });
const helperNegatives = [
  { name: 'replayed_email_from_other_attempt', error: 'Binding', email_proof_wire_hex: wire(api.CustodialEmailProofSchema, otherProof) },
  { name: 'omitted_fresh_guardian', error: 'FreshKey', submit_wire_hex: changedSubmit(v => { v.recover.transition.nextRecoveryPolicy = undefined; }) },
  { name: 'empty_guardian_policy', error: 'FreshKey', submit_wire_hex: changedSubmit(v => { v.recover.transition.nextRecoveryPolicy.guardians = []; }) },
  { name: 'wrong_kind_guardian', error: 'FreshKey', submit_wire_hex: changedSubmit(v => { v.recover.transition.nextRecoveryPolicy.guardians[0].kind = 1; }) },
  { name: 'missing_w1_proof', error: 'FreshKey', submit_wire_hex: changedSubmit(v => { v.recover.nextRecoveryKeyProofs = []; }) },
  { name: 'wrong_w1_signer', error: 'FreshKey', submit_wire_hex: changedSubmit(v => { v.recover.nextRecoveryKeyProofs = [signature(1, digest)]; }) },
  { name: 'retained_old_guardian', error: 'FreshKey', ...pendingMutation(retained) },
  { name: 'guardian_equals_r1', error: 'FreshKey', ...pendingMutation(signedMutation(body => { body.nextRecoveryPolicy = policy(newRoot); }, 2)) },
  { name: 'backdated_valid_from', error: 'Proposal', ...pendingMutation(backdated) },
  { name: 'w0_released_in_prepare', error: 'Proposal', proposal_wire_hex: (() => {
    const p = clone(api.CustodialRecoverProposalSchema, proposal); p.recover.authorizations = completed.authorizations;
    return wire(api.CustodialRecoverProposalSchema, p);
  })() },
  { name: 'w0_in_client_submission', error: 'Proposal', submit_wire_hex: changedSubmit(v => { v.recover.authorizations = completed.authorizations; }) },
  { name: 'missing_r1_proof', error: 'Proposal', submit_wire_hex: changedSubmit(v => { v.recover.nextAuthorityKeyProof = undefined; }) },
  { name: 'wrong_r1_signer', error: 'Proposal', submit_wire_hex: changedSubmit(v => { v.recover.nextAuthorityKeyProof = signature(1, digest); }) },
  { name: 'submission_before_window', error: 'Early', now: '1700604799' },
  { name: 'submission_after_veto', error: 'State', attempt_wire_hex: vetoedHex },
  { name: 'submission_at_expiry', error: 'Expired', now: '1700691200' },
  { name: 'unknown_state', error: 'State', attempt_wire_hex: changedAttempt(v => { v.custodial.state = 99; }) },
  { name: 'zero_state', error: 'State', attempt_wire_hex: changedAttempt(v => { v.custodial.state = 0; }) },
  { name: 'zero_window', error: 'Binding', attempt_wire_hex: changedAttempt(v => { v.custodial.effectiveWindowSecs = 0n; }) },
  { name: 'overflowing_window', error: 'Binding', attempt_wire_hex: changedAttempt(v => { v.custodial.effectiveWindowSecs = 0xffffffffffffffffn; }) },
  { name: 'start_plus_window_overflow', error: 'Binding', attempt_wire_hex: changedAttempt(v => { v.custodial.startedAt.seconds = 0x7fffffffffffffffn; }) },
  { name: 'eligibility_plus_expiry_overflow', error: 'Binding', attempt_wire_hex: changedAttempt(v => {
    v.custodial.startedAt.seconds = 0x7fffffffffffffffn - 604800n; v.eligibleAt.seconds = 0x7fffffffffffffffn;
  }) },
  { name: 'stale_attempt_version', error: 'Version', submit_wire_hex: changedSubmit(v => { v.expectedVersion = b(32, 8); }) },
  { name: 'short_attempt_version', error: 'Version', attempt_wire_hex: changedAttempt(v => { v.version = b(31, 3); }) },
  { name: 'altered_prepared_nonce', error: 'Proposal', submit_wire_hex: changedSubmit(v => { v.recover.transition.nonce = b(32, 8); }) },
];
for (const [field, size] of [['accountUuid', 16], ['attemptUuid', 16], ['proposedRootPublicKey', 32], ['challenge', 32]]) {
  for (const width of [size - 1, size + 1]) {
    const value = clone(api.CustodialEmailProofSchema, proof); value.binding[field] = b(width, 9);
    helperNegatives.push({ name: `${field}_width_${width}`, error: 'Binding', email_proof_wire_hex: wire(api.CustodialEmailProofSchema, value) });
  }
}
for (const width of [31, 33]) {
  const value = clone(api.CustodialEmailProofSchema, proof); value.emailSecret = b(width, 6);
  helperNegatives.push({ name: `email_secret_width_${width}`, error: 'Binding', email_proof_wire_hex: wire(api.CustodialEmailProofSchema, value) });
}
for (const [name, change] of [
  ['short_owner_id', v => { v.recover.transition.ownerId = b(31, 1); }],
  ['short_previous_hash', v => { v.recover.transition.previousStateHash = b(31, 1); }],
  ['short_nonce', v => { v.recover.transition.nonce = b(31, 7); }],
  ['short_r1_key', v => { v.recover.transition.nextAuthorityKey.publicKey = b(31, 1); }],
  ['short_w1_key', v => { v.recover.transition.nextRecoveryPolicy.guardians[0].key.publicKey = b(31, 1); }],
  ['short_r1_proof', v => { v.recover.nextAuthorityKeyProof.signature = b(63, 1); }],
  ['short_w1_proof', v => { v.recover.nextRecoveryKeyProofs[0].signature = b(63, 1); }],
]) helperNegatives.push({ name, error: name.includes('w1') ? 'FreshKey' : 'Proposal', submit_wire_hex: changedSubmit(change) });
const verifierNegatives = [];
const portableVector = (name, error, signed, extra = {}) => verifierNegatives.push({ name, error,
  recover_wire_hex: wire(owner.SignedOwnerKeyTransitionSchema, signed), ...extra });
const changedCompleted = change => { const v = clone(owner.SignedOwnerKeyTransitionSchema, completed); change(v); return v; };
portableVector('retained_old_guardian', 'Invalid', retained.signed, {
  detail: 'recovery must replace enough guardians to retire the current policy',
});
portableVector('missing_next_policy', 'Invalid', changedCompleted(v => { v.transition.nextRecoveryPolicy = undefined; }), { detail: 'transition has no next recovery policy' });
portableVector('empty_guardian_policy', 'Invalid', signedMutation(body => { body.nextRecoveryPolicy.guardians = []; }).signed, { detail: 'recovery threshold is outside the guardian set' });
portableVector('wrong_kind_guardian', 'Invalid', signedMutation(body => { body.nextRecoveryPolicy.guardians[0].kind = 1; }).signed, { detail: 'recovery threshold below two is not a Weft-only policy' });
portableVector('missing_w1_proof', 'Invalid', changedCompleted(v => { v.nextRecoveryKeyProofs = []; }), { detail: 'next recovery proof count does not match policy' });
portableVector('wrong_w1_signer', 'InvalidSignature', changedCompleted(v => { v.nextRecoveryKeyProofs = [signature(1, digest)]; }));
portableVector('invalid_w1_signature', 'InvalidSignature', changedCompleted(v => { v.nextRecoveryKeyProofs[0].signature[0] ^= 1; }));
portableVector('guardian_equals_r1', 'Invalid', signedMutation(body => { body.nextRecoveryPolicy = policy(newRoot); }, 2).signed, { detail: 'authority key cannot also be a recovery guardian' });
portableVector('insufficient_old_authorization', 'RecoveryThreshold', changedCompleted(v => { v.authorizations = []; }));
portableVector('invalid_old_authorization', 'InvalidSignature', changedCompleted(v => { v.authorizations[0].signature[0] ^= 1; }));
portableVector('wrong_old_signer', 'InvalidSignature', changedCompleted(v => { v.authorizations = [signature(3, digest)]; }));
portableVector('missing_r1_proof', 'InvalidSignature', changedCompleted(v => { v.nextAuthorityKeyProof = undefined; }));
portableVector('invalid_r1_signature', 'InvalidSignature', changedCompleted(v => { v.nextAuthorityKeyProof.signature[0] ^= 1; }));
portableVector('backdated_valid_from', 'NotYetValid', backdated.signed, { portable_accepts: true });
portableVector('submission_before_window', 'NotYetValid', completed, { now: '1700604799' });
portableVector('nonzero_old_authority_overlap', 'Invalid', signedMutation(body => { body.previousKeyValidUntilUnixSeconds = body.validFromUnixSeconds + 1n; }).signed, { detail: 'recovery retained compromised authority' });
// Distinct proof tags in both orders, plus repeated identical arms. Ordinary
// protobuf accepts these; admission must reject the original bytes first.
const ambiguousProofs = [];
for (const left of [3, 4, 5]) for (const right of [3, 4, 5]) {
  const arm = tag => toBinary(api.SubmitRecoveryProofRequestSchema, create(api.SubmitRecoveryProofRequestSchema, {
    proof: tag === 3 ? { case: 'signedTransition', value: create(SignedRecordSchema) }
      : tag === 4 ? { case: 'paperUnlock', value: create(api.PaperCodeUnlockSchema) }
        : { case: 'custodialEmail', value: proof },
  }));
  ambiguousProofs.push({ name: `proof_tags_${left}_then_${right}`, raw_wire_hex: hex(Buffer.concat([arm(left), arm(right)])), last_tag: right });
}
const releaseScenarios = [
  { name: 'prepare_then_winning_veto', attempt_wire_hex: vetoedHex, error: 'State', committed: false },
  { name: 'rollback_after_private_signing', attempt_wire_hex: wire(api.RecoveryAttemptSchema, attempt), private_signing: true, committed: false },
  { name: 'expiry_after_prepare', attempt_wire_hex: changedAttempt(v => { v.custodial.state = 6; }), error: 'State', now: '1700691200', committed: false },
  { name: 'veto_commits_before_submit', attempt_wire_hex: vetoedHex, error: 'State', committed: false },
  { name: 'submit_commits_before_veto', attempt_wire_hex: changedAttempt(v => { v.completed = true; v.custodial.state = 8; }), error: 'State', committed: true },
];
console.log(JSON.stringify({
  generated_by: 'node tests/generate-custodial-recovery-fixture.mjs',
  public_test_key_seeds: [11, 12, 13, 14], account_id: accountId, attempt_id: attemptId,
  email_canonical_hex: hex(canonicalCustodialEmailBinding(binding)), email_secret_hash_hex: hex(custodialEmailSecretHash(proof)),
  canonical_transition_hex: hex(canonical), signing_digest_hex: hex(digest), root_canonical_hex: hex(rootBody),
  old_guardian_wire_hex: wire(owner.AuthorizationVerificationKeySchema, oldGuardian),
  begin_wire_hex: wire(api.BeginCustodialRecoveryRequestSchema, create(api.BeginCustodialRecoveryRequestSchema, {
    clientOperationId: 'begin-1', accountId, proposedRootPublicKey: newRoot.publicKey })),
  email_proof_wire_hex: wire(api.CustodialEmailProofSchema, proof),
  proof_request_wire_hex: wire(api.SubmitRecoveryProofRequestSchema, proofRequest),
  attempt_wire_hex: wire(api.RecoveryAttemptSchema, attempt),
  proposal_wire_hex: wire(api.CustodialRecoverProposalSchema, proposal),
  submit_wire_hex: wire(api.SubmitCustodialRecoverRequestSchema, submit),
  completed_recover_wire_hex: wire(owner.SignedOwnerKeyTransitionSchema, completed),
  veto_wire_hex: wire(api.VetoCustodialRecoveryRequestSchema, veto),
  veto_signing_hex: hex(vetoSigning),
  negatives: helperNegatives,
  verifier_negatives: verifierNegatives,
  ambiguous_proofs: ambiguousProofs,
  release_scenarios: releaseScenarios,

}, null, 2));
