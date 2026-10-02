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
const int = (value, width) => { const out = Buffer.alloc(width); width === 4 ? out.writeUInt32BE(Number(value)) : out.writeBigInt64BE(BigInt(value)); return out; };
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
const canonical = Buffer.concat([int(1, 4), counted(body.ownerId), counted(body.previousStateHash),
  int(body.sequence, 8), int(body.kind, 4), keyBody(newRoot), policyBody(body.nextRecoveryPolicy),
  int(body.validFromUnixSeconds, 8), int(0, 8), counted(body.nonce)]);
const digest = hash(Buffer.from('heddle-owner-key-transition-v1'), canonical);
const prepared = create(owner.SignedOwnerKeyTransitionSchema, { transition: body,
  authorizations: [signature(1, digest)], nextRecoveryKeyProofs: [signature(3, digest)] });
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
// Deep clone using wire decoding for nested mutation isolation.
const missing = fromBinary(api.SubmitCustodialRecoverRequestSchema, toBinary(api.SubmitCustodialRecoverRequestSchema, submit));
missing.recover.transition.nextRecoveryPolicy = undefined;
missing.recover.nextRecoveryKeyProofs = [];
const reused = fromBinary(api.SubmitCustodialRecoverRequestSchema, toBinary(api.SubmitCustodialRecoverRequestSchema, submit));
reused.recover.transition.nextRecoveryPolicy = policy(oldGuardian);
const otherProof = create(api.CustodialEmailProofSchema, { ...proof, binding: { ...binding, attemptUuid: b(16, 9) } });
const vetoed = fromBinary(api.RecoveryAttemptSchema, toBinary(api.RecoveryAttemptSchema, attempt));
vetoed.vetoed = true; vetoed.custodial.state = 5;
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
  veto_wire_hex: wire(api.VetoCustodialRecoveryRequestSchema, veto),
  veto_signing_hex: hex(vetoSigning),
  negatives: [
    { name: 'replayed_email_from_other_attempt', error: 'Binding', email_proof_wire_hex: wire(api.CustodialEmailProofSchema, otherProof) },
    { name: 'omitted_fresh_guardian', error: 'FreshKey', submit_wire_hex: wire(api.SubmitCustodialRecoverRequestSchema, missing) },
    { name: 'retained_old_guardian', error: 'FreshKey', submit_wire_hex: wire(api.SubmitCustodialRecoverRequestSchema, reused) },
    { name: 'submission_before_window', error: 'Early', now: '1700604799' },
    { name: 'submission_after_veto', error: 'State', attempt_wire_hex: wire(api.RecoveryAttemptSchema, vetoed) },
    { name: 'submission_at_expiry', error: 'Expired', now: '1700691200' },
    { name: 'stale_attempt_version', error: 'Version', submit_wire_hex: changedSubmit(v => { v.expectedVersion = b(32, 8); }) },
    { name: 'altered_prepared_nonce', error: 'Proposal', submit_wire_hex: (() => {
      const v = fromBinary(api.SubmitCustodialRecoverRequestSchema, toBinary(api.SubmitCustodialRecoverRequestSchema, submit));
      v.recover.transition.nonce = b(32, 8); return wire(api.SubmitCustodialRecoverRequestSchema, v);
    })() },
  ],
}, null, 2));
