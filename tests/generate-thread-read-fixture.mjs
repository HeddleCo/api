// Deterministic browser-produced original for Rust's independent decoder.
// Run after `npm run build`: node tests/generate-thread-read-fixture.mjs
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { create } from '@bufbuild/protobuf';
import { ReviewDecisionSchema, ReviewDecision_Kind, ThreadOverviewSchema, ThreadProperty } from '../packages/typescript/dist/v1alpha2/thread_pb.js';
import { signThreadControl } from '../packages/typescript/dist/v1alpha2/thread-control.js';

const old = JSON.parse(readFileSync(new URL('./fixtures/thread-control-v1-rust.json', import.meta.url), 'utf8'))[4];
const raw = old.control;
const source = raw.control.value;
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 19)]), format: 'der', type: 'pkcs8' });
const publisher = new Uint8Array(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32));
const thread = new Uint8Array(32).fill(11);
const ref = { spool: { id: raw.spool }, id: { value: thread } };
const revision = bytes => ({ spool: ref.spool, revision: { case: 'state', value: { value: Uint8Array.from(bytes) } } });
const decision = create(ReviewDecisionSchema, {
  ref: { spool: ref.spool, id: source.id }, thread: ref,
  source: revision(source.source), target: revision(source.target),
  policyVersion: Uint8Array.from(source.policy_version), kind: ReviewDecision_Kind.READ,
  principalId: raw.actor.principal_id, explanation: source.explanation,
  expiresAt: { seconds: BigInt(source.expires_at_unix_seconds) },
  coverage: { selection: { case: 'symbols', value: { anchors: [{ path: 'src/main.rs', symbol: 'run' }] } } },
});
const overview = create(ThreadOverviewSchema, { ref, metadataFrontiers: [{
  property: ThreadProperty.REVIEW, recordId: source.id,
  version: Uint8Array.from(Buffer.from(old.property_version, 'hex')),
  operationIds: [new Uint8Array(32).fill(12), new Uint8Array(32).fill(13)],
}] });
const signed = await signThreadControl(overview, {
  clientOperationId: raw.client_operation_id, occurredAtMs: BigInt(raw.occurred_at_ms),
  control: { kind: 'review', value: decision },
}, {
  actor: { principalId: raw.actor.principal_id }, authorityEnvelope: Uint8Array.from(raw.authority_envelope),
  signer: { publicKey: publisher, sign: async bytes => new Uint8Array(sign(null, bytes, privateKey)) },
});
console.log(JSON.stringify({
  generated_by: 'node tests/generate-thread-read-fixture.mjs after npm run build at API 89ef0061',
  thread_hex: Buffer.from(thread).toString('hex'),
  canonical_hex: Buffer.from(signed.operation.canonicalRecord).toString('hex'),
  signature_hex: Buffer.from(signed.operation.signatures[0].signature).toString('hex'),
  publisher_hex: Buffer.from(publisher).toString('hex'),
  expected_kind: 'read', expected_path: 'src/main.rs', expected_symbol: 'run',
}));
