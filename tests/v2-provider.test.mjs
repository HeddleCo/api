import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EndpointKind } from '../packages/typescript/dist/v2alpha1/stream_pb.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { providerRecordSetCommitment, providerExtentSetDigest, providerAssemblyDigest, providerConsentSigningBytes, validateProviderPlan, providerOfferAsPlan, validateProviderOffer, validatePlanForOffer, validateProviderRegistration } from '../packages/typescript/dist/v2alpha1/provider.js';

const filled = (byte, length = 32) => new Uint8Array(length).fill(byte);
const hex = value => Buffer.from(value).toString('hex');
const endpoint = (kind, byte) => ({ kind, publicKey: filled(byte) });
function fixture() {
  const spool = { id: '123e4567-e89b-12d3-a456-426614174000' };
  const provider = endpoint(EndpointKind.PROVIDER, 4), client = endpoint(EndpointKind.DEVICE, 3);
  const expiresAt = { seconds: 1800000000n, nanos: 500 };
  const object = byte => ({ address: { algorithm: 'blake3', digest: filled(byte) }, kind: 'blob', facet: 1, size: 8n, availability: 4 });
  const records = [
    { object: object(8), encodedLength: 8n, encodedDigest: { algorithm: 'blake3', digest: filled(9) }, outputOffset: 16n,
      source: { case: 'provider', value: { extentIndex: 0, sourceOffset: 0n } } },
    { object: object(10), encodedLength: 8n, encodedDigest: { algorithm: 'blake3', digest: filled(11) }, outputOffset: 24n,
      source: { case: 'inline', value: {} } },
  ];
  const range = { packId: filled(5), objectEtag: 'etag-1', offset: 128n, length: 8n, recordSetCommitment: new Uint8Array() };
  range.recordSetCommitment = providerRecordSetCommitment(range, records, 0);
  const ticket = { attenuatedCapability: filled(99, 1), extentSetDigest: new Uint8Array(), spool,
    facet: 1, audience: 'Public', contentRoot: filled(6), packId: range.packId, objectEtag: range.objectEtag,
    offset: range.offset, length: range.length, provider, client, assemblyDigest: new Uint8Array(), expiresAt,
    recordSetCommitment: range.recordSetCommitment };
  const header = Buffer.alloc(16); header.write('LMPK'); header.writeUInt32BE(4, 4); header.writeBigUInt64BE(2n, 8);
  const plan = { extentSetDigest: new Uint8Array(), extents: [{ provider, ticket, range }],
    challenge: { nonce: filled(7, 16), thread: { spool, id: { value: filled(1) } },
      revision: { spool, revision: { case: 'state', value: { value: filled(2) } } },
      issuer: endpoint(EndpointKind.WEFT, 2), client, expiresAt, extentSetDigest: new Uint8Array(), assemblyDigest: new Uint8Array() },
    assemblyDigest: new Uint8Array(), packHeader: header, outputPackLength: 64n, records };
  plan.extentSetDigest = providerExtentSetDigest(plan);
  plan.challenge.extentSetDigest = plan.extentSetDigest;
  plan.extents[0].ticket.extentSetDigest = plan.extentSetDigest;
  plan.assemblyDigest = providerAssemblyDigest(plan);
  plan.challenge.assemblyDigest = plan.assemblyDigest;
  plan.extents[0].ticket.assemblyDigest = plan.assemblyDigest;
  return plan;
}
test('capability-free offer binds the same layout but never serves bytes', () => {
  const plan = fixture();
  const offer = {
    extentSetDigest: plan.extentSetDigest,
    extents: plan.extents.map(extent => ({
      provider: extent.provider, range: extent.range, spool: extent.ticket.spool,
      facet: extent.ticket.facet, audience: extent.ticket.audience,
      contentRoot: extent.ticket.contentRoot,
    })),
    challenge: plan.challenge, assemblyDigest: plan.assemblyDigest,
    packHeader: plan.packHeader, outputPackLength: plan.outputPackLength,
    records: plan.records,
  };
  validateProviderOffer(offer);
  validatePlanForOffer(offer, plan);
  assert.throws(() => validateProviderPlan(providerOfferAsPlan(offer)), /digest disagreement/);
  const moved = structuredClone(offer); moved.records[0].outputOffset += 1n;
  assert.throws(() => validateProviderOffer(moved), /output tiling/);
  const changed = structuredClone(plan); changed.extents[0].ticket.contentRoot = filled(12);
  assert.throws(() => validatePlanForOffer(offer, changed), /extent set/);
});
test('typed private pack registration covers exactly the issued ranges', () => {
  const plan = fixture();
  const registration = { plan, servingProvider: plan.extents[0].provider, packs: [{ packId: plan.extents[0].range.packId, objectKey: 'source/pack-1' }] };
  validateProviderRegistration(registration);
  const duplicate = structuredClone(registration); duplicate.packs.push(duplicate.packs[0]);
  assert.throws(() => validateProviderRegistration(duplicate), /pack count|Duplicate/);
  const other = structuredClone(registration); other.packs[0].packId = filled(99);
  assert.throws(() => validateProviderRegistration(other), /coverage/);
});
test('TS and Rust commit the same mixed provider/inline plan and consent bytes', () => {
  const plan = fixture();
  validateProviderPlan(plan);
  assert.equal(hex(plan.extents[0].range.recordSetCommitment), '649331f1c9636feebfff83e12f0fe9c8f0206a9c2d91446a970f0e3be1226fa7');
  assert.equal(hex(plan.extentSetDigest), '41fc120dd82033542f7edc7a7a9940f780658167bd620785292edece604708ca');
  assert.equal(hex(plan.assemblyDigest), '31c288e8d2e806e3937bee7a3eaafc9d273438d16d034de54e0d0fa6dff1ce5c');
  assert.equal(hex(blake3(providerConsentSigningBytes(plan.challenge, 'user:1'))),
    '7be03a24e3ef1a654bb4ad3adc3675d407b690b2dd3467713df72b90a69d82c6');
  const gap = structuredClone(plan); gap.records[0].outputOffset += 1n;
  assert.throws(() => providerAssemblyDigest(gap), /output tiling/);
  const changed = structuredClone(plan); changed.extents[0].ticket.assemblyDigest[0] ^= 1;
  assert.throws(() => validateProviderPlan(changed), /digest disagreement/);
  const wrongScope = structuredClone(plan); wrongScope.extents[0].ticket.spool.id = '123e4567-e89b-12d3-a456-426614174001';
  assert.throws(() => providerAssemblyDigest(wrongScope), /extent set/);
  const duplicate = structuredClone(plan); duplicate.records[1].object = structuredClone(duplicate.records[0].object);
  assert.throws(() => providerAssemblyDigest(duplicate), /Duplicate provider object/);
  const split = structuredClone(plan); split.records[0].source.value.sourceOffset = 1n;
  assert.throws(() => providerExtentSetDigest(split), /range tiling/);
  const badUuid = structuredClone(plan); badUuid.challenge.thread.spool = { id: 'zzze4567-e89b-12d3-a456-426614174000' };
  assert.throws(() => providerAssemblyDigest(badUuid), /source scope/);
  const inlineAlgorithm = structuredClone(plan); inlineAlgorithm.records[1].encodedDigest.algorithm = 'sha256';
  assert.throws(() => providerAssemblyDigest(inlineAlgorithm), /source object descriptor/);
  const badFacet = structuredClone(plan); badFacet.extents[0].ticket.facet = 2;
  assert.throws(() => providerExtentSetDigest(badFacet), /ticket scope/);
  const oversized = structuredClone(plan); oversized.outputPackLength = 512n * 1024n * 1024n + 1n;
  assert.throws(() => providerAssemblyDigest(oversized), /assembly bound/);
  const twoRoots = structuredClone(plan);
  twoRoots.records[1].source = { case: 'provider', value: { extentIndex: 1, sourceOffset: 0n } };
  const second = structuredClone(twoRoots.extents[0]);
  second.range.offset = 256n;
  second.range.recordSetCommitment = providerRecordSetCommitment(second.range, twoRoots.records, 1);
  second.ticket.offset = 256n;
  second.ticket.recordSetCommitment = second.range.recordSetCommitment;
  second.ticket.contentRoot = filled(7);
  twoRoots.extents.push(second);
  assert.throws(() => providerExtentSetDigest(twoRoots), /content root mismatch/);
});
