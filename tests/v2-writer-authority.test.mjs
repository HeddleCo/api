import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fromBinary } from '@bufbuild/protobuf';
import { NativeGenesisWitnessV1Schema, NativePublicProofBundleV1Schema } from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import { verifyNativeGenesisAuthority, validatePublicNativeBundle } from '../packages/typescript/dist/v1alpha2/native-witness.js';
import { ThreadControlAuthoritySchema } from '../packages/typescript/dist/v1alpha2/identity_pb.js';
import { ImportIdentityV1Schema, ImportAuthorityWitnessV1Schema, HostedLandingWitnessV1Schema, ImportPublicProofBundleV1Schema } from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import { SignedOwnerMintRootAttachmentSchema } from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import { SignedHostedWitnessStatementV1Schema } from '../packages/typescript/dist/common/hosted_witness_pb.js';
import { verifyWitnessPayload, validatePublicBundle } from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { decodeWriterAuthority, verifyWriterAccountBinding, checkWriterKeys, verifyRetainedOwnerMintRootAttachment } from '../packages/typescript/dist/v1alpha2/writer-authority.js';
import { keyId, verifySignature } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
import { statementSigningDigest } from '../packages/typescript/dist/v1alpha2/witness-trust.js';
const f=JSON.parse(readFileSync(new URL('./fixtures/writer-authority-alpha35.json',import.meta.url)));
const raw=h=>new Uint8Array(Buffer.from(h,'hex'));
const wire=(name,schema=NativeGenesisWitnessV1Schema)=>fromBinary(schema,raw(f.vectors[name].wire_hex));
const genesis=async name=>{const p=wire(name);await verifyNativeGenesisAuthority(p.binding,p.originalGenesis,p.creatorAuthorityEnvelope);};
test('cowriter StartThread',async()=>{await genesis('cowriter_start_thread');});
for(const v of f.negative.filter(v=>v.gate==='genesis'))test(`${v.id} REJECT then PASS`,async()=>{
  await assert.rejects(()=>genesis(v.id),{reason:v.expected});await genesis(v.control);
});
for(const name of f.positive.filter(n=>n!=='cowriter_start_thread'&&n!=='paired_after_rotate'))test(`API writer PASS ${name}`,async()=>{
  const landing=name==='cowriter_land_request',schema=landing?HostedLandingWitnessV1Schema:ImportAuthorityWitnessV1Schema;
  const p=wire(name,schema),s=wire(name+'_statement',SignedHostedWitnessStatementV1Schema);
  await verifySignature(raw(f.keys.witness.public_key_hex),statementSigningDigest(s.body),s.signature);
  await verifyWitnessPayload(s.body,{kind:landing?'landing':'authority',payload:p});
  const id=fromBinary(ImportIdentityV1Schema,raw(f.context.identity_wire_hex));
  verifyWriterAccountBinding(decodeWriterAuthority(p.authorityEnvelope),raw(f.context.account_hex),id.ownerAccountUuid,id.ownerId);
});
test('actor key cuts REJECT then PASS',()=>{
  const a=wire('cowriter_envelope',ThreadControlAuthoritySchema),publisher=raw(f.context.publisher_key_id_hex);
  for(const key of [publisher,keyId(a.mintRootPublicKey)]){
    assert.throws(()=>checkWriterKeys(a,publisher,[key]),{reason:'Revoked'});checkWriterKeys(a,publisher,[]);
  }
});
test('native and import policy cuts REJECT then PASS',async()=>{
  await assert.rejects(()=>validatePublicNativeBundle(wire('native_actor_key_revoked',NativePublicProofBundleV1Schema)),{reason:'Revoked'});
  await validatePublicNativeBundle(wire('cowriter_start_bundle',NativePublicProofBundleV1Schema));
  assert.throws(()=>validatePublicBundle(wire('import_actor_key_revoked',ImportPublicProofBundleV1Schema)),{reason:'Revoked'});
  validatePublicBundle(wire('cowriter_import_bundle',ImportPublicProofBundleV1Schema));
});
test('retained attachments REJECT then PASS',async()=>{
  const admitted=wire('paired_after_rotate',SignedOwnerMintRootAttachmentSchema),a=admitted.attachment;
  const e={accountUuid:a.accountUuid,mintRootPublicKey:a.mintRootKey.publicKey,issuerStateHash:a.ownerStateHash,issuerSequence:a.ownerSequence,issuerPublicKey:a.ownerKey.publicKey,issuerRetainedMintAuthority:true,admittedAttachments:[admitted],nowUnixSeconds:1100n};
  const verify=(value,context=e)=>verifyRetainedOwnerMintRootAttachment(value,context);
  await verify(admitted);
  await assert.rejects(()=>verify(admitted,{...e,issuerRetainedMintAuthority:false}),{reason:'Root'});await verify(admitted);
  for(const name of ['forged_old_owner_certificate','unknown_issuer']){await assert.rejects(()=>verify(wire(name,SignedOwnerMintRootAttachmentSchema)),{reason:'Root'});await verify(admitted);}
  const bad=wire('invalid_old_owner_signature',SignedOwnerMintRootAttachmentSchema);
  await assert.rejects(()=>verify(bad,{...e,admittedAttachments:[bad]}),{reason:'Signature'});
  const unknown=wire('unknown_issuer',SignedOwnerMintRootAttachmentSchema);
  await assert.rejects(()=>verify(unknown,{...e,admittedAttachments:[unknown]}),{reason:'Root'});await verify(admitted);
});
