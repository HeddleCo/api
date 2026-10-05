import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fromBinary, toBinary } from '@bufbuild/protobuf';
import { NativeGenesisWitnessV1Schema, NativePublicProofBundleV1Schema } from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import { verifyNativeGenesisAuthority, validatePublicNativeBundle } from '../packages/typescript/dist/v1alpha2/native-witness.js';
import { ThreadControlAuthoritySchema } from '../packages/typescript/dist/v1alpha2/identity_pb.js';
import { ImportIdentityV1Schema, ImportAuthorityWitnessV1Schema, HostedLandingWitnessV1Schema, ImportPublicProofBundleV1Schema } from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import { SignedOwnerMintRootAttachmentSchema, OwnerHistorySchema } from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import { SignedHostedWitnessStatementV1Schema } from '../packages/typescript/dist/common/hosted_witness_pb.js';
import { verifyWitnessPayload, validatePublicBundle } from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { decodeWriterAuthority, verifyWriterAccountBinding, checkWriterKeys, retainedMintRootIssuer, admittedOwnerMintRootAttachment, verifyRetainedWriterAttachment, verifyLandingActorBinding, verifyAuthorityActorBinding } from '../packages/typescript/dist/v1alpha2/writer-authority.js';
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

async function verifiedHistory(name){
 const h=wire(name,OwnerHistorySchema),root=h.root;
 await verifySignature(raw(f.keys.cowriter_owner.public_key_hex),raw(f.context.owner_root_signing_digest_hex),root.authorityProof.signature);
 for(let i=0;i<root.recoveryKeyProofs.length;i++)await verifySignature(root.root.recoveryPolicy.guardians[i].key.publicKey,raw(f.context.owner_root_signing_digest_hex),root.recoveryKeyProofs[i].signature);
 const s=h.acceptedTransitions[0],t=s.transition,digest=raw(f.context[t.kind===2?'recover_signing_digest_hex':'rotate_signing_digest_hex']);assert.deepEqual(t.previousStateHash,raw(f.context.issuer_state_hash_hex));assert.deepEqual(h.stateHash,digest);
 const keys=t.kind===2?root.root.recoveryPolicy.guardians.map(g=>g.key.publicKey):[raw(f.keys.cowriter_owner.public_key_hex)];
 for(let i=0;i<keys.length;i++)await verifySignature(keys[i],digest,s.authorizations[i].signature);
 await verifySignature(t.nextAuthorityKey.publicKey,digest,s.nextAuthorityKeyProof.signature);return h;
}
async function admission(name){
 const s=wire(name+'_statement',SignedHostedWitnessStatementV1Schema),p=wire(name+'_payload',ImportAuthorityWitnessV1Schema);
 await verifySignature(raw(f.keys.witness.public_key_hex),statementSigningDigest(s.body),s.signature);
 return admittedOwnerMintRootAttachment(s.body,{kind:'authority',payload:p});
}
test('retained attachments REJECT then PASS',async()=>{
 const awaitedRecover=await verifiedHistory('verified_recover_history'),unknownAdmission=await admission('admitted_unknown'),badAdmission=await admission('admitted_bad_signature');
 const h=await verifiedHistory('verified_rotate_history'),issuer=retainedMintRootIssuer(h,raw(f.context.issuer_state_hash_hex),0n),admitted=await admission('admitted_original'),mint=raw(f.keys.cowriter_device.public_key_hex);
 const cert=wire('paired_after_rotate',SignedOwnerMintRootAttachmentSchema),verify=(c,a=admitted)=>verifyRetainedWriterAttachment(toBinary(SignedOwnerMintRootAttachmentSchema,c),mint,issuer,a,1100n);
 await verify(cert);
 assert.throws(()=>retainedMintRootIssuer(awaitedRecover,raw(f.context.issuer_state_hash_hex),0n),{reason:'Root'});
 for(const name of ['forged_old_owner_certificate','unknown_issuer']){await assert.rejects(()=>verify(wire(name,SignedOwnerMintRootAttachmentSchema)),{reason:'Root'});await verify(cert);}
 await assert.rejects(()=>verify(wire('unknown_issuer',SignedOwnerMintRootAttachmentSchema),unknownAdmission),{reason:'Root'});
 await assert.rejects(()=>verify(wire('invalid_old_owner_signature',SignedOwnerMintRootAttachmentSchema),badAdmission),{reason:'Signature'});
 const unknown=raw(f.context.issuer_state_hash_hex);unknown[0]^=1;assert.throws(()=>retainedMintRootIssuer(h,unknown,0n),{reason:'Root'});await verify(cert);
});
test('retained strict decode REJECT then PASS',async()=>{
 const h=await verifiedHistory('verified_rotate_history'),issuer=retainedMintRootIssuer(h,raw(f.context.issuer_state_hash_hex),0n),admitted=await admission('admitted_original'),cert=raw(f.vectors.paired_after_rotate.wire_hex),mint=raw(f.keys.cowriter_device.public_key_hex);
 await assert.rejects(()=>verifyRetainedWriterAttachment(new Uint8Array([...cert,0x78,1]),mint,issuer,admitted,1100n),{reason:'Canonical'});
 await verifyRetainedWriterAttachment(cert,mint,issuer,admitted,1100n);
});
test('policy history REJECT then PASS',async()=>{
 for(const [mode,reason]of [['stripped','Canonical'],['absent','Canonical'],['reordered','Canonical'],['duplicated','Canonical'],['subtracted','Scope'],['predecessor_stripped','Canonical']]){
  await assert.rejects(()=>validatePublicNativeBundle(wire('native_policy_'+mode,NativePublicProofBundleV1Schema)),{reason});await validatePublicNativeBundle(wire('native_policy_chain',NativePublicProofBundleV1Schema));
  assert.throws(()=>validatePublicBundle(wire('import_policy_'+mode,ImportPublicProofBundleV1Schema)),{reason});validatePublicBundle(wire('import_policy_chain',ImportPublicProofBundleV1Schema));
 }
 const native=wire('native_actor_key_revoked',NativePublicProofBundleV1Schema);native.policies[0].body.policy.revokedKeyIds=[];
 await assert.rejects(()=>validatePublicNativeBundle(native),{reason:'Canonical'});await validatePublicNativeBundle(wire('cowriter_start_bundle',NativePublicProofBundleV1Schema));
 const imported=wire('import_actor_key_revoked',ImportPublicProofBundleV1Schema);imported.policies[0].body.policy.revokedKeyIds=[];
 assert.throws(()=>validatePublicBundle(imported),{reason:'Canonical'});validatePublicBundle(wire('cowriter_import_bundle',ImportPublicProofBundleV1Schema));

});
test('P2 P4 owner roots and duplicate histories',async()=>{
 for(const kind of ['p2','p4']){
  await assert.rejects(()=>validatePublicNativeBundle(wire(kind+'_self_signed_owner_uuid',NativePublicProofBundleV1Schema)),{reason:'Root'});await validatePublicNativeBundle(wire(kind+'_owner_bundle',NativePublicProofBundleV1Schema));
  await assert.rejects(()=>validatePublicNativeBundle(wire(kind+'_duplicate_history_poisoning',NativePublicProofBundleV1Schema)),{reason:'Canonical'});
  const duplicate=wire(kind+'_owner_bundle',NativePublicProofBundleV1Schema);duplicate.ownerHistories.push(duplicate.ownerHistories[0]);await assert.rejects(()=>validatePublicNativeBundle(duplicate),{reason:'Canonical'});
 }
});
test('actor subject binding REJECT then PASS',()=>{
 const id=fromBinary(ImportIdentityV1Schema,raw(f.context.identity_wire_hex)),account=raw(f.context.account_hex);
 assert.throws(()=>verifyAuthorityActorBinding(wire('p2_envelope_not_op_author',ImportAuthorityWitnessV1Schema),account,id.ownerAccountUuid,id.ownerId),{reason:'GenesisBinding'});
 verifyAuthorityActorBinding(wire('cowriter_capture_owner_thread',ImportAuthorityWitnessV1Schema),account,id.ownerAccountUuid,id.ownerId);
 const p=wire('requester_not_token_subject',HostedLandingWitnessV1Schema),key=p.request.signature.publicKey,control=wire('cowriter_land_request',HostedLandingWitnessV1Schema);
 assert.throws(()=>verifyLandingActorBinding(p,account,key,key,id.ownerAccountUuid,id.ownerId),{reason:'GenesisBinding'});verifyLandingActorBinding(control,account,key,key,id.ownerAccountUuid,id.ownerId);
 assert.throws(()=>verifyLandingActorBinding(control,account,new Uint8Array(32).fill(0x80),new Uint8Array(32).fill(0x80),id.ownerAccountUuid,id.ownerId),{reason:'KeyRole'});
 assert.throws(()=>verifyLandingActorBinding(control,account,new Uint8Array(32).fill(0x80),key,id.ownerAccountUuid,id.ownerId),{reason:'KeyRole'});
});
test('ownership counterparty revocations',async()=>{
 for(const kind of [2,3]){await assert.rejects(()=>validatePublicNativeBundle(wire('kind_'+kind+'_counterparty_revoked',NativePublicProofBundleV1Schema)),{reason:'Revoked'});await validatePublicNativeBundle(wire('ownership_counterparty_control',NativePublicProofBundleV1Schema));}
});
test('landing Reviews only',async()=>{
 await assert.rejects(()=>validatePublicNativeBundle(wire('p4_non_review',NativePublicProofBundleV1Schema)),{reason:'Semantic'});await validatePublicNativeBundle(wire('p4_owner_bundle',NativePublicProofBundleV1Schema));
});
test('attachment payload binding REJECT then PASS',async()=>{
 const s=wire('admitted_original_statement',SignedHostedWitnessStatementV1Schema),bad=wire('admitted_unknown_payload',ImportAuthorityWitnessV1Schema);
 await verifySignature(raw(f.keys.witness.public_key_hex),statementSigningDigest(s.body),s.signature);
 await assert.rejects(()=>admittedOwnerMintRootAttachment(s.body,{kind:'authority',payload:bad}),{reason:'Scope'});
 await admission('admitted_original');
});
