import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fromBinary, toBinary } from '@bufbuild/protobuf';
import { NativePublicProofBundleV1Schema } from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import { ImportPublicProofBundleV1Schema } from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import { SignedOwnerMintRootAttachmentSchema } from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import { validatePublicNativeBundle } from '../packages/typescript/dist/v1alpha2/native-witness.js';
import { validatePublicBundle } from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { admittedOwnerMintRootAttachment, decodeWriterAuthority, retainedMintRootIssuer, verifyRetainedWriterAttachment } from '../packages/typescript/dist/v1alpha2/writer-authority.js';
import { verifySignature } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
import { statementSigningDigest } from '../packages/typescript/dist/v1alpha2/witness-trust.js';
import { decode } from '../packages/typescript/dist/v1alpha2/_collaboration-msgpack.js';
const f=JSON.parse(readFileSync(new URL('./fixtures/boundary-attachment-alpha37.json',import.meta.url)));
const wire=(name,schema)=>fromBinary(schema,Buffer.from(f.vectors[name].wire_hex,'hex'));
for(const kind of ['native','import'])for(const purpose of [1,2]){
 const prefix=`${kind}_p${purpose}`,schema=kind==='native'?NativePublicProofBundleV1Schema:ImportPublicProofBundleV1Schema;
 test(`${prefix} retained acceptor ACCEPT; forged and original attachments REJECT then ACCEPT`,async()=>{
  const b=wire(prefix+'_control',schema);
  if(kind==='native')await validatePublicNativeBundle(b);else validatePublicBundle(b);
  const s=b.statements.find(s=>s.body.basis===2&&s.body.purpose===purpose);
  await verifySignature(Buffer.from(f.keys.witness.public_key_hex,'hex'),statementSigningDigest(s.body),s.signature);
  const p=(purpose===1?b.genesisWitnesses:b.authorityWitnesses)[0];
  const e=purpose===1?p.boundaryAcceptance:p.boundaryAcceptances[0];
  const a=decodeWriterAuthority(decode(e.signedAcceptance.canonicalRecord).accepting_author.authority),cert=a.mintRootAssociation.value;
  assert.equal(a.owner.acceptedTransitions[0].transition.kind,1);assert.equal(cert.attachment.ownerSequence,0n);
  const payload={kind:purpose===1?(kind==='native'?'native-genesis':'genesis'):'authority',payload:p};
  const admitted=await admittedOwnerMintRootAttachment(s.body,payload);
  const verify=(authority,certificate)=>verifyRetainedWriterAttachment(toBinary(SignedOwnerMintRootAttachmentSchema,certificate),authority.mintRootPublicKey,retainedMintRootIssuer(authority.owner,certificate.attachment.ownerStateHash,certificate.attachment.ownerSequence),admitted,1100n);
  await verify(a,cert);
  const forged=wire(prefix+'_forged_attachment',SignedOwnerMintRootAttachmentSchema);
  await assert.rejects(()=>verify(a,forged),{reason:'Root'});await verify(a,cert);
  const original=decodeWriterAuthority(purpose===1?p.creatorAuthorityEnvelope:p.authorityEnvelope);
  await assert.rejects(()=>verify(original,original.mintRootAssociation.value),{reason:'Root'});await verify(a,cert);
 });
 for(const mode of ['binary_publisher','binary_authority_digest'])test(`${prefix} strict acceptance ${mode} REJECT then ACCEPT`,async()=>{
  const bad=wire(prefix+'_'+mode,schema),good=wire(prefix+'_control',schema);
  if(kind==='native'){await assert.rejects(()=>validatePublicNativeBundle(bad),{reason:'Canonical'});await validatePublicNativeBundle(good);}
  else{assert.throws(()=>validatePublicBundle(bad),{reason:'Canonical'});validatePublicBundle(good);}
 });
}
