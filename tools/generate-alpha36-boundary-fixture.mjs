// Maintenance only. Existing corpora are read without modification.
import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { create, clone, fromBinary, toBinary } from '@bufbuild/protobuf';
import * as native from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import * as api from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import * as host from '../packages/typescript/dist/common/hosted_witness_pb.js';
import * as own from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import { SignedRecordSchema } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import { mintRootAttachmentSigningDigest } from '../packages/typescript/dist/v1alpha2/owner-certificates.js';
import { ThreadControlAuthoritySchema } from '../packages/typescript/dist/v1alpha2/identity_pb.js';
import { encode, decode } from '../packages/typescript/dist/v1alpha2/_collaboration-msgpack.js';
import { hash, keyId, join, utf8, sized, compare, canonicalHybridV1, signingDigest } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
import { signedNativeDigest, boundaryOctetsDigest, policyStateDigest } from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { statementSigningDigest } from '../packages/typescript/dist/v1alpha2/witness-trust.js';
import { blake3 } from '@noble/hashes/blake3.js';
const nf=JSON.parse(readFileSync('tests/fixtures/native-host-witness-v1.json'));
const inf=JSON.parse(readFileSync('tests/fixtures/import-authority-host-witness-v1.json'));
const wf=JSON.parse(readFileSync('tests/fixtures/writer-authority-alpha35.json'));
const raw=h=>new Uint8Array(Buffer.from(h,'hex')),hex=b=>Buffer.from(b).toString('hex');
const keys=wf.keys,key=n=>raw(keys[n].public_key_hex);
const sig=(n,b)=>new Uint8Array(sign(null,b,createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),raw(keys[n].seed_hex)]),format:'der',type:'pkcs8'})));
const load=(f,n,s)=>fromBinary(s,raw((f.wire_vectors??f.vectors)[n].wire_hex));
execFileSync('cargo',['build','--locked','--manifest-path','tools/hybrid-native/Cargo.toml'],{stdio:'inherit'});
const metadata=JSON.parse(execFileSync('cargo',['metadata','--locked','--no-deps','--format-version','1','--manifest-path','tools/hybrid-native/Cargo.toml'],{encoding:'utf8'}));
const codec=metadata.target_directory+'/debug/hybrid-native-conformance';
function octetsId(format,bytes){const n=new Uint8Array(8);new DataView(n.buffer).setBigUint64(0,BigInt(bytes.length),true);return blake3(join(utf8.encode(format),n,Uint8Array.of(0),bytes));}
function nativeBytes(format,value){return raw(execFileSync(codec,['encode',format],{input:hex(encode(value)),encoding:'utf8'}).trim());}
function record(format,value,signer){const bytes=nativeBytes(format,value);return create(SignedRecordSchema,{format,canonicalRecord:bytes,signatures:[{publicKey:key(signer),signature:sig(signer,join(utf8.encode(format),Uint8Array.of(0),bytes))}]});}
const nativeBase=load(nf,'start_thread',native.NativePublicProofBundleV1Schema);
const acceptor=fromBinary(ThreadControlAuthoritySchema,nativeBase.genesisWitnesses[0].creatorAuthorityEnvelope);
acceptor.mintRootPublicKey=key('cowriter_device');
acceptor.sealedBiscuit=new Uint8Array(readFileSync('/tmp/api-alpha36-acceptor-biscuit.binpb'));
const cert=acceptor.mintRootAssociation.value;cert.attachment.mintRootKey.publicKey=key('cowriter_device');
cert.ownerSignature=create(own.AuthorizationSignatureSchema,{signerKeyId:keyId(key('owner')),signature:sig('owner',mintRootAttachmentSigningDigest(cert.attachment))});
const envelope=toBinary(ThreadControlAuthoritySchema,acceptor);
const template=load(inf,'boundary_main',api.ImportBoundaryAcceptanceV1Schema);
function evidence(original,purpose){
 const m=decode(template.originalsManifest),entry=m.entries[0],originalValue=decode(original.canonicalRecord);
 entry.thread=purpose===1?Array.from(octetsId(original.format,original.canonicalRecord)):originalValue.thread;
 entry.subject=purpose===1?{Genesis:entry.thread}:{Source:Array.from(octetsId(original.format,original.canonicalRecord))};
 entry.publisher=Array.from(key('device'));
 const manifest=nativeBytes('heddle-original-publication-manifest-v1',m);
 const a=decode(template.signedAcceptance.canonicalRecord);
 a.originals_manifest=Array.from(octetsId('heddle-original-publication-manifest-v1',manifest));
 a.kinds=purpose===1?['AccountGenesis']:['Source'];a.accepting_publisher=Array.from(key('paired_leaf'));
 a.accepting_author.actor.principal_id=acceptor.owner.root.root.accountUuid;
 a.accepting_author.authority=envelope;a.accepting_author.authority_digest=Array.from(octetsId('heddle-thread-control-authority-v1',envelope));
 const signed=record('heddle-original-boundary-acceptance-v1',a,'paired_leaf');
 const id=octetsId(signed.format,signed.canonicalRecord),r=decode(template.originalReceipts[0].canonicalRecord);
 r.thread=entry.thread;r.basis={BoundaryAcceptance:{acceptance:Array.from(id)}};
 let receipt;
 if(purpose===1)receipt=record('heddle-thread-genesis-admission-v2',r,'witness');
 else {delete r.owner;delete r.creator;r.version=3;r.actor={principal_id:a.original_account,agent_id:null};r.publisher=Array.from(key('device'));r.subject={Operation:Array.from(octetsId(original.format,original.canonicalRecord))};receipt=record('heddle-thread-authority-admission-v3',r,'witness');}
 return create(api.ImportBoundaryAcceptanceV1Schema,{binding:{formatVersion:1,acceptanceId:id,signedAcceptanceDigest:signedNativeDigest(signed),originalsManifestDigest:boundaryOctetsDigest('heddle-boundary-originals-manifest-v1',manifest),publicationIntentDigest:boundaryOctetsDigest('heddle-boundary-publication-intent-v1',template.publicationIntent),originalReceiptDigests:[signedNativeDigest(receipt)]},signedAcceptance:signed,originalsManifest:manifest,publicationIntent:template.publicationIntent,originalReceipts:[receipt]});
}
const fixture={format_version:1,scope:'API signature/payload, account binding and selected policy cuts; native owner/Biscuit/manifest membership verification remains mandatory',keys,vectors:{}};
function wire(name,schema,b){fixture.vectors[name]={schema:schema.typeName,wire_hex:hex(toBinary(schema,b))};}
function sort(b){b.statements.sort((a,b)=>compare(statementSigningDigest(a.body),statementSigningDigest(b.body)));b.authorityWitnesses.sort((a,b)=>compare(signingDigest('heddle-import-authority-witness-payload-v1',api.ImportAuthorityWitnessV1Schema,a),signingDigest('heddle-import-authority-witness-payload-v1',api.ImportAuthorityWitnessV1Schema,b)));}
for(const [kind,schema,f,name] of [['native',native.NativePublicProofBundleV1Schema,nf,'account_source'],['import',api.ImportPublicProofBundleV1Schema,inf,'complete_export']])for(const purpose of [1,2]){
 const base=load(f,name,schema);
 // Use a source original; metadata acceptance is not source authority.
 if(kind==='import'){const source=load(nf,'account_source',native.NativePublicProofBundleV1Schema);base.authorityWitnesses=source.authorityWitnesses;base.statements.push(...source.statements.filter(s=>s.body.purpose===2));}
 const selected=base.statements.find(s=>s.body.purpose===purpose),s=selected.body;
 const payloadSchema=purpose===1?(kind==='native'?native.NativeGenesisWitnessV1Schema:api.ImportGenesisWitnessV1Schema):api.ImportAuthorityWitnessV1Schema;
 const p=(purpose===1?base.genesisWitnesses:base.authorityWitnesses).find(p=>hex(canonicalHybridV1(payloadSchema,p))===hex(s.canonicalPayload));
 const e=evidence(purpose===1?p.originalGenesis:p.original,purpose);
 if(purpose===1)p.boundaryAcceptance=e;else p.boundaryAcceptances=[e];
 s.basis=2;s.boundaryAcceptance=e.binding;s.canonicalPayload=canonicalHybridV1(payloadSchema,p);
 const prefix=`${kind}_p${purpose}`;
 function policyCut(b,ids){const last=b.policies.at(-1),cut=clone(own.SignedSpoolPolicyRecordSchema,last),body=cut.body;body.expectedHead=create(own.SignedPolicyHeadSchema,{stateHash:last.body.policyStateHash,sequence:last.body.sequence});body.sequence++;body.policy.revokedKeyIds=ids.sort(compare);body.policyStateHash=policyStateDigest(body);
 // policyStateDigest is the hash of the exact canonical body.
  // Reuse the normative owner-record layout for the signature.
 const u32=n=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n);return b;},integer=n=>{const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n);return b;};
 const bytes=join(u32(1),sized(body.spoolUuid),sized(body.expectedHead.stateHash),integer(body.expectedHead.sequence),integer(body.sequence),u32(0),u32(ids.length),...ids.map(sized),Uint8Array.of(body.policy.maxAudience===undefined?0:1),...(body.policy.maxAudience===undefined?[]:[u32(body.policy.maxAudience)]),u32(2),sized(utf8.encode('max_audience')),u32(1),sized(utf8.encode('revoked_key_ids')),u32(2),sized(body.ownerId),sized(body.ownerStateHash),integer(body.ownershipTransferSequence));
 cut.ownerSignature=create(own.AuthorizationSignatureSchema,{signerKeyId:keyId(key('owner')),signature:sig('owner',hash(utf8.encode('heddle-spool-signed-policy-signature-v2'),join(bytes,sized(body.policyStateHash))))});b.policies.push(cut);
 const target=b.statements.find(v=>v.body.purpose===purpose&&hex(v.body.hostTransactionId)===hex(s.hostTransactionId));target.body.policySequence=body.sequence;target.body.policyStateHash=body.policyStateHash;
 }
 for(const mode of ['control','original_revoked','acceptor_revoked','acceptor_mint_revoked','forged_acceptor','account_mismatch','owner_impersonation','ordinary_revoked']){
  const b=clone(schema,base),target=b.statements.find(v=>v.body.purpose===purpose&&hex(v.body.hostTransactionId)===hex(s.hostTransactionId));
  const bp=(purpose===1?b.genesisWitnesses:b.authorityWitnesses).find(p=>hex(canonicalHybridV1(payloadSchema,p))===hex(target.body.canonicalPayload));
  if(mode==='ordinary_revoked'){target.body.basis=1;target.body.boundaryAcceptance=undefined;if(purpose===1)bp.boundaryAcceptance=undefined;else bp.boundaryAcceptances=[];}
  if(['forged_acceptor','account_mismatch','owner_impersonation'].includes(mode)){
   const be=purpose===1?bp.boundaryAcceptance:bp.boundaryAcceptances[0],value=decode(be.signedAcceptance.canonicalRecord);
   if(mode==='forged_acceptor')value.accepting_publisher=Array.from(key('cowriter_owner'));
   if(mode==='account_mismatch'){value.accepting_author.actor.principal_id=acceptor.owner.root.root.accountUuid.slice();value.accepting_author.actor.principal_id[0]^=1;value.original_account=value.accepting_author.actor.principal_id;}
   if(mode==='owner_impersonation'){const bad=load(wf,'self_signed_owner_uuid',native.NativeGenesisWitnessV1Schema);value.accepting_author.actor.principal_id=base.genesisWitnesses[0].binding.body.identity.ownerAccountUuid;value.accepting_author.authority=bad.creatorAuthorityEnvelope;value.accepting_author.authority_digest=Array.from(octetsId('heddle-thread-control-authority-v1',bad.creatorAuthorityEnvelope));}
   be.signedAcceptance=record(be.signedAcceptance.format,value,'paired_leaf');const id=octetsId(be.signedAcceptance.format,be.signedAcceptance.canonicalRecord);be.binding.acceptanceId=id;be.binding.signedAcceptanceDigest=signedNativeDigest(be.signedAcceptance);
   be.originalReceipts=be.originalReceipts.map(r=>{const value=decode(r.canonicalRecord);value.basis={BoundaryAcceptance:{acceptance:Array.from(id)}};return record(r.format,value,'witness');});be.binding.originalReceiptDigests=be.originalReceipts.map(signedNativeDigest);target.body.boundaryAcceptance=be.binding;
  }
  target.body.canonicalPayload=canonicalHybridV1(payloadSchema,bp);
  policyCut(b,mode==='original_revoked'||mode==='ordinary_revoked'?[keyId(key('device'))]:mode==='acceptor_revoked'?[keyId(key('paired_leaf'))]:mode==='acceptor_mint_revoked'?[keyId(key('cowriter_device'))]:[]);
  for(const signed of b.statements)signed.signature=sig('witness',statementSigningDigest(signed.body));sort(b);wire(prefix+'_'+mode,schema,b);
 }
}
writeFileSync('tests/fixtures/boundary-acceptor-alpha36.json',JSON.stringify(fixture,null,2)+'\n');
console.log('alpha.36 boundary vectors:',Object.keys(fixture.vectors).length);
