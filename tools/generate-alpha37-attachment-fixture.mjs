// Maintenance only. Regenerate from frozen alpha.35/36 inputs; tests never sign.
import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { clone, create, fromBinary, toBinary } from '@bufbuild/protobuf';
import * as native from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import * as imp from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import * as own from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import { ThreadControlAuthoritySchema } from '../packages/typescript/dist/v1alpha2/identity_pb.js';
import { encode, decode } from '../packages/typescript/dist/v1alpha2/_collaboration-msgpack.js';
import { canonicalHybridV1, compare, hash, integer, join, keyId, sized, u32, utf8 } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
import { blake3 } from '@noble/hashes/blake3.js';
function nativeRecordId(format,bytes){const n=new Uint8Array(8);new DataView(n.buffer).setBigUint64(0,BigInt(bytes.length),true);return blake3(join(utf8.encode(format),n,Uint8Array.of(0),bytes));}
import { originalSignaturesDigest, signedNativeDigest } from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { mintRootAttachmentSigningDigest } from '../packages/typescript/dist/v1alpha2/owner-certificates.js';
import { statementSigningDigest } from '../packages/typescript/dist/v1alpha2/witness-trust.js';

const base=JSON.parse(readFileSync('tests/fixtures/boundary-acceptor-alpha36.json'));
const writer=JSON.parse(readFileSync('tests/fixtures/writer-authority-alpha35.json'));
const keys={...writer.keys,...base.keys},raw=h=>new Uint8Array(Buffer.from(h,'hex')),hex=b=>Buffer.from(b).toString('hex');
const sig=(role,bytes)=>new Uint8Array(sign(null,bytes,createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),raw(keys[role].seed_hex)]),format:'der',type:'pkcs8'})));
const auth=(role,digest)=>create(own.AuthorizationSignatureSchema,{signerKeyId:keyId(raw(keys[role].public_key_hex)),signature:sig(role,digest)});
execFileSync('cargo',['build','--locked','--manifest-path','tools/hybrid-native/Cargo.toml'],{stdio:'inherit'});
const metadata=JSON.parse(execFileSync('cargo',['metadata','--locked','--no-deps','--format-version','1','--manifest-path','tools/hybrid-native/Cargo.toml'],{encoding:'utf8'}));
const codec=metadata.target_directory+'/debug/hybrid-native-conformance';
const nativeBytes=(format,value)=>raw(execFileSync(codec,['encode',format],{input:hex(encode(value)),encoding:'utf8'}).trim());
const fixture={format_version:1,scope:'Exact retained boundary acceptor attachment admission; native owner/Biscuit checks remain mandatory',keys,vectors:{}};
for(const kind of ['native','import'])for(const purpose of [1,2]){
 const bundleSchema=kind==='native'?native.NativePublicProofBundleV1Schema:imp.ImportPublicProofBundleV1Schema;
 const payloadSchema=purpose===1?(kind==='native'?native.NativeGenesisWitnessV1Schema:imp.ImportGenesisWitnessV1Schema):imp.ImportAuthorityWitnessV1Schema;
 const initial=fromBinary(bundleSchema,raw(base.vectors[`${kind}_p${purpose}_control`].wire_hex));
 for(const mode of ['control','binary_publisher','binary_authority_digest']){
  const b=clone(bundleSchema,initial),s=b.statements.find(s=>s.body.basis===2&&s.body.purpose===purpose).body;
  const p=(purpose===1?b.genesisWitnesses:b.authorityWitnesses).find(p=>hex(canonicalHybridV1(payloadSchema,p))===hex(s.canonicalPayload));
  const e=purpose===1?p.boundaryAcceptance:p.boundaryAcceptances.find(e=>hex(e.binding.acceptanceId)===hex(s.boundaryAcceptance.acceptanceId));
  const old=clone(imp.ImportBoundaryAcceptanceV1Schema,e),a=decode(e.signedAcceptance.canonicalRecord);
  const envelope=fromBinary(ThreadControlAuthoritySchema,a.accepting_author.authority),h=envelope.owner;
  const template=fromBinary(own.OwnerHistorySchema,raw(writer.vectors.verified_rotate_history.wire_hex));
  const t=clone(own.OwnerKeyTransitionSchema,template.acceptedTransitions[0].transition);
  t.ownerId=h.root.root.ownerId;t.previousStateHash=h.stateHash;t.nextRecoveryPolicy=clone(own.RecoveryPolicySchema,h.root.root.recoveryPolicy);
  const encodedKey=k=>join(u32(k.algorithm),sized(k.publicKey)),r=t.nextRecoveryPolicy;
  const policy=join(u32(r.threshold),u32(r.guardians.length),...r.guardians.map(g=>join(u32(g.kind),encodedKey(g.key))),integer(r.windowSecs??604800n));
  const digest=hash(utf8.encode('heddle-owner-key-transition-v1'),join(u32(1),sized(t.ownerId),sized(t.previousStateHash),integer(t.sequence),u32(t.kind),encodedKey(t.nextAuthorityKey),policy,integer(t.validFromUnixSeconds,true),integer(t.previousKeyValidUntilUnixSeconds,true),sized(t.nonce)));
  h.acceptedTransitions.push(create(own.SignedOwnerKeyTransitionSchema,{transition:t,authorizations:[auth('owner',digest)],nextAuthorityKeyProof:auth('rotated_owner',digest)}));h.stateHash=digest;
  execFileSync(codec,['verify-owner-history','1100'],{input:hex(toBinary(own.OwnerHistorySchema,h)),encoding:'utf8'});
  a.accepting_author.authority=toBinary(ThreadControlAuthoritySchema,envelope);
  a.accepting_author.authority_digest=Array.from(nativeRecordId('heddle-thread-control-authority-v1',a.accepting_author.authority));
  if(mode==='control'){
   const forged=clone(own.SignedOwnerMintRootAttachmentSchema,envelope.mintRootAssociation.value);forged.attachment.nonce[0]^=1;forged.ownerSignature=auth('owner',mintRootAttachmentSigningDigest(forged.attachment));
   fixture.vectors[`${kind}_p${purpose}_forged_attachment`]={schema:own.SignedOwnerMintRootAttachmentSchema.typeName,wire_hex:hex(toBinary(own.SignedOwnerMintRootAttachmentSchema,forged))};
  }
  let bytes=nativeBytes(e.signedAcceptance.format,a);
  if(mode!=='control'){
   const malformed=decode(bytes);
   if(mode==='binary_publisher')malformed.accepting_publisher=Uint8Array.from(malformed.accepting_publisher);
   else malformed.accepting_author.authority_digest=Uint8Array.from(malformed.accepting_author.authority_digest);
   bytes=encode(malformed);
  }
  e.signedAcceptance.canonicalRecord=bytes;
  e.signedAcceptance.signatures[0].signature=sig('paired_leaf',join(utf8.encode(e.signedAcceptance.format),Uint8Array.of(0),bytes));
  const id=nativeRecordId(e.signedAcceptance.format,bytes);
  for(const receipt of e.originalReceipts){const value=decode(receipt.canonicalRecord);value.basis={BoundaryAcceptance:{acceptance:Array.from(id)}};receipt.canonicalRecord=nativeBytes(receipt.format,value);receipt.signatures[0].signature=sig('witness',join(utf8.encode(receipt.format),Uint8Array.of(0),receipt.canonicalRecord));}
  e.originalReceipts.sort((a,b)=>compare(signedNativeDigest(a),signedNativeDigest(b)));
  e.binding.acceptanceId=id;e.binding.signedAcceptanceDigest=signedNativeDigest(e.signedAcceptance);e.binding.originalReceiptDigests=e.originalReceipts.map(signedNativeDigest);
  if(purpose===2){
   p.dependencies=p.dependencies.map(d=>hex(signedNativeDigest(d))===hex(signedNativeDigest(old.signedAcceptance))?e.signedAcceptance:old.originalReceipts.some(r=>hex(signedNativeDigest(r))===hex(signedNativeDigest(d)))?e.originalReceipts.find(r=>r.format===d.format):d);
   p.dependencies.sort((a,b)=>compare(signedNativeDigest(a),signedNativeDigest(b)));
   s.originalSignaturesDigest=originalSignaturesDigest([p.original,...p.dependencies]);
  }
  s.boundaryAcceptance=e.binding;if(kind==='native')s.ownerStateHash=h.stateHash;s.canonicalPayload=canonicalHybridV1(payloadSchema,p);
  b.ownerHistories.push(h);
  for(const signed of b.statements)signed.signature=sig('witness',statementSigningDigest(signed.body));
  b.statements.sort((a,b)=>compare(statementSigningDigest(a.body),statementSigningDigest(b.body)));
  fixture.vectors[`${kind}_p${purpose}_${mode}`]={schema:bundleSchema.typeName,wire_hex:hex(toBinary(bundleSchema,b))};
 }
}
writeFileSync('tests/fixtures/boundary-attachment-alpha37.json',JSON.stringify(fixture,null,2)+'\n');
console.log('alpha.37 attachment vectors:',Object.keys(fixture.vectors).length);
