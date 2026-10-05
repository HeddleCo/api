// Maintenance only: frozen API-layer vectors, not full heddle authorization.
import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, sign } from 'node:crypto';
import { create, clone, fromBinary, toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import * as imp from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import * as own from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import * as host from '../packages/typescript/dist/common/hosted_witness_pb.js';
import { ThreadControlAuthoritySchema } from '../packages/typescript/dist/v1alpha2/identity_pb.js';
import { SignedRecordSchema } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import { encode, decode } from '../packages/typescript/dist/v1alpha2/_collaboration-msgpack.js';
import { hash, keyId, join, utf8, u32, sized, integer, compare, canonicalHybridV1, signingDigest } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
import { originalSignaturesDigest, authorityEnvelopeDigest, signedNativeDigest } from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { signedNativeGenesisAuthorityDigest } from '../packages/typescript/dist/v1alpha2/native-witness.js';
import { threadGenesisId } from '../packages/typescript/dist/v1alpha2/thread-genesis.js';
import { mintRootAttachmentSigningDigest } from '../packages/typescript/dist/v1alpha2/owner-certificates.js';
import { statementSigningDigest } from '../packages/typescript/dist/v1alpha2/witness-trust.js';
const native=JSON.parse(readFileSync('tests/fixtures/native-host-witness-v1.json'));
const imported=JSON.parse(readFileSync('tests/fixtures/import-authority-host-witness-v1.json'));
const raw=h=>new Uint8Array(Buffer.from(h,'hex')),hex=b=>Buffer.from(b).toString('hex'),fill=(n,size=32)=>new Uint8Array(size).fill(n);
const key=n=>raw(native.keys[n].public_key_hex);
const sig=(n,b)=>new Uint8Array(sign(null,b,createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),raw(native.keys[n].seed_hex)]),format:'der',type:'pkcs8'})));
const auth=(n,b)=>create(own.AuthorizationSignatureSchema,{signerKeyId:keyId(key(n)),signature:sig(n,b)});
const load=(f,n,s)=>fromBinary(s,raw(f.wire_vectors[n].wire_hex));
const base=load(native,'start_thread',api.NativePublicProofBundleV1Schema),identity=base.genesisWitnesses[0].binding.body.identity;
const originalEnvelope=fromBinary(ThreadControlAuthoritySchema,base.genesisWitnesses[0].creatorAuthorityEnvelope);
const account=fill(0x31,16),ownerAccount=identity.ownerAccountUuid;
function history(account,signer){
 const root=clone(own.OwnerRootSchema,originalEnvelope.owner.root.root);
 root.accountUuid=account;root.authorityKey.publicKey=key(signer);root.nonce=fill(0x32);
 const policy=root.recoveryPolicy,guardians=policy.guardians;
 const encodedKey=k=>join(u32(k.algorithm),sized(k.publicKey));
 const body=join(u32(1),sized(account),encodedKey(root.authorityKey),u32(policy.threshold),u32(guardians.length),...guardians.map(g=>join(u32(g.kind),encodedKey(g.key))),integer(policy.windowSecs??604800n),Uint8Array.of(0),sized(root.nonce),integer(0n,true));
 root.ownerId=hash(utf8.encode('heddle-owner-root-v1'),body);
 const digest=hash(utf8.encode('heddle-owner-root-v1'),join(u32(1),sized(root.ownerId),body.subarray(4)));
 const names=guardians.map(g=>Object.keys(native.keys).find(n=>hex(key(n))===hex(g.key.publicKey)));
 return create(own.OwnerHistorySchema,{root:{root,authorityProof:auth(signer,digest),recoveryKeyProofs:names.map(n=>auth(n,digest))},stateHash:digest});
}
const ownHistory=history(account,'wrong_root');
const envelope=clone(ThreadControlAuthoritySchema,originalEnvelope);envelope.owner=ownHistory;
envelope.sealedBiscuit=new Uint8Array(readFileSync('/tmp/api-alpha35-cowriter-biscuit.binpb'));
const certificate=envelope.mintRootAssociation.value;
certificate.attachment.accountUuid=account;certificate.attachment.ownerStateHash=ownHistory.stateHash;certificate.attachment.ownerSequence=0n;certificate.attachment.ownerKey.publicKey=key('wrong_root');
certificate.ownerSignature=auth('wrong_root',mintRootAttachmentSigningDigest(certificate.attachment));
const envelopeBytes=toBinary(ThreadControlAuthoritySchema,envelope);
function record(template,value,signers=['device']){
 const bytes=encode(value);return create(SignedRecordSchema,{format:template.format,canonicalRecord:bytes,signatures:signers.map(n=>({publicKey:key(n),signature:sig(n,join(utf8.encode(template.format),Uint8Array.of(0),bytes))})).sort((a,b)=>compare(a.publicKey,b.publicKey))});
}
function binding(account,env){
 const p=clone(api.NativeGenesisWitnessV1Schema,base.genesisWitnesses[0]);
 const value=decode(p.originalGenesis.canonicalRecord);value.owner.account=account;
 p.originalGenesis=record(p.originalGenesis,value);p.creatorAuthorityEnvelope=env;
 const b=p.binding.body;b.genesisDigest=threadGenesisId(p.originalGenesis.canonicalRecord);b.originalSignaturesDigest=originalSignaturesDigest([p.originalGenesis]);b.creatorAuthorityEnvelopeDigest=hash(env);
 p.binding.creatorSignature=auth('device',signingDigest('heddle-native-genesis-authority-v1',api.NativeGenesisAuthorityV1Schema,b));return p;
}
const fixture={format_version:1,scope:'API transport/binding, policy key cut and retained-certificate checks; full native owner/Biscuit/causal authorization is downstream',keys:native.keys,context:{identity_wire_hex:hex(toBinary(imp.ImportIdentityV1Schema,identity)),account_hex:hex(account),publisher_key_id_hex:hex(keyId(key('device'))),now_seconds:1100},vectors:{},positive:[],negative:[]};
const wire=(name,schema,value)=>{fixture.vectors[name]={schema:schema.typeName,wire_hex:hex(toBinary(schema,value))};return value;};
wire('cowriter_envelope',ThreadControlAuthoritySchema,envelope);wire('owner_envelope',ThreadControlAuthoritySchema,originalEnvelope);
wire('cowriter_start_thread',api.NativeGenesisWitnessV1Schema,binding(account,envelopeBytes));fixture.positive.push('cowriter_start_thread');
wire('account_mismatch',api.NativeGenesisWitnessV1Schema,binding(ownerAccount,envelopeBytes));fixture.negative.push({id:'account_mismatch',gate:'genesis',control:'cowriter_start_thread',expected:'GenesisBinding'});
const fake=clone(ThreadControlAuthoritySchema,envelope);fake.owner=history(ownerAccount,'wrong_root');
wire('self_signed_owner_uuid',api.NativeGenesisWitnessV1Schema,binding(ownerAccount,toBinary(ThreadControlAuthoritySchema,fake)));fixture.negative.push({id:'self_signed_owner_uuid',gate:'genesis',control:'cowriter_start_thread',expected:'Root'});
// Exact original signatures and testimony commitments. Native semantic
// verification of these operations is deferred to the released heddle cascade.
const old=load(native,'native_landing',api.NativePublicProofBundleV1Schema);
const oldSource=old.landingWitnesses[0].sourceOperation;
function source(name,thread){
 const value=decode(oldSource.canonicalRecord);value.thread=Array.from(thread);
 value.body.canonical.author.actor.principal_id=account;
 value.body.canonical.author.authority=Array.from(envelopeBytes);
 value.body.canonical.author.authority_digest=Array.from(authorityEnvelopeDigest(envelopeBytes));
 return wire(name,imp.ImportAuthorityWitnessV1Schema,create(imp.ImportAuthorityWitnessV1Schema,{formatVersion:1,kind:1,original:record(oldSource,value),authorityEnvelope:envelopeBytes}));
}
const start=fromBinary(api.NativeGenesisWitnessV1Schema,raw(fixture.vectors.cowriter_start_thread.wire_hex));
source('cowriter_capture_own_thread',start.binding.body.genesisDigest);
source('cowriter_capture_owner_thread',threadGenesisId(base.genesisWitnesses[0].originalGenesis.canonicalRecord));
const review=clone(imp.ImportAuthorityWitnessV1Schema,old.authorityWitnesses.find(p=>decode(p.original.canonicalRecord).body.kind==='metadata'));
const reviewValue=decode(review.original.canonicalRecord),control=decode(Uint8Array.from(reviewValue.body.canonical));
control.actor.principal_id=account;control.authority_envelope=Array.from(envelopeBytes);control.authority_digest=Array.from(authorityEnvelopeDigest(envelopeBytes));reviewValue.body.canonical=Array.from(encode(control));review.original=record(review.original,reviewValue);review.authorityEnvelope=envelopeBytes;
wire('cowriter_review',imp.ImportAuthorityWitnessV1Schema,review);
const claim=load(imported,'ownership_admission_payload',imp.ImportAuthorityWitnessV1Schema),claimValue=decode(claim.original.canonicalRecord);
claimValue.acceptance.actor.principal_id=account;claimValue.acceptance.authority=envelopeBytes;claimValue.acceptance.authority_digest=Array.from(authorityEnvelopeDigest(envelopeBytes));claim.original=record(claim.original,claimValue,['owner','device']);claim.authorityEnvelope=envelopeBytes;
wire('cowriter_claim',imp.ImportAuthorityWitnessV1Schema,claim);
const landing=clone(imp.HostedLandingWitnessV1Schema,old.landingWitnesses[0]);landing.authorityEnvelope=envelopeBytes;
wire('cowriter_land_request',imp.HostedLandingWitnessV1Schema,landing);
for(const name of ['cowriter_capture_own_thread','cowriter_capture_owner_thread','cowriter_review','cowriter_claim','cowriter_land_request']){
 const schema=name==='cowriter_land_request'?imp.HostedLandingWitnessV1Schema:imp.ImportAuthorityWitnessV1Schema,p=fromBinary(schema,raw(fixture.vectors[name].wire_hex));
 const s=clone(host.HostedWitnessStatementV1Schema,base.statements[0].body);s.purpose=name==='cowriter_land_request'?4:2;s.publisherKeyId=keyId(key('device'));s.authorityDigest=authorityEnvelopeDigest(envelopeBytes);s.canonicalPayload=canonicalHybridV1(schema,p);
 s.originalSignaturesDigest=name==='cowriter_land_request'?originalSignaturesDigest([p.execution,p.sourceOperation,...p.reviewEvidence],[p.request.signature]):originalSignaturesDigest([p.original,...p.dependencies]);
 wire(name+'_statement',host.SignedHostedWitnessStatementV1Schema,create(host.SignedHostedWitnessStatementV1Schema,{body:s,signature:sig('witness',statementSigningDigest(s))}));fixture.positive.push(name);
}
wire('paired_after_rotate',own.SignedOwnerMintRootAttachmentSchema,certificate);fixture.positive.push('paired_after_rotate');
const forged=clone(own.SignedOwnerMintRootAttachmentSchema,certificate);forged.attachment.nonce=fill(0x44);forged.ownerSignature=auth('wrong_root',mintRootAttachmentSigningDigest(forged.attachment));wire('forged_old_owner_certificate',own.SignedOwnerMintRootAttachmentSchema,forged);
const unknown=clone(own.SignedOwnerMintRootAttachmentSchema,certificate);unknown.attachment.ownerStateHash=fill(0x45);unknown.ownerSignature=auth('wrong_root',mintRootAttachmentSigningDigest(unknown.attachment));wire('unknown_issuer',own.SignedOwnerMintRootAttachmentSchema,unknown);
const badSignature=clone(own.SignedOwnerMintRootAttachmentSchema,certificate);badSignature.ownerSignature.signature[0]^=1;wire('invalid_old_owner_signature',own.SignedOwnerMintRootAttachmentSchema,badSignature);
for(const [id,expected] of [['actor_publisher_revoked','Revoked'],['actor_mint_revoked','Revoked'],['attachment_before_recover','Root'],['forged_old_owner_certificate','Root'],['unknown_issuer','Root'],['invalid_old_owner_signature','Signature']])fixture.negative.push({id,gate:id.startsWith('actor_')?'keys':'retained',control:id.startsWith('actor_')?'cowriter_envelope':'paired_after_rotate',expected});
writeFileSync('tests/fixtures/writer-authority-alpha35.json',JSON.stringify(fixture,null,2)+'\n');
console.log('alpha.35 writer vectors:',fixture.positive.length,'positive,',fixture.negative.length,'negative');
