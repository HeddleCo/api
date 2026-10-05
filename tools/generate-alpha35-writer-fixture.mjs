// Maintenance only: frozen API-layer vectors, not full heddle authorization.
import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
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
import { unarySigningBytes } from '../packages/typescript/dist/common/signing.js';
import { blake3 } from '@noble/hashes/blake3.js';
const native=JSON.parse(readFileSync('tests/fixtures/native-host-witness-v1.json'));
const imported=JSON.parse(readFileSync('tests/fixtures/import-authority-host-witness-v1.json'));
const raw=h=>new Uint8Array(Buffer.from(h,'hex')),hex=b=>Buffer.from(b).toString('hex'),fill=(n,size=32)=>new Uint8Array(size).fill(n);
for(const [name,seed] of [['cowriter_device',0x41],['cowriter_owner',0x42],['paired_leaf',0x43],['next_recovery_a',0x46],['next_recovery_b',0x47]]){
 const secret=fill(seed),privateKey=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),secret]),format:'der',type:'pkcs8'});
 native.keys[name]={seed_hex:hex(secret),public_key_hex:hex(new Uint8Array(createPublicKey(privateKey).export({format:'der',type:'spki'}).subarray(-32)))};
}
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
const ownHistory=history(account,'cowriter_owner');
const envelope=clone(ThreadControlAuthoritySchema,originalEnvelope);envelope.owner=ownHistory;
envelope.sealedBiscuit=new Uint8Array(readFileSync('/tmp/api-alpha35-cowriter-biscuit.binpb'));
const certificate=envelope.mintRootAssociation.value;
certificate.attachment.accountUuid=account;certificate.attachment.ownerStateHash=ownHistory.stateHash;certificate.attachment.ownerSequence=0n;certificate.attachment.ownerKey.publicKey=key('cowriter_owner');
envelope.mintRootPublicKey=key('cowriter_device');certificate.attachment.ownerKey.publicKey=key('cowriter_owner');certificate.attachment.mintRootKey.publicKey=key('cowriter_device');
certificate.ownerSignature=auth('cowriter_owner',mintRootAttachmentSigningDigest(certificate.attachment));
const envelopeBytes=toBinary(ThreadControlAuthoritySchema,envelope);
execFileSync('cargo',['build','--locked','--manifest-path','tools/hybrid-native/Cargo.toml'],{stdio:'inherit'});
const metadata=JSON.parse(execFileSync('cargo',['metadata','--locked','--no-deps','--format-version','1','--manifest-path','tools/hybrid-native/Cargo.toml'],{encoding:'utf8'}));
const nativeCodec=metadata.target_directory+'/debug/hybrid-native-conformance';
const nativeEncode=(format,value)=>raw(execFileSync(nativeCodec,['encode',format],{input:hex(encode(value)),encoding:'utf8'}).trim());
function typedId(format,bytes){const size=new Uint8Array(8);new DataView(size.buffer).setBigUint64(0,BigInt(bytes.length),true);return blake3(join(utf8.encode(format),size,Uint8Array.of(0),bytes));}
const nativeAuthorityDigest=typedId('heddle-thread-control-authority-v1',envelopeBytes);
function record(template,value,signers=['cowriter_device']){
 const bytes=nativeEncode(template.format,value);return create(SignedRecordSchema,{format:template.format,canonicalRecord:bytes,signatures:signers.map(n=>({publicKey:key(n),signature:sig(n,join(utf8.encode(template.format),Uint8Array.of(0),bytes))})).sort((a,b)=>compare(a.publicKey,b.publicKey))});
}
function binding(account,env){
 const p=clone(api.NativeGenesisWitnessV1Schema,base.genesisWitnesses[0]);
 const value=decode(p.originalGenesis.canonicalRecord);value.owner.account=account;value.creator=Array.from(key('cowriter_device'));
 p.originalGenesis=record(p.originalGenesis,value);p.creatorAuthorityEnvelope=env;
 const b=p.binding.body;b.creatorPublicKey=key('cowriter_device');b.publisherKeyId=keyId(key('cowriter_device'));b.genesisDigest=threadGenesisId(p.originalGenesis.canonicalRecord);b.originalSignaturesDigest=originalSignaturesDigest([p.originalGenesis]);b.creatorAuthorityEnvelopeDigest=hash(env);
 p.binding.creatorSignature=auth('cowriter_device',signingDigest('heddle-native-genesis-authority-v1',api.NativeGenesisAuthorityV1Schema,b));return p;
}
const fixture={format_version:1,scope:'API transport/binding, policy key cut and retained-certificate checks; full native owner/Biscuit/causal authorization is downstream',keys:native.keys,context:{identity_wire_hex:hex(toBinary(imp.ImportIdentityV1Schema,identity)),account_hex:hex(account),publisher_key_id_hex:hex(keyId(key('paired_leaf'))),now_seconds:1100},vectors:{},positive:[],negative:[]};
const wire=(name,schema,value)=>{if(schema===api.NativePublicProofBundleV1Schema){value.authorityWitnesses.sort((a,b)=>compare(signingDigest('heddle-import-authority-witness-payload-v1',imp.ImportAuthorityWitnessV1Schema,a),signingDigest('heddle-import-authority-witness-payload-v1',imp.ImportAuthorityWitnessV1Schema,b)));value.landingWitnesses.sort((a,b)=>compare(signingDigest('heddle-hosted-landing-witness-payload-v1',imp.HostedLandingWitnessV1Schema,a),signingDigest('heddle-hosted-landing-witness-payload-v1',imp.HostedLandingWitnessV1Schema,b)));value.statements.sort((a,b)=>compare(statementSigningDigest(a.body),statementSigningDigest(b.body)));}fixture.vectors[name]={schema:schema.typeName,wire_hex:hex(toBinary(schema,value))};return value;};
wire('cowriter_envelope',ThreadControlAuthoritySchema,envelope);wire('owner_envelope',ThreadControlAuthoritySchema,originalEnvelope);
wire('cowriter_start_thread',api.NativeGenesisWitnessV1Schema,binding(account,envelopeBytes));fixture.positive.push('cowriter_start_thread');
wire('account_mismatch',api.NativeGenesisWitnessV1Schema,binding(ownerAccount,envelopeBytes));fixture.negative.push({id:'account_mismatch',gate:'genesis',control:'cowriter_start_thread',expected:'GenesisBinding'});
const fake=clone(ThreadControlAuthoritySchema,envelope);fake.owner=history(ownerAccount,'cowriter_owner');
fake.sealedBiscuit=new Uint8Array(readFileSync('/tmp/api-alpha35-fake-owner-biscuit.binpb'));
const fakeCertificate=fake.mintRootAssociation.value;
fakeCertificate.attachment.accountUuid=ownerAccount;fakeCertificate.attachment.ownerStateHash=fake.owner.stateHash;
fakeCertificate.ownerSignature=auth('cowriter_owner',mintRootAttachmentSigningDigest(fakeCertificate.attachment));
wire('self_signed_owner_uuid',api.NativeGenesisWitnessV1Schema,binding(ownerAccount,toBinary(ThreadControlAuthoritySchema,fake)));fixture.negative.push({id:'self_signed_owner_uuid',gate:'genesis',control:'cowriter_start_thread',expected:'Root'});
// Exact original signatures and testimony commitments. Native semantic
// verification of these operations is deferred to the released heddle cascade.
const old=load(native,'native_landing',api.NativePublicProofBundleV1Schema);
const oldSource=old.landingWitnesses[0].sourceOperation;
function source(name,thread){
 const value=decode(oldSource.canonicalRecord);value.thread=Array.from(thread);
 value.publisher=Array.from(key('cowriter_device'));
 value.body.canonical.author.actor.principal_id=account;
 value.body.canonical.author.authority=envelopeBytes;
 value.body.canonical.author.authority_digest=Array.from(nativeAuthorityDigest);
 return wire(name,imp.ImportAuthorityWitnessV1Schema,create(imp.ImportAuthorityWitnessV1Schema,{formatVersion:1,kind:1,original:record(oldSource,value),authorityEnvelope:envelopeBytes}));
}
const start=fromBinary(api.NativeGenesisWitnessV1Schema,raw(fixture.vectors.cowriter_start_thread.wire_hex));
source('cowriter_capture_own_thread',start.binding.body.genesisDigest);
source('cowriter_capture_owner_thread',threadGenesisId(base.genesisWitnesses[0].originalGenesis.canonicalRecord));
const review=clone(imp.ImportAuthorityWitnessV1Schema,old.authorityWitnesses.find(p=>decode(p.original.canonicalRecord).body.kind==='metadata'));
const reviewValue=decode(review.original.canonicalRecord),control=decode(Uint8Array.from(reviewValue.body.canonical));
control.actor.principal_id=account;control.authority_envelope=Array.from(envelopeBytes);control.authority_digest=Array.from(nativeAuthorityDigest);reviewValue.body.canonical=Array.from(nativeEncode('heddle-thread-control-v1',control));reviewValue.publisher=Array.from(key('cowriter_device'));review.original=record(review.original,reviewValue);review.authorityEnvelope=envelopeBytes;
wire('cowriter_review',imp.ImportAuthorityWitnessV1Schema,review);
const claim=load(imported,'ownership_admission_payload',imp.ImportAuthorityWitnessV1Schema),claimValue=decode(claim.original.canonicalRecord);
claimValue.accepting_publisher=Array.from(key('cowriter_device'));claimValue.acceptance.actor.principal_id=account;claimValue.acceptance.authority=envelopeBytes;claimValue.acceptance.authority_digest=Array.from(nativeAuthorityDigest);claim.original=record(claim.original,claimValue,['owner','cowriter_device']);claim.authorityEnvelope=envelopeBytes;
wire('cowriter_claim',imp.ImportAuthorityWitnessV1Schema,claim);
const landing=clone(imp.HostedLandingWitnessV1Schema,old.landingWitnesses[0]);landing.authorityEnvelope=envelopeBytes;
landing.request.signature.publicKey=key('cowriter_device');landing.request.signingIdentity='principal:device-key:'+hex(key('cowriter_device'));
const requestBytes=await unarySigningBytes(landing.request.signingIdentity,landing.request.methodPath,landing.request.timestampMillis,landing.request.nonce,landing.request.requestBody);
landing.request.signature.signature=sig('cowriter_device',requestBytes);
const execution=decode(landing.execution.canonicalRecord),integration=decode(Uint8Array.from(execution.body.canonical));
integration.initiating_request_proof=Array.from(typedId('weft-hosted-landing-request-proof-v1',join(requestBytes,landing.request.signature.signature)));
execution.body.canonical=Array.from(nativeEncode('heddle-hosted-integration-v1',integration));landing.execution=record(landing.execution,execution,['witness']);
wire('cowriter_land_request',imp.HostedLandingWitnessV1Schema,landing);
for(const name of ['cowriter_capture_own_thread','cowriter_capture_owner_thread','cowriter_review','cowriter_claim','cowriter_land_request']){
 const schema=name==='cowriter_land_request'?imp.HostedLandingWitnessV1Schema:imp.ImportAuthorityWitnessV1Schema,p=fromBinary(schema,raw(fixture.vectors[name].wire_hex));
 const s=clone(host.HostedWitnessStatementV1Schema,base.statements[0].body);s.purpose=name==='cowriter_land_request'?4:2;s.publisherKeyId=keyId(key('cowriter_device'));s.authorityDigest=authorityEnvelopeDigest(envelopeBytes);s.canonicalPayload=canonicalHybridV1(schema,p);
 s.originalSignaturesDigest=name==='cowriter_land_request'?originalSignaturesDigest([p.execution,p.sourceOperation,...p.reviewEvidence],[p.request.signature]):originalSignaturesDigest([p.original,...p.dependencies]);
 wire(name+'_statement',host.SignedHostedWitnessStatementV1Schema,create(host.SignedHostedWitnessStatementV1Schema,{body:s,signature:sig('witness',statementSigningDigest(s))}));fixture.positive.push(name);
}
wire('paired_after_rotate',own.SignedOwnerMintRootAttachmentSchema,certificate);fixture.positive.push('paired_after_rotate');
const forged=clone(own.SignedOwnerMintRootAttachmentSchema,certificate);forged.attachment.nonce=fill(0x44);forged.ownerSignature=auth('cowriter_owner',mintRootAttachmentSigningDigest(forged.attachment));wire('forged_old_owner_certificate',own.SignedOwnerMintRootAttachmentSchema,forged);
const unknown=clone(own.SignedOwnerMintRootAttachmentSchema,certificate);unknown.attachment.ownerStateHash=fill(0x45);unknown.ownerSignature=auth('cowriter_owner',mintRootAttachmentSigningDigest(unknown.attachment));wire('unknown_issuer',own.SignedOwnerMintRootAttachmentSchema,unknown);
const badSignature=clone(own.SignedOwnerMintRootAttachmentSchema,certificate);badSignature.ownerSignature.signature[0]^=1;wire('invalid_old_owner_signature',own.SignedOwnerMintRootAttachmentSchema,badSignature);
for(const [id,expected] of [['actor_publisher_revoked','Revoked'],['actor_mint_revoked','Revoked'],['attachment_before_recover','Root'],['forged_old_owner_certificate','Root'],['unknown_issuer','Root'],['invalid_old_owner_signature','Signature']])fixture.negative.push({id,gate:id.startsWith('actor_')?'keys':'retained',control:id.startsWith('actor_')?'cowriter_envelope':'paired_after_rotate',expected});
// Exercise the policy cut at both real public-bundle entry points, with exact
// owner-signed policy bytes and freshly signed, policy-bound witness statements.
function cutPolicy(template,revoked){
 const policy=clone(own.SignedSpoolPolicyRecordSchema,template),b=policy.body;
 b.policy.revokedKeyIds=revoked;
 const body=join(u32(1),sized(b.spoolUuid),sized(b.expectedHead.stateHash),integer(b.expectedHead.sequence),integer(b.sequence),u32(0),u32(revoked.length),...revoked.map(sized),Uint8Array.of(b.policy.maxAudience===undefined?0:1),...(b.policy.maxAudience===undefined?[]:[u32(b.policy.maxAudience)]),u32(2),sized(utf8.encode('max_audience')),u32(1),sized(utf8.encode('revoked_key_ids')),u32(2),sized(b.ownerId),sized(b.ownerStateHash),integer(b.ownershipTransferSequence));
 b.policyStateHash=hash(utf8.encode('heddle-spool-signed-policy-v2'),body);
 policy.ownerSignature=auth('owner',hash(utf8.encode('heddle-spool-signed-policy-signature-v2'),join(body,sized(b.policyStateHash))));return policy;
}
const cowriterBundle=clone(api.NativePublicProofBundleV1Schema,base);cowriterBundle.genesisWitnesses=[start];
const s=cowriterBundle.statements[0].body;s.canonicalPayload=canonicalHybridV1(api.NativeGenesisWitnessV1Schema,start);s.authorityDigest=signedNativeGenesisAuthorityDigest(start.binding);s.originalSignaturesDigest=start.binding.body.originalSignaturesDigest;
s.publisherKeyId=start.binding.body.publisherKeyId;
cowriterBundle.statements[0].signature=sig('witness',statementSigningDigest(s));
wire('cowriter_start_bundle',api.NativePublicProofBundleV1Schema,cowriterBundle);
const importBundle=load(imported,'complete_export',imp.ImportPublicProofBundleV1Schema);
const oldP=load(imported,'authority_admission_payload',imp.ImportAuthorityWitnessV1Schema),newP=clone(imp.ImportAuthorityWitnessV1Schema,oldP);
const operation=decode(newP.original.canonicalRecord),controlMetadata=decode(Uint8Array.from(operation.body.canonical));controlMetadata.actor.principal_id=account;controlMetadata.authority_envelope=Array.from(envelopeBytes);controlMetadata.authority_digest=Array.from(nativeAuthorityDigest);operation.body.canonical=Array.from(nativeEncode('heddle-thread-control-v1',controlMetadata));operation.publisher=Array.from(key('cowriter_device'));newP.original=record(oldP.original,operation);newP.authorityEnvelope=envelopeBytes;
importBundle.authorityWitnesses.push(newP);
const importedStatement=clone(host.HostedWitnessStatementV1Schema,cowriterBundle.statements[0].body);importedStatement.purpose=2;importedStatement.canonicalPayload=canonicalHybridV1(imp.ImportAuthorityWitnessV1Schema,newP);importedStatement.authorityDigest=authorityEnvelopeDigest(envelopeBytes);importedStatement.originalSignaturesDigest=originalSignaturesDigest([newP.original,...newP.dependencies]);
importBundle.statements.push(create(host.SignedHostedWitnessStatementV1Schema,{body:importedStatement,signature:sig('witness',statementSigningDigest(importedStatement))}));
wire('cowriter_import_bundle',imp.ImportPublicProofBundleV1Schema,importBundle);
for(const [prefix,schema,bundle] of [['native',api.NativePublicProofBundleV1Schema,cowriterBundle],['import',imp.ImportPublicProofBundleV1Schema,importBundle]]){
 const b=clone(schema,bundle),policy=cutPolicy(b.policies[0],[keyId(key('cowriter_device'))]);b.policies=[policy];
 for(const signed of b.statements){signed.body.policyStateHash=policy.body.policyStateHash;signed.signature=sig('witness',statementSigningDigest(signed.body));}
 wire(prefix+'_actor_key_revoked',schema,b);
}

// Fix-round helpers and fully rebound negative bundles.
function rebound(schema,bundle,edit){
 const b=clone(schema,bundle);
 const references=b.statements.map(({body:s})=>s.purpose===2?b.authorityWitnesses.find(p=>hex(canonicalHybridV1(imp.ImportAuthorityWitnessV1Schema,p))===hex(s.canonicalPayload)):s.purpose===4?b.landingWitnesses.find(p=>hex(canonicalHybridV1(imp.HostedLandingWitnessV1Schema,p))===hex(s.canonicalPayload)):undefined);
 edit(b);
 for(const [i,signed] of b.statements.entries()){const s=signed.body,p=references[i];
  if(p){s.canonicalPayload=canonicalHybridV1(s.purpose===2?imp.ImportAuthorityWitnessV1Schema:imp.HostedLandingWitnessV1Schema,p);s.authorityDigest=authorityEnvelopeDigest(p.authorityEnvelope);s.originalSignaturesDigest=s.purpose===2?originalSignaturesDigest([p.original,...p.dependencies]):originalSignaturesDigest([p.execution,p.sourceOperation,...p.reviewEvidence],[p.request.signature]);}
  signed.signature=sig('witness',statementSigningDigest(s));
 }
 return b;
}
const p2Bundle=load(native,'native_metadata',api.NativePublicProofBundleV1Schema),p4Bundle=load(native,'native_landing',api.NativePublicProofBundleV1Schema);
wire('p2_owner_bundle',api.NativePublicProofBundleV1Schema,p2Bundle);wire('p4_owner_bundle',api.NativePublicProofBundleV1Schema,p4Bundle);
for(const [name,bundle] of [['p2',p2Bundle],['p4',p4Bundle]]){
 const bad=rebound(api.NativePublicProofBundleV1Schema,bundle,b=>{if(name==='p2')b.authorityWitnesses[0].authorityEnvelope=toBinary(ThreadControlAuthoritySchema,fake);else b.landingWitnesses[0].authorityEnvelope=toBinary(ThreadControlAuthoritySchema,fake);});
 wire(name+'_self_signed_owner_uuid',api.NativePublicProofBundleV1Schema,bad);
 const poisoned=clone(api.NativePublicProofBundleV1Schema,bad),h=clone(own.OwnerHistorySchema,poisoned.ownerHistories[0]);h.root.root.accountUuid=account;poisoned.ownerHistories.unshift(h);
 wire(name+'_duplicate_history_poisoning',api.NativePublicProofBundleV1Schema,poisoned);
}
const mismatchedP2=clone(imp.ImportAuthorityWitnessV1Schema,newP);mismatchedP2.authorityEnvelope=toBinary(ThreadControlAuthoritySchema,originalEnvelope);wire('p2_envelope_not_op_author',imp.ImportAuthorityWitnessV1Schema,mismatchedP2);
const mismatchedP4=clone(imp.HostedLandingWitnessV1Schema,landing);mismatchedP4.authorityEnvelope=toBinary(ThreadControlAuthoritySchema,originalEnvelope);wire('requester_not_token_subject',imp.HostedLandingWitnessV1Schema,mismatchedP4);
function bindPolicy(b,policies){b.policies=policies;const p=policies.at(-1).body;for(const signed of b.statements){signed.body.policyStateHash=p.policyStateHash;signed.body.policySequence=p.sequence;signed.signature=sig('witness',statementSigningDigest(signed.body));}return b;}
for(const [prefix,schema,bundle] of [['native',api.NativePublicProofBundleV1Schema,cowriterBundle],['import',imp.ImportPublicProofBundleV1Schema,importBundle]]){
 const first=cutPolicy(bundle.policies[0],[fill(0x90)]),second=clone(own.SignedSpoolPolicyRecordSchema,first);second.body.expectedHead=create(own.SignedPolicyHeadSchema,{stateHash:first.body.policyStateHash,sequence:1n});second.body.sequence=2n;
 const tip=cutPolicy(second,[fill(0x90)]),chain=bindPolicy(clone(schema,bundle),[first,tip]);wire(prefix+'_policy_chain',schema,chain);
 for(const mode of ['stripped','absent','reordered','duplicated','subtracted','predecessor_stripped']){
  const b=clone(schema,chain);
  if(mode==='stripped')b.policies[1].body.policy.revokedKeyIds=[];
  if(mode==='absent'){bindPolicy(b,[cutPolicy(bundle.policies[0],[])]);b.policies[0].body.policy=undefined;}
  if(mode==='reordered')b.policies.reverse();
  if(mode==='duplicated')b.policies.push(clone(own.SignedSpoolPolicyRecordSchema,b.policies[1]));
  if(mode==='subtracted')bindPolicy(b,[first,cutPolicy(second,[])]);
  if(mode==='predecessor_stripped')b.policies[0].body.policy.revokedKeyIds=[];
  wire(prefix+'_policy_'+mode,schema,b);
 }
}
// Claim and resolution counterparties need the same policy key cut as publisher.
const resolutionBundle=load(native,'ownership_resolution',api.NativePublicProofBundleV1Schema);
wire('ownership_counterparty_control',api.NativePublicProofBundleV1Schema,resolutionBundle);
for(const kind of [2,3]){
 const b=clone(api.NativePublicProofBundleV1Schema,resolutionBundle),statement=b.statements.find(s=>s.body.purpose===2&&b.authorityWitnesses.some(p=>p.kind===kind&&hex(canonicalHybridV1(imp.ImportAuthorityWitnessV1Schema,p))===hex(s.body.canonicalPayload)));
 const p=b.authorityWitnesses.find(p=>hex(canonicalHybridV1(imp.ImportAuthorityWitnessV1Schema,p))===hex(statement.body.canonicalPayload));
 const counterparty=p.original.signatures.find(k=>hex(keyId(k.publicKey))!==hex(statement.body.publisherKeyId));
 const first=b.policies[0],second=clone(own.SignedSpoolPolicyRecordSchema,first);second.body.expectedHead=create(own.SignedPolicyHeadSchema,{stateHash:first.body.policyStateHash,sequence:first.body.sequence});second.body.sequence=first.body.sequence+1n;
 const cut=cutPolicy(second,[keyId(counterparty.publicKey)]);b.policies=[first,cut];
 // Only this P2 testimony uses the introducing policy. Earlier P1 admissions
 // retain their unrevoked policy, so no publisher guard masks the counterparty.
 statement.body.policyStateHash=cut.body.policyStateHash;statement.body.policySequence=cut.body.sequence;statement.signature=sig('witness',statementSigningDigest(statement.body));
 wire('kind_'+kind+'_counterparty_revoked',api.NativePublicProofBundleV1Schema,b);
}
// Replace a P4 Review with a valid signed non-Review original; recommit all bytes.
const nonReview=rebound(api.NativePublicProofBundleV1Schema,p4Bundle,b=>{b.landingWitnesses[0].reviewEvidence=[b.landingWitnesses[0].sourceOperation];});wire('p4_non_review',api.NativePublicProofBundleV1Schema,nonReview);
// Independently verified history endpoints for retained issuers.
function transitioned(kind){
 const h=clone(own.OwnerHistorySchema,ownHistory),root=h.root.root,recovery=clone(own.RecoveryPolicySchema,root.recoveryPolicy);
 if(kind===2)recovery.guardians=[{kind:1,key:{algorithm:1,publicKey:key('next_recovery_a')}},{kind:1,key:{algorithm:1,publicKey:key('next_recovery_b')}}].map(g=>create(own.RecoveryGuardianSchema,g)).sort((a,b)=>compare(a.key.publicKey,b.key.publicKey));
 const t=create(own.OwnerKeyTransitionSchema,{formatVersion:1,ownerId:root.ownerId,previousStateHash:h.stateHash,sequence:1n,kind,nextAuthorityKey:{algorithm:1,publicKey:key('rotated_owner')},nextRecoveryPolicy:recovery,validFromUnixSeconds:1050n,previousKeyValidUntilUnixSeconds:kind===2?0n:1050n,nonce:fill(0x48)});
 const encodedKey=k=>join(u32(k.algorithm),sized(k.publicKey)),policy=join(u32(recovery.threshold),u32(recovery.guardians.length),...recovery.guardians.map(g=>join(u32(g.kind),encodedKey(g.key))),integer(recovery.windowSecs??604800n));
 const canonical=join(u32(1),sized(t.ownerId),sized(t.previousStateHash),integer(t.sequence),u32(t.kind),encodedKey(t.nextAuthorityKey),policy,integer(t.validFromUnixSeconds,true),integer(t.previousKeyValidUntilUnixSeconds,true),sized(t.nonce)),digest=hash(utf8.encode('heddle-owner-key-transition-v1'),canonical);
 const oldGuardians=root.recoveryPolicy.guardians.map(g=>Object.keys(native.keys).find(n=>hex(key(n))===hex(g.key.publicKey))),nextGuardians=recovery.guardians.map(g=>Object.keys(native.keys).find(n=>hex(key(n))===hex(g.key.publicKey)));
 h.acceptedTransitions=[create(own.SignedOwnerKeyTransitionSchema,{transition:t,authorizations:(kind===2?oldGuardians:['cowriter_owner']).map(n=>auth(n,digest)),nextAuthorityKeyProof:auth('rotated_owner',digest),nextRecoveryKeyProofs:kind===2?nextGuardians.map(n=>auth(n,digest)):[]})];h.stateHash=digest;
 const bytes=toBinary(own.OwnerHistorySchema,h);execFileSync(nativeCodec,['verify-owner-history','1100'],{input:hex(bytes),encoding:'utf8'});
 fixture.context[kind===2?'recover_signing_digest_hex':'rotate_signing_digest_hex']=hex(digest);return h;
}
wire('verified_rotate_history',own.OwnerHistorySchema,transitioned(1));wire('verified_recover_history',own.OwnerHistorySchema,transitioned(2));
fixture.context.issuer_state_hash_hex=hex(ownHistory.stateHash);fixture.context.issuer_sequence=0;
fixture.context.owner_root_signing_digest_hex=hex(ownHistory.stateHash);
for(const [name,attachment] of [['admitted_original',certificate],['admitted_unknown',unknown],['admitted_bad_signature',badSignature]]){
 const e=clone(ThreadControlAuthoritySchema,envelope);e.mintRootAssociation.value=attachment;
 const p=clone(imp.ImportAuthorityWitnessV1Schema,newP);p.authorityEnvelope=toBinary(ThreadControlAuthoritySchema,e);
 const s=clone(host.HostedWitnessStatementV1Schema,importedStatement);s.canonicalPayload=canonicalHybridV1(imp.ImportAuthorityWitnessV1Schema,p);s.authorityDigest=authorityEnvelopeDigest(p.authorityEnvelope);
 wire(name+'_payload',imp.ImportAuthorityWitnessV1Schema,p);wire(name+'_statement',host.SignedHostedWitnessStatementV1Schema,create(host.SignedHostedWitnessStatementV1Schema,{body:s,signature:sig('witness',statementSigningDigest(s))}));
}
writeFileSync('tests/fixtures/writer-authority-alpha35.json',JSON.stringify(fixture,null,2)+'\n');
console.log('alpha.35 writer vectors:',fixture.positive.length,'positive,',fixture.negative.length,'negative');
