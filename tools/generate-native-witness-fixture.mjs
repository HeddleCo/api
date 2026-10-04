// Maintenance only. Regenerate after reviewing layouts, never during tests.
import { createPrivateKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { create, clone, fromBinary, toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import * as imp from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import * as host from '../packages/typescript/dist/common/hosted_witness_pb.js';
import { OwnerHistorySchema } from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import { SignedRecordSchema } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import { StartThreadRequestSchema } from '../packages/typescript/dist/v1alpha2/thread_pb.js';
import { ThreadGenesisRecordSchema } from '../packages/typescript/dist/v1alpha2/sync_pb.js';
import { encode, decode } from '../packages/typescript/dist/v1alpha2/_collaboration-msgpack.js';
import { canonicalHybridV1, signingDigest, hash, keyId, join, utf8, compare } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
import { originalSignaturesDigest, signedNativeDigest, ownerChainDigest, boundaryOctetsDigest } from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { signNativeGenesisAuthority, signedNativeGenesisAuthorityDigest } from '../packages/typescript/dist/v1alpha2/native-witness.js';
import { threadGenesisId } from '../packages/typescript/dist/v1alpha2/thread-genesis.js';
import { witnessId, setSigningBytes, statementSigningDigest, leafDigest, merkleRoot } from '../packages/typescript/dist/v1alpha2/witness-trust.js';
import { blake3 } from '@noble/hashes/blake3.js';
const f=JSON.parse(readFileSync('tests/fixtures/import-authority-host-witness-v1.json','utf8'));
const raw=h=>new Uint8Array(Buffer.from(h,'hex')),hex=b=>Buffer.from(b).toString('hex'),fill=(v,n=32)=>new Uint8Array(n).fill(v);
const str=s=>utf8.encode(s);
const key=n=>raw(f.keys[n].public_key_hex);
const sig=(n,input)=>new Uint8Array(sign(null,input,createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),raw(f.keys[n].seed_hex)]),format:'der',type:'pkcs8'})));
const load=(n,s)=>fromBinary(s,raw((f.wire_vectors[n]??f.signed_vectors[n]??f.commitment_vectors[n]).wire_hex));
const oldBundle=load('complete_renewed_export',imp.ImportPublicProofBundleV1Schema);
const identity=load('identity',imp.ImportIdentityV1Schema),chain=load('owner_chain',imp.ImportOwnerChainV1Schema);
const envelope=raw(f.native_authority.wire_hex);
const fixture={format_version:1,keys:f.keys,wire_vectors:{},canonical_vectors:{},positive:[],negative:[]};
function wire(n,s,v){fixture.wire_vectors[n]={schema:s.typeName,wire_hex:hex(toBinary(s,v))};return v;}
function commit(n,s,v,d){fixture.canonical_vectors[n]={schema:s.typeName,wire_hex:hex(toBinary(s,v)),canonical_hex:hex(canonicalHybridV1(s,v)),domain:d,digest_hex:hex(signingDigest(d,s,v))};}
execFileSync('cargo',['build','--locked','--manifest-path','tools/hybrid-native/Cargo.toml'],{stdio:'inherit'});
const metadata=JSON.parse(execFileSync('cargo',['metadata','--locked','--no-deps','--format-version','1','--manifest-path','tools/hybrid-native/Cargo.toml'],{encoding:'utf8'}));
const codec=metadata.target_directory+'/debug/hybrid-native-conformance';
function nativeId(format,bytes){const n=new Uint8Array(8);new DataView(n.buffer).setBigUint64(0,BigInt(bytes.length),true);return blake3(join(str(format),n,Uint8Array.of(0),bytes));}
function native(format,value,signers){const bytes=raw(execFileSync(codec,['encode',format],{input:hex(encode(value)),encoding:'utf8'}).trim());return create(SignedRecordSchema,{format,canonicalRecord:bytes,signatures:signers.map(n=>({publicKey:key(n),signature:sig(n,join(str(format),Uint8Array.of(0),bytes))})).sort((a,b)=>compare(a.publicKey,b.publicKey))});}
function statement(n,p,schema,authority,signatures,publisher='device',boundary){const body=create(host.HostedWitnessStatementV1Schema,{formatVersion:1,executorId:witnessId(key('witness')),purpose:schema===api.NativeGenesisWitnessV1Schema?1:schema===imp.HostedLandingWitnessV1Schema?4:2,spoolUuid:identity.spoolUuid,spoolGenesisDigest:identity.spoolGenesisDigest,ownerId:identity.ownerId,ownerStateHash:identity.ownerStateHash,ownershipTransferSequence:0n,policyStateHash:oldBundle.policies[0].body.policyStateHash,policySequence:1n,basis:boundary?2:1,publisherKeyId:keyId(key(publisher)),authorityDigest:authority,originalSignaturesDigest:signatures,hostTransactionId:fill(n,16),admissionOrder:BigInt(n),observedAtUnixMillis:1100000n,canonicalPayload:canonicalHybridV1(schema,p),boundaryAcceptance:boundary});const signed=create(host.SignedHostedWitnessStatementV1Schema,{body,signature:sig('witness',statementSigningDigest(body))});return signed;}
async function genesis(name,original,env,signer){const binding=await signNativeGenesisAuthority(original,env,identity,chain,{publicKey:key(signer),sign:bytes=>sig(signer,bytes)});wire(name+'_binding',api.SignedNativeGenesisAuthorityV1Schema,binding);commit(name+'_binding_body',api.NativeGenesisAuthorityV1Schema,binding.body,'heddle-native-genesis-authority-v1');commit(name+'_binding',api.SignedNativeGenesisAuthorityV1Schema,binding,'heddle-signed-native-genesis-authority-v1');const p=create(api.NativeGenesisWitnessV1Schema,{formatVersion:1,kind:2,binding,originalGenesis:original,creatorAuthorityEnvelope:env});wire(name+'_payload',api.NativeGenesisWitnessV1Schema,p);commit(name+'_payload',api.NativeGenesisWitnessV1Schema,p,'heddle-native-genesis-witness-payload-v1');return p;}
// Original genesis is unchanged; this second signature binds native StartThread
// authority, with no import permission. Every carrier below is native typed.
const account=await genesis('start_thread',oldBundle.genesisWitnesses[0].originalGenesis,envelope,'device');
const accountStatement=statement(201,account,api.NativeGenesisWitnessV1Schema,signedNativeGenesisAuthorityDigest(account.binding),originalSignaturesDigest([account.originalGenesis]));
const localAuthority=load('ownership_admission_payload',imp.ImportAuthorityWitnessV1Schema),resolution=load('resolution_admission_payload',imp.ImportAuthorityWitnessV1Schema);
const localOriginal=localAuthority.dependencies.find(r=>r.format==='heddle-thread-genesis-v1');
const local=await genesis('local_adopt',localOriginal,new Uint8Array(),'owner');
const localStatement=statement(202,local,api.NativeGenesisWitnessV1Schema,signedNativeGenesisAuthorityDigest(local.binding),originalSignaturesDigest([localOriginal]),'owner');
function authority(p,n){return statement(n,p,imp.ImportAuthorityWitnessV1Schema,authorityEnvelopeDigest(p.authorityEnvelope),originalSignaturesDigest([p.original,...p.dependencies]));}
// authority digest counted length, not a fixed placeholder.
import { authorityEnvelopeDigest } from '../packages/typescript/dist/v1alpha2/import-authority.js';
function authorityStatement(p,n){const s=authority(p,n);s.body.authorityDigest=authorityEnvelopeDigest(p.authorityEnvelope);s.signature=sig('witness',statementSigningDigest(s.body));return s;}
const sourceTemplate=load('authority_admission_payload',imp.ImportAuthorityWitnessV1Schema).dependencies.find(r=>r.format==='heddle-thread-operation-v1');
const sourcePayload=create(imp.ImportAuthorityWitnessV1Schema,{formatVersion:1,kind:1,original:sourceTemplate,authorityEnvelope:envelope});
// Select the genesis of this exact source, independent of list sort order.
const sourceThread=new Uint8Array(decode(sourceTemplate.canonicalRecord).thread);
const sourceGenesis=oldBundle.genesisWitnesses.find(g=>hex(threadGenesisId(g.originalGenesis.canonicalRecord))===hex(sourceThread)).originalGenesis;
const accountSource=hex(threadGenesisId(account.originalGenesis.canonicalRecord))===hex(sourceThread)?account:await genesis('account_source',sourceGenesis,envelope,'device');
const sourceGenesisStatement=accountSource===account?accountStatement:statement(203,accountSource,api.NativeGenesisWitnessV1Schema,signedNativeGenesisAuthorityDigest(accountSource.binding),originalSignaturesDigest([accountSource.originalGenesis]));
function bundle(geneses,authorities,statements){return create(api.NativePublicProofBundleV1Schema,{formatVersion:1,ownerGenesis:oldBundle.ownerGenesis,ownerHistories:oldBundle.ownerHistories,ownerChains:[chain],policies:oldBundle.policies,genesisWitnesses:geneses.sort((a,b)=>compare(signedNativeGenesisAuthorityDigest(a.binding),signedNativeGenesisAuthorityDigest(b.binding))),authorityWitnesses:authorities.sort((a,b)=>compare(signingDigest('heddle-import-authority-witness-payload-v1',imp.ImportAuthorityWitnessV1Schema,a),signingDigest('heddle-import-authority-witness-payload-v1',imp.ImportAuthorityWitnessV1Schema,b))),statements:statements.sort((a,b)=>compare(statementSigningDigest(a.body),statementSigningDigest(b.body)))});}
const cases={start_thread:bundle([account],[],[accountStatement]),account_source:bundle([accountSource],[sourcePayload],[sourceGenesisStatement,authorityStatement(sourcePayload,204)]),local_adopt_push:bundle([local],[localAuthority],[localStatement,authorityStatement(localAuthority,205)]),ownership_resolution:bundle([local],[localAuthority,resolution,create(imp.ImportAuthorityWitnessV1Schema,{...localAuthority,original:resolution.dependencies.find(r=>r.format==='heddle-thread-ownership-claim-v1'&&hex(signedNativeDigest(r))!==hex(signedNativeDigest(localAuthority.original)))})],[])};
const metadataPayload=load('authority_admission_payload',imp.ImportAuthorityWitnessV1Schema);
cases.native_metadata=bundle([accountSource],[sourcePayload,metadataPayload],[sourceGenesisStatement,authorityStatement(sourcePayload,204),authorityStatement(metadataPayload,209)]);
// Build statements for each retained claim and the explicit resolution.
const resolutionBundle=cases.ownership_resolution;resolutionBundle.statements=[localStatement,...resolutionBundle.authorityWitnesses.map((p,i)=>authorityStatement(p,206+i))].sort((a,b)=>compare(statementSigningDigest(a.body),statementSigningDigest(b.body)));
function sortBundle(b){
 b.ownerChains.sort((a,b)=>compare(ownerChainDigest(a),ownerChainDigest(b)));
 b.genesisWitnesses.sort((a,b)=>compare(signedNativeGenesisAuthorityDigest(a.binding),signedNativeGenesisAuthorityDigest(b.binding)));
 b.authorityWitnesses.sort((a,b)=>compare(signingDigest('heddle-import-authority-witness-payload-v1',imp.ImportAuthorityWitnessV1Schema,a),signingDigest('heddle-import-authority-witness-payload-v1',imp.ImportAuthorityWitnessV1Schema,b)));
 b.landingWitnesses.sort((a,b)=>compare(signingDigest('heddle-hosted-landing-witness-payload-v1',imp.HostedLandingWitnessV1Schema,a),signingDigest('heddle-hosted-landing-witness-payload-v1',imp.HostedLandingWitnessV1Schema,b)));
 b.statements.sort((a,b)=>compare(statementSigningDigest(a.body),statementSigningDigest(b.body)));
 return b;
}
function landingStatement(p,n){return statement(n,p,imp.HostedLandingWitnessV1Schema,authorityEnvelopeDigest(p.authorityEnvelope),originalSignaturesDigest([p.execution,p.sourceOperation,...p.reviewEvidence],[p.request.signature]));}
// Genuine native landing, followed by an account capture on the landed target.
const landing=load('landing_payload',imp.HostedLandingWitnessV1Schema);
const landingThreads=new Set([landing.execution,landing.sourceOperation,...landing.reviewEvidence].map(r=>hex(new Uint8Array(decode(r.canonicalRecord).thread))));
const landingGeneses=[];
for(const g of oldBundle.genesisWitnesses){if(landingThreads.has(hex(threadGenesisId(g.originalGenesis.canonicalRecord))))landingGeneses.push(await genesis('landing_'+landingGeneses.length,g.originalGenesis,envelope,'device'));}
const landingAuthorities=[create(imp.ImportAuthorityWitnessV1Schema,{formatVersion:1,kind:1,original:landing.sourceOperation,authorityEnvelope:envelope}),create(imp.ImportAuthorityWitnessV1Schema,{formatVersion:1,kind:1,original:landing.reviewEvidence[0],dependencies:[landing.sourceOperation],authorityEnvelope:envelope})];
cases.native_landing=bundle(landingGeneses,landingAuthorities,[...landingGeneses.map((p,i)=>statement(211+i,p,api.NativeGenesisWitnessV1Schema,signedNativeGenesisAuthorityDigest(p.binding),originalSignaturesDigest([p.originalGenesis]))),...landingAuthorities.map((p,i)=>authorityStatement(p,213+i)),landingStatement(landing,215)]);
cases.native_landing.landingWitnesses=[landing];
const captureValue=decode(landing.sourceOperation.canonicalRecord);
captureValue.thread=decode(landing.execution.canonicalRecord).thread;
captureValue.parents=[Array.from(nativeId(landing.execution.format,landing.execution.canonicalRecord))];
const integration=decode(new Uint8Array(decode(landing.execution.canonicalRecord).body.canonical));
const child=JSON.parse(execFileSync(codec,['descendant-state'],{input:hex(new Uint8Array(integration.result.state)),encoding:'utf8'}));
captureValue.body.canonical.result.state=Array.from(raw(child.state_hex));
const capture=native('heddle-thread-operation-v1',captureValue,['device']);
const capturePayload=create(imp.ImportAuthorityWitnessV1Schema,{formatVersion:1,kind:1,original:capture,dependencies:[landing.execution],authorityEnvelope:envelope});
cases.post_landing_capture=clone(api.NativePublicProofBundleV1Schema,cases.native_landing);
cases.post_landing_capture.authorityWitnesses.push(capturePayload);
cases.post_landing_capture.statements.push(authorityStatement(capturePayload,216));
sortBundle(cases.post_landing_capture);
// Different bindings select exact retained chains; no binding is rewritten on export.
const longerChain=load('renew_rotated_chain',imp.ImportOwnerChainV1Schema);
const selected=clone(api.NativeGenesisWitnessV1Schema,landingGeneses[0]);
selected.binding=await signNativeGenesisAuthority(selected.originalGenesis,envelope,identity,longerChain,{publicKey:key('device'),sign:bytes=>sig('device',bytes)});
cases.distinct_owner_chains=bundle([selected,landingGeneses[1]],[],[statement(217,selected,api.NativeGenesisWitnessV1Schema,signedNativeGenesisAuthorityDigest(selected.binding),originalSignaturesDigest([selected.originalGenesis])),statement(218,landingGeneses[1],api.NativeGenesisWitnessV1Schema,signedNativeGenesisAuthorityDigest(landingGeneses[1].binding),originalSignaturesDigest([landingGeneses[1].originalGenesis]))]);
cases.distinct_owner_chains.ownerHistories.push(load('renew_rotated_owner_history',OwnerHistorySchema));
cases.distinct_owner_chains.ownerChains.push(longerChain);
sortBundle(cases.distinct_owner_chains);
// Exact native boundary evidence over the account genesis + native envelope.
const oldBoundary=load('boundary_main',imp.ImportBoundaryAcceptanceV1Schema);
const manifestValue=decode(oldBoundary.originalsManifest);manifestValue.entries[0].authority.authority_digest=Array.from(nativeId('heddle-thread-control-authority-v1',envelope));
const manifest=raw(execFileSync(codec,['encode','heddle-original-publication-manifest-v1'],{input:hex(encode(manifestValue)),encoding:'utf8'}).trim());
const intent=oldBoundary.publicationIntent;
const acceptanceValue=decode(oldBoundary.signedAcceptance.canonicalRecord);acceptanceValue.originals_manifest=Array.from(nativeId('heddle-original-publication-manifest-v1',manifest));
const acceptance=native('heddle-original-boundary-acceptance-v1',acceptanceValue,['device']),acceptanceId=nativeId(acceptance.format,acceptance.canonicalRecord);
const receiptValue=decode(oldBoundary.originalReceipts[0].canonicalRecord);receiptValue.basis={BoundaryAcceptance:{acceptance:Array.from(acceptanceId)}};receiptValue.authority_digest=Array.from(nativeId('heddle-thread-genesis-authority-v1',envelope));
const receipt=native('heddle-thread-genesis-admission-v2',receiptValue,['witness']);
const boundary=create(imp.ImportBoundaryAcceptanceV1Schema,{binding:{formatVersion:1,acceptanceId,signedAcceptanceDigest:signedNativeDigest(acceptance),originalsManifestDigest:boundaryOctetsDigest('heddle-boundary-originals-manifest-v1',manifest),publicationIntentDigest:boundaryOctetsDigest('heddle-boundary-publication-intent-v1',intent),originalReceiptDigests:[signedNativeDigest(receipt)]},signedAcceptance:acceptance,originalsManifest:manifest,publicationIntent:intent,originalReceipts:[receipt]});
const boundaryPayload=create(api.NativeGenesisWitnessV1Schema,{...accountSource,boundaryAcceptance:boundary});
cases.boundary_acceptance=bundle([boundaryPayload],[],[statement(210,boundaryPayload,api.NativeGenesisWitnessV1Schema,signedNativeGenesisAuthorityDigest(boundaryPayload.binding),originalSignaturesDigest([boundaryPayload.originalGenesis]),'device',boundary.binding)]);
wire('start_request',StartThreadRequestSchema,create(StartThreadRequestSchema,{clientOperationId:'native-start',spool:{id:'23232323-2323-2323-2323-232323232323'},threadGenesis:account.originalGenesis,creatorAuthority:envelope,nativeGenesisAuthority:account.binding}));
wire('thread_genesis_record',ThreadGenesisRecordSchema,create(ThreadGenesisRecordSchema,{genesis:account.originalGenesis,creatorAuthority:envelope,nativeGenesisAuthority:account.binding}));
// A current set plus an exact retired set/proof for all native statements.
const statements=Object.values(cases).flatMap(b=>b.statements),unique=[...new Map(statements.map(s=>[hex(statementSigningDigest(s.body)),s])).values()];
const currentBody=create(host.HostedWitnessSetV1Schema,{formatVersion:1,deploymentAuthority:'https://weft.example.test',descriptorRootId:'descriptor-root-1',generation:50n,issuedAtUnixMillis:1100000n,validUntilUnixMillis:1200000n,currentExecutorId:witnessId(key('witness')),entries:[{executorId:witnessId(key('witness')),publicKey:key('witness'),role:1,state:1,purposes:[1,2,3,4],activeFromUnixMillis:1000000n,activeUntilUnixMillis:1300000n}]});
function set(body){const input=setSigningBytes(body);return create(host.SignedHostedWitnessSetV1Schema,{body,bodyDigest:hash(input),rootSignature:sig('root',input)});}
const currentSet=set(currentBody);wire('current_set',host.SignedHostedWitnessSetV1Schema,currentSet);
for(const [name,b] of Object.entries(cases)){b.witnessSet=currentSet;wire(name,api.NativePublicProofBundleV1Schema,b);fixture.positive.push(name);}
const leaves=unique.map(s=>({s,h:leafDigest(s.body.purpose,canonicalHybridV1(host.HostedWitnessStatementV1Schema,s.body),s.signature)})).sort((a,b)=>compare(a.h,b.h));
function proofPath(i,items){if(items.length===1)return [];let k=1;while(k*2<items.length)k*=2;return i<k?[...proofPath(i,items.slice(0,k)),merkleRoot(items.slice(k))]:[...proofPath(i-k,items.slice(k)),merkleRoot(items.slice(0,k))];}
const retiredBody=clone(host.HostedWitnessSetV1Schema,currentBody);retiredBody.generation=51n;retiredBody.issuedAtUnixMillis=1300000n;retiredBody.validUntilUnixMillis=1400000n;retiredBody.currentExecutorId=witnessId(key('next_witness'));retiredBody.entries[0].state=2;retiredBody.entries[0].activeUntilUnixMillis=1300000n;retiredBody.entries[0].archiveRoot=merkleRoot(leaves.map(l=>l.h));retiredBody.entries[0].archiveLeafCount=BigInt(leaves.length);retiredBody.entries.push(create(host.HostedWitnessEntryV1Schema,{...currentBody.entries[0],executorId:witnessId(key('next_witness')),publicKey:key('next_witness'),activeFromUnixMillis:1300000n,activeUntilUnixMillis:1500000n}));retiredBody.entries.sort((a,b)=>compare(a.executorId,b.executorId));
const retiredSet=set(retiredBody);wire('retired_set',host.SignedHostedWitnessSetV1Schema,retiredSet);
const retired=clone(api.NativePublicProofBundleV1Schema,cases.start_thread);retired.witnessSet=retiredSet;
retired.historyProofs=retired.statements.map(s=>{const i=leaves.findIndex(l=>hex(statementSigningDigest(l.s.body))===hex(statementSigningDigest(s.body)));return create(host.HostedWitnessHistoryProofV1Schema,{executorId:s.body.executorId,purpose:s.body.purpose,leafIndex:BigInt(i),leafCount:BigInt(leaves.length),siblings:proofPath(i,leaves.map(l=>l.h))});});
wire('retired_start_thread',api.NativePublicProofBundleV1Schema,retired);fixture.positive.push('retired_start_thread');
function negative(name,control,edit,expected,gate='bundle'){const b=clone(api.NativePublicProofBundleV1Schema,cases[control]??retired);edit(b);wire(name,api.NativePublicProofBundleV1Schema,b);fixture.negative.push({id:name,control,expected,gate});}
// Alpha.30 cases use the unchanged current set. Append after sealing the
// alpha.28 archive so every existing signed vector and retirement proof stays exact.
const localCapture=localAuthority.dependencies.find(r=>r.format==='heddle-thread-operation-v1');
const targetValue=decode(localCapture.canonicalRecord),sourceValue=decode(sourceTemplate.canonicalRecord);
const merged=JSON.parse(execFileSync(codec,['merge-state'],{input:hex(encode([sourceValue.body.canonical.result.state,targetValue.body.canonical.result.state])),encoding:'utf8'}));
const localIntegrationValue={version:1,spool:decode(localAuthority.original.canonicalRecord).acceptance.spool,device:Array.from(key('owner')),author:{kind:'local_key'},source_thread:sourceValue.thread,source_operation:Array.from(nativeId(sourceTemplate.format,sourceTemplate.canonicalRecord)),source_revision:Array.from(raw(merged.source_id_hex)),target_thread:targetValue.thread,expected_target_frontier:[Array.from(nativeId(localCapture.format,localCapture.canonicalRecord))],result:{...targetValue.body.canonical.result,state:Array.from(raw(merged.state_hex))},result_visibility:'Internal',initiating_request_proof:Array.from(fill(19)),local_policy_version:Array.from(fill(20)),executed_at_ms:1000000n};
function integrationOriginal(value,signer='owner'){
 const canonical=raw(execFileSync(codec,['encode','heddle-local-integration-v1'],{input:hex(encode(value)),encoding:'utf8'}).trim());
 return native('heddle-thread-operation-v1',{version:1,thread:value.target_thread,parents:value.expected_target_frontier,publisher:value.device,body:{kind:'local_integration',canonical:Array.from(canonical)}},[signer]);
}
const localIntegration=integrationOriginal(localIntegrationValue);
function localIntegrationBundle(original){
 const claimValue=decode(localAuthority.original.canonicalRecord);
 claimValue.source_frontier=[Array.from(nativeId(original.format,original.canonicalRecord))];
 const p=clone(imp.ImportAuthorityWitnessV1Schema,localAuthority);
 p.original=native('heddle-thread-ownership-claim-v1',claimValue,['owner','device']);
 p.dependencies.push(accountSource.originalGenesis,sourceTemplate,original);
 p.dependencies.sort((a,b)=>compare(signedNativeDigest(a),signedNativeDigest(b)));
 const b=bundle([local,accountSource],[p,sourcePayload],[localStatement,sourceGenesisStatement,authorityStatement(sourcePayload,204),authorityStatement(p,219)]);
 b.witnessSet=currentSet;
 return sortBundle(b);
}
cases.local_integration_push=localIntegrationBundle(localIntegration);
wire('local_integration_push',api.NativePublicProofBundleV1Schema,cases.local_integration_push);fixture.positive.push('local_integration_push');
negative('local_integration_forged_signature','local_integration_push',b=>{
 const p=b.authorityWitnesses.find(p=>p.kind===2),r=p.dependencies.find(r=>hex(signedNativeDigest(r))===hex(signedNativeDigest(localIntegration)));
 r.signatures[0].signature[0]^=1;p.dependencies.sort((a,b)=>compare(signedNativeDigest(a),signedNativeDigest(b)));
 b.statements=b.statements.filter(s=>s.body.purpose!==2||hex(s.body.canonicalPayload)===hex(canonicalHybridV1(imp.ImportAuthorityWitnessV1Schema,sourcePayload)));
 b.statements.push(authorityStatement(p,219));sortBundle(b);
},'Signature');
negative('local_integration_missing_claim','local_integration_push',b=>{
 // Retain the integration in a witnessed dependency even when the claim is absent.
 b.authorityWitnesses=b.authorityWitnesses.filter(p=>p.kind!==2);
 const p=b.authorityWitnesses[0];p.dependencies=[localIntegration];
 b.statements=b.statements.filter(s=>s.body.purpose===1);b.statements.push(authorityStatement(p,204));sortBundle(b);
},'Scope');
for(const [name,env] of [['local_integration_purpose2',envelope],['local_integration_empty_purpose2',new Uint8Array()]])negative(name,'local_integration_push',b=>{
 const p=create(imp.ImportAuthorityWitnessV1Schema,{formatVersion:1,kind:1,original:localIntegration,authorityEnvelope:env});
 b.authorityWitnesses.push(p);const s=authorityStatement(p,220);s.body.publisherKeyId=keyId(key('owner'));s.signature=sig('witness',statementSigningDigest(s.body));b.statements.push(s);sortBundle(b);
},'Scope');
negative('local_integration_purpose4','local_integration_push',b=>{
 const p=clone(imp.HostedLandingWitnessV1Schema,landing);p.execution=localIntegration;p.sourceOperation=sourceTemplate;p.reviewEvidence=[];
 b.landingWitnesses.push(p);b.statements.push(landingStatement(p,221));sortBundle(b);
},'Scope');
negative('account_integration_as_local','local_integration_push',b=>{
 const value={...localIntegrationValue,device:Array.from(key('device')),author:decode(sourceTemplate.canonicalRecord).body.canonical.author};
 Object.assign(b,localIntegrationBundle(integrationOriginal(value,'device')));
},'Scope');
negative('missing_binding','start_thread',b=>b.genesisWitnesses[0].binding=undefined,'GenesisBinding');
negative('forged_binding','start_thread',b=>b.genesisWitnesses[0].binding.creatorSignature.signature[0]^=1,'Signature');
negative('substituted_envelope','start_thread',b=>b.genesisWitnesses[0].creatorAuthorityEnvelope[5]^=1,'GenesisBinding');
negative('missing_genesis_statement','start_thread',b=>b.statements=[],'Scope');
negative('missing_owner_chain','start_thread',b=>b.ownerChains=[],'Bounds');
negative('missing_selected_owner_chain','distinct_owner_chains',b=>b.ownerChains=b.ownerChains.filter(c=>hex(ownerChainDigest(c))!==hex(ownerChainDigest(longerChain))),'Scope');
negative('post_landing_missing_purpose4','post_landing_capture',b=>{b.landingWitnesses=[];b.statements=b.statements.filter(s=>s.body.purpose!==4);},'Scope');
negative('post_landing_missing_purpose4_statement','post_landing_capture',b=>b.statements=b.statements.filter(s=>s.body.purpose!==4),'Scope');
negative('post_landing_substituted_purpose4','post_landing_capture',b=>{
 const p=b.landingWitnesses[0],v=decode(p.execution.canonicalRecord);v.body.canonical=Array.from(raw(execFileSync(codec,['encode','heddle-hosted-integration-v1'],{input:hex(encode({...integration,executed_at_ms:1100001n})),encoding:'utf8'}).trim()));
 p.execution=native('heddle-thread-operation-v1',v,['witness']);
 b.statements=b.statements.filter(s=>s.body.purpose!==4);b.statements.push(landingStatement(p,215));sortBundle(b);
},'Scope');
negative('carried_set_digest_substitution','start_thread',b=>b.witnessSet.bodyDigest[0]^=1,'StaleContext','witness');
negative('missing_owner_history','start_thread',b=>b.ownerHistories=[],'Scope');
negative('missing_policy','start_thread',b=>b.policies=[],'Scope');
negative('missing_ownership_claim','local_adopt_push',b=>{b.authorityWitnesses=[];b.statements=b.statements.filter(s=>s.body.purpose===1);},'Scope');
negative('missing_authority_statement','account_source',b=>b.statements=b.statements.filter(s=>s.body.purpose===1),'Scope');
negative('missing_native_authority_dependency','native_metadata',b=>{b.authorityWitnesses=b.authorityWitnesses.filter(p=>p.dependencies.length);const payload=b.authorityWitnesses[0];b.statements=b.statements.filter(s=>s.body.purpose===1||hex(s.body.canonicalPayload)===hex(canonicalHybridV1(imp.ImportAuthorityWitnessV1Schema,payload)));},'Scope');
negative('boundary_receipt_substitution','boundary_acceptance',b=>{b.genesisWitnesses[0].boundaryAcceptance.originalReceipts[0]=oldBoundary.originalReceipts[0];b.statements[0].body.canonicalPayload=canonicalHybridV1(api.NativeGenesisWitnessV1Schema,b.genesisWitnesses[0]);b.statements[0].signature=sig('witness',statementSigningDigest(b.statements[0].body));},'BoundaryAcceptance');
negative('retired_proof_missing','retired_start_thread',b=>b.historyProofs=[],'Proof','witness');
negative('retired_proof_substitution','retired_start_thread',b=>b.historyProofs[0].siblings[0][0]^=1,'Proof','witness');
const malformedImport=clone(imp.ImportPublicProofBundleV1Schema,oldBundle);malformedImport.delegations=[];wire('import_without_delegation',imp.ImportPublicProofBundleV1Schema,malformedImport);fixture.negative.push({id:'import_without_delegation',control:'import_complete',expected:'Canonical',gate:'import'});wire('import_complete',imp.ImportPublicProofBundleV1Schema,oldBundle);
fixture.negative.push({id:'dual_carriers',control:'start_thread',expected:'Protocol',gate:'dispatch'});
writeFileSync('tests/fixtures/native-host-witness-v1.json',JSON.stringify(fixture,null,2)+'\n');
console.log(`generated ${fixture.positive.length} native positives, ${fixture.negative.length} negatives`);
