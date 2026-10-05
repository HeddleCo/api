// Maintenance only: produce all signed mixed-origin vectors through published codecs.
import {readFileSync,writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {create,clone,toBinary,fromBinary} from '@bufbuild/protobuf';
import * as imp from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import * as nat from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import * as host from '../packages/typescript/dist/common/hosted_witness_pb.js';
import {SignedRecordSchema} from '../packages/typescript/dist/v1alpha2/common_pb.js';
import {LandThreadRequestSchema} from '../packages/typescript/dist/v1alpha2/thread_pb.js';
import {decode,encode} from '../packages/typescript/dist/v1alpha2/_collaboration-msgpack.js';
import {canonicalHybridV1,signingDigest,compare,hash,keyId,join} from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
import {signedOperationDigest,manifestDigest,publicationPayload,frontierDigest} from '../packages/typescript/dist/v1alpha2/import-authority.js';
import {signedNativeDigest,originalSignaturesDigest} from '../packages/typescript/dist/v1alpha2/import-authority.js';
import {signedNativeGenesisAuthorityDigest} from '../packages/typescript/dist/v1alpha2/native-witness.js';
import {unarySigningBytes} from '../packages/typescript/dist/signing.js';
import {statementSigningDigest,setSigningBytes} from '../packages/typescript/dist/v1alpha2/witness-trust.js';
import {raw,hex,fill,key,sig,load,nativeId,native,statement,genesis,bundle,sortBundle,authorityStatement,landingStatement,account,sourceTemplate,envelope,currentSet,codec} from './generate-native-witness-fixture.mjs';
const original=JSON.parse(readFileSync('tests/fixtures/import-authority-host-witness-v1.json'));
const f={format_version:1,keys:original.keys,wire_vectors:{},positive:[],negative:[],stages:[],receiver_negative:[]};
function wire(name,schema,value){f.wire_vectors[name]={schema:schema.typeName,wire_hex:hex(toBinary(schema,value))};return value;}
function codecJson(command,value){return JSON.parse(execFileSync(codec,[command],{input:hex(value),encoding:'utf8'}));}
function ref(record,origin){return create(imp.ForeignDependencyV1Schema,{formatVersion:1,origin,threadGenesisDigest:record.format==='heddle-thread-genesis-v1'?nativeId(record.format,record.canonicalRecord):new Uint8Array(decode(record.canonicalRecord).thread),signedNativeDigest:signedNativeDigest(record)});}
function refs(records,origin){return [...new Map(records.map(r=>[hex(signedNativeDigest(r)),ref(r,origin)])).values()].sort((a,b)=>compare(a.signedNativeDigest,b.signedNativeDigest));}
function fresh(s){s.body.observedAtUnixMillis=1200000n;s.signature=sig('witness',statementSigningDigest(s.body));return s;}
const mixedSet=clone(host.SignedHostedWitnessSetV1Schema,currentSet);mixedSet.body.issuedAtUnixMillis=1200000n;mixedSet.body.validUntilUnixMillis=1300000n;mixedSet.body.generation=60n;mixedSet.bodyDigest=hash(setSigningBytes(mixedSet.body));mixedSet.rootSignature=sig('root',setSigningBytes(mixedSet.body));wire('mixed_set',host.SignedHostedWitnessSetV1Schema,mixedSet);
const imported=clone(imp.ImportPublicProofBundleV1Schema,load('current_export',imp.ImportPublicProofBundleV1Schema));
imported.witnessSet=mixedSet;
const importedOriginals=[];
for(let i=0;i<imported.operations.length;i++){
 const op=imported.operations[i],v=decode(sourceTemplate.canonicalRecord);v.thread=Array.from(op.body.genesisDigest);v.publisher=Array.from(key('job'));v.body.canonical.author={kind:'local_key'};
 const root=codecJson('git-root-state',new Uint8Array(v.body.canonical.result.state));v.body.canonical.result.state=Array.from(raw(root.state_hex));
 const capture=native('heddle-thread-operation-v1',v,['job']);const name='import_tip_'+i;wire(name,SignedRecordSchema,capture);importedOriginals.push(capture);
 const content=create(imp.ImportContentV1Schema,{formatVersion:1,canonicalCapture:raw(execFileSync(codec,['encode','capture'],{input:hex(encode(v.body.canonical.result)),encoding:'utf8'}).trim())});
 const before=signedOperationDigest(op);
 op.body.resultingFrontierDigest=frontierDigest(create(imp.ImportFrontierV1Schema,{formatVersion:1,threadId:op.body.genesisDigest,operationIds:[nativeId(capture.format,capture.canonicalRecord)]}));
 op.body.resultingContentDigest=signingDigest('heddle-import-content-v1',imp.ImportContentV1Schema,content);
 op.jobSignature.signature=sig('job',signingDigest('heddle-delegated-import-operation-v1',imp.DelegatedImportOperationV1Schema,op.body));
 for(const m of imported.manifests)for(const slot of m.slots)if(hex(slot.signedOperationDigest)===hex(before)){slot.signedOperationDigest=signedOperationDigest(op);slot.resultingFrontierDigest=op.body.resultingFrontierDigest;}
}
imported.terminalManifest=clone(imp.ImportResultManifestV1Schema,imported.manifests.find(m=>m.slots.length===2));
let prefix=create(imp.ImportResultManifestV1Schema,{...imported.terminalManifest,slots:[]});
for(let i=0;i<imported.operations.length;i++){
 const op=imported.operations[i];prefix.slots.push(imported.terminalManifest.slots.find(s=>hex(s.signedOperationDigest)===hex(signedOperationDigest(op))));prefix.slots.sort((a,b)=>a.refName.localeCompare(b.refName));
 const p3=imported.statements.filter(s=>s.body.purpose===3)[i];p3.body.canonicalPayload=canonicalHybridV1(imp.ImportPublicationWitnessV1Schema,publicationPayload(op,prefix));p3.body.originalSignaturesDigest=hash(op.jobSignature.signature);p3.signature=sig('witness',statementSigningDigest(p3.body));
}
imported.manifests.sort((a,b)=>compare(manifestDigest(a),manifestDigest(b)));
const tip=importedOriginals[0];
const tipResult=decode(tip.canonicalRecord).body.canonical.result;
// Native child branches from the imported main's actual converted Git State.
const childState=codecJson('descendant-state',new Uint8Array(tipResult.state));
const gValue=decode(account.originalGenesis.canonicalRecord);gValue.name='alpha34-native-child';gValue.nonce=Array.from(fill(230,16));gValue.parent=decode(tip.canonicalRecord).thread;gValue.base=Array.from(raw(childState.base_id_hex));
const childGenesis=await genesis('alpha34_child',native('heddle-thread-genesis-v1',gValue,['device']),envelope,'device');
const childThread=nativeId(childGenesis.originalGenesis.format,childGenesis.originalGenesis.canonicalRecord);
const childValue=decode(sourceTemplate.canonicalRecord);childValue.thread=Array.from(childThread);childValue.body.canonical.result.state=Array.from(raw(childState.state_hex));
const child=native('heddle-thread-operation-v1',childValue,['device']);
const childP2=create(imp.ImportAuthorityWitnessV1Schema,{formatVersion:1,kind:1,original:child,authorityEnvelope:envelope});
const childP1=fresh(statement(230,childGenesis,nat.NativeGenesisWitnessV1Schema,signedNativeGenesisAuthorityDigest(childGenesis.binding),originalSignaturesDigest([childGenesis.originalGenesis])));
const childStage=bundle([childGenesis],[childP2],[childP1,fresh(authorityStatement(childP2,231))]);childStage.witnessSet=mixedSet;
wire('native_child_stage',nat.NativePublicProofBundleV1Schema,childStage);wire('native_child',SignedRecordSchema,child);
f.stages.push({id:'native_child_stage',origin:2,originals:['native_child']});
// A separate native target has an empty frontier for fast-forward and a capture for merge.
const targetValue=decode(account.originalGenesis.canonicalRecord);targetValue.name='alpha34-native-target';targetValue.nonce=Array.from(fill(227,16));
const targetGenesis=await genesis('alpha34_target',native('heddle-thread-genesis-v1',targetValue,['device']),envelope,'device');
const targetThread=nativeId(targetGenesis.originalGenesis.format,targetGenesis.originalGenesis.canonicalRecord);
const targetCaptureValue=decode(sourceTemplate.canonicalRecord);targetCaptureValue.thread=Array.from(targetThread);
const targetCapture=native('heddle-thread-operation-v1',targetCaptureValue,['device']);
const targetP2=create(imp.ImportAuthorityWitnessV1Schema,{formatVersion:1,kind:1,original:targetCapture,authorityEnvelope:envelope});
const targetP1=fresh(statement(227,targetGenesis,nat.NativeGenesisWitnessV1Schema,signedNativeGenesisAuthorityDigest(targetGenesis.binding),originalSignaturesDigest([targetGenesis.originalGenesis])));
const targetEmpty=bundle([targetGenesis],[],[targetP1]);targetEmpty.witnessSet=mixedSet;
const targetStage=bundle([targetGenesis],[targetP2],[targetP1,fresh(authorityStatement(targetP2,228))]);targetStage.witnessSet=mixedSet;

const template=load('landing_payload',imp.HostedLandingWitnessV1Schema);
const reviewValue=decode(template.reviewEvidence[0].canonicalRecord);reviewValue.thread=decode(tip.canonicalRecord).thread;
const reviewControl=decode(new Uint8Array(reviewValue.body.canonical));
reviewControl.control.value.source=Array.from(raw(codecJson('merge-state',encode([decode(tip.canonicalRecord).body.canonical.result.state,decode(tip.canonicalRecord).body.canonical.result.state])).source_id_hex));
reviewControl.occurred_at_ms=1200000;reviewValue.body.canonical=Array.from(raw(execFileSync(codec,['encode','heddle-thread-control-v1'],{input:hex(encode(reviewControl)),encoding:'utf8'}).trim()));
const importedReview=native('heddle-thread-operation-v1',reviewValue,['device']);wire('import_review',SignedRecordSchema,importedReview);
const reviewP2=create(imp.ImportAuthorityWitnessV1Schema,{formatVersion:1,kind:1,original:importedReview,dependencies:[tip],authorityEnvelope:envelope});
imported.authorityWitnesses=[reviewP2];imported.statements.push(fresh(authorityStatement(reviewP2,236)));
wire('import_stage',imp.ImportPublicProofBundleV1Schema,imported);f.stages.push({id:'import_stage',origin:1,originals:[...importedOriginals.map((_,i)=>'import_tip_'+i),'import_review']});
// Account source authorization and native-child landing frontier reference the import tip.
const childForeignP2=clone(imp.ImportAuthorityWitnessV1Schema,childP2);childForeignP2.dependencies=[tip];
const childForeign=clone(nat.NativePublicProofBundleV1Schema,childStage);childForeign.authorityWitnesses=[childForeignP2];childForeign.statements=[childP1,fresh(authorityStatement(childForeignP2,232))];childForeign.foreignDependencies=refs([tip],1);sortBundle(childForeign);
wire('native_child_imported_frontier',nat.NativePublicProofBundleV1Schema,childForeign);f.positive.push({id:'native_child_imported_frontier',carrier:'native',stage:'import_stage'});
const integrationTemplate=decode(new Uint8Array(decode(template.execution.canonicalRecord).body.canonical));
async function landing(name,source,targetThread,parents,result,carrier,targetCarrier){
 const request=clone(imp.HostedLandingRequestProofV1Schema,template.request),body=fromBinary(LandThreadRequestSchema,request.requestBody);
 request.timestampMillis=1200000n;
 const sv=decode(source.canonicalRecord);
 const sourceId=codecJson('merge-state',encode([sv.body.canonical.result.state,sv.body.canonical.result.state])).source_id_hex;
 if(parents.length){const targetState=codecJson('merge-state',encode([decode(parents[0].canonicalRecord).body.canonical.result.state,decode(parents[0].canonicalRecord).body.canonical.result.state])).source_id_hex;body.expectedTarget.revision.value.value=raw(targetState);}
 body.thread.id.value=new Uint8Array(sv.thread);body.target.id.value=targetThread;body.source.revision.value.value=raw(sourceId);request.requestBody=toBinary(LandThreadRequestSchema,body);
 request.signature.signature=sig('device',await unarySigningBytes(request.signingIdentity,request.methodPath,request.timestampMillis,request.nonce,request.requestBody));
 const requestCommit=nativeId('weft-hosted-landing-request-proof-v1',join(await unarySigningBytes(request.signingIdentity,request.methodPath,request.timestampMillis,request.nonce,request.requestBody),request.signature.signature));
 const integration={...integrationTemplate,executed_at_ms:1200000,source_thread:sv.thread,source_operation:Array.from(nativeId(source.format,source.canonicalRecord)),source_revision:Array.from(raw(sourceId)),target_thread:Array.from(targetThread),expected_target_frontier:parents.map(r=>Array.from(nativeId(r.format,r.canonicalRecord))),result,review_evidence:[],initiating_request_proof:Array.from(requestCommit)};
 const execution=native('heddle-thread-operation-v1',{version:1,thread:Array.from(targetThread),parents:integration.expected_target_frontier,publisher:Array.from(key('witness')),body:{kind:'integration',canonical:Array.from(raw(execFileSync(codec,['encode','heddle-hosted-integration-v1'],{input:hex(encode(integration)),encoding:'utf8'}).trim()))}},['witness']);
 const payload=create(imp.HostedLandingWitnessV1Schema,{formatVersion:1,execution,request,sourceOperation:source,authorityEnvelope:envelope});
 const b=carrier==='native'?clone(nat.NativePublicProofBundleV1Schema,targetCarrier):clone(imp.ImportPublicProofBundleV1Schema,imported);
 b.landingWitnesses=[payload];b.statements.push(fresh(landingStatement(payload,233)));b.foreignDependencies=refs([source],carrier==='native'?1:2);
 if(carrier==='native')sortBundle(b);
 wire(name,carrier==='native'?nat.NativePublicProofBundleV1Schema:imp.ImportPublicProofBundleV1Schema,b);f.positive.push({id:name,carrier,stage:carrier==='native'?'import_stage':'native_child_stage'});return b;
}
const ff=await landing('import_tip_native_fast_forward',tip,targetThread,[],tipResult,'native',targetEmpty);
const merged=codecJson('merge-state',encode([tipResult.state,targetCaptureValue.body.canonical.result.state]));
await landing('import_tip_native_merge',tip,targetThread,[targetCapture],{...tipResult,state:Array.from(raw(merged.state_hex))},'native',targetStage);
const mainThread=new Uint8Array(decode(tip.canonicalRecord).thread);
const mergedBack=codecJson('merge-state',encode([childValue.body.canonical.result.state,tipResult.state]));
await landing('native_child_imported_main',child,mainThread,[tip],{...tipResult,state:Array.from(raw(mergedBack.state_hex))},'import');
// Landing review path also resolves a foreign original by its exact Thread and digest.
const reviews=clone(nat.NativePublicProofBundleV1Schema,ff),reviewLanding=reviews.landingWitnesses[0];
reviewLanding.reviewEvidence=[importedReview];
const reviewExecution=decode(reviewLanding.execution.canonicalRecord),reviewIntegration=decode(new Uint8Array(reviewExecution.body.canonical));
reviewIntegration.review_evidence=[Array.from(nativeId(importedReview.format,importedReview.canonicalRecord))];
reviewExecution.body.canonical=Array.from(raw(execFileSync(codec,['encode','heddle-hosted-integration-v1'],{input:hex(encode(reviewIntegration)),encoding:'utf8'}).trim()));
reviewLanding.execution=native('heddle-thread-operation-v1',reviewExecution,['witness']);
reviews.foreignDependencies=refs([tip,importedReview],1);reviews.statements=reviews.statements.filter(s=>s.body.purpose!==4);reviews.statements.push(fresh(landingStatement(reviewLanding,237)));sortBundle(reviews);wire('foreign_review_closure',nat.NativePublicProofBundleV1Schema,reviews);f.positive.push({id:'foreign_review_closure',carrier:'native',stage:'import_stage'});
function negative(name,control,edit,expected){const schema=f.wire_vectors[control].schema===nat.NativePublicProofBundleV1Schema.typeName?nat.NativePublicProofBundleV1Schema:imp.ImportPublicProofBundleV1Schema;const b=fromBinary(schema,raw(f.wire_vectors[control].wire_hex));edit(b);wire(name,schema,b);f.negative.push({id:name,control,carrier:schema===nat.NativePublicProofBundleV1Schema?'native':'import',expected});}
for(const [carrier,control]of [['native','foreign_review_closure'],['import','native_child_imported_main']]){
 negative(carrier+'_missing_foreign',control,b=>b.foreignDependencies=[],'Scope');
 negative(carrier+'_unreferenced_foreign',control,b=>{b.foreignDependencies.push(ref(childGenesis.originalGenesis,carrier==='native'?1:2));b.foreignDependencies.sort((a,b)=>compare(a.signedNativeDigest,b.signedNativeDigest));},'Scope');
 negative(carrier+'_duplicate_foreign',control,b=>b.foreignDependencies.splice(0,0,clone(imp.ForeignDependencyV1Schema,b.foreignDependencies[0])),'Canonical');
 negative(carrier+'_unsorted_foreign',control,b=>{if(b.foreignDependencies.length===1)b.foreignDependencies.push(ref(childGenesis.originalGenesis,2));b.foreignDependencies.sort((a,b)=>compare(b.signedNativeDigest,a.signedNativeDigest));},'Canonical');
 negative(carrier+'_same_origin_foreign',control,b=>b.foreignDependencies[0].origin=carrier==='native'?2:1,'Scope');
 negative(carrier+'_thread_mismatch',control,b=>b.foreignDependencies[0].threadGenesisDigest[0]^=1,'Scope');
 negative(carrier+'_digest_mismatch',control,b=>{b.foreignDependencies[0].signedNativeDigest[0]^=1;b.foreignDependencies.sort((a,b)=>compare(a.signedNativeDigest,b.signedNativeDigest));},'Scope');
 negative(carrier+'_foreign_version',control,b=>b.foreignDependencies[0].formatVersion=2,'Version');
 negative(carrier+'_foreign_origin_unknown',control,b=>b.foreignDependencies[0].origin=3,'Version');
 negative(carrier+'_foreign_width',control,b=>b.foreignDependencies[0].signedNativeDigest=new Uint8Array(31),'Canonical');
 negative(carrier+'_foreign_over_bound',control,b=>b.foreignDependencies=Array.from({length:129},()=>b.foreignDependencies[0]),'Bounds');
}
f.receiver_negative.push({id:'missing_frontier_stage',control:'native_child_imported_frontier',omit_stage:true,expected:'Scope'},{id:'missing_import_stage',control:'import_tip_native_fast_forward',omit_stage:true,expected:'Scope'},{id:'missing_native_stage',control:'native_child_imported_main',omit_stage:true,expected:'Scope'},{id:'unbound_local_key_import_source',control:'import_tip_native_fast_forward',unbind:true,expected:'ImportPermission'});
const job=clone(nat.NativePublicProofBundleV1Schema,ff),r=job.landingWitnesses[0].request;r.signature.publicKey=key('job');r.signingIdentity='principal:device-key:'+hex(key('job'));r.signature.signature=sig('job',await unarySigningBytes(r.signingIdentity,r.methodPath,r.timestampMillis,r.nonce,r.requestBody));const jobExecution=decode(job.landingWitnesses[0].execution.canonicalRecord),jobIntegration=decode(new Uint8Array(jobExecution.body.canonical));jobIntegration.initiating_request_proof=Array.from(nativeId('weft-hosted-landing-request-proof-v1',join(await unarySigningBytes(r.signingIdentity,r.methodPath,r.timestampMillis,r.nonce,r.requestBody),r.signature.signature)));jobExecution.body.canonical=Array.from(raw(execFileSync(codec,['encode','heddle-hosted-integration-v1'],{input:hex(encode(jobIntegration)),encoding:'utf8'}).trim()));job.landingWitnesses[0].execution=native('heddle-thread-operation-v1',jobExecution,['witness']);job.statements=job.statements.filter(s=>s.body.purpose!==4);const js=fresh(landingStatement(job.landingWitnesses[0],235));js.body.publisherKeyId=keyId(key('job'));js.signature=sig('witness',statementSigningDigest(js.body));job.statements.push(js);sortBundle(job);wire('job_signed_landing',nat.NativePublicProofBundleV1Schema,job);f.receiver_negative.push({id:'job_signed_landing',control:'import_tip_native_fast_forward',expected:'KeyRole'});
f.negative.push({id:'dual_carriers',control:'import_tip_native_fast_forward',carrier:'dispatch',expected:'Protocol'});
writeFileSync('tests/fixtures/foreign-dependencies-alpha34.json',JSON.stringify(f,null,2)+'\n');
console.log(`Generated alpha.34: ${f.positive.length} closures, ${f.negative.length} reference negatives, ${f.receiver_negative.length} staged/role negatives`);
