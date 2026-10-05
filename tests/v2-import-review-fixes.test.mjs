import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {create,clone} from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as common from '../packages/typescript/dist/common/index.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
import * as w from '../packages/typescript/dist/v1alpha2/witness-trust.js';
const files=['import-review-fixes-alpha32','import-authority-host-witness-v1','import-sibling-jobs-alpha32','import-job-control-alpha31'].map(n=>JSON.parse(readFileSync(new URL('./fixtures/'+n+'.json',import.meta.url))));
const bytes=h=>new Uint8Array(Buffer.from(h,'hex'));
function v(n){const r=files.map(f=>f.wire_vectors?.[n]??f.signed_vectors?.[n]).find(Boolean);return a.strictDecode((r.schema.includes('.common.')?common:api)[r.schema.split('.').at(-1)+'Schema'],bytes(r.wire_hex),2*a.MAX_BUNDLE_BYTES);}
const old=files[1],pin={authority:old.context.authority,rootId:old.context.root_id,publicKey:bytes(old.keys.root.public_key_hex),epoch:1n};
const owner=(b,i=0)=>({identity:b.delegations[i].body.identity,ownerPublicKey:bytes(old.keys.owner.public_key_hex),ownerChainDigest:b.delegations[i].body.ownerChainDigest,authorityExpiresAtSeconds:2000n,effectiveFromUnixSeconds:0n,effectiveUntilUnixSeconds:undefined,forbiddenJobKeys:[],knownJobAssociations:[]});
const verify=(b,snapshot,resolver=(i,t)=>owner(b,i))=>a.verifyImportBundleWitnesses(b,pin,snapshot,1350000n,resolver,()=>{});
const reason=r=>e=>e instanceof a.HybridContractError&&e.reason===r;
for(const row of files[0].negatives)test('review fix publication '+row.id+' REJECT then PASS',async()=>{
 for(const [name,refuses] of [[row.id,true],[row.control,false]]){
  const b=v(name),i=b.delegations.length-1,d=await a.verifyImportDelegation(b.delegations[i],a.resolveBundlePermission(b,b.delegations[i].body.parentPermissionDigest),{...owner(b,i),nowUnixSeconds:1250n});
  const before=create(api.ImportResultManifestV1Schema,{...b.terminalManifest,slots:[]});
  for(const [index,o] of b.operations.entries()){
   if(refuses&&index===1){await assert.rejects(a.checkImportPublicationBudget(o,d,before),reason('Scope'));await assert.rejects(a.verifyNewImportOperation(o,d,1250n,before),reason('Scope'));break;}
   await a.checkImportPublicationBudget(o,d,before);await a.verifyNewImportOperation(o,d,1250n,before);
   before.slots.push(b.terminalManifest.slots.find(s=>Buffer.from(s.signedOperationDigest).equals(Buffer.from(a.signedOperationDigest(o)))));before.slots.sort((x,y)=>x.refName.localeCompare(y.refName));await a.checkImportPublicationBudget(o,d,before);
  }
  const set=await w.verifyWitnessSet(b.witnessSet,{authority:pin.authority,rootId:pin.rootId,rootPublicKey:pin.publicKey,rootEpoch:pin.epoch,nowUnixMillis:1350000n,clockFloorUnixMillis:1000000n,knownJobKeys:[]});
  const publication=a.verifyImportPublication(b.operations.at(-1),d,b.terminalManifest,b.statements.find(s=>s.body.purpose===3&&s.body.admissionOrder===101n),set,undefined,1350000n);
  if(refuses){await assert.rejects(publication,reason('Scope'));await assert.rejects(verify(b),reason('Scope'));}else{await publication;await verify(b);}
 }
});
test('review fix owner resolver REJECT then PASS',async()=>{
 const b=v('review_control');
 for(const current of [false,true]){await assert.rejects(verify(b,undefined,(i,time)=>{if(i===1)assert.equal(time,1250n);return {...owner(b,i),...(i===1?{authorityExpiresAtSeconds:current?(1n<<63n)-1n:1240n,effectiveFromUnixSeconds:current?1260n:0n,effectiveUntilUnixSeconds:current?undefined:1260n}:{})};}),reason('Scope'));await verify(b);}
 await assert.rejects(a.verifyImportBundleWitnesses(b,pin,undefined,1350000n,undefined,()=>{}),reason('Canonical'));
 const calls=[];await verify(b,undefined,(i,t)=>{calls.push([i,t]);return owner(b,i);});assert.ok(calls.length>2);
});
test('review fix recovery prefix REJECT then PASS',async()=>{
 const first=await verify(v('witnessed_prefix_recovery'));assert.equal(first.evidence,'recovery');assert.equal(first.snapshot.acceptedHistory[0].delegations.length,1);assert.equal(first.snapshot.jobAssociations.length,1);
 await assert.rejects(verify(v('review_renewed_recovery'),first.snapshot),reason('HighWater'));await verify(v('witnessed_prefix_recovery'),first.snapshot);
});
test('review fix renewal overflow reason REJECT then PASS',async()=>{
 const b={delegations:[v('overflow_predecessor')]},d=await a.verifyImportDelegation(b.delegations[0],undefined,{...owner(b),nowUnixSeconds:1100n});
 await assert.rejects(a.verifyImportRenewal(v('overflow_renewal'),d,v('overflow_manifest'),1n,undefined,{...owner(b),nowUnixSeconds:1250n}),reason('Bounds'));
 await a.verifyImportRenewal(v('overflow_control_renewal'),d,v('overflow_manifest_control'),1n,undefined,{...owner(b),nowUnixSeconds:1250n});
});
test('review fix renewal host maximum and original window REJECT then PASS',async()=>{
 const read=v('job_state_partial'),b=read.retainedProof,predecessor=await a.verifyImportRenewalPredecessor(read.state,v('permission'),{...owner(b),nowUnixSeconds:1600n});
 const configuration=v('import_configuration');configuration.limits.maxResultBytes=1n;
 const run=admitted=>a.prepareImportSourceScope(v('renew_prepare_request'),v('renew_source_moved_head'),'github',configuration,v('scope').destinationVersion,{original:b.delegations[0],admitted,nowUnixSeconds:1600n},{predecessor,state:read.state,source:read.retainedSource});
 assert.throws(()=>run(false),reason('OriginalWindowEnded'));run(true);
});
test('review fix reservation ownership and destinations REJECT then PASS',()=>{
 const spool=v('identity').spoolUuid,sa=v('scope_a'),sb=v('scope_b'),ja=v('delegation_a').body.logicalJobId,jb=v('delegation_b').body.logicalJobId,held=[{spoolUuid:spool,logicalJobId:ja,branches:sa.branches}];
 const conflict=e=>reason('PreparationRefused')(e)&&e.preparationRefusalReason===api.ImportPreparationRefusalReason.DESTINATION_CONFLICT;
 assert.throws(()=>a.checkImportSpoolReservations(spool,ja,sa,[],true),conflict);a.checkImportSpoolReservations(spool,ja,sa,held,true);
 for(const field of ['targetThreadId','genesisDigest']){const selected=clone(api.ImportPermissionScopeV1Schema,sb);selected.branches[0][field]=sa.branches[0][field];assert.throws(()=>a.checkImportSpoolReservations(spool,jb,selected,held,false),conflict);a.checkImportSpoolReservations(spool,jb,sb,held,false);
  const combined=create(api.ImportPermissionScopeV1Schema,{...sa,maxOperations:2,branches:[...sa.branches,...selected.branches].sort((x,y)=>x.refName.localeCompare(y.refName))});assert.throws(()=>a.validateImportScope(combined),reason('Scope'));combined.branches=[...sa.branches,...sb.branches].sort((x,y)=>x.refName.localeCompare(y.refName));a.validateImportScope(combined);
 }
});
test('review fix original window releases only the job reservations REJECT then PASS',()=>{
 const spool=v('identity').spoolUuid,sa=v('scope_a'),sb=v('scope_b'),da=v('delegation_a'),jb=v('delegation_b').body.logicalJobId;
 const held=[{spoolUuid:spool,logicalJobId:da.body.logicalJobId,branches:sa.branches},{spoolUuid:spool,logicalJobId:jb,branches:sb.branches}],facts={original:da,admitted:false,nowUnixSeconds:da.body.expiresAtUnixSeconds};
 assert.throws(()=>a.checkOriginalImportWindow(facts),reason('OriginalWindowEnded'));assert.throws(()=>a.checkImportSpoolReservations(spool,v('delegation_fresh').body.logicalJobId,sa,held,false),reason('PreparationRefused'));
 const after=a.releaseEndedImportReservations(spool,da.body.logicalJobId,facts,held);assert.equal(after.length,1);assert.equal(after[0],held[1]);a.checkImportSpoolReservations(spool,v('delegation_fresh').body.logicalJobId,sa,after,false);a.checkOriginalImportWindow({...facts,admitted:true});
});
test('review fix renew activation original window REJECT then PASS',async()=>{
 const r=v('alpha31_fresh_renew_request'),read=v('job_state_partial'),b=read.retainedProof;
 assert.throws(()=>a.validateImportRenewRequest(r,read,false,false,1300n),reason('OriginalWindowEnded'));
 await assert.rejects(a.verifyImportRenewSubmission(r,read,{...owner(b),nowUnixSeconds:1100n},{...owner(b),nowUnixSeconds:1300n},false,false),reason('OriginalWindowEnded'));
 a.validateImportRenewRequest(r,read,false,true,1300n);await a.verifyImportRenewSubmission(r,read,{...owner(b),nowUnixSeconds:1100n},{...owner(b),nowUnixSeconds:1300n},false,true);
});
test('review fix retry original window REJECT then PASS',async()=>{
 const read=v('control_renewed_state'),b=read.retainedProof,d=await a.verifyImportDelegation(read.state.activePredecessor,a.resolveBundlePermission(b,read.state.activePredecessor.body.parentPermissionDigest),{...owner(b,b.delegations.length-1),nowUnixSeconds:1300n}),caller={authenticatedPop:true,destinationWriter:true,callerAccount:'owner',connectionOwnerAccount:'owner',authorizedSource:read.retainedSource,exactGrantsCurrent:true,selectedCommitsAvailable:true};
 const context={read,original:v('control_original'),retryLineageId:read.state.retryLineageId,logicalJobTerminal:false,originalAdmitted:false,nowUnixSeconds:1300n};
 assert.throws(()=>a.checkImportRetryAdmission(v('control_retry_renewed'),context,d,caller),reason('OriginalWindowEnded'));a.checkImportRetryAdmission(v('control_retry_renewed'),{...context,originalAdmitted:true},d,caller);
});
test('review fix signed Rust/TS canonical parity',()=>{
 for(const [name,row] of Object.entries(files[0].signed_vectors)){const r=v(name),schema=api[row.body_schema.split('.').at(-1)+'Schema'];assert.equal(Buffer.from(a.canonicalHybridV1(schema,r.body)).toString('hex'),row.canonical_hex);assert.equal(Buffer.from(a.signingDigest(row.domain,schema,r.body)).toString('hex'),row.signing_input_hex);}
});
test('review fix narrowed bundle REJECT then PASS',async()=>{
 await assert.rejects(verify(v('narrowed_over')),reason('Scope'));await verify(v('narrowed_at'));
});
test('review fix renewal narrowing guards independently REJECT then PASS',async()=>{
 for(const kind of ['certificate','permission']){await assert.rejects(verify(v(`renew_${kind}_over`)),reason('RenewalFork'));await verify(v(`renew_${kind}_at`));}
});
