import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {clone,create,toBinary} from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as common from '../packages/typescript/dist/common/hosted_witness_pb.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
const f=JSON.parse(readFileSync(new URL('./fixtures/import-consumer-alpha32.json',import.meta.url)));
const old=JSON.parse(readFileSync(new URL('./fixtures/import-authority-host-witness-v1.json',import.meta.url)));
const control=JSON.parse(readFileSync(new URL('./fixtures/import-job-control-alpha31.json',import.meta.url)));
const bytes=h=>new Uint8Array(Buffer.from(h,'hex'));
function v(name){const r=f.wire_vectors[name]??control.wire_vectors[name]??old.wire_vectors[name]??old.signed_vectors[name];return a.strictDecode((r.schema.includes('.common.')?common:api)[r.schema.split('.').at(-1)+'Schema'],bytes(r.wire_hex),2*a.MAX_BUNDLE_BYTES);}
const rejects=reason=>e=>e instanceof a.HybridContractError&&e.reason===reason;
function caller(read,account='owner',change={}){return {authenticatedPop:true,destinationWriter:true,callerAccount:account,connectionOwnerAccount:'owner',authorizedSource:change.replacement?v('control_public_state').retainedSource:read.retainedSource,exactGrantsCurrent:change.grants??true,selectedCommitsAvailable:change.commits??true};}
const context=(read,change={})=>({read,logicalJobTerminal:change.terminal??false,originalAdmitted:change.admitted??true,nowUnixSeconds:BigInt(change.now??1100)});
for(const row of f.availability)test(`alpha32 caller availability ${row.id}`,()=>{
 const read=v(row.read),actual=a.importJobControlAvailability(context(read,row.change),caller(read,row.caller,row.change));
 assert.deepEqual(toBinary(api.ImportJobControlAvailabilityV1Schema,actual),toBinary(api.ImportJobControlAvailabilityV1Schema,read.controlAvailability));
 a.validateImportControlStateResponse(create(api.GetImportJobStateRequestSchema,{...v('job_state_request'),logicalJobId:read.state.logicalJobId}),read);
});
for(const row of f.state_negatives)test(`alpha32 controls REJECT then PASS ${row.id}`,()=>{
 assert.throws(()=>a.validateImportControlStateResponse(v('job_state_request'),v(row.read)),rejects(row.expected));
 a.validateImportControlStateResponse(v('job_state_request'),v(row.control));
});
test('alpha32 availability authorizes only authenticated destination writers',()=>{
 const read=v('consumer_controls_owner'),c=caller(read);
 for(const change of [{authenticatedPop:false},{destinationWriter:false},{callerAccount:''}])assert.throws(()=>a.importJobControlAvailability(context(read),{...c,...change}),rejects('Scope'));
 a.importJobControlAvailability(context(read),c);
});
test('alpha32 advisory availability never overrides admission',()=>{
 const read=v('consumer_controls_connected_co_writer'),scope=read.state.activePredecessor.body.scope;
 read.controlAvailability=clone(api.ImportJobControlAvailabilityV1Schema,v('consumer_controls_owner').controlAvailability);
 assert.throws(()=>a.checkImportControlCaller('Retry',read.retainedSource,scope,caller(read,'co-writer')),rejects('SourceSelection'));
 assert.throws(()=>a.checkImportControlCaller('Renew',read.retainedSource,scope,caller(read,'co-writer')),rejects('SourceSelection'));
 read.controlAvailability=clone(api.ImportJobControlAvailabilityV1Schema,v('consumer_controls_lost_grant').controlAvailability);
 a.checkImportControlCaller('Retry',read.retainedSource,scope,caller(read));
 a.checkImportControlCaller('Renew',read.retainedSource,scope,caller(read));
 const cancel=caller(read,'co-writer');delete cancel.connectionOwnerAccount;delete cancel.authorizedSource;cancel.exactGrantsCurrent=false;cancel.selectedCommitsAvailable=false;
 a.checkImportControlCaller('Cancel',read.retainedSource,scope,cancel);
});
function pin(replacement=false){return {authority:old.context.authority,rootId:replacement?'descriptor-root-2':old.context.root_id,publicKey:bytes(old.keys[replacement?'wrong_root':'root'].public_key_hex),epoch:replacement?2n:1n};}
function owners(bundle){return bundle.delegations.map(d=>({identity:d.body.identity,ownerPublicKey:bytes(old.keys.owner.public_key_hex),ownerChainDigest:d.body.ownerChainDigest,authorityExpiresAtSeconds:2000n,forbiddenJobKeys:[],knownJobAssociations:[]}));}
function policy(b){assert.deepEqual(toBinary(api.SignedSpoolPolicyRecordSchema,b.policies[0]),toBinary(api.SignedSpoolPolicyRecordSchema,v('signed_policy')));}
const verify=(b,snapshot,now=1150000n,replacement=false,hook=policy)=>a.verifyImportBundleWitnesses(b, pin(replacement), snapshot, now, (i,t)=>({...(owners(b))[i],effectiveFromUnixSeconds:0n,effectiveUntilUnixSeconds:undefined}), hook);
for(const row of f.recovery)test(`alpha32 recovery snapshot ${row.id}`,async()=>{
 const initialBundle=v('review_scheduled_recovery');if(row.initial_set)initialBundle.witnessSet=v(row.initial_set);
 const initial=row.input?await verify(initialBundle,undefined,row.initial_set?1350000n:1100000n):undefined;
 const input=structuredClone(initial?.snapshot),bundle=v(row.bundle);
 if(row.remove_set)bundle.witnessSet=undefined;
 if(row.replacement)bundle.witnessSet=v('alpha31_replacement_set');
 const result=await verify(bundle,initial?.snapshot,row.replacement?1350000n:1150000n,row.replacement);
 assert.equal(result.evidence,'recovery');assert.equal(result.snapshotAdvanced,row.expected_advanced);
 assert.equal(!!result.snapshot,row.expected_snapshot);assert.deepEqual(result.ownerCheckTimesUnixSeconds,[undefined]);
 assert.deepEqual(initial?.snapshot,input,'input unchanged');
 if(!row.expected_advanced)assert.deepEqual(result.snapshot,input,'persisting recovery is a no-op');
 if(result.snapshot){assert.deepEqual(result.snapshot.acceptedHistory,[]);assert.deepEqual(result.snapshot.jobAssociations,[]);}
 if(row.expected_advanced){assert.equal(result.snapshot.clockFloorUnixMillis,row.replacement?1350000n:1150000n);assert.deepEqual(toBinary(common.SignedHostedWitnessSetV1Schema,result.snapshot.witnessSet),toBinary(common.SignedHostedWitnessSetV1Schema,bundle.witnessSet));}
 // Returned copies cannot corrupt receiver-owned trust.
 if(result.snapshot){result.snapshot.root.publicKey[0]^=1;assert.deepEqual(initial?.snapshot,input);}
});
for(const row of f.receipt_negatives)test(`alpha32 authenticated receipts REJECT then PASS ${row.id}`,async()=>{
 const initial=await verify(v(row.bundle),undefined,1350000n),input=structuredClone(initial.snapshot),b=v(row.bundle);
 if(row.change==='observation')b.statements[0].body.observedAtUnixMillis+=1000n;
 if(row.change==='signature')b.statements[0].signature[0]^=1;
 if(row.change==='remove_set')b.witnessSet=undefined;
 if(row.change==='set_signature')b.witnessSet.rootSignature[0]^=1;
 await assert.rejects(verify(b,initial.snapshot,1350000n),rejects(row.expected));assert.deepEqual(initial.snapshot,input);
 await verify(v(row.bundle),initial.snapshot,1350000n);
});
test('alpha32 selected owner times are internal and receipt ordered',async()=>{
 const b=v('review_control'),first=await verify(b,undefined,1350000n);
 assert.deepEqual(first.ownerCheckTimesUnixSeconds,[1100n,1250n]);
 b.statements.reverse();const reversed=await verify(b,undefined,1350000n);assert.deepEqual(reversed.ownerCheckTimesUnixSeconds,first.ownerCheckTimesUnixSeconds);
 const admission=await verify(v('review_scheduled_admitted'),undefined,1350000n);assert.deepEqual(admission.ownerCheckTimesUnixSeconds,[1200n]);
 const noSet=v('review_scheduled_recovery');noSet.witnessSet=undefined;let calls=0;
 await verify(noSet,undefined,1100000n,false,(bundle,statement)=>{calls++;assert.equal(statement,undefined);policy(bundle);});assert.equal(calls,1);
 await assert.rejects(verify(noSet,undefined,1100000n,false,()=>{throw new a.HybridContractError('Signature');}),rejects('Signature'));
 // Runtime callers cannot inject a check time, including through object spread.
 const inputs=owners(b).map(o=>({...o,nowUnixSeconds:900n}));
 const result=await a.verifyImportBundleWitnesses(b, pin(), undefined, 1350000n, (i,t)=>({...(inputs)[i],effectiveFromUnixSeconds:0n,effectiveUntilUnixSeconds:undefined}), policy);assert.deepEqual(result.ownerCheckTimesUnixSeconds,[1100n,1250n]);
});
test('alpha32 availability wire discloses no account or connection identity',()=>{
 assert.equal(api.GetImportJobStateResponseSchema.fields.find(f=>f.number===6).message,api.ImportJobControlAvailabilityV1Schema);
 assert.deepEqual(api.ImportJobControlAvailabilityV1Schema.fields.map(f=>f.name),['retry','renew','cancel']);
 assert.deepEqual(api.ImportControlAvailabilityV1Schema.fields.map(f=>f.name),['available','unavailable']);
});
