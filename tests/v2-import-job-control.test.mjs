import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
const f=JSON.parse(readFileSync(new URL('./fixtures/import-job-control-alpha31.json',import.meta.url)));
const old=JSON.parse(readFileSync(new URL('./fixtures/import-authority-host-witness-v1.json',import.meta.url)));
const bytes=h=>new Uint8Array(Buffer.from(h,'hex')),raw=(h,len=32)=>new Uint8Array(len).fill(parseInt(h,16));
function v(name){const r=f.wire_vectors[name]??old.wire_vectors[name]??old.signed_vectors[name];return a.strictDecode(api[r.schema.split('.').at(-1)+'Schema'],bytes(r.wire_hex),2*a.MAX_BUNDLE_BYTES);}
const rejects=reason=>e=>e instanceof a.HybridContractError&&e.reason===reason;
function caller(read,account='owner'){return {authenticatedPop:true,destinationWriter:true,callerAccount:account,connectionOwnerAccount:'owner',authorizedSource:read.retainedSource,exactGrantsCurrent:true,selectedCommitsAvailable:true};}
async function active(read){const signed=read.state.activePredecessor,d=signed.body;return a.verifyImportDelegation(signed,a.resolveBundlePermission(read.retainedProof,d.parentPermissionDigest),{identity:d.identity,ownerPublicKey:bytes(old.keys.owner.public_key_hex),ownerChainDigest:d.ownerChainDigest,authorityExpiresAtSeconds:2000n,nowUnixSeconds:read.state.authorityEpoch===1n?1100n:1250n,forbiddenJobKeys:[],knownJobAssociations:[]});}
async function retry(change={}){
 const read=v(change.read??'control_connected_state'),request=v('control_retry_connected'),original=v('control_original'),c=caller(read),lineage=change.lineage?raw(change.lineage,16):read.state.retryLineageId;
 if(change.operation_version)request.expectedOperationVersion=raw(change.operation_version);
 if(change.epoch)request.expectedAuthorityEpoch=BigInt(change.epoch);
 if(change.active_digest)request.activeDelegationDigest=raw(change.active_digest);
 if(change.operation_job)original.subject.subject.value.hybridJob.logicalJobId=raw(change.operation_job,16);
 if(change.operation_state)original.state=change.operation_state;
 if(change.superseded)original.supersededBy=create(api.OperationRefSchema,{spool:original.ref.spool,id:f.prior_attempt_ids[1]});
 if(change.replacement_connection){c.authorizedSource=v('control_public_state').retainedSource;}
 for(const [key,field] of [['exact_grants_current','exactGrantsCurrent'],['selected_commits_available','selectedCommitsAvailable'],['authenticated_pop','authenticatedPop'],['destination_writer','destinationWriter']])if(key in change)c[field]=change[key];
 a.checkImportRetryAdmission(request,{read,original,retryLineageId:lineage,logicalJobTerminal:change.terminal??false,nowUnixSeconds:BigInt(change.now??1100)},await active(read),c);
}
for(const row of f.control_vectors)test(`job control ${row.id}`,async()=>{
 const read=v(row.read),d=read.state.activePredecessor.body,c=caller(read,row.caller);
 assert.equal(row.ordinary_operation_visible,false);
 if(row.action==='Cancel'){c.connectionOwnerAccount=undefined;c.authorizedSource=undefined;c.exactGrantsCurrent=false;c.selectedCommitsAvailable=false;}
 const run=async()=>{
  a.checkImportControlCaller(row.action,read.retainedSource,d.scope,c);
  if(row.action==='Cancel')a.checkImportCancelRequest(v('cancel_active'),read.state.activePredecessor,read.state.authorityEpoch,false);
  if(row.action==='Retry')a.checkImportRetryAdmission(v(row.read==='control_public_state'?'control_retry_public':'control_retry_connected'),{read,original:v(row.read==='control_public_state'?'control_public_original':'control_original'),retryLineageId:read.state.retryLineageId,logicalJobTerminal:false,nowUnixSeconds:1100n},await active(read),c);
 };
 if(row.expected==='OK')await run();else {await assert.rejects(run(),rejects(row.expected));await retry();}
});
for(const row of f.retry_negatives)test(`retry admission REJECT then PASS ${row.id}`,async()=>{await assert.rejects(retry(row.change),rejects(row.expected));await retry();});
for(const row of f.state_negatives)test(`retry disclosure REJECT then PASS ${row.id}`,()=>{
 assert.throws(()=>a.validateImportRetryStateResponse(v('job_state_request'),v(row.read)),rejects(row.expected));
 a.validateImportRetryStateResponse(v('job_state_request'),v('control_connected_state'));
});
test('explicit retry unavailability is bounded; no target can be admitted',async()=>{
 for(let reason=1;reason<=6;reason++){
  const read=v('control_unavailable_'+reason),verified=await active(read);a.validateImportRetryStateResponse(v('job_state_request'),read);
  assert.throws(()=>a.checkImportRetryAdmission(v('control_retry_connected'),{read,original:v('control_original'),retryLineageId:read.state.retryLineageId,logicalJobTerminal:false,nowUnixSeconds:1100n},verified,caller(read)),rejects('StaleContext'));
 }
 await retry();
});
for(const row of f.receipt_negatives)test(`control receipt REJECT then PASS ${row.id}`,()=>{
 const check=row.kind==='Renew'?a.validateImportRenewResponse:(req,res)=>a.validateImportRetryResponse(req,res,f.prior_attempt_ids);
 assert.throws(()=>check(v(row.request),v(row.response)),rejects(row.expected));
 check(v(row.kind==='Renew'?'renew_request_partial':'control_retry_connected'),v(row.kind==='Renew'?'control_renew_applied':'control_retry_pending'));
});
for(const row of f.replay_vectors)test(`frozen ${row.kind} replay returns exact stored receipt; changed bytes refuse`,()=>{
 const request=v(row.request),wire=toBinary(api[row.kind==='Retry'?'RetryImportSourceRequestSchema':'RenewImportJobRequestSchema'],request),check=row.kind==='Retry'?a.checkImportRetryReplay:a.checkImportRenewReplay;
 const response=v(row.response),receipt=toBinary(api.MutationResponseSchema,response),stored=new Map([[request.clientOperationId,{wire,receipt}]]);
 function replay(body){const entry=stored.get(request.clientOperationId);check(body,entry.wire);return entry.receipt;}
 const changed=wire.slice();changed[changed.length-1]^=1;
 assert.throws(()=>replay(changed),rejects(row.changed_byte_expected));assert.deepEqual(replay(wire),receipt);
});
function sizedRequest(row){
 const request=create(api.CommitImportJobRequestSchema,{proof:{}}),size=row.decoded_protobuf_bytes;
 if(row.kind==='request')request.clientOperationId='x'.repeat(size);else request.proof.creatorAuthorityEnvelopes=[new Uint8Array(size)];
 for(let i=0;i<4;i++){
  const measured=toBinary(row.kind==='request'?api.CommitImportJobRequestSchema:api.ImportPublicProofBundleV1Schema,row.kind==='request'?request:request.proof).length;
  if(measured===size)return request;
  if(row.kind==='request')request.clientOperationId='x'.repeat(request.clientOperationId.length+size-measured);else request.proof.creatorAuthorityEnvelopes=[new Uint8Array(request.proof.creatorAuthorityEnvelopes[0].length+size-measured)];
 }
 throw Error('boundary recipe did not converge');
}
for(const row of f.bound_vectors)test(`Commit decoded bound ${row.id}`,async()=>{
 const request=sizedRequest(row);
 if(row.expected==='OK')a.validateImportCommitRequestBounds(request);else {
  assert.throws(()=>a.validateImportCommitRequestBounds(request),rejects('Bounds'));
  await assert.rejects(a.validateImportCommitRequest(request,'github',v('source_connected'),v('import_configuration')),rejects('Bounds'));
  a.validateImportCommitRequestBounds(sizedRequest({...row,decoded_protobuf_bytes:row.decoded_protobuf_bytes-1}));
 }
});
test('Renew applied acknowledgement followed by explicit Retry under replacement authority',async()=>{
 const flow=f.renew_retry_flow,renew=v(flow.renew_request),retryRequest=v(flow.retry_request),read=v(flow.new_state);
 a.validateImportRenewResponse(renew,v(flow.renew_response));assert.equal(v(flow.renew_response).receipt.outcome.value.resultingVersions.length,0);
 assert.notEqual(renew.clientOperationId,retryRequest.clientOperationId);
 a.checkImportRetryAdmission(retryRequest,{read,original:v('control_original'),retryLineageId:read.state.retryLineageId,logicalJobTerminal:false,nowUnixSeconds:1250n},await active(read),caller(read));
});
