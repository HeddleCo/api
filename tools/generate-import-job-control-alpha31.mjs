// Additive, compact host-admission vectors; signed inputs remain in the frozen fixture.
import { readFileSync, writeFileSync } from 'node:fs';
import { create, clone, fromBinary, toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
const previous=JSON.parse(readFileSync('tests/fixtures/import-authority-host-witness-v1.json'));
const f={format_version:1,wire_vectors:{},control_vectors:[],retry_negatives:[],state_negatives:[],receipt_negatives:[],bound_vectors:[]};
const raw=(n,len=32)=>new Uint8Array(len).fill(n),hex=b=>Buffer.from(b).toString('hex');
const v=n=>{const r=f.wire_vectors[n]??previous.wire_vectors[n]??previous.signed_vectors[n];return fromBinary(api[r.schema.split('.').at(-1)+'Schema'],Buffer.from(r.wire_hex,'hex'));};
const wire=(name,s,value)=>{f.wire_vectors[name]={schema:s.typeName,wire_hex:hex(toBinary(s,value))};return value;};
const base=v('job_state_partial'),destination=v('job_state_request').destination;
const originalId=a.initialImportOperationId(base.state.retryLineageId,false),version=raw(0xb1);
function state(name,read){read.retryAvailability={case:'eligibleRetryTarget',value:create(api.ImportEligibleRetryTargetV1Schema,{operationRef:{spool:destination,id:originalId},operationVersion:version})};return wire(name,api.GetImportJobStateResponseSchema,read);}
const connected=state('control_connected_state',base);
const publicRead=v('job_state_empty');publicRead.state.activePredecessor=v('public_delegation');publicRead.retainedProof=v('commit_public_source').proof;publicRead.retainedSource=create(api.ImportSourceSelectionV1Schema,{providerRepositoryId:publicRead.state.activePredecessor.body.scope.sourceUrl});
publicRead.state.logicalJobId=publicRead.state.activePredecessor.body.logicalJobId;
publicRead.state.committedManifest.logicalJobId=publicRead.state.logicalJobId;
publicRead.retainedProof.terminalManifest=publicRead.state.committedManifest;
publicRead.retainedProof.manifests=[publicRead.state.committedManifest];
state('control_public_state',publicRead);
const renewed=state('control_renewed_state',v('job_state_after_r1'));
const original=wire('control_original',api.OperationRecordSchema,create(api.OperationRecordSchema,{ref:{spool:destination,id:originalId},version,state:4,subject:{subject:{case:'import',value:{hybridJob:{logicalJobId:base.state.logicalJobId}}}}}));
const publicOriginal=clone(api.OperationRecordSchema,original);publicOriginal.subject.subject.value.hybridJob.logicalJobId=publicRead.state.logicalJobId;wire('control_public_original',api.OperationRecordSchema,publicOriginal);
function retry(name,read){return wire(name,api.RetryImportSourceRequestSchema,create(api.RetryImportSourceRequestSchema,{clientOperationId:name,originalOperation:original.ref,expectedOperationVersion:version,logicalJobId:read.state.logicalJobId,activeDelegationDigest:a.signedDelegationDigest(read.state.activePredecessor),expectedAuthorityEpoch:read.state.authorityEpoch}));}
retry('control_retry_connected',connected);retry('control_retry_public',publicRead);retry('control_retry_renewed',renewed);
const renewRequest=v('renew_request_partial');
wire('control_renew_applied',api.MutationResponseSchema,create(api.MutationResponseSchema,{receipt:{clientOperationId:renewRequest.clientOperationId,outcome:{case:'applied',value:{}}}}));
const physicalId='b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2';
wire('control_retry_pending',api.MutationResponseSchema,create(api.MutationResponseSchema,{receipt:{clientOperationId:'control_retry_connected',outcome:{case:'pendingOperation',value:{spool:destination,id:physicalId}}}}));
f.prior_attempt_ids=[originalId,'b3b3b3b3-b3b3-b3b3-b3b3-b3b3b3b3b3b3'];
for(const [id,action,caller,read,expected] of [
 ['co_writer_cancel','Cancel','co-writer','control_connected_state','OK'],
 ['co_writer_connected_retry','Retry','co-writer','control_connected_state','SourceSelection'],
 ['co_writer_public_retry','Retry','co-writer','control_public_state','OK'],
 ['owner_retry','Retry','owner','control_connected_state','OK'],
 ['co_writer_connected_renew','Renew','co-writer','control_connected_state','SourceSelection'],
 ['co_writer_public_renew','Renew','co-writer','control_public_state','OK'],
 ['owner_renew','Renew','owner','control_connected_state','OK'],
])f.control_vectors.push({id,action,caller,read,expected,ordinary_operation_visible:false,control:'owner_retry'});
for(const [id,change,expected] of [
 ['lost_grant',{exact_grants_current:false},'SourceSelection'],['commit_unavailable',{selected_commits_available:false},'SourceSelection'],
 ['replacement_connection',{replacement_connection:true},'SourceSelection'],['missing_pop',{authenticated_pop:false},'Scope'],['not_writer',{destination_writer:false},'Scope'],
 ['stale_operation_cas',{operation_version:'b4'},'StaleContext'],['stale_authority_epoch',{epoch:9},'StaleContext'],['stale_authority_digest',{active_digest:'b4'},'StaleContext'],
 ['foreign_lineage',{lineage:'b4'},'Scope'],['foreign_operation_job',{operation_job:'b4'},'Scope'],['in_progress',{operation_state:2},'StaleContext'],
 ['completed_attempt',{operation_state:3},'StaleContext'],['superseded',{superseded:true},'StaleContext'],['logical_job_cancelled',{terminal:true},'Revoked'],
 ['logical_job_revoked',{terminal:true},'Revoked'],['expired_authority',{now:1300},'Expired'],['old_epoch_after_renew',{read:'control_renewed_state'},'StaleContext'],
])f.retry_negatives.push({id,change,expected,control:'control_retry_connected'});
for(const [id,mutate,expected] of [
 ['missing_target',s=>s.retryAvailability={case:undefined},'Canonical'],['zero_reason',s=>s.retryAvailability={case:'retryUnavailable',value:0},'Canonical'],
 ['unknown_reason',s=>s.retryAvailability={case:'retryUnavailable',value:77},'Canonical'],
 ['foreign_destination',s=>s.retryAvailability.value.operationRef.spool.id='b4b4b4b4-b4b4-b4b4-b4b4-b4b4b4b4b4b4','Scope'],
 ['nil_attempt',s=>s.retryAvailability.value.operationRef.id='00000000-0000-0000-0000-000000000000','Canonical'],
 ['empty_version',s=>s.retryAvailability.value.operationVersion=raw(0,0),'Bounds'],['unbounded_version',s=>s.retryAvailability.value.operationVersion=raw(1,257),'Bounds'],
]){const s=clone(api.GetImportJobStateResponseSchema,connected);mutate(s);const name='control_state_'+id;wire(name,api.GetImportJobStateResponseSchema,s);f.state_negatives.push({id,read:name,expected});}
for(let reason=1;reason<=6;reason++){const s=clone(api.GetImportJobStateResponseSchema,connected);s.retryAvailability={case:'retryUnavailable',value:reason};wire('control_unavailable_'+reason,api.GetImportJobStateResponseSchema,s);}
const r=clone(api.RetryImportSourceRequestSchema,v('control_retry_connected'));r.clientOperationId=physicalId;wire('control_retry_uuid_request',api.RetryImportSourceRequestSchema,r);
for(const [id,kind,mutate,expected,request] of [
 ['renew_schedules_attempt','Renew',r=>r.receipt.outcome={case:'pendingOperation',value:create(api.RecordRefSchema,{spool:destination,id:physicalId})},'Semantic','renew_request_partial'],
 ['renew_wrong_receipt_id','Renew',r=>r.receipt.clientOperationId='other','Semantic','renew_request_partial'],
 ['retry_applied','Retry',r=>r.receipt.outcome={case:'applied',value:create(api.AppliedSchema,{})},'PendingOperation','control_retry_connected'],
 ['retry_reuses_prior_uuid','Retry',r=>r.receipt.outcome.value.id=f.prior_attempt_ids[1],'PendingOperation','control_retry_connected'],
 ['retry_reuses_predecessor_uuid','Retry',r=>r.receipt.outcome.value.id=originalId,'PendingOperation','control_retry_connected'],
 ['retry_uses_request_uuid','Retry',r=>r.receipt.clientOperationId=physicalId,'PendingOperation','control_retry_uuid_request'],
 ['retry_wrong_receipt_id','Retry',r=>r.receipt.clientOperationId='other','PendingOperation','control_retry_connected'],
 ['retry_foreign_destination','Retry',r=>r.receipt.outcome.value.spool=create(api.SpoolRefSchema,{id:f.prior_attempt_ids[1]}),'PendingOperation','control_retry_connected'],
]){const response=clone(api.MutationResponseSchema,v(kind==='Renew'?'control_renew_applied':'control_retry_pending'));mutate(response);wire('control_receipt_'+id,api.MutationResponseSchema,response);f.receipt_negatives.push({id,kind,response:'control_receipt_'+id,request,expected});}
f.replay_vectors=['Retry','Renew'].map(kind=>({kind,request:kind==='Retry'?'control_retry_connected':'renew_request_partial',response:kind==='Retry'?'control_retry_pending':'control_renew_applied',changed_byte_expected:'OperationIdReused'}));
// Compact length recipes avoid checking multi-megabyte hex blobs into the API.
for(const [id,kind,size,expected] of [['commit_at_limit','request',2097152,'OK'],['commit_one_over','request',2097153,'Bounds'],['proof_at_limit','proof',1048576,'OK'],['proof_one_over','proof',1048577,'Bounds']])f.bound_vectors.push({id,kind,decoded_protobuf_bytes:size,expected});
f.renew_retry_flow={renew_request:'renew_request_partial',renew_response:'control_renew_applied',new_state:'control_renewed_state',retry_request:'control_retry_renewed',physical_attempt_count_after_renew:1,physical_attempt_count_after_retry:2};
writeFileSync('tests/fixtures/import-job-control-alpha31.json',JSON.stringify(f,null,2)+'\n');
console.log('alpha.31 job-control vectors generated; existing fixture untouched');
