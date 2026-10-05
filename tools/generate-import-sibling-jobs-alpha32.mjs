// Maintenance only: append an independent frozen corpus without rewriting any
// existing fixture. Tests consume these bytes and never generate signatures.
import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, sign } from 'node:crypto';
import { clone, create, fromBinary, toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { hash, keyId, join, utf8 } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
const base=JSON.parse(readFileSync('tests/fixtures/import-authority-host-witness-v1.json'));
const bytes=h=>new Uint8Array(Buffer.from(h,'hex')),hex=b=>Buffer.from(b).toString('hex');
const raw=(n,size=32)=>new Uint8Array(size).fill(n);
const v=n=>{const r=base.signed_vectors[n]??base.wire_vectors[n];return fromBinary(api[r.schema.split('.').at(-1)+'Schema'],bytes(r.wire_hex));};
const f={format_version:1,base_head:'b9f590afc23f2b37f20b34af09f5cb2389a8c6ad',wire_vectors:{},signed_vectors:{},scenarios:[],gate_vectors:[]};
const wire=(name,schema,value)=>{f.wire_vectors[name]={schema:schema.typeName,wire_hex:hex(toBinary(schema,value))};return value;};
function signed(name,schema,body,envelope,field,key,domain){
 const input=a.signingDigest(domain,schema,body),publicKey=bytes(base.keys[key].public_key_hex);
 const privateKey=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),bytes(base.keys[key].seed_hex)]),format:'der',type:'pkcs8'});
 const signature=new Uint8Array(sign(null,input,privateKey));
 const result=create(envelope,{body,[field]:{signerKeyId:keyId(publicKey),signature}});
 f.signed_vectors[name]={schema:envelope.typeName,body_schema:schema.typeName,wire_hex:hex(toBinary(envelope,result)),canonical_hex:hex(a.canonicalHybridV1(schema,body)),signing_input_hex:hex(input),domain,public_key_hex:hex(publicKey),signature_hex:hex(signature)};
 return result;
}
const configuration=v('import_configuration');configuration.limits.maxResultBytes=1500n;
wire('configuration',api.GetImportConfigurationResponseSchema,configuration);
wire('source',api.ProviderRepositorySchema,v('source_connected'));
wire('identity',api.ImportIdentityV1Schema,v('identity'));
f.current_destination_hex=hex(v('scope').destinationVersion);
f.changed_destination_hex=hex(raw(0x42));
const initial=v('commit_request'),original=initial.proof;
for(const [name,index,id,key,total,changed] of [['a',0,0xa1,'job',1000n,false],['b',1,0xb1,'renew_job',1500n,false],['fresh',1,0xc1,'direct_job',1500n,true]]){
 const scope=v('scope');scope.branches=[scope.branches[index]];scope.maxOperations=1;scope.maxResultBytes=total;if(changed)scope.destinationVersion=raw(0x42);
 wire('scope_'+name,api.ImportPermissionScopeV1Schema,scope);
 const parent=v('permission').body;parent.logicalJobId=raw(id,16);parent.retryLineageId=raw(id+1,16);parent.scope=scope;parent.nonce=raw(id+2);parent.cancellationId=raw(id+3);
 const permission=signed('permission_'+name,api.ImportMemberPermissionV1Schema,parent,api.SignedImportMemberPermissionV1Schema,'ownerSignature','owner',a.PERMISSION_DOMAIN);
 const envelope=join(utf8.encode('heddle-signed-import-member-permission-v1\0'),a.canonicalHybridV1(api.SignedImportMemberPermissionV1Schema,permission));
 const genesis=clone(api.ImportGenesisAuthorityV1Schema,original.genesisAuthorities[index].body);genesis.parentPermissionDigest=a.signedPermissionDigest(permission);genesis.creatorAuthorityEnvelopeDigest=hash(envelope);
 const binding=signed('genesis_'+name,api.ImportGenesisAuthorityV1Schema,genesis,api.SignedImportGenesisAuthorityV1Schema,'creatorSignature','device',a.GENESIS_DOMAIN);
 const d=v('delegation').body;d.logicalJobId=parent.logicalJobId;d.retryLineageId=parent.retryLineageId;d.delegationId=raw(id+4,16);d.cancellationId=raw(id+5);d.jobPublicKey=bytes(base.keys[key].public_key_hex);d.jobKeyId=keyId(d.jobPublicKey);d.parentPermissionDigest=a.signedPermissionDigest(permission);d.scope=scope;d.branchManifest=[create(api.ImportBranchManifestV1Schema,{limit:scope.branches[0],genesisAuthorityDigest:a.signedGenesisDigest(binding)})];
 const delegation=signed('delegation_'+name,api.ImportJobDelegationV1Schema,d,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device',a.DELEGATION_DOMAIN);
 const prepared=v('commit_preparation');prepared.proposal=a.delegationPreparation(d);
 wire('prepared_'+name,api.PrepareImportJobResponseSchema,prepared);
 const request=v('prepare_request');request.clientOperationId='sibling-prepare-'+name;request.retryLineageId=d.retryLineageId;request.proposedScope=scope;
 wire('prepare_'+name,api.PrepareImportJobRequestSchema,request);
 const proof=clone(api.ImportPublicProofBundleV1Schema,original);proof.memberPermission=permission;proof.memberPermissions=[permission];proof.delegations=[delegation];proof.genesisAuthorities=[binding];proof.originalGeneses=[original.originalGeneses[index]];proof.creatorAuthorityEnvelopes=[envelope];
 const commit=clone(api.CommitImportJobRequestSchema,initial);commit.clientOperationId='sibling-commit-'+name;commit.proof=proof;
 wire('commit_'+name,api.CommitImportJobRequestSchema,commit);
 const operation=v(index===0?'operation_dev':'operation_main').body;operation.logicalJobId=d.logicalJobId;operation.retryLineageId=d.retryLineageId;operation.physicalOperationId=d.retryLineageId;operation.delegationDigest=a.signedDelegationDigest(delegation);
 const publication=signed('operation_'+name,api.DelegatedImportOperationV1Schema,operation,api.SignedDelegatedImportOperationV1Schema,'jobSignature',key,a.OPERATION_DOMAIN);
 wire('manifest_'+name,api.ImportResultManifestV1Schema,create(api.ImportResultManifestV1Schema,{formatVersion:1,logicalJobId:d.logicalJobId,retryLineageId:d.retryLineageId,slots:[{refName:operation.refName,slotId:operation.slotId,signedOperationDigest:a.signedOperationDigest(publication),resultingFrontierDigest:operation.resultingFrontierDigest,resultBytes:operation.resultBytes}]}));
}
const duplicate=fromBinary(api.ImportPermissionScopeV1Schema,bytes(f.wire_vectors.scope_b.wire_hex));duplicate.branches=[v('scope').branches[0]];duplicate.branches[0].slotId=9n;
wire('duplicate_ref',api.ImportPermissionScopeV1Schema,duplicate);
const other=clone(api.ImportPermissionScopeV1Schema,duplicate);other.sourceUrl='https://github.com/heddleco/other.git';wire('duplicate_other_source',api.ImportPermissionScopeV1Schema,other);
const changedSlot=v('scope');changedSlot.branches=[changedSlot.branches[0]];changedSlot.maxOperations=1;changedSlot.maxResultBytes=1000n;changedSlot.branches[0].slotId=7n;wire('changed_slot',api.ImportPermissionScopeV1Schema,changedSlot);
const boundary=v('scope');boundary.maxOperations=256;boundary.maxResultBytes=1500n;boundary.branches=Array.from({length:256},(_,i)=>{const b=clone(api.ImportBranchLimitV1Schema,boundary.branches[0]);b.refName='refs/heads/b'+String(i).padStart(3,'0');return b;});wire('scope_256',api.ImportPermissionScopeV1Schema,boundary);
const oversized=clone(api.ImportPermissionScopeV1Schema,boundary);const last=clone(api.ImportBranchLimitV1Schema,boundary.branches[0]);last.refName='refs/heads/b256';oversized.branches.push(last);wire('scope_257',api.ImportPermissionScopeV1Schema,oversized);
const overBudget=v('scope');overBudget.branches=[overBudget.branches[1]];overBudget.maxOperations=1;overBudget.maxResultBytes=1501n;wire('scope_over_host_budget',api.ImportPermissionScopeV1Schema,overBudget);
for(const [name,field] of [['duplicate','proposed_scope.branches.ref_name'],['slot','proposed_scope.branches.slot_id'],['stale','proposed_scope.destination_version']])wire('refusal_'+name,api.PrepareImportJobResponseSchema,create(api.PrepareImportJobResponseSchema,{refusal:{reason:5,field}}));
const step=(action,job,scope='scope_'+job,expected='OK')=>({action,job,scope,expected});
f.scenarios=[
 {id:'sequential',steps:[step('prepare','a'),step('commit','a'),step('prepare','b'),step('commit','b')]},
 {id:'concurrent_reverse_commit',steps:[step('prepare','a'),step('prepare','b'),step('commit','b'),step('commit','a')]},
 {id:'after_completion',steps:[step('prepare','a'),step('commit','a'),step('complete','a'),step('prepare','b'),step('commit','b')]},
 {id:'prepared_sibling_survives_completion',steps:[step('prepare','a'),step('prepare','b'),step('commit','a'),step('complete','a'),step('commit','b')]},
 {id:'duplicate_prepared_ref_then_pass',steps:[step('prepare','a'),step('prepare','b','duplicate_ref','DESTINATION_CONFLICT'),step('prepare','b'),step('commit','b')]},
 {id:'duplicate_active_other_source_then_pass',steps:[step('prepare','a'),step('commit','a'),step('prepare','b','duplicate_other_source','DESTINATION_CONFLICT'),step('prepare','b'),step('commit','b')]},
 {id:'same_job_slot_rebinding_then_pass',steps:[step('prepare','a'),step('check','a','changed_slot','DESTINATION_CONFLICT'),step('check','a')]},
 {id:'released_reservation_then_pass',steps:[step('prepare','a'),step('prepare','b','duplicate_ref','DESTINATION_CONFLICT'),step('expire_prepare','a'),step('check','b','duplicate_ref')]},
];
f.gate_vectors=[
 {id:'stale_prepare',kind:'prepare',scope:'scope_b',current:'changed_destination_hex',expected:'DESTINATION_CONFLICT',control:'scope_fresh'},
 {id:'stale_activation',kind:'activate',scope:'scope_b',current:'changed_destination_hex',expected:'StaleContext',control:'scope_fresh'},
 {id:'per_job_branch_bound',kind:'prepare',scope:'scope_257',current:'current_destination_hex',expected:'INVALID_SCOPE',control:'scope_256'},
 {id:'per_job_budget_bound',kind:'prepare',scope:'scope_over_host_budget',current:'current_destination_hex',expected:'BUDGET_EXCEEDED',control:'scope_b'},
];
writeFileSync('tests/fixtures/import-sibling-jobs-alpha32.json',JSON.stringify(f,null,2)+'\n');
console.log('Frozen sibling jobs: '+f.scenarios.length+' scenarios; '+f.gate_vectors.length+' fail-then-pass gates. Existing fixtures untouched.');
