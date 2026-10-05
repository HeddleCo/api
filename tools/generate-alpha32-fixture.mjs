// Deliberate alpha.32 additions; run after the three existing import generators.
import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, sign } from 'node:crypto';
import { clone, create, fromBinary, toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as host from '../packages/typescript/dist/common/index.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
import * as w from '../packages/typescript/dist/v1alpha2/witness-trust.js';
import { hash, keyId, join, utf8 } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
const path='tests/fixtures/import-authority-host-witness-v1.json',f=JSON.parse(readFileSync(path));
const bytes=h=>new Uint8Array(Buffer.from(h,'hex')),hex=b=>Buffer.from(b).toString('hex'),key=n=>bytes(f.keys[n].public_key_hex);
const sig=(n,input)=>new Uint8Array(sign(null,input,createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),bytes(f.keys[n].seed_hex)]),format:'der',type:'pkcs8'})));
const v=n=>{const r=f.signed_vectors[n]??f.wire_vectors[n];return fromBinary((r.schema.includes('.common.')?host:api)[r.schema.split('.').at(-1)+'Schema'],bytes(r.wire_hex));};
const wire=(n,s,value)=>{f.wire_vectors[n]={schema:s.typeName,wire_hex:hex(toBinary(s,value))};return value;};
function signed(n,bs,b,ss,field,k,domain){const input=a.signingDigest(domain,bs,b),signature={signerKeyId:keyId(key(k)),signature:sig(k,input)},value=create(ss,{body:b,[field]:signature});f.signed_vectors[n]={schema:ss.typeName,body_schema:bs.typeName,wire_hex:hex(toBinary(ss,value)),canonical_hex:hex(a.canonicalHybridV1(bs,b)),signing_input_hex:hex(input),domain,public_key_hex:hex(key(k)),signature_hex:hex(signature.signature)};return value;}
for(const [name,total] of [['large',50n<<30n],['over_host_max',(1n<<40n)+1n],['u64_max',(1n<<64n)-1n]]){
 const scope=v('scope');scope.maxResultBytes=total;wire('alpha32_total_'+name,api.ImportPermissionScopeV1Schema,scope);
 const config=v('import_configuration');config.limits.maxResultBytes=name==='u64_max'?total:1n<<40n;wire('alpha32_configuration_'+name,api.GetImportConfigurationResponseSchema,config);
 const commit=v('commit_request');commit.proof.delegations[0].body.scope=scope;wire('alpha32_commit_'+name,api.CommitImportJobRequestSchema,commit);
 if(name!=='over_host_max'){const manifest=v('partial_manifest');manifest.slots[0].resultBytes=total;wire('alpha32_manifest_'+name,api.ImportResultManifestV1Schema,manifest);}
}
const lowered=v('alpha32_configuration_large');lowered.limits.maxResultBytes=49n<<30n;wire('alpha32_configuration_lowered',api.GetImportConfigurationResponseSchema,lowered);
const largeOwner=v('direct_owner').body;largeOwner.scope.maxResultBytes=50n<<30n;signed('alpha32_large_owner',api.ImportJobDelegationV1Schema,largeOwner,api.SignedImportJobDelegationV1Schema,'delegatingSignature','owner',a.DELEGATION_DOMAIN);
for(const [name,total] of [['widening',2001n],['narrowing',999n]]){const b=v('delegation').body;b.scope.maxResultBytes=total;signed('alpha32_'+name,api.ImportJobDelegationV1Schema,b,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device',a.DELEGATION_DOMAIN);}
const remaining=v('scope');remaining.branches=remaining.branches.filter(b=>b.refName==='refs/heads/dev');remaining.maxOperations=1;remaining.maxResultBytes-=v('partial_manifest').slots[0].resultBytes;wire('alpha32_remaining',api.ImportPermissionScopeV1Schema,remaining);
wire('alpha32_consumption_reset',api.ImportPublicProofBundleV1Schema,v('review_cumulative_budget_maxResultBytes'));
for(const [name,state,size] of [['unknown',0,0n],['unknown_nonzero',0,1n],['unknown_enum',7,0n],['available',1,1234n],['empty',1,0n]]){const r=v(state===1?'source_connected':'source_public_github');r.sizeEstimateState=state;r.gitSizeKib=size;wire('alpha32_estimate_'+name,api.ProviderRepositorySchema,r);}
const recovery=v('review_recovery');
for(const original of recovery.originalGeneses){original.signatures.push(create(api.RecordSignatureSchema,{publicKey:key('direct_job'),signature:sig('direct_job',join(utf8.encode(original.format+'\0'),original.canonicalRecord))}));original.signatures.sort((a,b)=>Buffer.compare(a.publicKey,b.publicKey));if(hex(original.signatures[0].publicKey)===hex(key('device')))throw Error('additional signature must precede creator');}
wire('alpha32_multisignature_recovery',api.ImportPublicProofBundleV1Schema,recovery);
const noCreator=clone(api.ImportPublicProofBundleV1Schema,recovery);noCreator.originalGeneses[0].signatures=noCreator.originalGeneses[0].signatures.filter(s=>hex(s.publicKey)!==hex(key('device')));wire('alpha32_missing_creator',api.ImportPublicProofBundleV1Schema,noCreator);
// Both publications use one certificate: individually below the total, jointly over it.
for(const [name,total] of [['over',v('operation_main').body.resultBytes*2n-1n],['at',v('operation_main').body.resultBytes*2n]]){
 const b=v('review_control'),d=v('delegation').body;d.scope.maxResultBytes=total;
 const delegation=signed('alpha32_aggregate_'+name+'_delegation',api.ImportJobDelegationV1Schema,d,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device',a.DELEGATION_DOMAIN);
 b.delegations=[delegation];b.renewals=[];b.memberPermission=v('permission');b.memberPermissions=[v('permission')];
 b.operations=['operation_main','operation_dev'].map((n,i)=>{const o=v(n).body;o.delegationDigest=a.signedDelegationDigest(delegation);return signed('alpha32_aggregate_'+name+'_operation_'+i,api.DelegatedImportOperationV1Schema,o,api.SignedDelegatedImportOperationV1Schema,'jobSignature','job',a.OPERATION_DOMAIN);});
 const progressive=clone(api.ImportResultManifestV1Schema,b.terminalManifest);progressive.slots=[];b.manifests=[];b.statements=b.statements.filter(s=>s.body.purpose===1);
 const template=v('publication_statement').body;
 b.operations.forEach((o,i)=>{progressive.slots.push(create(api.ImportCommittedSlotV1Schema,{refName:o.body.refName,slotId:o.body.slotId,signedOperationDigest:a.signedOperationDigest(o),resultingFrontierDigest:o.body.resultingFrontierDigest,resultBytes:o.body.resultBytes}));progressive.slots.sort((x,y)=>x.refName.localeCompare(y.refName));b.manifests.push(clone(api.ImportResultManifestV1Schema,progressive));const body=clone(host.HostedWitnessStatementV1Schema,template);body.authorityDigest=o.body.delegationDigest;body.originalSignaturesDigest=hash(o.jobSignature.signature);body.publisherKeyId=keyId(key('job'));body.admissionOrder=100n+BigInt(i);body.observedAtUnixMillis=i?1250000n:1100000n;body.canonicalPayload=a.canonicalHybridV1(api.ImportPublicationWitnessV1Schema,a.publicationPayload(o,progressive));b.statements.push(create(host.SignedHostedWitnessStatementV1Schema,{body,signature:sig('witness',w.statementSigningDigest(body))}));});
 b.terminalManifest=progressive;b.manifests.sort((x,y)=>Buffer.compare(a.manifestDigest(x),a.manifestDigest(y)));wire('alpha32_aggregate_'+name,api.ImportPublicProofBundleV1Schema,b);
}
const ended=v('job_state_empty');ended.retryAvailability={case:'retryUnavailable',value:7};wire('alpha32_original_window_ended',api.GetImportJobStateResponseSchema,ended);
f.alpha32_vectors={total_over:'alpha32_total_over_host_max',large_total:'alpha32_total_large',u64_max:'alpha32_total_u64_max',widening:'alpha32_widening',narrowing:'alpha32_narrowing',remaining:'alpha32_remaining',consumption_reset:'alpha32_consumption_reset',unknown_estimate:'alpha32_estimate_unknown',aggregate_negative:'alpha32_aggregate_over',aggregate_control:'alpha32_aggregate_at',original_window_ended:'alpha32_original_window_ended',multisignature:'alpha32_multisignature_recovery'};
writeFileSync(path,JSON.stringify(f,null,2)+'\n');
// Native witnessing is unchanged. Only its two import-dispatch carriers embed
// the revised import scope and must follow this hard cut.
const nativePath='tests/fixtures/native-host-witness-v1.json',native=JSON.parse(readFileSync(nativePath));
const imported=v('complete_renewed_export');
native.wire_vectors.import_complete={schema:api.ImportPublicProofBundleV1Schema.typeName,wire_hex:hex(toBinary(api.ImportPublicProofBundleV1Schema,imported))};
imported.delegations=[];
native.wire_vectors.import_without_delegation={schema:api.ImportPublicProofBundleV1Schema.typeName,wire_hex:hex(toBinary(api.ImportPublicProofBundleV1Schema,imported))};
writeFileSync(nativePath,JSON.stringify(native,null,2)+'\n');
console.log('alpha.32 total, renewal, estimate, genesis and evidence vectors appended; only two native import-dispatch carriers updated');
