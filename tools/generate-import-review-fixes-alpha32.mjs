// Independent review-fix corpus; never rewrites an existing frozen fixture.
import {readFileSync,writeFileSync} from 'node:fs';
import {createPrivateKey,sign} from 'node:crypto';
import {clone,create,fromBinary,toBinary} from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as common from '../packages/typescript/dist/common/index.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
import * as w from '../packages/typescript/dist/v1alpha2/witness-trust.js';
import {hash,keyId} from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
const base=JSON.parse(readFileSync('tests/fixtures/import-authority-host-witness-v1.json'));
const siblings=JSON.parse(readFileSync('tests/fixtures/import-sibling-jobs-alpha32.json'));
const out={baseline:'2e238de4bf334fa6950af756d574c29a3948bca0',signed_vectors:{},wire_vectors:{}};
const bytes=h=>new Uint8Array(Buffer.from(h,'hex')),hex=b=>Buffer.from(b).toString('hex');
const v=(name,f=base)=>{const r=f.signed_vectors[name]??f.wire_vectors[name];return fromBinary((r.schema.includes('.common.')?common:api)[r.schema.split('.').at(-1)+'Schema'],bytes(r.wire_hex));};
const key=n=>bytes(base.keys[n].public_key_hex);
const sig=(n,input)=>new Uint8Array(sign(null,input,createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),bytes(base.keys[n].seed_hex)]),format:'der',type:'pkcs8'})));
const wire=(n,s,value)=>{out.wire_vectors[n]={schema:s.typeName,wire_hex:hex(toBinary(s,value))};return value;};
function signed(n,bs,b,ss,field,k,domain){const input=a.signingDigest(domain,bs,b),signature={signerKeyId:keyId(key(k)),signature:sig(k,input)},value=create(ss,{body:b,[field]:signature});out.signed_vectors[n]={schema:ss.typeName,body_schema:bs.typeName,wire_hex:hex(toBinary(ss,value)),canonical_hex:hex(a.canonicalHybridV1(bs,b)),signing_input_hex:hex(input),domain,public_key_hex:hex(key(k)),signature_hex:hex(signature.signature)};return value;}
function publications(name,b,delegation,job,totalEach,operations){
 b.operations=operations??['operation_main','operation_dev'].map((n,i)=>{const o=v(n).body;o.delegationDigest=a.signedDelegationDigest(delegation);o.resultBytes=totalEach;return signed(name+'_operation_'+i,api.DelegatedImportOperationV1Schema,o,api.SignedDelegatedImportOperationV1Schema,'jobSignature',job,a.OPERATION_DOMAIN);});
 const progressive=clone(api.ImportResultManifestV1Schema,b.terminalManifest);progressive.slots=[];b.manifests=[];b.statements=b.statements.filter(s=>s.body.purpose===1);
 b.operations.forEach((o,i)=>{progressive.slots.push(create(api.ImportCommittedSlotV1Schema,{refName:o.body.refName,slotId:o.body.slotId,signedOperationDigest:a.signedOperationDigest(o),resultingFrontierDigest:o.body.resultingFrontierDigest,resultBytes:o.body.resultBytes}));progressive.slots.sort((x,y)=>x.refName.localeCompare(y.refName));b.manifests.push(clone(api.ImportResultManifestV1Schema,progressive));const body=v('publication_statement').body;body.authorityDigest=o.body.delegationDigest;body.originalSignaturesDigest=hash(o.jobSignature.signature);body.publisherKeyId=keyId(key(Array.isArray(job)?job[i]:job));body.admissionOrder=100n+BigInt(i);body.observedAtUnixMillis=1250000n+BigInt(i)*1000n;body.canonicalPayload=a.canonicalHybridV1(api.ImportPublicationWitnessV1Schema,a.publicationPayload(o,progressive));b.statements.push(create(common.SignedHostedWitnessStatementV1Schema,{body,signature:sig('witness',w.statementSigningDigest(body))}));});
 b.terminalManifest=progressive;b.manifests.sort((x,y)=>Buffer.compare(a.manifestDigest(x),a.manifestDigest(y)));wire(name,api.ImportPublicProofBundleV1Schema,b);
}
for(const [name,total] of [['publication_twice_total',v('alpha32_aggregate_at').delegations[0].body.scope.maxResultBytes],['publication_exact_total',v('alpha32_aggregate_at').delegations[0].body.scope.maxResultBytes/2n]]){
 const b=v('alpha32_aggregate_at');publications(name,b,b.delegations[0],'job',total);
}
for(const [name,each] of [['narrowed_over',600n],['narrowed_at',500n]]){
 const b=v('review_control'),d0=v('delegation');
 const permission=v('renewed_permission').body;permission.scope=clone(api.ImportPermissionScopeV1Schema,d0.body.scope);permission.scope.maxResultBytes=1500n;permission.nonce=new Uint8Array(32).fill(0x91);
 const parent=signed(name+'_permission',api.ImportMemberPermissionV1Schema,permission,api.SignedImportMemberPermissionV1Schema,'ownerSignature','owner',a.PERMISSION_DOMAIN);
 const next=v('review_control').delegations[1].body;next.scope=clone(api.ImportPermissionScopeV1Schema,d0.body.scope);next.scope.maxResultBytes=1000n;next.branchManifest=d0.body.branchManifest;next.parentPermissionDigest=a.signedPermissionDigest(parent);
 const d1=signed(name+'_delegation',api.ImportJobDelegationV1Schema,next,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device',a.DELEGATION_DOMAIN);
 const empty=clone(api.ImportResultManifestV1Schema,b.terminalManifest);empty.slots=[];
 const renewal=v('review_control').renewals[0].body;renewal.committedManifestDigest=a.manifestDigest(empty);renewal.replacement=d1;
 b.delegations=[d0,d1];b.renewals=[signed(name+'_renewal',api.ImportJobRenewalV1Schema,renewal,api.SignedImportJobRenewalV1Schema,'delegatingSignature','device',a.RENEWAL_DOMAIN)];b.memberPermission=parent;b.memberPermissions=[v('permission'),parent].sort((x,y)=>Buffer.compare(a.signedPermissionDigest(x),a.signedPermissionDigest(y)));
 publications(name,b,d1,'renew_job',each);b.manifests.push(empty);b.manifests.sort((x,y)=>Buffer.compare(a.manifestDigest(x),a.manifestDigest(y)));wire(name,api.ImportPublicProofBundleV1Schema,b);
}
// Overflow is exercised directly in renewal accounting, independently of a byte budget refusal.
const overflow=v('partial_manifest');overflow.slots=[...v('review_control').terminalManifest.slots];overflow.slots.forEach(s=>s.resultBytes=1n<<63n);wire('overflow_manifest',api.ImportResultManifestV1Schema,overflow);
const control=clone(api.ImportResultManifestV1Schema,overflow);control.slots.forEach(s=>s.resultBytes=1n);wire('overflow_manifest_control',api.ImportResultManifestV1Schema,control);
const scope=v('scope_256',siblings);scope.branches.forEach((b,i)=>{b.targetThreadId=new Uint8Array(32);new DataView(b.targetThreadId.buffer).setUint32(28,i+1);b.genesisDigest=b.targetThreadId.slice();});wire('unique_scope_256',api.ImportPermissionScopeV1Schema,scope);
out.negatives=[{id:'publication_twice_total',control:'publication_exact_total',expected:'Scope'},{id:'narrowed_over',control:'narrowed_at',expected:'Scope'}];
out.owner_transition={bundle:'review_control',delegation:1,deadline:1240,claimed_at:1260,expected:'Scope'};
writeFileSync('tests/fixtures/import-review-fixes-alpha32.json',JSON.stringify(out,null,2)+'\n');
const recovery=v('review_renewed_recovery');recovery.statements=v('review_control').statements.filter(s=>s.body.purpose===1);recovery.genesisWitnesses=v('review_control').genesisWitnesses;wire('witnessed_prefix_recovery',api.ImportPublicProofBundleV1Schema,recovery);
writeFileSync('tests/fixtures/import-review-fixes-alpha32.json',JSON.stringify(out,null,2)+'\n');
const old=v('direct_owner').body;old.scope.maxResultBytes=(1n<<64n)-1n;old.scope.maxOperations=3;
const extra=clone(api.ImportBranchLimitV1Schema,old.scope.branches[0]);extra.refName='refs/heads/extra';extra.genesisDigest=new Uint8Array(32).fill(0x42);extra.targetThreadId=new Uint8Array(32).fill(0x43);old.scope.branches.push(extra);old.scope.branches.sort((x,y)=>x.refName.localeCompare(y.refName));old.branchManifest.push(create(api.ImportBranchManifestV1Schema,{limit:extra,genesisAuthorityDigest:new Uint8Array(32).fill(0x44)}));old.branchManifest.sort((x,y)=>x.limit.refName.localeCompare(y.limit.refName));
const predecessor=signed('overflow_predecessor',api.ImportJobDelegationV1Schema,old,api.SignedImportJobDelegationV1Schema,'delegatingSignature','owner',a.DELEGATION_DOMAIN);
const next=clone(api.ImportJobDelegationV1Schema,old);next.delegationId=new Uint8Array(16).fill(0x45);next.jobPublicKey=key('renew_job');next.jobKeyId=keyId(next.jobPublicKey);next.predecessorDelegationDigest=a.signedDelegationDigest(predecessor);next.scope.branches=[extra];next.scope.maxOperations=1;next.scope.maxResultBytes=1n;next.branchManifest=old.branchManifest.filter(m=>m.limit.refName===extra.refName);next.notBeforeUnixSeconds=1200n;next.expiresAtUnixSeconds=1800n;
const replacement=signed('overflow_replacement',api.ImportJobDelegationV1Schema,next,api.SignedImportJobDelegationV1Schema,'delegatingSignature','owner',a.DELEGATION_DOMAIN);
for(const [name,m] of [['overflow',overflow],['overflow_control',control]]){m.logicalJobId=old.logicalJobId;m.retryLineageId=old.retryLineageId;wire(name==='overflow'?'overflow_manifest':'overflow_manifest_control',api.ImportResultManifestV1Schema,m);const r=create(api.ImportJobRenewalV1Schema,{formatVersion:1,predecessorDelegationDigest:a.signedDelegationDigest(predecessor),expectedAuthorityEpoch:1n,committedManifestDigest:a.manifestDigest(m),replacement});signed(name+'_renewal',api.ImportJobRenewalV1Schema,r,api.SignedImportJobRenewalV1Schema,'delegatingSignature','owner',a.RENEWAL_DOMAIN);}
writeFileSync('tests/fixtures/import-review-fixes-alpha32.json',JSON.stringify(out,null,2)+'\n');
// Each renewal narrowing gate has a signed negative that reaches only that gate.
for(const kind of ['certificate','permission'])for(const over of [true,false]){
 const name=`renew_${kind}_${over?'over':'at'}`,b=v('review_control'),initial=v('delegation').body;initial.scope.maxResultBytes=1000n;
 const d0=signed(name+'_initial',api.ImportJobDelegationV1Schema,initial,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device',a.DELEGATION_DOMAIN);
 const remainder=1000n-v('operation_main').body.resultBytes,after=v('review_control').delegations[1].body;after.predecessorDelegationDigest=a.signedDelegationDigest(d0);after.scope.maxResultBytes=remainder+(kind==='certificate'&&over?1n:0n);
 let parent;
 if(kind==='certificate'){after.delegatingPublicKey=key('owner');after.parentPermissionDigest=new Uint8Array(32);b.memberPermission=v('permission');b.memberPermissions=[v('permission')];}
 else{const permission=v('renewed_permission').body;permission.scope.maxResultBytes=remainder+(over?1n:0n);parent=signed(name+'_permission',api.ImportMemberPermissionV1Schema,permission,api.SignedImportMemberPermissionV1Schema,'ownerSignature','owner',a.PERMISSION_DOMAIN);after.parentPermissionDigest=a.signedPermissionDigest(parent);b.memberPermission=parent;b.memberPermissions=[v('permission'),parent].sort((x,y)=>Buffer.compare(a.signedPermissionDigest(x),a.signedPermissionDigest(y)));}
 const delegator=kind==='certificate'?'owner':'device',d1=signed(name+'_replacement',api.ImportJobDelegationV1Schema,after,api.SignedImportJobDelegationV1Schema,'delegatingSignature',delegator,a.DELEGATION_DOMAIN);
 const operations=['operation_main','operation_dev'].map((n,i)=>{const o=v(n).body;o.delegationDigest=a.signedDelegationDigest(i?d1:d0);if(i)o.resultBytes=remainder;return signed(name+'_operation_'+i,api.DelegatedImportOperationV1Schema,o,api.SignedDelegatedImportOperationV1Schema,'jobSignature',i?'renew_job':'job',a.OPERATION_DOMAIN);});
 b.delegations=[d0,d1];publications(name,b,d1,['job','renew_job'],0n,operations);
 const firstManifest=b.manifests.find(m=>m.slots.length===1),renewal=v('review_control').renewals[0].body;renewal.predecessorDelegationDigest=a.signedDelegationDigest(d0);renewal.committedManifestDigest=a.manifestDigest(firstManifest);renewal.replacement=d1;
 b.renewals=[signed(name+'_renewal',api.ImportJobRenewalV1Schema,renewal,api.SignedImportJobRenewalV1Schema,'delegatingSignature',delegator,a.RENEWAL_DOMAIN)];wire(name,api.ImportPublicProofBundleV1Schema,b);
}
writeFileSync('tests/fixtures/import-review-fixes-alpha32.json',JSON.stringify(out,null,2)+'\n');
