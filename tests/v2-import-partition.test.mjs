import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { clone,create,fromBinary,toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as common from '../packages/typescript/dist/common/index.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { hash } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
import { bytes,buildJob,commitInputs,ownerContext,selection,vector } from './import-partition-support.mjs';
const f=JSON.parse(readFileSync(new URL('./fixtures/import-partition-alpha49.json',import.meta.url)));
const materials=f.selection.map(m=>({limit:fromBinary(api.ImportBranchLimitV1Schema,bytes(m.limit_wire_hex)),original:fromBinary(api.SignedRecordSchema,bytes(m.original_wire_hex))}));
const branches=materials.map(m=>m.limit),build=bs=>buildJob(bs,materials,true);
const hex=b=>Buffer.from(b).toString('hex'),expected=reason=>e=>e.reason===reason;
for(const c of f.cases)test(`format 2 partition Rust/TS golden ${c.id}`,async()=>{
 const before=branches.map(b=>hex(toBinary(api.ImportBranchLimitV1Schema,b)));
 const jobs=a.partitionImportBranches(branches,{maxBranches:c.max_branches,maxRecordBytes:c.max_record_bytes,maxBundleBytes:c.max_bundle_bytes,buildJob:build});
 assert.deepEqual(jobs.map(p=>({count:p.delegations[0].body.scope.branches.length,record_bytes:a.canonicalHybridV1(api.SignedImportJobDelegationV1Schema,p.delegations[0]).length,proof_bytes:toBinary(api.ImportPublicProofBundleV1Schema,p).length,proof_sha256:hex(hash(toBinary(api.ImportPublicProofBundleV1Schema,p)))})),c.jobs);
 assert.deepEqual(jobs.flatMap(p=>p.delegations[0].body.scope.branches.map(b=>b.refName)),branches.map(b=>b.refName));
 assert.equal(new Set(jobs.map(p=>hex(p.delegations[0].body.jobPublicKey))).size,jobs.length);
 for(const proof of jobs){const {request,source,configuration,prepared}=commitInputs(proof);await a.verifyImportCommitSubmission(request,prepared,'public-git',source,configuration,ownerContext());}
 assert.deepEqual(branches.map(b=>hex(toBinary(api.ImportBranchLimitV1Schema,b))),before);
 console.log(`PARTITION ${c.id}: ${jobs.map(p=>p.delegations[0].body.scope.branches.length).join(',')} verified`);
});
test('worst UTF-8 refs and maximum digests fit at exactly MAX_BRANCHES',async()=>{
 assert.equal(a.MAX_BRANCHES,25);assert.ok(branches.every(b=>Buffer.byteLength(b.refName)===1024&&b.pinnedCommitOid.length===32));
 const proof=build(branches.slice(0,a.MAX_BRANCHES));
 const {request,source,configuration,prepared}=commitInputs(proof);
 await a.verifyImportCommitSubmission(request,prepared,'public-git',source,configuration,ownerContext());
 assert.ok(a.canonicalHybridV1(api.SignedImportJobDelegationV1Schema,proof.delegations[0]).length<=a.MAX_RECORD_BYTES);
 assert.ok(toBinary(api.ImportPublicProofBundleV1Schema,proof).length<=a.MAX_BUNDLE_BYTES);
 // Exercise the conservative provider-length term independently of provider support.
 const d=clone(api.SignedImportJobDelegationV1Schema,proof.delegations[0]);d.body.scope.provider='p'.repeat(64);
 assert.equal(a.canonicalHybridV1(api.SignedImportJobDelegationV1Schema,d).length,63404);
 const over=build(branches.slice(0,26));over.delegations[0].body.scope.provider='p'.repeat(64);
 assert.equal(a.canonicalHybridV1(api.SignedImportJobDelegationV1Schema,over.delegations[0]).length,65824);
 assert.throws(()=>a.partitionImportBranches(branches,{maxBranches:26,maxRecordBytes:65536,maxBundleBytes:a.MAX_BUNDLE_BYTES,buildJob:build}),expected('Bounds'));
 console.log(`BOUNDARY 25 branches: record ${a.canonicalHybridV1(api.SignedImportJobDelegationV1Schema,proof.delegations[0]).length}, proof ${toBinary(api.ImportPublicProofBundleV1Schema,proof).length}`);
});
test('proof encoding grows linearly at 16, 64 and 256 branches',()=>{
 const sizes=f.sizes.map(v=>{const m=selection(v.branches),p=buildJob(m.map(m=>m.limit),m),after=toBinary(api.ImportPublicProofBundleV1Schema,p).length;p.formatVersion=1;p.creatorAuthorityEnvelopes=Array(v.branches).fill(p.creatorAuthorityEnvelopes[0]);const before=toBinary(api.ImportPublicProofBundleV1Schema,p).length;assert.deepEqual({branches:v.branches,before,after},{branches:v.branches,before:v.before,after:v.after});assert.equal(hex(toBinary(api.ImportPublicProofBundleV1Schema,buildJob(m.map(m=>m.limit),m))),v.after_wire_hex);return after;});
 // Protobuf length-prefix thresholds and decimal genesis names add small steps.
 assert.ok(Math.abs((sizes[2]-sizes[1])/192-(sizes[1]-sizes[0])/48)<8);
 assert.ok(f.sizes[2].before>15*f.sizes[0].before);
 assert.ok(sizes[2]<17*sizes[0]);
 console.log('PROOF SIZE',JSON.stringify(f.sizes.map(({after_wire_hex,...v})=>v)));
});
test('format 1 frozen commits and format 2 dedup preserve signed bytes',async()=>{
 const request=vector('commit_request'),original=clone(api.ImportPublicProofBundleV1Schema,request.proof);
 const source=vector('source_connected');source.refs=original.delegations[0].body.scope.branches.map(b=>({$typeName:api.ProviderRefSchema.typeName,name:b.refName,kind:1,hashAlgorithm:1,headOid:Buffer.from(b.pinnedCommitOid).toString('hex')}));
 const config=vector('import_configuration');await a.validateImportCommitRequest(request,'github',source,config);
 request.proof.formatVersion=2;request.proof.creatorAuthorityEnvelopes=[request.proof.creatorAuthorityEnvelopes[0]];
 await assert.rejects(a.validateImportCommitRequest(request,'github',source,config),expected('Version'));
 config.importProofBundleFormatVersion=2;config.limits.maxBranches=25;await a.validateImportCommitRequest(request,'github',source,config);
 for(const field of ['memberPermission','delegations','genesisAuthorities','originalGeneses'])assert.deepEqual(request.proof[field],original[field]);
 request.proof.creatorAuthorityEnvelopes.push(request.proof.creatorAuthorityEnvelopes[0]);await assert.rejects(a.validateImportCommitRequest(request,'github',source,config),expected('Canonical'));
 request.proof=original;await a.validateImportCommitRequest(request,'github',source,config);
});
test('partition rejects invalid inputs and an oversized single branch',()=>{
 const limits={maxBranches:25,maxRecordBytes:65536,maxBundleBytes:a.MAX_BUNDLE_BYTES,buildJob:build};
 assert.deepEqual(a.partitionImportBranches([],limits),[]);
 assert.throws(()=>a.partitionImportBranches([...branches].reverse(),limits),expected('Canonical'));
 assert.throws(()=>a.partitionImportBranches(branches,{...limits,maxRecordBytes:1}),expected('Bounds'));
 assert.throws(()=>a.partitionImportBranches(branches,{...limits,maxBundleBytes:1}),expected('Bounds'));
 assert.throws(()=>a.partitionImportBranches(branches,{...limits,buildJob:bs=>{const p=build(bs);p.formatVersion=1;return p;}}),expected('Version'));
});

test('versioned byte caps and context reserve reject at one byte over',()=>{
 const proof=build(branches.slice(0,25)),{request}=commitInputs(proof);
 a.validateImportCommitRequestBounds(request);
 const changed=clone(api.CommitImportJobRequestSchema,request);changed.proof.statements=[create(common.SignedHostedWitnessStatementV1Schema,{body:{canonicalPayload:new Uint8Array(65536)}})];
 const context=clone(api.ImportPublicProofBundleV1Schema,changed.proof);context.memberPermission=undefined;context.delegations=[];context.genesisAuthorities=[];context.originalGeneses=[];context.creatorAuthorityEnvelopes=[];
 let padding=65536;
 while(toBinary(api.ImportPublicProofBundleV1Schema,context).length!==a.MAX_COMMIT_CONTEXT_BYTES){padding-=toBinary(api.ImportPublicProofBundleV1Schema,context).length-a.MAX_COMMIT_CONTEXT_BYTES;context.statements[0].body.canonicalPayload=new Uint8Array(padding);}
 changed.proof.statements=context.statements;a.validateImportCommitRequestBounds(changed);
 changed.proof.statements[0].body.canonicalPayload=new Uint8Array(padding+1);assert.throws(()=>a.validateImportCommitRequestBounds(changed),expected('Bounds'));
 const record=clone(api.ImportPublicProofBundleV1Schema,proof);record.formatVersion=1;record.creatorAuthorityEnvelopes=Array(25).fill(new Uint8Array(65536));
 const old={...request,proof:record};assert.throws(()=>a.validateImportCommitRequestBounds(old),expected('Bounds'));
 record.formatVersion=2;a.validateImportCommitRequestBounds(old);
 record.formatVersion=3;assert.throws(()=>a.validateImportCommitRequestBounds(old),expected('Version'));
 const config=clone(api.GetImportConfigurationResponseSchema,commitInputs(proof).configuration);config.limits.maxBranches=26;assert.throws(()=>a.validateImportConfiguration(config),expected('Bounds'));config.limits.maxBranches=25;a.validateImportConfiguration(config);config.importProofBundleFormatVersion=3;assert.throws(()=>a.validateImportConfiguration(config),expected('Version'));
});
test('new bundle table rejects missing, extra and reordered envelope entries',async()=>{
 const p=build(branches.slice(0,2)),input=commitInputs(p);
 input.request.proof.creatorAuthorityEnvelopes=[];
 await assert.rejects(a.validateImportCommitRequest(input.request,'public-git',input.source,input.configuration),expected('GenesisBinding'));
 input.request.proof=p;p.creatorAuthorityEnvelopes=[new Uint8Array([1])];
 await assert.rejects(a.validateImportCommitRequest(input.request,'public-git',input.source,input.configuration),expected('GenesisBinding'));
 const exportProof=vector('complete_export');exportProof.formatVersion=2;exportProof.creatorAuthorityEnvelopes=[...new Map(exportProof.creatorAuthorityEnvelopes.map(e=>[hex(hash(e)),e])).entries()].sort(([a],[b])=>a.localeCompare(b)).map(([,e])=>e);
 a.validatePublicBundle(exportProof);
 exportProof.creatorAuthorityEnvelopes.push(exportProof.creatorAuthorityEnvelopes[0]);assert.throws(()=>a.validatePublicBundle(exportProof),expected('Canonical'));
});

test('format 2 capacity includes maximum opaque originals and distinct envelopes',()=>{
 const {request}=commitInputs(build(branches.slice(0,25))),p=request.proof;
 p.originalGeneses.forEach(o=>{o.canonicalRecord=new Uint8Array(a.MAX_RECORD_BYTES);o.signatures=Array.from({length:16},()=>create(api.RecordSignatureSchema,{publicKey:new Uint8Array(32),signature:new Uint8Array(64)}));});
 p.creatorAuthorityEnvelopes=Array.from({length:25},(_,i)=>new Uint8Array(65536).fill(i));
 const size=toBinary(api.ImportPublicProofBundleV1Schema,p).length;assert.ok(size<=a.MAX_BUNDLE_BYTES);a.validateImportCommitRequestBounds(request);console.log(`OPAQUE CAPACITY ${size} <= ${a.MAX_BUNDLE_BYTES}`);
});

test('format 2 bounds the parent scope as well as the child delegation',()=>{
 const proof=build(branches.slice(0,25));proof.memberPermission.body.scope.branches=branches.slice(0,26);
 assert.throws(()=>a.validatePublicBundle(proof),expected('Bounds'));
});
test('digest order is enforced for multiple distinct envelopes',async()=>{
 const p=build(branches.slice(0,2)),entries=[new Uint8Array([1]),new Uint8Array([2])].sort((a,b)=>Buffer.compare(hash(a),hash(b)));
 p.creatorAuthorityEnvelopes=entries;
 p.genesisAuthorities.forEach((g,i)=>{g.body.creatorAuthorityEnvelopeDigest=hash(entries[i]);p.delegations[0].body.branchManifest[i].genesisAuthorityDigest=a.signedGenesisDigest(g);});
 const {request,source,configuration}=commitInputs(p);await a.validateImportCommitRequest(request,'public-git',source,configuration);
 p.creatorAuthorityEnvelopes.reverse();await assert.rejects(a.validateImportCommitRequest(request,'public-git',source,configuration),expected('Canonical'));
});
