// Maintenance only. Emit shared golden inputs and measured expected jobs.
import { writeFileSync } from 'node:fs';
import { toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { hash } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
import { selection,buildJob } from '../tests/import-partition-support.mjs';
const hex=b=>Buffer.from(b).toString('hex');
const materials=selection(53,true),branches=materials.map(m=>m.limit),build=bs=>buildJob(bs,materials,true);
const f={format_version:2,max_branches:a.MAX_BRANCHES,selection:materials.map(m=>({limit_wire_hex:hex(toBinary(api.ImportBranchLimitV1Schema,m.limit)),original_wire_hex:hex(toBinary(api.SignedRecordSchema,m.original))})),cases:[],sizes:[]};
const recordSize=n=>a.canonicalHybridV1(api.SignedImportJobDelegationV1Schema,build(branches.slice(0,n)).delegations[0]).length;
const proofSize=n=>toBinary(api.ImportPublicProofBundleV1Schema,build(branches.slice(0,n))).length;
for(const [id,maxBranches,maxRecordBytes,maxBundleBytes] of [['count',25,65536,4194304],['record',25,recordSize(7),4194304],['record_minus_one',25,recordSize(7)-1,4194304],['proof',25,65536,proofSize(5)],['proof_minus_one',25,65536,proofSize(5)-1],['mixed',9,recordSize(7),proofSize(5)]]){
 const jobs=a.partitionImportBranches(branches,{maxBranches,maxRecordBytes,maxBundleBytes,buildJob:build});
 f.cases.push({id,max_branches:maxBranches,max_record_bytes:maxRecordBytes,max_bundle_bytes:maxBundleBytes,jobs:jobs.map(p=>({count:p.delegations[0].body.scope.branches.length,record_bytes:a.canonicalHybridV1(api.SignedImportJobDelegationV1Schema,p.delegations[0]).length,proof_bytes:toBinary(api.ImportPublicProofBundleV1Schema,p).length,proof_sha256:hex(hash(toBinary(api.ImportPublicProofBundleV1Schema,p)))}))});
}
for(const n of [16,64,256]){const m=selection(n),p=buildJob(m.map(m=>m.limit),m);const after=toBinary(api.ImportPublicProofBundleV1Schema,p).length,after_wire_hex=hex(toBinary(api.ImportPublicProofBundleV1Schema,p));p.formatVersion=1;p.creatorAuthorityEnvelopes=Array(n).fill(p.creatorAuthorityEnvelopes[0]);f.sizes.push({branches:n,before:toBinary(api.ImportPublicProofBundleV1Schema,p).length,after,after_wire_hex});}
writeFileSync('tests/fixtures/import-partition-alpha49.json',JSON.stringify(f,null,2)+'\n');console.log(f.cases.map(c=>[c.id,c.jobs.map(j=>j.count)]));console.log(f.sizes.map(({after_wire_hex,...v})=>v));
