// Inventory changes against alpha.32; never produces or modifies signed vectors.
import {execFileSync} from 'node:child_process';
import {existsSync,readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {fromBinary,toBinary} from '@bufbuild/protobuf';
import * as native from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import * as imported from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import * as hosted from '../packages/typescript/dist/common/hosted_witness_pb.js';
import * as owners from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import * as common from '../packages/typescript/dist/v1alpha2/common_pb.js';
import assert from 'node:assert/strict';
const baseline='c9bd6ba2';
const git=(...args)=>execFileSync('git',args,{maxBuffer:64*1024*1024});
const sha=value=>createHash('sha256').update(value).digest('hex');
const recordSha=value=>sha(JSON.stringify(value));
const paths=[...git('ls-tree','-r','--name-only',baseline,'tests/fixtures').toString().trim().split('\n'),'tests/fixtures/foreign-dependencies-alpha34.json'];
const manifest={baseline,reason:'Foreign references on both public bundles; new mixed-origin signed corpus. Every existing signed/canonical record remains byte-identical. Only import descriptor metadata changes.',fixtures:{},retired_files:[],retired_corpora:{},unaffected_files:{}};
const groups=new Set(['signed_vectors','wire_vectors','commitment_vectors','raw_commitment_vectors','canonical_vectors','operations']);
function records(value){return Array.isArray(value)?Object.fromEntries(value.map((v,i)=>[String(v.id??v.name??v.count??i),v])):value;}
for(const path of paths){
 if(path==='tests/fixtures/foreign-dependencies-alpha34.json'){manifest.fixtures[path]={sha256:sha(readFileSync(path)),new_file:true};continue;}
 const before=git('show',`${baseline}:${path}`);
 if(!existsSync(path)){
  manifest.retired_files.push(path);const old=JSON.parse(before);
  manifest.retired_corpora[path]={sha256:sha(before),records:Object.fromEntries([...groups].filter(g=>g in old).map(g=>[g,Object.keys(records(old[g]))]))};
  continue;
 }
 const after=readFileSync(path);
 if(before.equals(after)){manifest.unaffected_files[path]=sha(after);continue;}
 const old=JSON.parse(before),current=JSON.parse(after),entry={groups:{},changed_metadata:[],retired_metadata:[],unchanged_metadata_sha256:{}};
 for(const group of [...new Set([...Object.keys(old),...Object.keys(current)])]){
  if(!groups.has(group)){
   if(!(group in current))entry.retired_metadata.push(group);
   else if(!(group in old)||recordSha(old[group])!==recordSha(current[group]))entry.changed_metadata.push(group);
   else entry.unchanged_metadata_sha256[group]=recordSha(current[group]);
   continue;
  }
  const a=records(old[group]??{}),b=records(current[group]??{}),result={changed:[],added:[],retired:[],unchanged_sha256:{},affected_sha256:{}};
  for(const id of [...new Set([...Object.keys(a),...Object.keys(b)])]){
   if(!(id in b))result.retired.push(id);
   else if(!(id in a)){result.added.push(id);result.affected_sha256[id]=recordSha(b[id]);}
   else if(recordSha(a[id])!==recordSha(b[id])){result.changed.push(id);result.affected_sha256[id]=recordSha(b[id]);}
   else result.unchanged_sha256[id]=recordSha(b[id]);
  }
  entry.groups[group]=result;
 }
 entry.sha256=sha(after);manifest.fixtures[path]=entry;
}
// Fix-round continuity also covers nested signed records/statements in the alpha.34 corpus.
const path='tests/fixtures/foreign-dependencies-alpha34.json',fixBaseline='474ccc97';
const prior=JSON.parse(git('show',`${fixBaseline}:${path}`)),current=JSON.parse(readFileSync(path));
const schemas=new Map(Object.values({...native,...imported,...hosted,...common,...owners}).filter(s=>s&&typeof s==='object'&&s.kind==='message').map(s=>[s.typeName,s]));
function signedParts(vector){
 const parts=[];
 function walk(value){if(!value||typeof value!=='object'||value instanceof Uint8Array)return;
  if(value.$typeName&&(value.$typeName.endsWith('.SignedRecord')||value.$typeName.split('.').at(-1).startsWith('Signed'))){const schema=schemas.get(value.$typeName);assert.ok(schema,value.$typeName);parts.push(sha(toBinary(schema,value)));}
  for(const [key,child] of Object.entries(value))if(key!=='$typeName')if(Array.isArray(child))child.forEach(walk);else walk(child);
 }
 walk(fromBinary(schemas.get(vector.schema),Buffer.from(vector.wire_hex,'hex')));return [...new Set(parts)].sort();
}
const changed=[];
for(const [id,old] of Object.entries(prior.wire_vectors)){
 const value=current.wire_vectors[id];assert.ok(value,id);
 assert.deepEqual(signedParts(value),signedParts(old),id+': existing signed parts');
 if(value.wire_hex!==old.wire_hex)changed.push(id);
}
manifest.fix_round={baseline:fixBaseline,unchanged_signed_parts_by_vector:Object.fromEntries(Object.entries(prior.wire_vectors).map(([id,v])=>[id,signedParts(v)])),changed_carrier_wires:changed,added_vectors:Object.keys(current.wire_vectors).filter(id=>!(id in prior.wire_vectors)),reason:'ForeignDependencyV1 tag 5 prefix_admission_order and byte-bound vectors alter carrier encoding only; all existing nested signed originals, payload commitments, signatures, manifests and statements are unchanged.'};
writeFileSync('breaking/0.31.0-alpha.34-vectors.json',JSON.stringify(manifest,null,2)+'\n');
console.log('Generated exact alpha.34 vector inventory');
