// Inventory changes against alpha.32; never produces or modifies signed vectors.
import {execFileSync} from 'node:child_process';
import {existsSync,readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const baseline='77f73219';
const git=(...args)=>execFileSync('git',args,{maxBuffer:64*1024*1024});
const sha=value=>createHash('sha256').update(value).digest('hex');
const recordSha=value=>sha(JSON.stringify(value));
const paths=git('ls-tree','-r','--name-only',baseline,'tests/fixtures').toString().trim().split('\n');
const manifest={baseline,reason:'One-shot signed layout, publication-time P1/P3, minimal state and dependent witness/seal carriers. Non-import canonical records remain unchanged.',fixtures:{},retired_files:[],retired_corpora:{},unaffected_files:{}};
const groups=new Set(['signed_vectors','wire_vectors','commitment_vectors','raw_commitment_vectors','canonical_vectors','operations']);
function records(value){return Array.isArray(value)?Object.fromEntries(value.map((v,i)=>[String(v.id??v.name??v.count??i),v])):value;}
for(const path of paths){
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
writeFileSync('breaking/0.31.0-alpha.33-vectors.json',JSON.stringify(manifest,null,2)+'\n');
console.log('Generated exact alpha.33 vector inventory');
