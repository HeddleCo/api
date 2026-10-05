import assert from 'node:assert/strict';
import {existsSync,readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const manifest=JSON.parse(readFileSync('breaking/0.31.0-alpha.34-vectors.json'));
const sha=v=>createHash('sha256').update(v).digest('hex');
const recordSha=v=>sha(JSON.stringify(v));
let changed=0,added=0,retired=0,unchanged=0;
for(const [path,entry] of Object.entries(manifest.fixtures)){
 const bytes=readFileSync(path),fixture=JSON.parse(bytes);assert.equal(sha(bytes),entry.sha256,path);
 if(entry.new_file){assert.equal(fixture.positive.length,5);assert.equal(fixture.negative.length,23);assert.equal(fixture.receiver_negative.length,5);continue;}
 for(const [group,result] of Object.entries(entry.groups)){
  const values=Array.isArray(fixture[group])?Object.fromEntries(fixture[group].map((v,i)=>[String(v.id??v.name??v.count??i),v])):fixture[group]??{};
  assert.deepEqual(Object.keys(values).sort(),[...result.changed,...result.added,...Object.keys(result.unchanged_sha256)].sort(),`${path}: ${group} exact inventory`);
  for(const [id,hash] of Object.entries(result.unchanged_sha256)){assert.equal(recordSha(values[id]),hash,`${path}: unaffected ${group}.${id}`);unchanged++;}
  for(const [id,hash] of Object.entries(result.affected_sha256))assert.equal(recordSha(values[id]),hash,`${path}: regenerated ${group}.${id}`);
  for(const id of result.retired)assert.equal(values[id],undefined,`${path}: retired ${group}.${id}`);
  changed+=result.changed.length;added+=result.added.length;retired+=result.retired.length;
 }
 for(const [name,hash] of Object.entries(entry.unchanged_metadata_sha256))assert.equal(recordSha(fixture[name]),hash,`${path}: unaffected metadata ${name}`);
 for(const name of entry.retired_metadata)assert.equal(fixture[name],undefined,`${path}: retired metadata ${name}`);
}
for(const path of manifest.retired_files)assert.equal(existsSync(path),false,`retired fixture ${path}`);
for(const [path,hash] of Object.entries(manifest.unaffected_files))assert.equal(sha(readFileSync(path)),hash,`unaffected fixture ${path}`);
assert.equal(changed,0,'no existing signed/canonical record changes');assert.equal(retired,0,'no existing record retirement');assert.ok(unchanged>0,'nonempty continuity coverage');
console.log(`alpha.34 continuity: ${changed} changed, ${added} added, ${retired} retired, ${unchanged} unchanged records; ${Object.keys(manifest.unaffected_files).length} byte-identical fixture files; ${manifest.retired_files.length} retired corpora`);
