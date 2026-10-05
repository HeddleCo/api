import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const manifest=JSON.parse(readFileSync('breaking/0.31.0-alpha.32-vectors.json'));
const digest=v=>createHash('sha256').update(v).digest('hex');
let unchanged=0,changed=0,retired=0;
for(const [path,groups] of Object.entries(manifest.fixtures)){
 const fixture=JSON.parse(readFileSync(path));
 for(const [name,records] of Object.entries(groups)){
  if(name.startsWith('dependent_metadata'))continue;
  const values=Array.isArray(fixture[name])?Object.fromEntries(fixture[name].map(v=>[String(v.id??v.count),v])):fixture[name];
  for(const [id,sha] of Object.entries(records.unchanged_sha256)){assert.equal(digest(JSON.stringify(values[id])),sha,`${path}: unaffected ${name}.${id}`);unchanged++;}
  for(const id of records.changed){assert.ok(values[id],`${path}: affected ${name}.${id} missing`);changed++;}
  for(const id of records.retired??[]){assert.equal(values[id],undefined,`${path}: retired ${name}.${id} remains`);retired++;}
 }
}
for(const [path,sha] of Object.entries(manifest.unaffected_files))assert.equal(digest(readFileSync(path)),sha,`unaffected fixture file ${path}`);
console.log(`alpha.32 continuity: ${changed} changed, ${retired} retired, ${unchanged} unaffected vector records and ${Object.keys(manifest.unaffected_files).length} unaffected fixture files verified`);
