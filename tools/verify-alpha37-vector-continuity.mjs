import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const manifest=JSON.parse(readFileSync('breaking/0.31.0-alpha.37-vectors.json'));
assert.ok(Object.keys(manifest.unchanged_files).length>0,'nonempty alpha.36 baseline');
for(const [path,sha] of Object.entries(manifest.unchanged_files))assert.equal(createHash('sha256').update(readFileSync(path)).digest('hex'),sha,`unchanged alpha.36 fixture ${path}`);
console.log(`alpha.37 continuity: ${Object.keys(manifest.unchanged_files).length} byte-identical alpha.36 fixture files`);
