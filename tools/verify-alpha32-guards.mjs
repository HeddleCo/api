// Maintenance evidence: each regression must fail with its guard disabled and
// pass after restoring the built runtime. Never edits source or signed fixtures.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const path='packages/typescript/dist/v1alpha2/import-authority.js',original=readFileSync(path,'utf8');
const directory=process.argv[2]??'/tmp/api-alpha32-guards';mkdirSync(directory,{recursive:true});
const cases=[
 ['total_over_1gib','alpha32 total over',[['v.maxResultBytes > MAX_RESULT_BYTES','false']]],
 ['total_widening','alpha32 widening',[['c.maxResultBytes <= p.maxResultBytes','true']]],
 ['total_narrowing','alpha32 widening',[['c.maxResultBytes <= p.maxResultBytes','c.maxResultBytes === p.maxResultBytes']]],
 ['partial_remaining','alpha32 remaining',[['remaining.maxResultBytes -= slot.resultBytes','remaining.maxResultBytes -= 0n']]],
 ['renewal_consumption','alpha32 consumption',[['ns.maxResultBytes > os.maxResultBytes - consumed','false'],['scope.maxResultBytes > old.maxResultBytes - consumed','false']]],
 ['aggregate_total','alpha32 aggregate',[['totalBytes > originalScope.maxResultBytes','false'],['count.bytes > scope.maxResultBytes','false']]],
 ['unknown_estimate','alpha32 unknown estimate',[['source.sizeEstimateState === 0 && source.gitSizeKib === 0n','source.sizeEstimateState === 0']]],
 ['original_window','alpha32 original window',[['availability.value > 7','availability.value > 6']]],
 ['creator_selection','alpha32 creator selection',[['original.signatures.find(s => equal(s.publicKey, g.creatorPublicKey))','original.signatures[0]']]],
 ['evidence_discriminant','alpha32 creator selection',[['times.every(t => t !== undefined)','true']]],
];
const run=(name,pattern,stage)=>{const result=spawnSync('node',['--test','--test-name-pattern='+pattern,'tests/v2-import-authority-witness.test.mjs'],{encoding:'utf8'});writeFileSync(`${directory}/${name}-${stage}.log`,result.stdout+result.stderr);return result.status;};
try {
 for(const [name,pattern,replacements] of cases){let mutated=original;for(const [from,to] of replacements){if(!mutated.includes(from))throw Error('missing mutation: '+from);mutated=mutated.replace(from,to);}writeFileSync(path,mutated);const red=run(name,pattern,'red');writeFileSync(path,original);const green=run(name,pattern,'green');console.log(`${name}: disabled guard exit ${red}; restored guard exit ${green}`);if(red!==1||green!==0)throw Error(`${name}: guard was not demonstrated`);}
} finally {writeFileSync(path,original);}
