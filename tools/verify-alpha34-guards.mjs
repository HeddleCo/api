// Mutation probes for the compiled TS validators and the staged receiver model.
// Every probe must execute a failing test, then pass after exact restoration.
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const directory=process.argv[2]??'/tmp/api-alpha34-guards';mkdirSync(directory,{recursive:true});
const helper='packages/typescript/dist/v1alpha2/_foreign-dependencies.js';
const cases=[
 ['native_foreign_support','packages/typescript/dist/v1alpha2/native-witness.js','foreign closure PASS native_child_imported_frontier','await foreign.verify(original);','reject("Scope");'],
 ['import_foreign_support','packages/typescript/dist/v1alpha2/import-authority.js','foreign closure PASS native_child_imported_main','foreign.require(original);','reject("Scope");'],
 ['foreign_bound',helper,'foreign REJECT then PASS native_foreign_over_bound','entries.length > 128','false'],
 ['foreign_sort',helper,'foreign REJECT then PASS native_unsorted_foreign','i && compare(entries[i - 1].signedNativeDigest, entry.signedNativeDigest) >= 0','false'],
 ['foreign_origin',helper,'foreign REJECT then PASS native_same_origin_foreign','entry.origin === carrier','false'],
 ['foreign_thread',helper,'foreign REJECT then PASS import_thread_mismatch',' && equal(e.threadGenesisDigest, thread)',''],
 ['foreign_digest',helper,'foreign REJECT then PASS import_digest_mismatch','equal(e.signedNativeDigest, digest) && ',''],
 ['foreign_unused',helper,'foreign REJECT then PASS native_unreferenced_foreign','this.used.size !== this.entries.length','false'],
 ['foreign_version',helper,'foreign REJECT then PASS import_foreign_version','entry.formatVersion !== 1 || ',''],
 ['foreign_unknown_origin',helper,'foreign REJECT then PASS import_foreign_origin_unknown',' || ![1, 2].includes(entry.origin)',''],
 ['foreign_width',helper,'foreign REJECT then PASS import_foreign_width','width(entry.signedNativeDigest, 32);',''],
 ['local_import_binding','tests/v2-foreign-dependencies.test.mjs','staged receiver REJECT unchanged then PASS unbound_local_key_import_source',"if(!row?.job||!equal(row.job,new Uint8Array(source.publisher)))reject('ImportPermission');",''],
 ['job_landing_role','tests/v2-foreign-dependencies.test.mjs','staged receiver REJECT unchanged then PASS job_signed_landing',"if(equal(requestKey,bytes(f.keys.job.public_key_hex)))reject('KeyRole');",''],
 ['missing_stage','tests/v2-foreign-dependencies.test.mjs','staged receiver REJECT unchanged then PASS missing_frontier_stage',"if(!row||row.origin!==ref.origin||!equal(row.thread,ref.threadGenesisDigest))reject('Scope');",''],
];
function run(name,pattern,stage){const r=spawnSync('node',['--test','--test-reporter=tap','--test-name-pattern='+pattern,'tests/v2-foreign-dependencies.test.mjs'],{encoding:'utf8'});writeFileSync(`${directory}/${name}-${stage}.log`,r.stdout+r.stderr);if(stage==='red'&&!/^not ok /m.test(r.stdout))throw Error(name+': no failing test');if(stage==='green'&&!/^# pass [1-9]/m.test(r.stdout))throw Error(name+': no passing test');return r.status;}
for(const [name,path,pattern,from,to] of cases){
 const original=readFileSync(path,'utf8');
 try{
  if(!original.includes(from))throw Error('missing mutation '+name);
  writeFileSync(path,original.replaceAll(from,to));const red=run(name,pattern,'red');
  writeFileSync(path,original);const green=run(name,pattern,'green');
  console.log(`alpha.34 ${name}: broken exit ${red}; restored exit ${green}`);
  if(red!==1||green!==0)throw Error('guard not demonstrated: '+name);
 }finally{writeFileSync(path,original);}
}
