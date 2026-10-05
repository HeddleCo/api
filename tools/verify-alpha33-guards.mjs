// Mutate ONE JS guard per case; require a real test failure and restored pass.
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const path='packages/typescript/dist/v1alpha2/import-authority.js',original=readFileSync(path,'utf8');
const directory=process.argv[2]??'/tmp/api-alpha33-guards';mkdirSync(directory,{recursive:true});
const cases=[
 ['p1_window','alpha33 direct P1 pair',`interval(d.notBeforeUnixSeconds, d.expiresAtUnixSeconds, admission.observedAtUnixMillis / 1000n);`,``],
 ['p1_p3_time','alpha33 bundle p1_time_mismatch',`admission.observedAtUnixMillis !== publication.observedAtUnixMillis`,`false`],
 ['p1_p3_transaction','alpha33 bundle p1_foreign_transaction',`!equal(admission.hostTransactionId, publication.hostTransactionId)`,`false`],
 ['p1_p3_order','alpha33 bundle p1_order_after_p3',`admission.admissionOrder >= publication.admissionOrder`,`false`],
 ['p1_p3_executor','alpha33 bundle executor_mismatch',`!equal(admission.executorId, publication.executorId)`,`false`],
 ['duplicate_p1','alpha33 bundle duplicate_p1',`admittedGeneses.has(key)`,`false`],
 ['duplicate_p3','alpha33 bundle duplicate_p3',`if (matches.length !== 1)
            reject("Transition");`,`if (matches.length === 0)
            reject("Transition");`],
 ['unconsumed_p3','alpha33 bundle unconsumed_p3',`s.body?.purpose === 3 && !selectedPublications.some(p => equal(toBinary(SignedHostedWitnessStatementV1Schema, p), toBinary(SignedHostedWitnessStatementV1Schema, s)))`,`false`],
 ['signed_window_ceiling','alpha33 signed window ceiling',`d.expiresAtUnixSeconds - d.notBeforeUnixSeconds > MAX_DELEGATION_WINDOW_SECONDS`,`false`],
 ['host_window_ceiling','alpha33 host window ceiling',`prepared.maxValidityDurationSeconds > MAX_DELEGATION_WINDOW_SECONDS`,`false`],
 ['window_24h','alpha33 24h',`end - start > prepared.maxValidityDurationSeconds`,`end - start > 3600n`],
 ['host_budget_bytes','alpha33 direct publication budget',`signed.body.resultBytes > remaining.maxResultBytes`,`false`],
 ['retry_status_reason','alpha33 status retry reason',`!(response.status === 1 ? [1, 2, 6] : response.status === 2 ? [3] : response.status === 3 ? [4] : response.status === 4 ? [5] : response.status === 5 ? [7] : []).includes(availability.value)`,`(availability.value < 1 || availability.value > 7)`],
 ['hostile_body','alpha33 hostile missing operation body',`(o.body ?? reject("Canonical")).genesisDigest`,`o.body.genesisDigest`],
 ['commit_conflict_wire','alpha33 Commit conflict wire',`reason: ErrorReason.IMPORT_DESTINATION_CONFLICT`,`reason: ErrorReason.ALREADY_EXISTS`],
 ['sibling_full_ref','alpha33 direct sibling full ref',`b.refName === selected.refName`,`false`,'tests/v2-import-sibling-jobs.test.mjs'],
 ['sibling_target','alpha33 sibling target identity',`equal(b.targetThreadId, selected.targetThreadId)`,`false`,'tests/v2-import-sibling-jobs.test.mjs'],
 ['sibling_genesis','alpha33 sibling target identity',`equal(b.genesisDigest, selected.genesisDigest)`,`false`,'tests/v2-import-sibling-jobs.test.mjs'],
];
function run(name,pattern,stage,file){
 const r=spawnSync('node',['--test','--test-reporter=tap','--test-name-pattern='+pattern,file??'tests/v2-import-authority-witness.test.mjs'],{encoding:'utf8'});
 writeFileSync(`${directory}/${name}-${stage}.log`,r.stdout+r.stderr);
 if(stage==='red'&&!/^not ok /m.test(r.stdout))throw Error(name+': not a test failure');
 if(stage==='green'&&!/^# pass [1-9]/m.test(r.stdout))throw Error(name+': no passing test executed');
 return r.status;
}
try{
 for(const [name,pattern,from,to,file] of cases){
  if(!original.includes(from))throw Error('missing mutation '+from);
  writeFileSync(path,original.replace(from,to));const red=run(name,pattern,'red',file);
  writeFileSync(path,original);const green=run(name,pattern,'green',file);
  console.log(`${name}: broken exit ${red}; restored exit ${green}`);
  if(red!==1||green!==0)throw Error('guard not demonstrated: '+name);
 }
}finally{writeFileSync(path,original);}
