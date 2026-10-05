// Negative-path evidence against built JS; restores bytes even on failure.
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const path='packages/typescript/dist/v1alpha2/import-authority.js',original=readFileSync(path,'utf8');
const directory=process.argv[2]??'/tmp/api352-consumer-guards';mkdirSync(directory,{recursive:true});
const cases=[
 ['caller_owner','alpha32 caller availability connected_co_writer','retained.connection && caller.connectionOwnerAccount !== caller.callerAccount ? R.NOT_CONNECTION_OWNER','false ? R.NOT_CONNECTION_OWNER'],
 ['required_controls','alpha32 controls REJECT then PASS','validateImportRetryStateResponse(request, response);\n    const controls =','validateImportRetryStateResponse(request, response); return;\n    const controls ='],
 ['recovery_noop','alpha32 recovery snapshot same_set','if (witnessedPrefix > 0 || newSet)','if (true)'],
 ['recovery_history','alpha32 recovery snapshot new_set','acceptedHistory: witnessedPrefix > 0 ? history : snapshot?.acceptedHistory ?? []','acceptedHistory: history'],
 ['receipt_times','alpha32 selected owner times','owner = await resolveOwner(i, times[i]?.time)','owner = await resolveOwner(i, 900n)'],
];
const run=(name,stage,pattern)=>{const r=spawnSync('node',['--test','--test-name-pattern='+pattern,'tests/v2-import-consumer.test.mjs'],{encoding:'utf8'});writeFileSync(`${directory}/${name}-${stage}.log`,r.stdout+r.stderr);return r.status;};
try {
 for(const [name,pattern,from,to] of cases){if(!original.includes(from))throw Error('missing mutation: '+from);writeFileSync(path,original.replace(from,to));const red=run(name,'red',pattern);writeFileSync(path,original);const green=run(name,'green',pattern);console.log(`${name}: disabled guard exit ${red}; restored guard exit ${green}`);if(red!==1||green!==0)throw Error(`${name}: guard not demonstrated`);}
}finally{writeFileSync(path,original);}
