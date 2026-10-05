// Load-bearing regressions: disable each guard, require failure, restore and require pass.
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const path='packages/typescript/dist/v1alpha2/import-authority.js',original=readFileSync(path,'utf8');
const directory=process.argv[2]??'/tmp/api-alpha33-guards';mkdirSync(directory,{recursive:true});
const cases=[
 ['p1_window','alpha33 bundle p1_(outside_window|at_expiry)',[[`await verifyImportDelegation(bundle.delegations[0], resolveBundlePermission(bundle, initial.parentPermissionDigest), await resolveOwner(s.observedAtUnixMillis / 1000n));`,``]]],
 ['p1_p3_order','alpha33 bundle p1_(time_mismatch|order_after_p3|foreign_transaction)',[[`if (s.observedAtUnixMillis !== publication.observedAtUnixMillis || !equal(s.hostTransactionId, publication.hostTransactionId) || s.admissionOrder >= publication.admissionOrder)`,`if (false)`]]],
 ['window_24h','alpha33 24h',[[`end - start > prepared.maxValidityDurationSeconds`,`end - start > prepared.maxValidityDurationSeconds || end - start > 3600n`]]],
 ['duplicate_sibling_commit','alpha33 duplicate sibling ref',[[`held.branches.some(b => b.refName === selected.refName || equal(b.targetThreadId, selected.targetThreadId) || equal(b.genesisDigest, selected.genesisDigest))`,`false`]],'tests/v2-import-sibling-jobs.test.mjs'],
 ['cumulative_2x','alpha33 cumulative budget',[
  [`totalBytes > originalScope.maxResultBytes`,`false`],[`count.bytes > scope.maxResultBytes`,`false`],
  [`await checkImportPublicationBudget(operation, delegation, before);`,``],
  [`await checkImportPublicationBudget(o, verified[index], committedBefore);`,``],
 ]],
];
const run=(name,pattern,stage,file)=>{const r=spawnSync('node',['--test','--test-name-pattern='+pattern,file??'tests/v2-import-authority-witness.test.mjs'],{encoding:'utf8'});writeFileSync(`${directory}/${name}-${stage}.log`,r.stdout+r.stderr);return r.status;};
try{for(const [name,pattern,replacements,file] of cases){let mutated=original;for(const [from,to] of replacements){if(!mutated.includes(from))throw Error('missing mutation '+from);mutated=mutated.replace(from,to);}writeFileSync(path,mutated);const red=run(name,pattern,'red',file);writeFileSync(path,original);const green=run(name,pattern,'green',file);console.log(`${name}: broken exit ${red}; restored exit ${green}`);if(red!==1||green!==0)throw Error('guard not demonstrated: '+name);}}finally{writeFileSync(path,original);}
