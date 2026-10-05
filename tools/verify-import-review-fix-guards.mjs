// Fail-then-pass evidence against built JS. Source and signed fixtures stay intact.
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const path='packages/typescript/dist/v1alpha2/import-authority.js',original=readFileSync(path,'utf8'),directory=process.argv[2]??'/tmp/api352-review-ts-guards';mkdirSync(directory,{recursive:true});
const cases=[
 ['renew_certificate_remaining','review fix renewal narrowing',[['ns.maxResultBytes > os.maxResultBytes - consumed','false']]],
 ['renew_permission_remaining','review fix renewal narrowing',[['scope.maxResultBytes > old.maxResultBytes - consumed','false']]],
 ['publication_live','review fix publication',[['remaining.maxOperations === 0 || signed.body.resultBytes > remaining.maxResultBytes','false']]],
 ['publication_witness','review fix publication',[['await checkImportPublicationBudget(operation, delegation, before);','']]],
 ['owner_interval','review fix owner resolver',[['time !== undefined && (time < facts.effectiveFromUnixSeconds','false && time !== undefined && (time < facts.effectiveFromUnixSeconds']]],
 ['reservation_ownership','review fix reservation ownership',[['activation && !ownsReservation','false && activation && !ownsReservation']]],
 ['sibling_thread','review fix reservation ownership',[['|| equal(b.targetThreadId, selected.targetThreadId)','']]],
 ['sibling_genesis','review fix reservation ownership',[['|| equal(b.genesisDigest, selected.genesisDigest)','']]],
 ['scope_thread','review fix reservation ownership',[['equal(other.targetThreadId, b.targetThreadId)','false']]],
 ['scope_genesis','review fix reservation ownership',[['equal(other.genesisDigest, b.genesisDigest)','false']]],
 ['prepare_window','review fix renewal host maximum',[['checkOriginalImportWindow(originalAdmission ?? reject("Canonical"));','']]],
 ['renew_window','review fix renew activation',[['checkOriginalImportWindow({ original: retained.delegations[0] ?? reject("Canonical"), admitted: originalAdmitted, nowUnixSeconds: now });','']]],
 ['retry_window','review fix retry original',[['checkOriginalImportWindow({ original: context.read.retainedProof?.delegations[0] ?? reject("Canonical"), admitted: context.originalAdmitted, nowUnixSeconds: context.nowUnixSeconds });','']]],
 ['reservation_release','review fix original window releases',[['return reservations.filter(r => !equal(r.spoolUuid, spoolUuid) || !equal(r.logicalJobId, logicalJobId));','return [...reservations];']]],
 ['prepare_max_retained','review fix renewal host maximum',[['selectedConfiguration.limits.maxResultBytes = (1n << 64n) - 1n;','selectedConfiguration.limits.maxResultBytes = 1n;']]],
 ['recovery_prefix','review fix recovery prefix',[['acceptedHistory: witnessedPrefix > 0 ? history :','acceptedHistory: witnessed ? history :']]],
 ['overflow_reason','review fix renewal overflow',[['if (consumed >= (1n << 64n))','if (false)']]],
 ['narrowed_certificate','review fix narrowed bundle',[['await checkImportPublicationBudget(operation, delegation, before);',''],['await checkImportPublicationBudget(o, verified[index], committedBefore);',''],['count.bytes > scope.maxResultBytes','false']]],
];
const run=(name,stage,pattern)=>{const r=spawnSync('node',['--test','--test-name-pattern='+pattern,'tests/v2-import-review-fixes.test.mjs'],{encoding:'utf8'});writeFileSync(`${directory}/${name}-${stage}.log`,r.stdout+r.stderr);return r.status;};
try{for(const [name,pattern,replacements] of cases){if(process.argv[3]&&name!==process.argv[3])continue;let mutant=original;for(const [from,to] of replacements){if(!mutant.includes(from))throw Error('missing mutation: '+from);mutant=mutant.replace(from,to);}writeFileSync(path,mutant);const red=run(name,'red',pattern);writeFileSync(path,original);const green=run(name,'green',pattern);console.log(`${name}: disabled guard exit ${red}; restored guard exit ${green}`);if(red!==1||green!==0)throw Error(`${name}: guard not demonstrated`);}}finally{writeFileSync(path,original);}
