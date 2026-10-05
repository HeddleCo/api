// Mutation probes for the compiled TS validators and the staged receiver model.
// Every probe must execute a failing test, then pass after exact restoration.
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const directory=process.argv[2]??'/tmp/api-alpha34-guards';mkdirSync(directory,{recursive:true});
const helper='packages/typescript/dist/v1alpha2/_foreign-dependencies.js';
const cases=[
 ['native_foreign_support','packages/typescript/dist/v1alpha2/native-witness.js','foreign closure PASS native_child_imported_frontier','await foreign.verify(original);','reject("Scope");'],
 ['import_foreign_support','packages/typescript/dist/v1alpha2/import-authority.js','foreign closure PASS native_child_imported_main','foreign.require(original);','reject("Scope");'],
 ['foreign_bound','packages/typescript/dist/v1alpha2/native-witness.js','foreign REJECT then PASS native_foreign_over_bound','toBinary(api.NativePublicProofBundleV1Schema, b).length > 1048576','false'],
 ['foreign_sort',helper,'foreign REJECT then PASS native_unsorted_foreign','i && compare(entries[i - 1].signedNativeDigest, entry.signedNativeDigest) >= 0','false'],
 ['foreign_origin',helper,'foreign REJECT then PASS native_same_origin_foreign','entry.origin === carrier','false'],
 ['foreign_thread',helper,'foreign REJECT then PASS import_thread_mismatch',' && equal(e.threadGenesisDigest, thread)',''],
 ['foreign_digest',helper,'foreign REJECT then PASS import_digest_mismatch','equal(e.signedNativeDigest, digest) && ',''],
 ['foreign_unused',helper,'foreign REJECT then PASS native_unreferenced_foreign','this.used.size !== this.entries.length','false'],
 ['foreign_version',helper,'foreign REJECT then PASS import_foreign_version','entry.formatVersion !== 1 || ',''],
 ['foreign_unknown_origin',helper,'foreign REJECT then PASS import_foreign_origin_unknown',' || ![ForeignDependencyOrigin.IMPORT, ForeignDependencyOrigin.NATIVE].includes(entry.origin)',''],
 ['foreign_width',helper,'foreign REJECT then PASS import_foreign_width','width(entry.signedNativeDigest, 32);',''],
 ['local_import_binding','tests/v2-foreign-dependencies.test.mjs','staged receiver REJECT then PASS unbound_local_key_import_source',"if(!row?.job||!equal(row.job,new Uint8Array(source.publisher)))reject('ImportPermission');",''],
 ['job_landing_role','packages/typescript/dist/v1alpha2/native-witness.js','foreign REJECT then PASS job_signed_landing','verifyLandingKeyRoles(p, set.knownJobKeys);',''],
 ['missing_stage','tests/v2-foreign-dependencies.test.mjs','staged receiver REJECT then PASS missing_frontier_stage',"if(!row||row.origin!==ref.origin||!equal(row.thread,ref.threadGenesisDigest)||row.admissionOrder!==ref.prefixAdmissionOrder||!equal(row.spool,b.ownerGenesis.genesis.spoolUuid)||row.authority!==b.witnessSet.body.deploymentAuthority)reject('Scope');",''],
 ['native_p2_subject','packages/typescript/dist/v1alpha2/native-witness.js','foreign REJECT then PASS native_foreign_p2_subject','if (!b.genesisWitnesses.some(g => g.originalGenesis && equal(threadGenesisId(g.originalGenesis.canonicalRecord), subjectThread)))','if (false)'],
 ['import_p2_subject','packages/typescript/dist/v1alpha2/import-authority.js','foreign REJECT then PASS import_foreign_p2_subject','if (!b.genesisWitnesses.some(g => g.originalGenesis && equal(threadGenesisId(g.originalGenesis.canonicalRecord), subjectThread)))','if (false)'],
 ['import_execution','packages/typescript/dist/v1alpha2/import-authority.js','foreign REJECT then PASS import_foreign_execution','if (!b.genesisWitnesses.some(g => g.originalGenesis && equal(threadGenesisId(g.originalGenesis.canonicalRecord), thread)))','if (false)'],
 ['import_genesis_identity','packages/typescript/dist/v1alpha2/import-authority.js','foreign REJECT then PASS import_genesis_signature_substitution','else if (original.format === "heddle-thread-genesis-v1" && !b.genesisWitnesses.some(p => p.originalGenesis && equal(toBinary(SignedRecordSchema, p.originalGenesis), toBinary(SignedRecordSchema, original))))','else if (false)'],
 ['prefix_nonzero',helper,'foreign REJECT then PASS import_foreign_prefix_zero','entry.prefixAdmissionOrder === 0n','false'],
 ['known_job_roles','packages/typescript/dist/v1alpha2/import-authority.js','foreign REJECT then PASS known_job_landing_key','knownJobKeys.some(k => equal(k, key))','false'],
 ['forbidden_landing_roles','packages/typescript/dist/v1alpha2/import-authority.js','foreign REJECT then PASS forbidden_job_landing_key','forbiddenKeys.some(k => equal(k, key))','false'],
 ['import_delegation_job_role','packages/typescript/dist/v1alpha2/import-authority.js','foreign REJECT then PASS import_job_signed_landing','verifyLandingKeyRoles(p, b.delegations.flatMap(d => d.body ? [d.body.jobPublicKey] : []));',''],
 ['prefix_extension','tests/v2-foreign-dependencies.test.mjs','prefix staging bidirectional fresh receiver','await this.installPrefix(foreign.id,catalog,visiting);',"reject('Scope');"],
 ['prefix_binding','tests/v2-foreign-dependencies.test.mjs','staged receiver REJECT then PASS installed_order_mismatch','||row.admissionOrder!==ref.prefixAdmissionOrder',''],
 ['installed_spool','tests/v2-foreign-dependencies.test.mjs','staged receiver REJECT then PASS installed_spool_mismatch','||!equal(row.spool,b.ownerGenesis.genesis.spoolUuid)',''],
 ['installed_authority','tests/v2-foreign-dependencies.test.mjs','staged receiver REJECT then PASS installed_authority_mismatch','||row.authority!==b.witnessSet.body.deploymentAuthority',''],
 ['installed_bytes','tests/v2-foreign-dependencies.test.mjs','staged receiver REJECT then PASS installed_bytes_mismatch','!equal(toBinary(SignedRecordSchema,original),toBinary(SignedRecordSchema,row.record))','false'],
 ['account_admission','tests/v2-foreign-dependencies.test.mjs','staged receiver REJECT then PASS missing_account_source_admission','||this.rows.get(digest)?.admissionPurpose!==2',''],
 ['integration_admission','tests/v2-foreign-dependencies.test.mjs','staged receiver REJECT then PASS missing_integration_source_admission','this.rows.get(digest)?.admissionPurpose!==4||',''],
 ['original_cycle','tests/v2-foreign-dependencies.test.mjs','prefix staging genuine cycle REJECT then PASS','visiting.includes(key)','false'],
 ['import_selected_roles','packages/typescript/dist/v1alpha2/import-authority.js','foreign REJECT then PASS import_(known|forbidden)_landing_key','verifyLandingKeyRoles(payload, owner.knownJobAssociations.map(a => a.key), owner.forbiddenLandingKeys);',''],
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
