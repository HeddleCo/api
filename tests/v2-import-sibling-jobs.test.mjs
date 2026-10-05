import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
const f=JSON.parse(readFileSync(new URL('./fixtures/import-sibling-jobs-alpha32.json',import.meta.url)));
const base=JSON.parse(readFileSync(new URL('./fixtures/import-authority-host-witness-v1.json',import.meta.url)));
const bytes=h=>new Uint8Array(Buffer.from(h,'hex'));
const record=n=>{const r=f.wire_vectors[n]??f.signed_vectors[n];return a.strictDecode(api[r.schema.split('.').at(-1)+'Schema'],bytes(r.wire_hex));};
const expected=e=>e instanceof a.HybridContractError?(e.reason==='PreparationRefused'?api.ImportPreparationRefusalReason[e.preparationRefusalReason]:e.reason):String(e);
const context=()=>({identity:record('identity'),ownerPublicKey:bytes(base.keys.owner.public_key_hex),ownerChainDigest:bytes(base.context.owner_chain_digest_hex),authorityExpiresAtSeconds:2000n,nowUnixSeconds:1100n,forbiddenJobKeys:['owner','device','witness','next_witness','root'].map(k=>bytes(base.keys[k].public_key_hex)),knownJobAssociations:[]});
const verify=job=>a.verifyImportCommitSubmission(record('commit_'+job),record('prepared_'+job),'github',record('source'),record('configuration'),context());
for(const scenario of f.scenarios)test('alpha32 sibling '+scenario.id,async()=>{
 const inventory=new Map(),id=record('identity').spoolUuid,current=bytes(f.current_destination_hex);
 for(const step of scenario.steps){
  const original=structuredClone(inventory);let actual='OK';
  try{
   const scope=record(step.scope),d=record('delegation_'+step.job).body;
   if(step.action==='complete'){
    assert.equal(inventory.get(step.job).active,true);
    await a.verifyDelegatedImportOperation(record('operation_'+step.job),await verify(step.job));
    assert.equal(a.checkImportSlotReplay(record('manifest_'+step.job),record('operation_'+step.job)),true);
    inventory.delete(step.job);
   }else if(step.action==='expire_prepare'){
    assert.equal(inventory.get(step.job).active,false);inventory.delete(step.job);
   }else if(step.action==='commit'){
    a.checkImportDestinationVersion(scope,current);
    assert.ok(inventory.has(step.job),'activation owns its reservation');
    a.checkImportSpoolReservations(id, d.logicalJobId, scope, [...inventory.values()]);
    await verify(step.job);inventory.get(step.job).active=true;
   }else{
    const selected=a.prepareImportScope(scope,record('configuration'),current);
    a.checkImportSpoolReservations(id, d.logicalJobId, selected, [...inventory.values()]);
    if(step.action==='prepare'){
     a.validateImportPreparationResponse(record('prepare_'+step.job),record('prepared_'+step.job));
     inventory.set(step.job,{spoolUuid:id,logicalJobId:d.logicalJobId,branches:selected.branches,active:false});
    }
   }
  }catch(error){actual=expected(error);}
  console.log(`SIBLING ${scenario.id}.${step.action}.${step.job}: ${actual}`);
  assert.equal(actual,step.expected);
  if(actual!=='OK')assert.deepEqual(inventory,original,'refusal changes no reservations');
 }
});
for(const v of f.gate_vectors)test('alpha32 sibling '+v.id+' REJECT then PASS',()=>{
 const run=scope=>v.kind==='activate'?a.checkImportDestinationVersion(record(scope),bytes(f[v.current])):a.prepareImportScope(record(scope),record('configuration'),bytes(f[v.current]));
 assert.throws(()=>run(v.scope),e=>expected(e)===v.expected);run(v.control);
 console.log(`SIBLING ${v.id}: ${v.expected} -> OK`);
});
test('alpha32 sibling signed parity and independent totals',async()=>{
 for(const [name,v] of Object.entries(f.signed_vectors)){
  const value=record(name),body=api[v.body_schema.split('.').at(-1)+'Schema'];
  assert.equal(Buffer.from(a.canonicalHybridV1(body,value.body)).toString('hex'),v.canonical_hex);
  assert.equal(Buffer.from(a.signingDigest(v.domain,body,value.body)).toString('hex'),v.signing_input_hex);
 }
 for(const job of ['a','b','fresh']){
  await a.verifyDelegatedImportOperation(record('operation_'+job),await verify(job));
  assert.equal(a.checkImportSlotReplay(record('manifest_'+job),record('operation_'+job)),true);
 }
 const sa=record('scope_a'),sb=record('scope_b');
 assert.ok(sa.maxResultBytes+sb.maxResultBytes>record('configuration').limits.maxResultBytes);
 assert.equal(sa.branches[0].slotId,sb.branches[0].slotId,'slot number may repeat for disjoint refs');
 assert.notDeepEqual(record('delegation_a').body.jobPublicKey,record('delegation_b').body.jobPublicKey);
 assert.notDeepEqual(record('manifest_a').logicalJobId,record('manifest_b').logicalJobId);
 // Reservations are scoped to spool, and inspection leaves caller inputs intact.
 const held={spoolUuid:new Uint8Array(16).fill(0xff),logicalJobId:record('delegation_a').body.logicalJobId,branches:sa.branches};
 const before=toBinary(api.ImportPermissionScopeV1Schema,sa);
 a.checkImportSpoolReservations(record('identity').spoolUuid, record('delegation_b').body.logicalJobId, sa, [held]);
 assert.deepEqual(toBinary(api.ImportPermissionScopeV1Schema,sa),before);
});
test('alpha32 sibling typed refusal fields REJECT then PASS',()=>{
 for(const [name,field] of [['duplicate','proposed_scope.branches.ref_name'],['slot','proposed_scope.branches.slot_id'],['stale','proposed_scope.destination_version']]){
  const response=record('refusal_'+name);
  assert.equal(response.refusal.field,field);
  assert.throws(()=>a.validateImportPreparationResponse(record('prepare_b'),response),e=>expected(e)==='DESTINATION_CONFLICT');
  a.validateImportPreparationResponse(record('prepare_b'),record('prepared_b'));
 }
});
test('alpha33 duplicate sibling ref refuses at Commit with activation exclusivity',async()=>{
 // Prepare stores two proposals without reserving refs; activation checks the unique inventory.
 for(const job of ['a','duplicate'])a.validateImportPreparationResponse(record('prepare_'+job),record('prepared_'+job));
 await verify('a');await verify('duplicate');
 const identity=record('identity'),held={spoolUuid:identity.spoolUuid,logicalJobId:record('delegation_a').body.logicalJobId,branches:record('scope_a').branches};
 assert.throws(()=>a.checkImportSpoolReservations(identity.spoolUuid,record('delegation_duplicate').body.logicalJobId,record('scope_duplicate'),[held]),e=>expected(e)==='DESTINATION_CONFLICT');
 a.checkImportSpoolReservations(identity.spoolUuid,record('delegation_b').body.logicalJobId,record('scope_b'),[held]);await verify('b');
});
