import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { test } from "node:test";
import * as api from "../packages/typescript/dist/v1alpha2/index.js";
import * as common from "../packages/typescript/dist/common/index.js";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/import-authority-host-witness-v1.json", import.meta.url)));

test("HYBRID conformance vectors require the additive wire messages", () => {
  assert.ok(fixture.messages.length > 0);
  for (const name of fixture.messages) {
    const schema = (name.includes(".common.") ? common : api)[`${name.split(".").at(-1)}Schema`];
    assert.ok(schema, `missing ${name}`);
    assert.equal(schema.typeName, name);
  }
});

import { create, fromBinary, toBinary, getOption } from '@bufbuild/protobuf';
import { verify as nodeVerify, createPublicKey } from 'node:crypto';
import * as authority from '../packages/typescript/dist/v1alpha2/import-authority.js';
import * as witness from '../packages/typescript/dist/v1alpha2/witness-trust.js';
import { createServiceClient } from '../packages/typescript/dist/v1alpha2/client.js';
const bytes=v=>new Uint8Array(Buffer.from(v,'hex'));
const schemaFor=name=>(name.includes('.common.')?common:api)[`${name.split('.').at(-1)}Schema`];
function vector(name){const v=fixture.signed_vectors[name]??fixture.wire_vectors[name];return authority.strictDecode(schemaFor(v.schema),bytes(v.wire_hex));}
function ownerContext(now=1100n){return {identity:vector('identity'),ownerPublicKey:bytes(fixture.keys.owner.public_key_hex),ownerChainDigest:bytes(fixture.context.owner_chain_digest_hex),authorityExpiresAtSeconds:2000n,nowUnixSeconds:now,forbiddenJobKeys:['owner','device','witness','next_witness','root'].map(n=>bytes(fixture.keys[n].public_key_hex)),knownJobAssociations:[]};}
function setContext(now=1100000n){return {authority:fixture.context.authority,rootId:fixture.context.root_id,rootPublicKey:bytes(fixture.keys.root.public_key_hex),rootEpoch:1n,nowUnixMillis:now,clockFloorUnixMillis:1000000n,knownJobKeys:['job','renew_job','direct_job'].map(n=>bytes(fixture.keys[n].public_key_hex))};}
function assertCrypto(key,input,signature){const publicKey=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),key]),format:'der',type:'spki'});assert.ok(nodeVerify(null,input,publicKey,signature),'fixed signature');}
function expected(reason){return error=>error instanceof authority.HybridContractError&&error.reason===reason;}

for(const [name,v] of Object.entries(fixture.signed_vectors))test(`fixed canonical/signature/wire vector: ${name}`,()=>{
  const value=vector(name),body=value.body,schema=schemaFor(v.body_schema),canonical=authority.canonicalHybridV1(schema,body);
  assert.deepEqual(canonical,bytes(v.canonical_hex));
  const input=v.body_schema.endsWith('HostedWitnessSetV1')?witness.setSigningBytes(body):authority.signingDigest(v.domain,schema,body);
  assert.deepEqual(input,bytes(v.signing_input_hex));
  assert.deepEqual(toBinary(schemaFor(v.schema),value),bytes(v.wire_hex));
  const signature=value.rootSignature??value.signature??value.ownerSignature?.signature??value.creatorSignature?.signature??value.delegatingSignature?.signature??value.jobSignature?.signature;
  assert.deepEqual(signature,bytes(v.signature_hex));assertCrypto(bytes(v.public_key_hex),input,signature);
});
test('frozen descriptor fields and public proof-only lookup',()=>{
  for(const entry of fixture.descriptors){const schema=schemaFor(entry.name);assert.equal(schema.fields.length,entry.fields.length);for(const f of entry.fields){const actual=schema.fields.find(a=>a.number===f.number);assert.equal(actual?.name,f.name);assert.equal(actual?.message?.typeName??actual?.enum?.typeName??String(actual?.scalar),f.type);assert.equal(actual?.fieldKind==='list',f.list);}}
  for(const descriptor of fixture.enums){const schema=(descriptor.name.includes(".common.")?common:api)[`${descriptor.name.split(".").at(-1)}Schema`];assert.deepEqual(schema.values.map(v=>({name:v.name,number:v.number})),descriptor.values);}
  assert.equal(fixture.protocol.gated_methods.length,11);
  const rpc=api.IntegrationService.method.getHostedWitnessHistoryProof,contract=getOption(rpc,common.rpc_contract);
  assert.equal(contract.authorizationAccess,common.AuthorizationAccess.PUBLIC);assert.equal(contract.signingTier,common.SigningTier.NONE);assert.equal(contract.effect,common.RpcEffect.READ_ONLY);assert.deepEqual(contract.mandatoryFeatures,[1]);
  const response=vector('lookup_response');assert.equal(api.GetHostedWitnessHistoryProofResponseSchema.fields.length,1);assert.ok(response.proof);assert.ok(toBinary(api.GetHostedWitnessHistoryProofResponseSchema,response).length<=4096);witness.validateWitnessLookup(vector('lookup_request'));
});
test('owner -> typed member permission -> job -> operation -> exact publication; direct owner control',async()=>{
  const d=await authority.verifyImportDelegation(vector('delegation'),vector('permission'),ownerContext());
  await authority.verifyImportMemberPermission(vector('permission'),ownerContext());
  await authority.verifyImportDelegation(vector('direct_owner'),undefined,ownerContext());
  assert.deepEqual(authority.ownerChainDigest(vector('owner_chain')),bytes(fixture.context.owner_chain_digest_hex));
  for(const name of ['dev','main']){const g=fixture.originals[name];assertCrypto(bytes(fixture.keys.device.public_key_hex),Buffer.concat([Buffer.from('heddle-thread-genesis-v1\0'),bytes(g.canonical_hex)]),bytes(g.signature_hex));await authority.verifyImportGenesisAuthority(vector(`genesis_${name}`),d,bytes(g.genesis_digest_hex),bytes(g.signature_hex),new Uint8Array((await import('@noble/hashes/sha2.js')).sha256(bytes(g.envelope_hex))));await authority.verifyNewImportOperation(vector(`operation_${name}`),d,1100n);}
  const set=await witness.verifyWitnessSet(vector('current_set'),setContext());
  await authority.verifyImportPublication(vector('operation_main'),d,vector('partial_manifest'),vector('publication_statement'),set,undefined,1100000n);
  const retired=await witness.verifyWitnessSet(vector('retired_set'),setContext(1350000n),set);
  await authority.verifyImportPublication(vector('operation_main'),d,vector('partial_manifest'),vector('publication_statement'),retired,vector('publication_proof'),1350000n);
  await assert.rejects(authority.verifyNewImportOperation(vector('operation_main'),d,1350n),expected('Expired'));
});
for(const v of fixture.negative_vectors)test(`isolated negative gate: ${v.id}`,async()=>{
  if(v.type==='set'){const p=v.previous?await witness.verifyWitnessSet(vector(v.previous),setContext()):undefined;await assert.rejects(witness.verifyWitnessSet(authority.strictDecode(common.SignedHostedWitnessSetV1Schema,bytes(v.wire_hex)),setContext(),p),expected(v.expected));return;}
  if(v.type==='statement'){const set=await witness.verifyWitnessSet(vector(v.set),setContext(BigInt(v.now_ms)));await assert.rejects(witness.resolveWitnessStatement(set,authority.strictDecode(common.SignedHostedWitnessStatementV1Schema,bytes(v.wire_hex)),vector(v.proof),v.new_work,BigInt(v.now_ms)),expected(v.expected));return;}
  const d=await authority.verifyImportDelegation(vector('delegation'),vector('permission'),ownerContext());
  if(v.type==='operation')await assert.rejects(authority.verifyDelegatedImportOperation(authority.strictDecode(api.SignedDelegatedImportOperationV1Schema,bytes(v.wire_hex)),d),expected(v.expected));
  if(v.type==='new_operation')await assert.rejects(authority.verifyNewImportOperation(vector('operation_main'),d,BigInt(v.now_seconds)),expected(v.expected));
  if(v.type==='renewal')await assert.rejects(authority.verifyImportRenewal(authority.strictDecode(api.SignedImportJobRenewalV1Schema,bytes(v.wire_hex)),d,vector('partial_manifest'),1n,v.member===false?undefined:vector('permission'),ownerContext(BigInt(v.now_seconds))),expected(v.expected));
});
for(const v of fixture.unrelated_permissions)test(`correctly signed ${v.format} cannot delegate import`,async()=>{assertCrypto(bytes(v.public_key_hex),bytes(v.signing_input_hex),bytes(v.signature_hex));if(v.wire_hex){const record=fromBinary(api.SignedOwnerCapabilitySchema,bytes(v.wire_hex));assert.deepEqual(record.signature.signature,bytes(v.signature_hex));assert.equal(record.capability.formatVersion,v.format==='PURGE-v1'?1:3);}await assert.rejects(authority.verifyImportDelegation(vector('delegation'),undefined,ownerContext()),expected('ImportPermission'));});
for(const tree of fixture.trees)test(`static Merkle tree ${tree.count}: exact root and every path`,()=>{
  const leaves=tree.leaves_hex.map(bytes);assert.deepEqual(witness.merkleRoot(leaves),bytes(tree.root_hex));const entry=create(common.HostedWitnessEntryV1Schema,{executorId:new Uint8Array(32).fill(1),state:2,archiveRoot:bytes(tree.root_hex),archiveLeafCount:BigInt(tree.count)});
  for(const p of tree.paths){const proof=create(common.HostedWitnessHistoryProofV1Schema,{executorId:entry.executorId,purpose:3,leafIndex:BigInt(p.index),leafCount:BigInt(tree.count),siblings:p.siblings_hex.map(bytes)});witness.verifyWitnessInclusion(leaves[p.index],proof,entry);const extra=structuredClone(proof);extra.siblings.push(new Uint8Array(32));assert.throws(()=>witness.verifyWitnessInclusion(leaves[p.index],extra,entry),expected('Proof'));}
});
test('concurrent signed renewals serialize and fence the paused old worker',async()=>{
  const scenario=fixture.retry_scenarios[0],previous=await authority.verifyImportDelegation(vector('delegation'),vector('permission'),ownerContext()),committed=vector(scenario.committed_manifest);let epoch=BigInt(scenario.initial_epoch),next;
  for(const event of scenario.events){if(event.action==='activate_renewal'){if(event.result==='OK'){next=await authority.verifyImportRenewal(vector(event.certificate),previous,committed,epoch,vector('permission'),ownerContext(1200n));epoch++;}else await assert.rejects(authority.verifyImportRenewal(vector(event.certificate),previous,committed,epoch,vector('permission'),ownerContext(1200n)),expected(event.result));}else if(BigInt(event.expected_epoch)!==epoch){assert.equal(event.result,'StaleContext');const stale=vector(event.operation);assert.throws(()=>authority.checkImportJobFence(stale.body.logicalJobId,stale.body.delegationDigest,BigInt(event.expected_epoch),next,epoch),expected('StaleContext'));assert.equal(authority.checkImportSlotReplay(committed,vector(event.operation)),false);}else{const active=vector(event.operation);authority.checkImportJobFence(active.body.logicalJobId,active.body.delegationDigest,BigInt(event.expected_epoch),next,epoch);await authority.verifyNewImportOperation(vector(event.operation),next,1250n);assert.equal(authority.checkImportSlotReplay(vector(scenario.final_manifest),vector(event.operation)),true);}assert.equal(epoch,BigInt(event.epoch_after));}
  assert.equal(vector(scenario.final_manifest).slots.length,scenario.committed_slot_count);
  const completed=vector('terminal_manifest');await assert.rejects(authority.verifyImportRenewal(vector('renewal'),previous,completed,1n,vector('permission'),ownerContext(1200n)),expected('RenewalFork'));
});
test('commit success/response loss: physical retry and fresh Fetch recover exact original result',async()=>{
  const scenario=fixture.retry_scenarios[1],operation=vector(scenario.original_operation),manifest=vector(scenario.manifest),receipt=vector(scenario.receipt);
  assert.notDeepEqual(operation.body.physicalOperationId,bytes(scenario.physical_retry_operation_id_hex));assert.deepEqual(operation.body.logicalJobId,bytes(scenario.logical_job_id_hex));assert.deepEqual(operation.body.retryLineageId,bytes(scenario.retry_original_operation_hex));
  assert.equal(authority.checkImportSlotReplay(manifest,operation),scenario.expected_replay);assert.equal(manifest.slots.length,scenario.committed_slot_count);
  const d=await authority.verifyImportDelegation(vector('delegation'),vector('permission'),ownerContext());const set=await witness.verifyWitnessSet(vector('retired_set'),setContext(1350000n));await authority.verifyImportPublication(operation,d,manifest,receipt,set,vector('publication_proof'),1350000n);
  assert.deepEqual(toBinary(common.SignedHostedWitnessStatementV1Schema,receipt),bytes(fixture.signed_vectors[scenario.receipt].wire_hex));assert.deepEqual(toBinary(api.ImportResultManifestV1Schema,manifest),bytes(fixture.wire_vectors[scenario.manifest].wire_hex));
  const conflict=vector('renewed_operation_dev');conflict.body.refName=operation.body.refName;conflict.body.slotId=operation.body.slotId;assert.throws(()=>authority.checkImportSlotReplay(manifest,conflict),expected('SlotConflict'));
});
test('cached contexts fail after generation, expiry, clock rollback and root replacement',async()=>{
  const current=await witness.verifyWitnessSet(vector('current_set'),setContext()),statement=vector('publication_statement'),context=await witness.resolveWitnessStatement(current,statement,undefined,false,1100000n);
  witness.recheckWitnessContext(context,current,statement,1100000n);
  const saved=await witness.restoreWitnessHistorySnapshot(vector('newer_set'),setContext(1400000n));await assert.rejects(witness.verifyWitnessSet(vector('current_set'),setContext(),saved),expected('HighWater'));
  const newer=await witness.verifyWitnessSet(vector('newer_set'),setContext(),current);assert.throws(()=>witness.recheckWitnessContext(context,newer,statement,1100000n),expected('StaleContext'));
  assert.throws(()=>witness.recheckWitnessContext(context,current,statement,1300000n),expected('Expired'));
  await assert.rejects(witness.verifyWitnessSet(vector('current_set'),{...setContext(),clockFloorUnixMillis:1200000n}),expected('StaleContext'));
  const replaced=await witness.verifyWitnessSet(vector('current_set'),{...setContext(),rootEpoch:2n});assert.throws(()=>witness.recheckWitnessContext(context,replaced,statement,1100000n),expected('StaleContext'));
});
test('unknown fields and bounds fail closed before trust or archive lookup',()=>{
  const good=bytes(fixture.signed_vectors.current_set.wire_hex);assert.throws(()=>authority.strictDecode(common.SignedHostedWitnessSetV1Schema,Buffer.concat([good,Buffer.from([0xf8,7,1])])),expected('Canonical'));
  assert.throws(()=>authority.strictDecode(common.SignedHostedWitnessSetV1Schema,new Uint8Array(1048577)),expected('Bounds'));
  assert.throws(()=>witness.validateWitnessLookup({executorId:new Uint8Array(31),statementLeafDigest:new Uint8Array(32)}),expected('Canonical'));
  const proof=vector('publication_proof');proof.siblings=Array.from({length:65},()=>new Uint8Array(32));const entry=vector('retired_set').body.entries.find(e=>e.state===2);assert.throws(()=>witness.verifyWitnessInclusion(bytes(fixture.wire_vectors.lookup_request.wire_hex).subarray(0,32),proof,entry),expected('Bounds'));
});
test('mandatory protocol/version gate blocks incompatible client before transport',async()=>{
  let calls=0;const transport={unary:async()=>{calls++;return new Uint8Array();}},path='/heddle.api.v1alpha2.IntegrationService/PrepareImportJob';
  const client=createServiceClient(api.IntegrationService,transport,new Set([path]));await assert.rejects(client.prepareImportJob({clientOperationId:'test'}),expected('Protocol'));assert.equal(calls,0);
  for(const value of [undefined,create(common.ProtocolCompatibilitySchema,{protocolVersion:1,mandatoryFeatures:[1]}),create(common.ProtocolCompatibilitySchema,{protocolVersion:2}),create(common.ProtocolCompatibilitySchema,{protocolVersion:2,mandatoryFeatures:[1,2]})])assert.throws(()=>authority.requireHybridPeer(value),expected('Protocol'));
  const sync=createServiceClient(api.SyncService,{open:async function*(){calls++;}},new Set(['/heddle.api.v1alpha2.SyncService/ReplicateThread']));
  await assert.rejects(async()=>{for await(const frame of sync.replicateThread((async function*(){yield {body:{case:'open',value:{}}};})())){}},expected('Protocol'));assert.equal(calls,0);
  authority.requireHybridPeer(create(common.ProtocolCompatibilitySchema,{protocolVersion:2,mandatoryFeatures:[1]}));
});

test('verification snapshots exclude asynchronous DTO and pin mutation',async()=>{const set=vector('current_set'),e=setContext(),pending=witness.verifyWitnessSet(set,e);set.body.generation=999n;e.rootEpoch=2n;const checked=await pending;assert.equal(checked.body.generation,10n);assert.equal(checked.rootEpoch,1n);const copy=checked.body;copy.generation=999n;assert.equal(checked.body.generation,10n);const member=vector('permission'),d=vector('delegation'),promise=authority.verifyImportDelegation(d,member,ownerContext());member.body.scope.maxOperations=256;d.body.scope.sourceUrl='https://other.example.test/repo.git';const verified=await promise;assert.equal(verified.body.scope.sourceUrl,'https://github.com/heddleco/example.git');});
