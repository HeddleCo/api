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
import { hash, join, u32, integer, sized, utf8, keyId } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
const bytes=v=>new Uint8Array(Buffer.from(v,'hex'));
const schemaFor=name=>(name.includes('.common.')?common:api)[`${name.split('.').at(-1)}Schema`];
function vector(name){const v=fixture.signed_vectors[name]??fixture.wire_vectors[name];return authority.strictDecode(schemaFor(v.schema),bytes(v.wire_hex));}
function ownerContext(now=1100n){return {identity:vector('identity'),ownerPublicKey:bytes(fixture.keys.owner.public_key_hex),ownerChainDigest:bytes(fixture.context.owner_chain_digest_hex),authorityExpiresAtSeconds:2000n,nowUnixSeconds:now,forbiddenJobKeys:['owner','device','witness','next_witness','root'].map(n=>bytes(fixture.keys[n].public_key_hex)),knownJobAssociations:[]};}
function setContext(now=1100000n){return {authority:fixture.context.authority,rootId:fixture.context.root_id,rootPublicKey:bytes(fixture.keys.root.public_key_hex),rootEpoch:1n,nowUnixMillis:now,clockFloorUnixMillis:1000000n,knownJobKeys:['job','renew_job','direct_job'].map(n=>bytes(fixture.keys[n].public_key_hex))};}
function assertCrypto(key,input,signature){const publicKey=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),key]),format:'der',type:'spki'});assert.ok(nodeVerify(null,input,publicKey,signature),'fixed signature');}
function expected(reason){return error=>error instanceof authority.HybridContractError&&error.reason===reason;}
// Only the owner/root keys are pinned. Derive this root-only history's context
// from the exported originals, rather than a second fixture identity/chain.
function exportOwnerContext(b){
  const history=b.ownerHistories[0],signed=history.root,root=signed.root,owner=bytes(fixture.keys.owner.public_key_hex);
  assert.deepEqual(history.acceptedTransitions,[]);assert.deepEqual(root.authorityKey.publicKey,owner);
  const encodedKey=k=>{assert.equal(k.algorithm,1);return join(u32(k.algorithm),sized(k.publicKey));},recovery=root.recoveryPolicy;
  const withoutId=join(u32(root.formatVersion),sized(root.accountUuid),encodedKey(root.authorityKey),u32(recovery.threshold),u32(recovery.guardians.length),...recovery.guardians.map(g=>join(u32(g.kind),encodedKey(g.key))),integer(recovery.windowSecs??604800n),new Uint8Array([Number(root.claimableDeferredHuman)]),sized(root.nonce),integer(root.claimableUntilUnixSeconds,true));
  assert.deepEqual(root.ownerId,hash(utf8.encode('heddle-owner-root-v1'),withoutId));
  const stateHash=hash(utf8.encode('heddle-owner-root-v1'),join(u32(root.formatVersion),sized(root.ownerId),withoutId.subarray(4)));
  assert.deepEqual(history.stateHash,stateHash);assert.deepEqual(signed.authorityProof.signerKeyId,keyId(owner));assertCrypto(owner,stateHash,signed.authorityProof.signature);
  assert.equal(signed.recoveryKeyProofs.length,recovery.guardians.length);recovery.guardians.forEach((g,i)=>{assert.deepEqual(signed.recoveryKeyProofs[i].signerKeyId,keyId(g.key.publicKey));assertCrypto(g.key.publicKey,stateHash,signed.recoveryKeyProofs[i].signature);});
  const genesis=b.ownerGenesis.genesis;assert.deepEqual(genesis.ownerPublicKey,root.authorityKey);assert.deepEqual(b.ownerGenesis.ownerSignature.signerKeyId,keyId(owner));assertCrypto(owner,hash(owner,genesis.spoolUuid),b.ownerGenesis.ownerSignature.signature);
  const spoolDigest=hash(utf8.encode('heddle-spool-owner-genesis-v1'),sized(genesis.spoolUuid),encodedKey(genesis.ownerPublicKey)),identity=b.delegations[0].body.identity;
  assert.deepEqual(identity.spoolUuid,genesis.spoolUuid);assert.deepEqual(identity.spoolGenesisDigest,spoolDigest);assert.deepEqual(identity.ownerId,root.ownerId);assert.deepEqual(identity.ownerAccountUuid,root.accountUuid);assert.deepEqual(identity.ownerStateHash,stateHash);
  assert.deepEqual(b.ownerChain.spoolGenesisDigest,spoolDigest);assert.deepEqual(b.ownerChain.ownerStateHashes,[stateHash]);
  const chain=authority.ownerChainDigest(b.ownerChain),forbiddenJobKeys=[owner,bytes(fixture.keys.root.public_key_hex),...b.originalGeneses.flatMap(g=>g.signatures.map(s=>s.publicKey)),...b.witnessSet.body.entries.map(e=>e.publicKey)];
  return now=>({identity,ownerPublicKey:owner,ownerChainDigest:chain,authorityExpiresAtSeconds:2000n,nowUnixSeconds:now,forbiddenJobKeys,knownJobAssociations:[]});
}

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
for(const v of fixture.negative_vectors)test(`isolated negative gate: ${v.id}; first check: ${v.first_failing_check}`,async()=>{
  assert.ok(v.first_failing_check);if(v.type==='set'){const p=v.previous?await witness.verifyWitnessSet(vector(v.previous),setContext()):undefined;await assert.rejects(witness.verifyWitnessSet(authority.strictDecode(common.SignedHostedWitnessSetV1Schema,bytes(v.wire_hex)),setContext(),p),expected(v.expected));await witness.verifyWitnessSet(vector(v.control),setContext(),p);return;}
  if(v.type==='statement'){const set=await witness.verifyWitnessSet(vector(v.set),setContext(BigInt(v.now_ms)));await assert.rejects(witness.resolveWitnessStatement(set,authority.strictDecode(common.SignedHostedWitnessStatementV1Schema,bytes(v.wire_hex)),vector(v.proof),v.new_work,BigInt(v.now_ms)),expected(v.expected));const fresh=v.new_work===true;const controlSet=await witness.verifyWitnessSet(vector(fresh?'current_set':'retired_set'),setContext(fresh?1100000n:1350000n));await witness.resolveWitnessStatement(controlSet,vector(v.control),fresh?undefined:vector('publication_proof'),fresh,fresh?1100000n:1350000n);return;}
  const d=await authority.verifyImportDelegation(vector('delegation'),vector('permission'),ownerContext());
  if(v.type==='operation')await assert.rejects(authority.verifyDelegatedImportOperation(authority.strictDecode(api.SignedDelegatedImportOperationV1Schema,bytes(v.wire_hex)),d),expected(v.expected));
  if(v.type==='new_operation')await assert.rejects(authority.verifyNewImportOperation(vector('operation_main'),d,BigInt(v.now_seconds)),expected(v.expected));
  if(v.type==='operation')await authority.verifyDelegatedImportOperation(vector(v.control),d);
  if(v.type==='new_operation')await authority.verifyNewImportOperation(vector(v.control),d,1299n);
  if(v.type==='renewal')await assert.rejects(authority.verifyImportRenewal(authority.strictDecode(api.SignedImportJobRenewalV1Schema,bytes(v.wire_hex)),d,vector('partial_manifest'),1n,v.member===false?undefined:vector('renewed_permission'),ownerContext(BigInt(v.now_seconds))),expected(v.expected));
  if(v.type==='renewal')await authority.verifyImportRenewal(vector(v.control),d,vector('partial_manifest'),1n,vector('renewed_permission'),ownerContext(1200n));
});
for(const v of fixture.unrelated_permissions)test(`correctly signed ${v.format} cannot delegate import`,async()=>{assertCrypto(bytes(v.public_key_hex),bytes(v.signing_input_hex),bytes(v.signature_hex));if(v.wire_hex){const record=fromBinary(api.SignedOwnerCapabilitySchema,bytes(v.wire_hex));assert.deepEqual(record.signature.signature,bytes(v.signature_hex));assert.equal(record.capability.formatVersion,v.format==='PURGE-v1'?1:3);}const evidence=v.wire_hex?{kind:'owner_capability',record:fromBinary(api.SignedOwnerCapabilitySchema,bytes(v.wire_hex))}:{kind:'online_role',role:'Developer'};assert.throws(()=>authority.selectImportPermission(evidence),expected('ImportPermission'));const parent=authority.selectImportPermission({kind:'import',record:vector('permission')});await authority.verifyImportDelegation(vector('delegation'),parent,ownerContext());});
for(const tree of fixture.trees)test(`static Merkle tree ${tree.count}: exact root and every path`,()=>{
  const leaves=tree.leaves_hex.map(bytes);assert.deepEqual(witness.merkleRoot(leaves),bytes(tree.root_hex));const entry=create(common.HostedWitnessEntryV1Schema,{executorId:new Uint8Array(32).fill(1),state:2,archiveRoot:bytes(tree.root_hex),archiveLeafCount:BigInt(tree.count)});
  for(const p of tree.paths){const proof=create(common.HostedWitnessHistoryProofV1Schema,{executorId:entry.executorId,purpose:3,leafIndex:BigInt(p.index),leafCount:BigInt(tree.count),siblings:p.siblings_hex.map(bytes)});witness.verifyWitnessInclusion(leaves[p.index],proof,entry);const extra=structuredClone(proof);extra.siblings.push(new Uint8Array(32));assert.throws(()=>witness.verifyWitnessInclusion(leaves[p.index],extra,entry),expected('Proof'));}
});
test('concurrent signed renewals serialize and fence the paused old worker',async()=>{
  const scenario=fixture.retry_scenarios[0],previous=await authority.verifyImportDelegation(vector('delegation'),vector('permission'),ownerContext()),committed=vector(scenario.committed_manifest);let epoch=BigInt(scenario.initial_epoch),next;
  for(const event of scenario.events){if(event.action==='activate_renewal'){if(event.result==='OK'){next=await authority.verifyImportRenewal(vector(event.certificate),previous,committed,epoch,vector('renewed_permission'),ownerContext(1200n));epoch++;}else await assert.rejects(authority.verifyImportRenewal(vector(event.certificate),previous,committed,epoch,vector('renewed_permission'),ownerContext(1200n)),expected(event.result));}else if(BigInt(event.expected_epoch)!==epoch){assert.equal(event.result,'StaleContext');const stale=vector(event.operation);await authority.verifyNewImportOperation(stale,previous,1250n);assert.throws(()=>authority.checkImportJobFence(stale.body.logicalJobId,stale.body.delegationDigest,BigInt(event.expected_epoch),next,epoch),expected('StaleContext'));assert.equal(authority.checkImportSlotReplay(committed,vector(event.operation)),false);}else{const active=vector(event.operation);authority.checkImportJobFence(active.body.logicalJobId,active.body.delegationDigest,BigInt(event.expected_epoch),next,epoch);await authority.verifyNewImportOperation(vector(event.operation),next,1250n);assert.equal(authority.checkImportSlotReplay(vector(scenario.final_manifest),vector(event.operation)),true);}assert.equal(epoch,BigInt(event.epoch_after));}
  assert.equal(vector(scenario.final_manifest).slots.length,scenario.committed_slot_count);
  const completed=vector('completed_slot_manifest');await assert.rejects(authority.verifyImportRenewal(vector('completed_slot_renewal'),previous,completed,1n,vector('renewed_permission'),ownerContext(1200n)),expected('CommittedSlot'));
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

for(const [name,v] of Object.entries(fixture.commitment_vectors))test(`frozen payload/commitment preimage: ${name}`,()=>{const schema=schemaFor(v.schema),value=authority.strictDecode(schema,bytes(v.wire_hex));assert.deepEqual(authority.canonicalHybridV1(schema,value),bytes(v.canonical_hex));assert.deepEqual(Buffer.concat([Buffer.from(v.domain),Buffer.from(authority.canonicalHybridV1(schema,value))]),Buffer.from(bytes(v.preimage_hex)));assert.deepEqual(authority.signingDigest(v.domain,schema,value),bytes(v.digest_hex));if(schema===api.ImportFrontierV1Schema)assert.deepEqual(authority.frontierDigest(value),bytes(v.digest_hex));if(schema===api.ImportContentV1Schema)assert.deepEqual(authority.contentDigest(value),bytes(v.digest_hex));});

test('all witness purposes match actual original records and signature dependencies',async()=>{
  const set=await witness.verifyWitnessSet(vector('current_set'),setContext());
  for(const [statement,payload,kind] of [['genesis_admission','genesis_payload','genesis'],['authority_admission','authority_admission_payload','authority'],['ownership_admission','ownership_admission_payload','authority'],['resolution_admission','resolution_admission_payload','authority'],['landing_statement','landing_payload','landing']]){
    const s=vector(statement);await witness.resolveWitnessStatement(set,s,undefined,false,1100000n);await authority.verifyWitnessPayload(s.body,{kind,payload:vector(payload)});
    const changed=vector(payload);if(kind==='genesis')changed.originalGenesis.signatures[0].signature=s.signature;else if(kind==='authority')changed.original.signatures[0].signature=s.signature;else changed.request.signature.signature=s.signature;
    await assert.rejects(authority.verifyWitnessPayload(s.body,{kind,payload:changed}),expected('Signature'));
  }
  const signed=vector('witness_without_owner');await witness.resolveWitnessStatement(set,signed,undefined,false,1100000n);
  await assert.rejects(authority.verifyWitnessPayload(signed.body,{kind:'authority',payload:vector('missing_owner_payload')}),expected('Signature'));
  const d=await authority.verifyImportDelegation(vector('delegation'),vector('permission'),ownerContext());
  await assert.rejects(authority.verifyDelegatedImportOperation(vector('witness_without_job'),d),expected('Signature'));
});

test('fresh receiver verifies complete renewed export with replaced expired permission and both original manifests',async()=>{
  const b=vector('complete_renewed_export');authority.validatePublicBundle(b);
  const owner=exportOwnerContext(b),set=await witness.verifyWitnessSet(b.witnessSet,{...setContext(1350000n),knownJobKeys:b.delegations.map(d=>d.body.jobPublicKey)});
  const authenticatedTime=async(name,proofName)=>{const signed=vector(name);assert.ok(b.statements.some(s=>Buffer.from(toBinary(common.SignedHostedWitnessStatementV1Schema,s)).equals(Buffer.from(toBinary(common.SignedHostedWitnessStatementV1Schema,signed)))));await witness.resolveWitnessStatement(set,signed,vector(proofName),false,1350000n);const receipt=signed.body;const policy=b.policies.find(p=>p.body.sequence===receipt.policySequence&&Buffer.from(p.body.policyStateHash).equals(Buffer.from(receipt.policyStateHash)));assert.ok(policy);assert.deepEqual(policy.body.spoolUuid,receipt.spoolUuid);assert.deepEqual(policy.body.ownerId,receipt.ownerId);assert.deepEqual(policy.body.ownerStateHash,receipt.ownerStateHash);const key=b.ownerHistories[0].root.root.authorityKey.publicKey;assert.deepEqual(policy.ownerSignature.signerKeyId,keyId(key));assertCrypto(key,bytes(fixture.policy.signature_input_hex),policy.ownerSignature.signature);return receipt.observedAtUnixMillis/1000n;};
  const publicationTime=await authenticatedTime('publication_statement','publication_proof'),renewedTime=await authenticatedTime('renewed_publication_statement','renewed_publication_proof');
  const d0=b.delegations[0],d1=b.delegations[1],p0=authority.resolveBundlePermission(b,d0.body.parentPermissionDigest),p1=authority.resolveBundlePermission(b,d1.body.parentPermissionDigest);
  assert.notDeepEqual(authority.signedPermissionDigest(p0),authority.signedPermissionDigest(p1));await assert.rejects(authority.verifyImportMemberPermission(p0,owner(1350n)),expected('Expired'));
  const old=await authority.verifyImportDelegation(d0,p0,owner(publicationTime));
  for(const g of b.genesisAuthorities){const payload=b.genesisWitnesses.find(p=>Buffer.from(authority.signedGenesisDigest(p.binding)).equals(Buffer.from(authority.signedGenesisDigest(g))));assert.ok(payload);const main=Buffer.from(authority.signedGenesisDigest(g)).equals(Buffer.from(authority.signedGenesisDigest(vector('genesis_main'))));const name=main?'genesis_admission':'genesis_dev_admission',proof=main?'genesis_proof':'genesis_dev_proof',admissionTime=await authenticatedTime(name,proof);await authority.verifyWitnessPayload(vector(name).body,{kind:'genesis',payload});const atAdmission=await authority.verifyImportDelegation(d0,p0,owner(admissionTime));const original=b.originalGeneses.find(o=>Buffer.from(api.threadGenesisId(o.canonicalRecord)).equals(Buffer.from(g.body.genesisDigest)));assert.ok(original);assert.equal(original.format,'heddle-thread-genesis-v1');const signature=original.signatures.find(s=>Buffer.from(s.publicKey).equals(Buffer.from(g.body.creatorPublicKey)));assert.ok(signature);assertCrypto(signature.publicKey,join(utf8.encode(original.format+'\0'),original.canonicalRecord),signature.signature);const envelope=b.creatorAuthorityEnvelopes.find(e=>Buffer.from(hash(e)).equals(Buffer.from(g.body.creatorAuthorityEnvelopeDigest)));assert.ok(envelope);await authority.verifyImportGenesisAuthority(g,atAdmission,api.threadGenesisId(original.canonicalRecord),signature.signature,hash(envelope));}
  const renewal=b.renewals[0],committed=authority.resolveBundleManifest(b,renewal.body.committedManifestDigest);const next=await authority.verifyImportRenewal(renewal,old,committed,1n,p1,owner(renewedTime));
  for(const op of b.operations){const d=Buffer.from(op.body.delegationDigest).equals(Buffer.from(old.digest))?old:next;
    const match=b.manifests.flatMap(m=>b.statements.filter(s=>s.body.purpose===3&&Buffer.from(s.body.canonicalPayload).equals(Buffer.from(authority.canonicalHybridV1(api.ImportPublicationWitnessV1Schema,authority.publicationPayload(op,m))))).map(s=>({m,s})))[0];assert.ok(match);
    const leaf=witness.leafDigest(3,authority.canonicalHybridV1(common.HostedWitnessStatementV1Schema,match.s.body),match.s.signature),proof=fromBinary(common.HostedWitnessHistoryProofV1Schema,bytes(fixture.wire_vectors[Buffer.from(op.body.delegationDigest).equals(Buffer.from(old.digest))?'publication_proof':'renewed_publication_proof'].wire_hex));
    assert.ok(leaf.length===32);await authority.verifyImportPublication(op,d,match.m,match.s,set,proof,1350000n);
  }
  for(const key of ['memberPermissions','manifests']){const missing=vector('complete_renewed_export');missing[key].shift();assert.throws(()=>authority.validatePublicBundle(missing),expected(key==='memberPermissions'?'ImportPermission':'StaleManifest'));const duplicate=vector('complete_renewed_export');duplicate[key].push(duplicate[key][0]);assert.throws(()=>authority.validatePublicBundle(duplicate),expected('Canonical'));}
});

test('historical export rejects zero policies and removal of each branch admission original',()=>{
  const b=vector('complete_renewed_export');authority.validatePublicBundle(b);
  const zero=vector('complete_renewed_export');zero.policies=[];assert.throws(()=>authority.validatePublicBundle(zero),expected('Scope'));console.log('B REJECT zero-policy export: Scope');
  const duplicate=vector('complete_renewed_export');duplicate.policies.push(duplicate.policies[0]);assert.throws(()=>authority.validatePublicBundle(duplicate),expected('Canonical'));
  // Reference-only chain; native gate separately rejects signature/preimage mutations.
  const chain=vector('complete_renewed_export'),second=fromBinary(api.SignedSpoolPolicyRecordSchema,toBinary(api.SignedSpoolPolicyRecordSchema,chain.policies[0]));second.body.expectedHead=create(api.SignedPolicyHeadSchema,{stateHash:second.body.policyStateHash,sequence:1n});second.body.sequence=2n;second.body.policyStateHash=new Uint8Array(32).fill(0x7b);chain.policies.push(second);for(const receipt of chain.statements){receipt.body.policySequence=2n;receipt.body.policyStateHash=second.body.policyStateHash;}authority.validatePublicBundle(chain);chain.policies.shift();assert.throws(()=>authority.validatePublicBundle(chain),expected('Scope'));
  for(let i=0;i<b.genesisWitnesses.length;i++)for(const part of ['admission','payload','genesis','envelope']){
    const missing=vector('complete_renewed_export'),payload=b.genesisWitnesses[i];
    if(part==='admission')missing.statements=missing.statements.filter(s=>!Buffer.from(s.body.canonicalPayload).equals(Buffer.from(authority.canonicalHybridV1(api.ImportGenesisWitnessV1Schema,payload))));
    if(part==='payload')missing.genesisWitnesses.splice(i,1);
    if(part==='genesis')missing.originalGeneses=missing.originalGeneses.filter(g=>!Buffer.from(authority.signedNativeDigest(g)).equals(Buffer.from(authority.signedNativeDigest(payload.originalGenesis))));
    if(part==='envelope')missing.creatorAuthorityEnvelopes=missing.creatorAuthorityEnvelopes.filter(e=>!Buffer.from(e).equals(Buffer.from(payload.creatorAuthorityEnvelope)));
    assert.throws(()=>authority.validatePublicBundle(missing),expected('Scope'));console.log(`B REJECT missing branch ${i} genesis ${part}: Scope`);
  }
});

test('renewal prepare wire response supplies exact signed CAS state',()=>{const r=vector('renewal_preparation');authority.validateRenewalPreparation(r);const renewal=vector('renewal').body;assert.equal(r.renewalState.authorityEpoch,renewal.expectedAuthorityEpoch);assert.deepEqual(authority.manifestDigest(r.renewalState.committedManifest),renewal.committedManifestDigest);assert.deepEqual(authority.signedDelegationDigest(r.renewalState.activePredecessor),renewal.predecessorDelegationDigest);r.renewalState.logicalJobId=new Uint8Array(16);assert.throws(()=>authority.validateRenewalPreparation(r),expected('StaleContext'));});

test('publication wins without changing authority epoch: first failing check is manifest CAS',async()=>{const s=fixture.retry_scenarios[2],old=await authority.verifyImportDelegation(vector('delegation'),vector('permission'),ownerContext()),r=vector(s.renewal),member=vector('renewed_permission');await authority.verifyNewImportOperation(vector(s.publication),old,BigInt(s.now_seconds));await authority.verifyImportRenewal(r,old,vector(s.before_manifest),1n,member,ownerContext(1250n));assert.equal(authority.checkImportSlotReplay(vector(s.after_manifest),vector(s.publication)),true);await assert.rejects(authority.verifyImportRenewal(r,old,vector(s.after_manifest),1n,member,ownerContext(1250n)),expected('StaleManifest'));});

test('genuine legacy HostedImport signature cannot enter hybrid import dispatch',()=>{const original=vector('legacy_hosted_import');for(const signature of original.signatures)assertCrypto(signature.publicKey,Buffer.concat([Buffer.from(original.format+'\0'),Buffer.from(original.canonicalRecord)]),signature.signature);assert.throws(()=>authority.requireImportOperationFormat(original.format),expected('Protocol'));authority.requireImportOperationFormat(authority.OPERATION_DOMAIN);});

test('root ID multibyte shared vectors enforce 256 UTF-8 bytes',async()=>{const good=vector('root_id_boundary'),bad=vector('root_id_over_boundary');assert.equal(Buffer.byteLength(good.body.descriptorRootId),256);assert.equal(Buffer.byteLength(bad.body.descriptorRootId),258);await witness.verifyWitnessSet(good,{...setContext(),rootId:good.body.descriptorRootId});await assert.rejects(witness.verifyWitnessSet(bad,{...setContext(),rootId:bad.body.descriptorRootId}),expected('Bounds'));});

test('negotiated native client validates mandatory openings and ready responses',async()=>{const protocol=create(common.ProtocolCompatibilitySchema,{protocolVersion:2,mandatoryFeatures:[1]}),path='/heddle.api.v1alpha2.SyncService/ReplicateThread';let calls=0;const transport={open:async function*(_method,requests){calls++;for await(const _ of requests){}yield toBinary(api.ReplicateThreadResponseSchema,create(api.ReplicateThreadResponseSchema,{body:{case:'ready',value:{}}}));}};const client=createServiceClient(api.SyncService,transport,new Set([path]),protocol);await assert.rejects(async()=>{for await(const _ of client.replicateThread((async function*(){yield {body:{case:'open',value:{protocol}}};})())){}},expected('Protocol'));assert.equal(calls,1);});
for(const [name,v] of Object.entries(fixture.raw_commitment_vectors))test(`frozen raw commitment: ${name}`,async()=>{const preimage=Buffer.concat([Buffer.from(v.domain),Buffer.from(bytes(v.canonical_hex))]);assert.deepEqual(preimage,Buffer.from(bytes(v.preimage_hex)));assert.deepEqual(new Uint8Array((await import('@noble/hashes/sha2.js')).sha256(preimage)),bytes(v.digest_hex));});
