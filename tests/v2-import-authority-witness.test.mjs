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
test('submission observe requires signed disclosure',()=>{
 const scope=vector('scope');authority.validateImportScope(scope);
 scope.branches[0].refMode=2;scope.branches[0].pinnedCommitOid=new Uint8Array();
 assert.throws(()=>authority.validateImportScope(scope), 'observe mode must carry the signed disclosure');
});
for(const v of fixture.submission_vectors.changed_preparations)test(`submission Prepare REJECT then PASS: ${v.id}`,()=>{
 const request=vector('prepare_request');
 assert.throws(()=>authority.validateImportPreparationResponse(request,vector(v.response)),expected(v.expected));
 authority.validateImportPreparationResponse(request,vector(v.control));
});
for(const v of fixture.submission_vectors.commit_negatives)test(`submission Commit REJECT then PASS: ${v.id}`,async()=>{
 await assert.rejects(authority.validateImportCommitRequest(vector(v.request),vector(v.request).source?.connection?'github':'public-git', vector(vector(v.request).source?.connection?'source_connected':'source_public_github'), vector('import_configuration')),expected(v.expected));
 await authority.validateImportCommitRequest(vector(v.control),vector(v.control).source?.connection?'github':'public-git', vector(vector(v.control).source?.connection?'source_connected':'source_public_github'), vector('import_configuration'));
});
for(const v of fixture.submission_vectors.scope_refusals)test(`submission typed refusal REJECT then PASS: ${v.id}`,()=>{
 const scope=vector('scope'),configuration=vector(v.configuration);
 const refusal=e=>expected('PreparationRefused')(e)&&e.preparationRefusalReason===v.reason;
 assert.throws(()=>authority.prepareImportScope(vector(v.scope),configuration,scope.destinationVersion),refusal);
 assert.throws(()=>authority.validateImportPreparationResponse(vector('prepare_request'),vector(`prepare_refusal_${v.id}`)),refusal);
 assert.deepEqual(authority.prepareImportScope(scope,configuration,scope.destinationVersion),scope);
});
test('submission CAS issuance preserves all choices and leaves the request untouched',()=>{
 const request=vector('prepare_issue_token'),scope=vector('scope');
 authority.validateImportPreparationResponse(request,vector('commit_preparation'));
 assert.deepEqual(authority.prepareImportScope(request.proposedScope,vector('import_configuration'),scope.destinationVersion),scope);
 assert.equal(request.proposedScope.destinationVersion.length,0);
 const refused=vector('prepare_refusal_converter');refused.refusal.reason=99;
 assert.throws(()=>authority.validateImportPreparationResponse(vector('prepare_request'),refused),expected('Version'));
});
test('submission ImportSource misuse REJECT then PASS with Commit',async()=>{
 assert.throws(()=>authority.validateImportSource(vector('import_source_misuse')),expected('ImportSourceRequiresCommit'));
 await authority.validateImportCommitRequest(vector('commit_request'),'github', vector('source_connected'), vector('import_configuration'));
});
test('submission Commit pending operation and immutable replay',async()=>{
 const request=vector('commit_request'),response=vector('commit_response');
 await authority.verifyImportCommitSubmission(request,vector('commit_preparation'),'github', vector('source_connected'), vector('import_configuration'),ownerContext());
 authority.checkImportCommitReplay(request,vector('commit_request'),response);
 const changed=vector('commit_request');changed.initialBaseState=new Uint8Array();
 assert.throws(()=>authority.checkImportCommitReplay(changed,request,response),expected('OperationIdReused'));
 response.receipt.outcome={case:'applied',value:create(api.AppliedSchema)};
 assert.throws(()=>authority.validateImportCommitResponse(request,response),expected('PendingOperation'));
 await assert.rejects(authority.validateImportCommitRequest(request,'gitlab', vector('source_connected'), vector('import_configuration')),expected('SourceSelection'));
 for(const name of ['commit_hosted_base','commit_public_source'])await authority.validateImportCommitRequest(vector(name),name==='commit_public_source'?'public-git':'github', vector(name==='commit_public_source'?'source_public_github':'source_connected'), vector('import_configuration'));
});
test('submission signed observe disclosure REJECT then PASS; known OID always pinned',async()=>{
 const pinned=vector('scope').branches[0],observe=vector('scope_observe_disclosed').branches[0];
 assert.throws(()=>authority.validateImportScope(vector('scope_observe_undisclosed')),expected('RefDisclosure'));
 authority.validateImportScope(vector('scope_observe_disclosed'));
 authority.validateImportRefSelection(pinned,pinned.pinnedCommitOid);
 assert.throws(()=>authority.validateImportRefSelection(observe,pinned.pinnedCommitOid),expected('RefPinning'));
 authority.validateImportRefSelection(observe);
 const parent=undefined,geneses=[0,1].map(n=>vector(`direct_genesis_${n}`));
 await assert.rejects(authority.verifyPreparedImportDelegation(vector('submission_observe_undisclosed_preparation'),vector('submission_observe_undisclosed_delegation'),parent,geneses,ownerContext()),expected('RefDisclosure'));
 await authority.verifyPreparedImportDelegation(vector('submission_observe_preparation'),vector('submission_observe_delegation'),parent,geneses,ownerContext());
});
test('submission configuration defaults carry their exact encoding and authenticated RPC',()=>{
 const config=vector('import_configuration'),c=config.converters[0];
 authority.validateImportConfiguration(config);
 assert.equal(c.optionsEncoding,'heddle-import-options-empty-v1');
 assert.deepEqual(authority.conversionOptionsDigest(c.converterVersion,c.defaultOptions),vector('scope').optionsDigest);
 c.defaultOptions=Uint8Array.of(1);assert.throws(()=>authority.validateImportConfiguration(config),expected('Canonical'));
 const contract=getOption(api.IntegrationService.method.getImportConfiguration,common.rpc_contract);
 assert.equal(contract.effect,common.RpcEffect.READ_ONLY);
 assert.equal(contract.authorizationAccess,common.AuthorizationAccess.AUTHENTICATED_PRINCIPAL);
 assert.equal(contract.signingTier,common.SigningTier.PROOF_OF_POSSESSION);
});
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
  const expected = ['CancelImportJob', 'CommitImportJob', 'GetHostedWitnessHistoryProof', 'GetImportJobState', 'ImportSource',
    'PrepareImportJob', 'RenewImportJob', 'RetryImportSource', 'SynchronizeRemote']
    .map(name => `/heddle.api.v1alpha2.IntegrationService/${name}`);
  const actual = Object.values(api).filter(value => value?.kind === "service").flatMap(service => service.methods)
    .filter(method => getOption(method, common.rpc_contract).mandatoryFeatures.length)
    .map(method => `/${method.parent.typeName}/${method.name}`).sort();
  assert.deepEqual(actual, expected);
  assert.deepEqual(fixture.protocol.gated_methods, expected);
  for (const method of api.IntegrationService.methods.filter(method => expected.includes(`/${method.parent.typeName}/${method.name}`)))
    assert.deepEqual(getOption(method, common.rpc_contract).mandatoryFeatures, [1]);
  for (const method of [api.SyncService.method.fetch, api.SyncService.method.publishContent, api.SyncService.method.replicateThread])
    assert.deepEqual(getOption(method, common.rpc_contract).mandatoryFeatures, []);
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
  if(v.type==='renewal')await assert.rejects(authority.verifyImportRenewal(authority.strictDecode(api.SignedImportJobRenewalV1Schema,bytes(v.wire_hex)),d,vector('partial_manifest'),1n,v.member===false?undefined:vector(v.parent??'renewed_permission'),ownerContext(BigInt(v.now_seconds))),expected(v.expected));
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
test('mandatory import protocol/version gate blocks every incompatible client before transport', async () => {
  let calls = 0;
  const transport = { unary: async () => { calls++; return new Uint8Array(); } };
  const methods = ['importSource', 'retryImportSource', 'synchronizeRemote', 'prepareImportJob',
    'commitImportJob', 'renewImportJob', 'cancelImportJob', 'getHostedWitnessHistoryProof'];
  const implemented = new Set(methods.map(name => `/heddle.api.v1alpha2.IntegrationService/${api.IntegrationService.method[name].name}`));
  for (const protocol of [undefined,
    create(common.ProtocolCompatibilitySchema, { protocolVersion: 1, mandatoryFeatures: [1] }),
    create(common.ProtocolCompatibilitySchema, { protocolVersion: 2 }),
    create(common.ProtocolCompatibilitySchema, { protocolVersion: 2, mandatoryFeatures: [1, 2] }),
  ]) {
    assert.throws(() => authority.requireHybridPeer(protocol), expected('Protocol'));
    const client = createServiceClient(api.IntegrationService, transport, implemented, protocol);
    for (const name of methods) await assert.rejects(client[name]({ clientOperationId: 'test' }), expected('Protocol'));
  }
  assert.equal(calls, 0);
  authority.requireHybridPeer(create(common.ProtocolCompatibilitySchema, { protocolVersion: 2, mandatoryFeatures: [1] }));
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


for(const [name,v] of Object.entries(fixture.raw_commitment_vectors))test(`frozen raw commitment: ${name}`,async()=>{const preimage=Buffer.concat([Buffer.from(v.domain),Buffer.from(bytes(v.canonical_hex))]);assert.deepEqual(preimage,Buffer.from(bytes(v.preimage_hex)));assert.deepEqual(new Uint8Array((await import('@noble/hashes/sha2.js')).sha256(preimage)),bytes(v.digest_hex));});

test('boundary passing genesis and dependency vectors',async()=>{
  const set=await witness.verifyWitnessSet(vector('current_set'),setContext());
  // Native semantic negatives have valid shared commitments and signatures.
  for(const v of [...fixture.boundary_vectors.passing,...fixture.boundary_vectors.native_negative]){const s=vector(v.statement);await witness.resolveWitnessStatement(set,s,undefined,false,1100000n);await authority.verifyWitnessPayload(s.body,{kind:v.kind,payload:vector(v.payload)});}
});
for(const v of fixture.boundary_vectors.negative)test('boundary '+v.name,async()=>{
  const set=await witness.verifyWitnessSet(vector('current_set'),setContext()),s=vector(v.statement);
  assertCrypto(bytes(fixture.keys.witness.public_key_hex),witness.statementSigningDigest(s.body),s.signature);
  if(v.name==='missing_binding')await assert.rejects(witness.resolveWitnessStatement(set,s,undefined,false,1100000n),expected(v.expected));
  else await witness.resolveWitnessStatement(set,s,undefined,false,1100000n);
  await assert.rejects(authority.verifyWitnessPayload(s.body,{kind:'genesis',payload:vector(v.payload)}),expected(v.expected));
  console.log(`BOUNDARY REJECT ${v.name}: ${v.expected}`);
  const good=vector(v.control_statement);await witness.resolveWitnessStatement(set,good,undefined,false,1100000n);await authority.verifyWitnessPayload(good.body,{kind:'genesis',payload:vector(v.control_payload)});
  console.log(`BOUNDARY PASS ${v.name}: exact control`);
});
test('boundary dependency requires exact evidence',async()=>{
  const bad=vector('boundary_dependency_missing_statement');await assert.rejects(authority.verifyWitnessPayload(bad.body,{kind:'authority',payload:vector('boundary_dependency_missing_payload')}),expected('BoundaryAcceptance'));
  console.log('BOUNDARY REJECT dependency_missing_binding: BoundaryAcceptance');
  await authority.verifyWitnessPayload(vector('boundary_authority_statement').body,{kind:'authority',payload:vector('boundary_authority_payload')});
  console.log('BOUNDARY PASS dependency_missing_binding: exact control');
});

// Per-case inputs keep downstream parent/genesis and time checks independent.
function commitInputs(v,control=false){
 const pick=(field,fallback)=>v[control?`control_${field}`:field]??(control?v[field]:undefined)??fallback;
 const parentName=control?(v.control_parent??v.parent??'permission'):(v.parent===null?null:pick('parent','permission'));
 return {prepared:vector(pick('preparation','commit_preparation')),signed:vector(control?v.control:v.delegation),parent:parentName===null?undefined:vector(parentName),geneses:pick('geneses',['genesis_dev','genesis_main']).map(vector),context:{...ownerContext(BigInt(pick('now_seconds',1100))),authorityExpiresAtSeconds:BigInt(pick('authority_expires_at_seconds',2000))}};
}
function assertCommitIsolation(v,input){
 const d=input.signed.body,p=input.parent?.body,now=input.context.nowUnixSeconds;
 if(['parent_amplification','parent_ref'].includes(v.id)){
  for(const [i,g] of input.geneses.entries()){
   assert.deepEqual(g.body.parentPermissionDigest,d.parentPermissionDigest,`${v.id}: genesis must bind the child's parent`);
   assert.deepEqual(authority.signedGenesisDigest(g),d.branchManifest[i].genesisAuthorityDigest);
  }
 }
 if(['window_duration','window_too_early'].includes(v.id)){
  assert.ok(d.notBeforeUnixSeconds>=p.notBeforeUnixSeconds,`${v.id}: parent must contain child start`);
  assert.ok(d.expiresAtUnixSeconds<=p.expiresAtUnixSeconds,`${v.id}: parent must contain child end`);
 }
 if(v.id==='window_empty')assert.ok(d.expiresAtUnixSeconds>now,'reversed window must not also violate E>T');
 if(v.id==='reservation_expired'){
  assert.equal(now,input.prepared.reservationExpiresAtUnixSeconds);
  assert.ok(d.notBeforeUnixSeconds<=now-1n&&d.expiresAtUnixSeconds>now&&p.expiresAtUnixSeconds>now,'reservation must expire during otherwise valid authority');
  const control=commitInputs(v,true);assert.equal(control.context.nowUnixSeconds,now-1n);assert.deepEqual(control.signed,input.signed);
 }
}
for(const v of fixture.commit_vectors.negative)test(`Commit REJECT then PASS: ${v.id}; ${v.first_failing_check}`,async()=>{
 const input=commitInputs(v);assertCommitIsolation(v,input);
 await assert.rejects(authority.verifyPreparedImportDelegation(input.prepared,input.signed,input.parent,input.geneses,input.context),expected(v.expected));
 console.log(`COMMIT REJECT ${v.id}: ${v.expected} (${v.first_failing_check})`);
 const control=commitInputs(v,true);
 await authority.verifyPreparedImportDelegation(control.prepared,control.signed,control.parent,control.geneses,control.context);
 console.log(`COMMIT PASS ${v.id} control at ${control.context.nowUnixSeconds}`);
});
for(const name of fixture.commit_vectors.passing)test(`browser-completed Commit: ${name}`,async()=>{
 const d=await authority.verifyPreparedImportDelegation(vector('commit_preparation'),vector(name),vector('permission'),[vector('genesis_dev'),vector('genesis_main')],ownerContext());
 if(name==='commit_future_within_skew'){
  const operation=vector('commit_future_operation');
  await assert.rejects(authority.verifyNewImportOperation(operation,d,1199n),expected('Expired'));
  await authority.verifyNewImportOperation(operation,d,1200n);
  console.log('COMMIT FUTURE OPERATION: 1199 Expired; 1200 PASS');
 }
});

test('P2 isolated private-source gate: public control differs only by private',async()=>{
 const good=vector('commit_public_source'),bad=vector('submission_private_without_connection');
 bad.source.private=false;assert.deepEqual(bad,good);bad.source.private=true;
 await authority.validateImportCommitRequest(good,'public-git', vector('source_public_github'), vector('import_configuration'));console.log('P2 PRIVATE CONTROL PASS');
 await assert.rejects(authority.validateImportCommitRequest(bad,'public-git', vector('source_public_github'), vector('import_configuration')),expected('SourceSelection'));
 console.log('P2 PRIVATE NEGATIVE SourceSelection');
});
test('P2 isolated signed direct-owner disclosure gate',async()=>{
 const good=vector('submission_observe_request'),bad=vector('submission_observe_undisclosed_request');
 const gd=good.proof.delegations[0].body,bd=bad.proof.delegations[0].body;
 bd.scope.branches[0].refDisclosure=1;bd.branchManifest[0].limit.refDisclosure=1;assert.deepEqual(bd,gd);
 assert.deepEqual(bad.proof.originalGeneses,good.proof.originalGeneses);assert.deepEqual(bad.proof.genesisAuthorities,good.proof.genesisAuthorities);
 await authority.verifyImportCommitSubmission(good,vector('submission_observe_preparation'),'github', vector('source_connected'), vector('import_configuration'),ownerContext());console.log('P2 DISCLOSURE CONTROL PASS');
 await assert.rejects(authority.verifyImportCommitSubmission(vector('submission_observe_undisclosed_request'),vector('submission_observe_undisclosed_preparation'),'github', vector('source_connected'), vector('import_configuration'),ownerContext()),expected('RefDisclosure'));
 console.log('P2 DISCLOSURE NEGATIVE RefDisclosure');
});
for(const v of fixture.amendment_vectors.permission_negatives)test(`remaining renewal parent: ${v.id}`,async()=>{
 const old=await authority.verifyImportDelegation(vector('delegation'),vector('permission'),ownerContext());
 await assert.rejects(authority.verifyImportRenewal(vector(v.renewal),old,vector('partial_manifest'),1n,vector(v.parent),ownerContext(1200n)),expected(v.expected));
 await authority.verifyImportRenewal(vector('renewal'),old,vector('partial_manifest'),1n,vector('renewed_permission'),ownerContext(1200n));
});
test('renewed permission retains cancellation lineage, fresh nonce and exact replay',async()=>{
 const old=vector('permission'),next=vector('renewed_permission'),d=vector('renewed_delegation');
 assert.deepEqual(next.body.cancellationId,old.body.cancellationId);assert.notDeepEqual(next.body.nonce,old.body.nonce);
 assert.deepEqual(next.body.scope, d.body.scope);assert.equal(next.body.scope.branches.length,1);
 await authority.verifyImportMemberPermission(next,ownerContext(1350n));await authority.verifyImportMemberPermission(vector('renewed_permission'),ownerContext(1350n));
 assert.deepEqual(toBinary(api.SignedImportMemberPermissionV1Schema,next),bytes(fixture.signed_vectors.renewed_permission.wire_hex));
 const sameParent=await authority.verifyImportDelegation(d,next,ownerContext(1350n));
 await authority.verifyImportRenewal(vector('reused_parent_renewal'),sameParent,vector('partial_manifest'),2n,next,ownerContext(1350n));
 authority.checkImportRevocations(d,next,[]);
 for(const id of [old.body.cancellationId,d.body.cancellationId])assert.throws(()=>authority.checkImportRevocations(d,next,[id]),expected('Revoked'));
});
for(const v of fixture.amendment_vectors.cancel_negatives)test(`active Cancel selector: ${v.id}`,()=>{
 assert.throws(()=>authority.checkImportCancelRequest(vector(v.request),vector(v.active),BigInt(v.epoch),v.cancelled),expected(v.expected));
 authority.checkImportCancelRequest(vector('cancel_active'),vector('delegation'),1n,false);
});
test('Cancel exact replay precedes terminal and epoch checks; changed replay refuses',()=>{
 authority.checkImportCancelReplay(vector('cancel_active'),vector('cancel_active'));
 assert.throws(()=>authority.checkImportCancelReplay(vector('cancel_changed_replay'),vector('cancel_active')),expected('OperationIdReused'));
});
for(const v of fixture.amendment_vectors.recovery)test(`non-executable expired predecessor: ${v.id}`,async()=>{
 const state=vector(v.state),e=ownerContext(BigInt(v.now));assert.ok(state.activePredecessor.body.expiresAtUnixSeconds<=e.nowUnixSeconds);
 await assert.rejects(authority.verifyImportDelegation(state.activePredecessor,vector('permission'),e),expected('Expired'));
 const token=await authority.verifyImportRenewalPredecessor(state,vector('permission'),e);
 await assert.rejects(authority.verifyNewImportOperation(vector('operation_main'),token,e.nowUnixSeconds),expected('Canonical'));
 const renewed=await authority.verifyImportRenewalFromState(vector(v.renewal),token,state,vector('renewed_permission'),e);
 assert.deepEqual(renewed.digest,authority.signedDelegationDigest(vector('renewed_delegation')));
 for(const mutate of [s=>s.authorityEpoch++,s=>s.logicalJobId[0]^=1,s=>{if(s.committedManifest.slots.length)s.committedManifest.slots[0].signedOperationDigest[0]^=1;else s.committedManifest.slots.push(vector('partial_manifest').slots[0]);},s=>s.activePredecessor.delegatingSignature.signature[0]^=1]){
  const changed=vector(v.state);mutate(changed);
  await assert.rejects(authority.verifyImportRenewalFromState(vector(v.renewal),token,changed,vector('renewed_permission'),e),expected('StaleContext'));
 }
 const bad=vector(v.state);bad.activePredecessor.delegatingSignature.signature[0]^=1;
 await assert.rejects(authority.verifyImportRenewalPredecessor(bad,vector('permission'),e),expected('Signature'));
 await assert.rejects(authority.verifyImportRenewalFromState(vector(v.renewal),token,state,vector('renewed_permission'),ownerContext(1800n)),expected('Expired'));
 // Mutation after async verification cannot change the bound snapshot.
 state.authorityEpoch++;await assert.rejects(authority.verifyImportRenewalFromState(vector(v.renewal),token,state,vector('renewed_permission'),e),expected('StaleContext'));
});
for(const v of fixture.amendment_vectors.preflight)test(`browser preflight and strict host Commit: ${v.id}`,async()=>{
 const p=vector('commit_preparation'),d=vector('delegation'),member=vector('permission'),g=[vector('genesis_dev'),vector('genesis_main')],e=ownerContext(BigInt(v.now));
 for(const [method,result] of [[authority.preflightPreparedImportDelegation,v.preflight],[authority.verifyPreparedImportDelegation,v.host]]){
  if(result==='OK'){const token=await method(p,d,member,g,e);if(method===authority.preflightPreparedImportDelegation)assert.equal(token,undefined);}
  else await assert.rejects(method(p,d,member,g,e),expected(result));
 }
});
test('browser preflight still checks proposal, signatures, parent and exclusive expiry',async()=>{
 const g=[vector('genesis_dev'),vector('genesis_main')];
 await assert.rejects(authority.preflightPreparedImportDelegation(vector('commit_preparation'),vector('commit_bad_signature'),vector('permission'),g,ownerContext(999n)),expected('Signature'));
 await assert.rejects(authority.preflightPreparedImportDelegation(vector('prepare_changed_converterVersion'),vector('delegation'),vector('permission'),g,ownerContext(999n)),expected('PreparedFields'));
 await assert.rejects(authority.preflightPreparedImportDelegation(vector('commit_preparation'),vector('delegation'),undefined,g,ownerContext(999n)),expected('ImportPermission'));
});
for(const v of fixture.amendment_vectors.lineage)test(`initial lineage allocation: ${v.id}`,()=>{
 if(v.expected==='OK')assert.equal(authority.initialImportOperationId(bytes(v.lineage_hex),v.occupied),v.operation_id);
 else assert.throws(()=>authority.initialImportOperationId(bytes(v.lineage_hex),v.occupied),expected(v.expected));
});
test('Commit receipt must name the reserved first physical operation',()=>{
 authority.validateImportCommitResponse(vector('commit_request'),vector('commit_response'));
 assert.throws(()=>authority.validateImportCommitResponse(vector('commit_request'),vector('commit_wrong_lineage_response')),expected('PendingOperation'));
});

for(const v of fixture.renew_submission_vectors.negative)test(`alpha24 Renew REJECT then PASS: ${v.id}`,()=>{
  const read=vector(v.read),request=vector(v.request);
  if(v.outer_field_bytes)request.clientOperationId='x'.repeat(v.outer_field_bytes);
  if(v.envelope_bytes)request.proof.creatorAuthorityEnvelopes=[new Uint8Array(v.envelope_bytes).fill(1)];
  assert.throws(()=>authority.validateImportRenewRequest(request,read),expected(v.expected));
  authority.validateImportRenewRequest(vector(v.control),read);
});
for(const v of fixture.renew_submission_vectors.read_request_negative)test(`alpha24 Read request REJECT then PASS: ${v.id}`,()=>{
 assert.throws(()=>authority.validateImportJobStateRequest(vector(v.request)),expected(v.expected));
 authority.validateImportJobStateRequest(vector(v.control));
});
for(const v of fixture.renew_submission_vectors.read_negative)test(`alpha24 Read REJECT then PASS: ${v.id}`,()=>{
  const request=vector('job_state_request'),response=vector(v.response);
  if(v.outer_field_bytes)response.state.logicalJobId=new Uint8Array(v.outer_field_bytes).fill(1);
  if(v.envelope_bytes)response.retainedProof.creatorAuthorityEnvelopes=[new Uint8Array(v.envelope_bytes).fill(1)];
  assert.throws(()=>authority.validateImportJobStateResponse(request,response),expected(v.expected));
  authority.validateImportJobStateResponse(request,vector(v.control));
});
for(const v of fixture.renew_submission_vectors.prepare_negative)test(`alpha24 Prepare race REJECT then PASS: ${v.id}`,()=>{
  const request=vector(v.request),response=vector(v.response);
  assert.throws(()=>authority.validateRenewalPreparationFromRead(request,response,vector(v.read)),expected(v.expected));
  authority.validateRenewalPreparationFromRead(request,response,vector(v.control));
});
for(const v of fixture.renew_submission_vectors.passing)test(`alpha24 frozen actual Renew: ${v.id}`,async()=>{
  const request=vector(v.request),read=vector(v.read),original=exportOwnerContext(vector('complete_renewed_export'))(1350n);
  let current=original;
  if(v.rotated){
    const transition=vector('renew_owner_rotation'),digest=hash(utf8.encode('heddle-owner-key-transition-v1'),bytes(fixture.renew_submission_vectors.rotation.canonical_hex));
    assert.deepEqual(digest,bytes(fixture.renew_submission_vectors.rotation.digest_hex));
    assert.deepEqual(transition.transition.previousStateHash,original.identity.ownerStateHash);
    assertCrypto(original.ownerPublicKey,digest,transition.authorizations[0].signature);
    const key=bytes(fixture.keys.rotated_owner.public_key_hex);assertCrypto(key,digest,transition.nextAuthorityKeyProof.signature);
    assert.deepEqual(transition.transition.nextAuthorityKey.publicKey,key);
    assert.deepEqual(vector('renew_rotated_owner_history').acceptedTransitions,[transition]);
    current={...original,identity:vector('renew_rotated_identity'),ownerPublicKey:key,ownerChainDigest:authority.ownerChainDigest(vector('renew_rotated_chain'))};
    await assert.rejects(authority.verifyImportRenewSubmission(request,read,current,current),expected('Root'));
  }
  const token=await authority.verifyImportRenewSubmission(request,read,original,current);
  assert.deepEqual(token.digest,authority.signedDelegationDigest(request.renewal.body.replacement));
  assert.deepEqual(toBinary(api.RenewImportJobRequestSchema,request),bytes(fixture.wire_vectors[v.request].wire_hex));
  const frozen=toBinary(api.RenewImportJobRequestSchema,request);authority.checkImportRenewReplay(frozen,frozen);
  assert.throws(()=>authority.checkImportRenewReplay(join(frozen,Uint8Array.of(0)),frozen),expected('OperationIdReused'));
  await assert.rejects(authority.verifyImportRenewSubmission(request,read,original,{...current,nowUnixSeconds:1800n}),expected('Expired'));
  assert.deepEqual(request.proof.delegations,read.retainedProof.delegations);
  assert.deepEqual(request.proof.renewals,read.retainedProof.renewals);
});
test('alpha24 job-state read is authenticated destination-writer only, bounded and gated',()=>{
 const contract=getOption(api.IntegrationService.method.getImportJobState,common.rpc_contract);
 assert.equal(contract.effect,common.RpcEffect.READ_ONLY);assert.equal(contract.retryBehavior,common.RetryBehavior.SAFE);
 assert.equal(contract.authorizationAccess,common.AuthorizationAccess.AUTHENTICATED_PRINCIPAL);
 assert.equal(contract.authorizationRole,common.AuthorizationRole.RESOURCE_WRITER);
 assert.equal(contract.signingTier,common.SigningTier.PROOF_OF_POSSESSION);
 assert.equal(contract.authorizationExistence,common.AuthorizationExistence.HIDE);
 assert.deepEqual(contract.authorizationRequestTargets,[create(common.AuthorizationRequestTargetSchema,{path:'destination',role:common.AuthorizationRole.RESOURCE_WRITER})]);
 assert.deepEqual(contract.mandatoryFeatures,[1]);
 const empty=vector('job_state_empty');authority.validateImportJobStateResponse(vector('job_state_request'),empty);assert.deepEqual(empty.state.committedManifest.slots,[]);
});

for(const v of fixture.source_vectors.configuration_negative)test(`alpha25 configuration: ${v.id}`,()=>{
 assert.throws(()=>authority.validateImportConfiguration(vector(v.configuration)),expected(v.expected));
 authority.validateImportConfiguration(vector(v.control));console.log(`ALPHA25 REJECT then PASS configuration.${v.id}: ${v.expected}`);
});
for(const v of fixture.source_vectors.resolution)test(`alpha25 resolver: ${v.id}`,()=>{
 if(v.expected){assert.throws(()=>authority.resolveImportProvider(vector(v.source),v.connection_provider),expected(v.expected));authority.resolveImportProvider(vector(v.control),v.control_connection_provider);console.log(`ALPHA25 REJECT then PASS resolver.${v.id}: ${v.expected}`);}
 else assert.equal(authority.resolveImportProvider(vector(v.source),v.connection_provider),v.provider);
});
for(const v of fixture.source_vectors.hash_negative)test(`alpha25 discovery: ${v.id}`,()=>{
 assert.throws(()=>authority.validateRepositoryHashAlgorithm(vector(v.source),v.known),expected(v.expected));
 authority.validateRepositoryHashAlgorithm(vector(v.control),true);console.log(`ALPHA25 REJECT then PASS discovery.${v.id}: ${v.expected}`);
});
for(const v of fixture.source_vectors.scope_negative)test(`alpha25 discovered scope: ${v.id}`,()=>{
 assert.throws(()=>authority.validateDiscoveredImportScope(vector(v.scope),vector(v.source)),expected(v.expected));
 authority.validateDiscoveredImportScope(vector('scope_public_sha256_observe'),vector('source_public_sha256'));console.log(`ALPHA25 REJECT then PASS scope.${v.id}: ${v.expected}`);
});
for(const v of fixture.source_vectors.prepare_negative)test(`alpha25 Prepare source: ${v.id}`,()=>{
 const scope=vector('scope');
 assert.throws(()=>authority.prepareImportSourceScope(vector(v.request),vector('source_public_sha256'),undefined,vector('import_configuration'),scope.destinationVersion),expected(v.expected));
 authority.prepareImportSourceScope(vector('prepare_public_sha256'),vector('source_public_sha256'),undefined,vector('import_configuration'),scope.destinationVersion);console.log(`ALPHA25 REJECT then PASS prepare.${v.id}: ${v.expected}`);
});
test('alpha25 unknown discovery is retryable, optional converter recommendation and SHA256 observe',()=>{
 authority.validateRepositoryHashAlgorithm(vector('source_unknown'),false);
 authority.validateImportConfiguration(vector('configuration_no_default'));
 authority.validateDiscoveredImportScope(vector('scope_public_sha256_observe'),vector('source_public_sha256'));
 const contract=getOption(api.IntegrationService.method.resolveImportSource,common.rpc_contract);
 assert.equal(contract.effect,common.RpcEffect.READ_ONLY);assert.equal(contract.retryBehavior,common.RetryBehavior.SAFE);
 assert.equal(contract.authorizationAccess,common.AuthorizationAccess.AUTHENTICATED_PRINCIPAL);
 assert.equal(contract.authorizationRole,common.AuthorizationRole.CALLER_BOUND);assert.equal(contract.signingTier,common.SigningTier.PROOF_OF_POSSESSION);
});
for(const id of ['operations_budget','result_bytes_budget'])test(`alpha25 remaining parent: ${id}`,async()=>{
 const v=fixture.amendment_vectors.permission_negatives.find(v=>v.id===id);
 const old=await authority.verifyImportDelegation(vector('delegation'),vector('permission'),ownerContext());
 const p=vector(v.parent).body.scope,good=vector('renewed_permission').body.scope;
 assert.deepEqual(p.branches,good.branches);
 if(id==='operations_budget')assert.equal(p.maxResultBytes,good.maxResultBytes);else assert.equal(p.maxOperations,good.maxOperations);
 await assert.rejects(authority.verifyImportRenewal(vector(v.renewal),old,vector('partial_manifest'),1n,vector(v.parent),ownerContext(1200n)),expected('RenewalFork'));
 await authority.verifyImportRenewal(vector('renewal'),old,vector('partial_manifest'),1n,vector('renewed_permission'),ownerContext(1200n));console.log(`ALPHA25 REJECT then PASS remaining_parent.${id}: RenewalFork`);
});
for(const v of fixture.source_vectors.signed_observe)test(`alpha25 signed SHA256 observe: ${v.id}`,async()=>{
 await authority.verifyImportCommitSubmission(vector(v.request),vector(v.preparation),v.provider,vector(v.source),vector('import_configuration'),ownerContext());
 console.log(`ALPHA25 signed SHA256 observe ${v.id}: PASS`);
});
for(const v of fixture.source_vectors.commit_negative)test(`alpha25 Commit source: ${v.id}`,async()=>{
 await assert.rejects(authority.validateImportCommitRequest(vector(v.request),'github',vector(v.source),vector(v.configuration)),expected(v.expected));
 await authority.validateImportCommitRequest(vector(v.control),'github',vector(v.control_source),vector('import_configuration'));
 console.log(`ALPHA25 REJECT then PASS commit.${v.id}: ${v.expected}`);
});
test('alpha25 multiple converter recommendation can name a later advertised entry',()=>authority.validateImportConfiguration(vector('configuration_multiple')));
test('alpha25 public selector may omit the repository ID while current discovery binds the exact URL',async()=>{
 const request=vector('commit_public_source');request.source.providerRepositoryId='';
 await authority.validateImportCommitRequest(request,'public-git',vector('source_public_github'),vector('import_configuration'));
 const prepare=vector('prepare_public_sha256');prepare.source.providerRepositoryId='';
 authority.prepareImportSourceScope(prepare,vector('source_public_sha256'),undefined,vector('import_configuration'),vector('scope').destinationVersion);
});
test('alpha25 Commit preserves a frozen pinned commit after branch movement',async()=>{
 const request=vector('commit_request'),current=vector('commit_source_different_oid');
 assert.notDeepEqual(request.proof.delegations[0].body.scope.branches[0].pinnedCommitOid,new Uint8Array(Buffer.from(current.refs[0].headOid,'hex')));
 await authority.validateImportCommitRequest(request,'github',current,vector('import_configuration'));
});

test('alpha25 renewal source Prepare shared vectors',async()=>{
 const read=vector('job_state_partial'),state=read.state;
 const predecessor=await authority.verifyImportRenewalPredecessor(state,vector('permission'),ownerContext(1600n));
 authority.validateRenewalPreparationFromRead(vector('renew_prepare_request'),vector('renewal_preparation'),read);
 const failures=[];
 for(const v of fixture.source_vectors.renewal_prepare){
  const request=vector(v.request),source=vector(v.source),configuration=vector(v.configuration??'import_configuration');
  if(v.id==='replacement_pin')assert.equal(Buffer.from(request.proposedScope.branches[0].pinnedCommitOid).toString('hex'),source.refs[0].headOid,'replacement matches current head but exceeds retained authority');
  let actual='OK';
  try{
   const retained=v.retained?{predecessor,state:v.state?vector(v.state):state,source:read.retainedSource}:undefined;
   const destinationVersion=vector('scope').destinationVersion;
   const prepared=authority.prepareImportSourceScope(request,source,'github',configuration,destinationVersion,retained);
   assert.deepEqual(prepared,{...request.proposedScope,destinationVersion},'retained selection stays exact');
  }catch(e){actual=e.reason==='PreparationRefused'?`${e.reason}(${api.ImportPreparationRefusalReason[e.preparationRefusalReason].split('_').map(s=>s[0]+s.slice(1).toLowerCase()).join('')})`:e.reason;}
  console.log(`ALPHA25 renewal_source.${v.id}: ${actual}`);
  if(actual!==v.expected)failures.push(`${v.id}: expected ${v.expected}, got ${actual}`);
 }
 assert.deepEqual(failures,[]);
});

test('alpha25 renewal source Prepare rejects an unverified predecessor token',()=>{
 const request=vector('renew_prepare_request');
 assert.throws(()=>authority.prepareImportSourceScope(request,vector('renew_source_moved_head'),'github',vector('import_configuration'),request.proposedScope.destinationVersion,{predecessor:{},state:vector('job_state_partial').state,source:vector('job_state_partial').retainedSource}),expected('Canonical'));
});

test('alpha25 fresh source Prepare with null retained context still requires the known pin',()=>{
 const request=vector('fresh_prepare_retained_pin');
 assert.throws(()=>authority.prepareImportSourceScope(request,vector('renew_source_moved_head'),'github',vector('import_configuration'),request.proposedScope.destinationVersion,null),expected('RefPinning'));
});

test('alpha27 retained custody recovery and grant refusal vectors',async()=>{
 const read=vector('job_state_partial'),state=read.state;
 const predecessor=await authority.verifyImportRenewalPredecessor(state,vector('permission'),ownerContext(1600n));
 const failures=[];
 const result=(label,run,want)=>{let actual='OK';try{run();}catch(e){actual=e.reason;}console.log(`ALPHA27 ${label}: ${actual}`);if(actual!==want)failures.push(`${label}: expected ${want}, got ${actual}`);};
 for(const v of fixture.custody_vectors.read)result(`read.${v.id}`,()=>authority.validateImportJobStateResponse(vector('job_state_request'),vector(v.response)),v.expected);
 for(const v of fixture.custody_vectors.prepare){
  const request=vector(v.request),source=vector(v.source);
  // A second browser recovers the selector from the read, without inventory.
  if(v.id==='second_browser_recovery')assert.deepEqual(request.source,read.retainedSource);
  result(`browser.${v.id}`,()=>authority.validateRenewalPreparationFromRead(request,vector('renewal_preparation'),read),v.revoked?'OK':v.expected);
  result(`host.${v.id}`,()=>authority.prepareImportSourceScope(request,source,v.revoked?undefined:'github',vector('import_configuration'),vector('scope').destinationVersion,{predecessor,state,source:read.retainedSource}),v.expected);
 }
 assert.deepEqual(failures,[]);
});

test('alpha27 Resolve exact identity and redirect refusal vectors',()=>{
 const failures=[];
 for(const v of fixture.custody_vectors.resolve){
  let actual='OK';try{authority.validateResolveImportSourceResponse(vector(v.request),vector(v.response),v.connection_provider);}catch(e){actual=e.reason;}
  console.log(`ALPHA27 resolve.${v.id}: ${actual}`);
  if(actual!==v.expected)failures.push(`${v.id}: expected ${v.expected}, got ${actual}`);
 }
 assert.deepEqual(failures,[]);
});
