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
function setContext(now=1100000n){return {authority:fixture.context.authority,rootId:fixture.context.root_id,rootPublicKey:bytes(fixture.keys.root.public_key_hex),rootEpoch:1n,nowUnixMillis:now,clockFloorUnixMillis:1000000n,knownJobKeys:['job','sibling_job','direct_job'].map(n=>bytes(fixture.keys[n].public_key_hex))};}
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
    'PrepareImportJob', 'RetryImportSource', 'SynchronizeRemote']
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
  for(const name of ['dev','main']){const g=fixture.originals[name];assertCrypto(bytes(fixture.keys.device.public_key_hex),Buffer.concat([Buffer.from('heddle-thread-genesis-v1\0'),bytes(g.canonical_hex)]),bytes(g.signature_hex));await authority.verifyImportGenesisAuthority(vector(`genesis_${name}`),d,bytes(g.genesis_digest_hex),bytes(g.signature_hex),new Uint8Array((await import('@noble/hashes/sha2.js')).sha256(bytes(g.envelope_hex))));await authority.verifyNewImportOperation(vector(`operation_${name}`), d, 1100n, emptyFor(vector(`operation_${name}`)));}
  const set=await witness.verifyWitnessSet(vector('current_set'),setContext());
  await authority.verifyImportPublication(vector('operation_main'),d,vector('partial_manifest'),vector('publication_statement'),set,undefined,1100000n);
  const retired=await witness.verifyWitnessSet(vector('retired_set'),setContext(1350000n),set);
  await authority.verifyImportPublication(vector('operation_main'),d,vector('partial_manifest'),vector('publication_statement'),retired,vector('publication_proof'),1350000n);
  await assert.rejects(authority.verifyNewImportOperation(vector('operation_main'), d, 1350n, emptyFor(vector('operation_main'))),expected('Expired'));
});
for(const v of fixture.negative_vectors)test(`isolated negative gate: ${v.id}; first check: ${v.first_failing_check}`,async()=>{
  assert.ok(v.first_failing_check);if(v.type==='set'){const p=v.previous?await witness.verifyWitnessSet(vector(v.previous),setContext()):undefined;await assert.rejects(witness.verifyWitnessSet(authority.strictDecode(common.SignedHostedWitnessSetV1Schema,bytes(v.wire_hex)),setContext(),p),expected(v.expected));await witness.verifyWitnessSet(vector(v.control),setContext(),p);return;}
  if(v.type==='statement'){const set=await witness.verifyWitnessSet(vector(v.set),setContext(BigInt(v.now_ms)));await assert.rejects(witness.resolveWitnessStatement(set,authority.strictDecode(common.SignedHostedWitnessStatementV1Schema,bytes(v.wire_hex)),vector(v.proof),v.new_work,BigInt(v.now_ms)),expected(v.expected));const fresh=v.new_work===true;const controlSet=await witness.verifyWitnessSet(vector(fresh?'current_set':'retired_set'),setContext(fresh?1100000n:1350000n));await witness.resolveWitnessStatement(controlSet,vector(v.control),fresh?undefined:vector('publication_proof'),fresh,fresh?1100000n:1350000n);return;}
  const d=await authority.verifyImportDelegation(vector('delegation'),vector('permission'),ownerContext());
  if(v.type==='operation')await assert.rejects(authority.verifyDelegatedImportOperation(authority.strictDecode(api.SignedDelegatedImportOperationV1Schema,bytes(v.wire_hex)),d),expected(v.expected));
  if(v.type==='new_operation')await assert.rejects(authority.verifyNewImportOperation(vector('operation_main'), d, BigInt(v.now_seconds), emptyFor(vector('operation_main'))),expected(v.expected));
  if(v.type==='operation')await authority.verifyDelegatedImportOperation(vector(v.control),d);
  if(v.type==='new_operation')await authority.verifyNewImportOperation(vector(v.control), d, 1299n, emptyFor(vector(v.control)));
});
for(const v of fixture.unrelated_permissions)test(`correctly signed ${v.format} cannot delegate import`,async()=>{assertCrypto(bytes(v.public_key_hex),bytes(v.signing_input_hex),bytes(v.signature_hex));if(v.wire_hex){const record=fromBinary(api.SignedOwnerCapabilitySchema,bytes(v.wire_hex));assert.deepEqual(record.signature.signature,bytes(v.signature_hex));assert.equal(record.capability.formatVersion,v.format==='PURGE-v1'?1:3);}const evidence=v.wire_hex?{kind:'owner_capability',record:fromBinary(api.SignedOwnerCapabilitySchema,bytes(v.wire_hex))}:{kind:'online_role',role:'Developer'};assert.throws(()=>authority.selectImportPermission(evidence),expected('ImportPermission'));const parent=authority.selectImportPermission({kind:'import',record:vector('permission')});await authority.verifyImportDelegation(vector('delegation'),parent,ownerContext());});
for(const tree of fixture.trees)test(`static Merkle tree ${tree.count}: exact root and every path`,()=>{
  const leaves=tree.leaves_hex.map(bytes);assert.deepEqual(witness.merkleRoot(leaves),bytes(tree.root_hex));const entry=create(common.HostedWitnessEntryV1Schema,{executorId:new Uint8Array(32).fill(1),state:2,archiveRoot:bytes(tree.root_hex),archiveLeafCount:BigInt(tree.count)});
  for(const p of tree.paths){const proof=create(common.HostedWitnessHistoryProofV1Schema,{executorId:entry.executorId,purpose:3,leafIndex:BigInt(p.index),leafCount:BigInt(tree.count),siblings:p.siblings_hex.map(bytes)});witness.verifyWitnessInclusion(leaves[p.index],proof,entry);const extra=structuredClone(proof);extra.siblings.push(new Uint8Array(32));assert.throws(()=>witness.verifyWitnessInclusion(leaves[p.index],extra,entry),expected('Proof'));}
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
    'commitImportJob', 'cancelImportJob', 'getHostedWitnessHistoryProof'];
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
  await assert.rejects(authority.verifyNewImportOperation(operation, d, 1199n, emptyFor(operation)),expected('Expired'));
  await authority.verifyNewImportOperation(operation, d, 1200n, emptyFor(operation));
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
 assert.throws(()=>authority.prepareImportSourceScope(vector(v.request), vector('source_public_sha256'), undefined, vector('import_configuration'), scope.destinationVersion),expected(v.expected));
 authority.prepareImportSourceScope(vector('prepare_public_sha256'), vector('source_public_sha256'), undefined, vector('import_configuration'), scope.destinationVersion);console.log(`ALPHA25 REJECT then PASS prepare.${v.id}: ${v.expected}`);
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
 authority.prepareImportSourceScope(prepare, vector('source_public_sha256'), undefined, vector('import_configuration'), vector('scope').destinationVersion);
});
test('alpha25 Commit preserves a frozen pinned commit after branch movement',async()=>{
 const request=vector('commit_request'),current=vector('commit_source_different_oid');
 assert.notDeepEqual(request.proof.delegations[0].body.scope.branches[0].pinnedCommitOid,new Uint8Array(Buffer.from(current.refs[0].headOid,'hex')));
 await authority.validateImportCommitRequest(request,'github',current,vector('import_configuration'));
});
const rootPin=()=>({authority:fixture.context.authority,rootId:fixture.context.root_id,publicKey:bytes(fixture.keys.root.public_key_hex),epoch:1n});
const ownerAt=time=>({...ownerContext(time??0n),effectiveFromUnixSeconds:0n,effectiveUntilUnixSeconds:undefined});
const verifyBundle=(name,now=1350000n,snapshot=undefined,resolve=ownerAt,policy=()=>{})=>authority.verifyImportBundleWitnesses(vector(name),rootPin(),snapshot,now,resolve,policy);
for(const v of fixture.bundle_vectors.negative)test(`alpha33 bundle ${v.id} refuses then accepts`,async()=>{
 await assert.rejects(verifyBundle(v.bundle,BigInt(v.now_ms??1350000)),expected(v.expected));
 await verifyBundle(v.control,BigInt(v.now_ms??1350000));
});
test('alpha33 owner resolver checks every authenticated time and effective interval',async()=>{
 const times=[];const result=await verifyBundle('complete_export',1350000n,undefined,time=>{times.push(time);return ownerAt(time);});
 assert.equal(result.evidence,'witnessed');assert.equal(result.ownerCheckTimeUnixSeconds,1100n);
 assert.ok(times.includes(1100n)&&times.includes(1200n));assert.deepEqual(result.acceptedHistory,vector('terminal_manifest'));
 await assert.rejects(verifyBundle('current_export',1200000n,undefined,time=>({...ownerAt(time),effectiveFromUnixSeconds:1200n})),expected('Scope'));
 await assert.rejects(verifyBundle('current_export',1200000n,undefined,time=>({...ownerAt(time),authorityExpiresAtSeconds:1299n})),expected('Scope'));
 await assert.rejects(verifyBundle('complete_export',1350000n,undefined,ownerAt,()=>{throw new authority.HybridContractError('Revoked');}),expected('Revoked'));
});
test('alpha33 24h window accepted with host advertised duration',async()=>{
 const d=vector('window_24h');assert.equal(d.body.expiresAtUnixSeconds-d.body.notBeforeUnixSeconds,86400n);
 const e={...ownerContext(),authorityExpiresAtSeconds:100000n};const geneses=d.body.branchManifest.map((_,i)=>vector('direct_genesis_'+i));
 await authority.verifyPreparedImportDelegation(vector('window_24h_preparation'),d,undefined,geneses,e);
 const short=vector('window_24h_preparation');short.maxValidityDurationSeconds=3600n;
 await assert.rejects(authority.verifyPreparedImportDelegation(short,d,undefined,geneses,e),expected('ValidityBounds'));
});
test('alpha33 cumulative budget uses the 2x case under one delegation',async()=>{
 await assert.rejects(verifyBundle('aggregate_over',1200000n),expected('Scope'));
 const result=await verifyBundle('aggregate_at',1200000n);assert.equal(result.acceptedHistory.slots.length,2);
 assert.equal(vector('aggregate_at').delegations.length,1);
});
test('alpha33 recovery changes only authenticated set trust and retains rollback protection',async()=>{
 const recovery=await verifyBundle('recovery');assert.equal(recovery.evidence,'recovery');assert.equal(recovery.snapshot,undefined);
 const witnessed=await verifyBundle('complete_export');await assert.rejects(verifyBundle('recovery',1350000n,witnessed.snapshot),expected('HighWater'));
 const b=vector('recovery');b.witnessSet=vector('retired_set');
 const fresh=await authority.verifyImportBundleWitnesses(b,rootPin(),undefined,1350000n,ownerAt,()=>{});
 assert.equal(fresh.evidence,'recovery');assert.equal(fresh.snapshot.acceptedHistory.length,0);assert.equal(fresh.snapshot.jobAssociations.length,0);
});
test('alpha33 minimal state, Retry, Cancel and host custody checks',async()=>{
 const request=vector('retry_request'),state=vector('job_state'),source=vector('prepare_request').source,active=await authority.verifyImportDelegation(vector('delegation'),vector('permission'),ownerContext());
 authority.validateImportJobStateResponse(vector('job_state_request'),state);
 assert.deepEqual(api.GetImportJobStateResponseSchema.fields.map(f=>f.name),['status','active_cancellation_id','authority_epoch','eligible_retry_target','retry_unavailable','active_delegation_digest']);
 const context={read:state,original:vector('retry_original'),retryLineageId:active.body.retryLineageId,logicalJobTerminal:false,retainedSource:source,committedManifest:vector('empty_manifest'),nowUnixSeconds:1100n};
 const caller={authenticatedPop:true,destinationWriter:true,callerAccount:'owner',connectionOwnerAccount:'owner',authorizedSource:source,exactGrantsCurrent:true,selectedCommitsAvailable:true};
 authority.checkImportRetryAdmission(request,context,active,caller);
 assert.throws(()=>authority.checkImportRetryAdmission(request,{...context,nowUnixSeconds:1300n},active,caller),expected('Expired'));
 assert.throws(()=>authority.checkImportRetryAdmission(request,context,active,{...caller,connectionOwnerAccount:'other'}),expected('SourceSelection'));
 assert.throws(()=>authority.checkImportRetryAdmission(request,{...context,logicalJobTerminal:true},active,caller),expected('Revoked'));
 const stale=vector('retry_request');stale.expectedAuthorityEpoch=2n;assert.throws(()=>authority.checkImportRetryAdmission(stale,context,active,caller),expected('StaleContext'));
 const cancel=create(api.CancelImportJobRequestSchema,{clientOperationId:'cancel',destination:vector('job_state_request').destination,logicalJobId:active.body.logicalJobId,cancellationId:state.activeCancellationId,expectedAuthorityEpoch:1n});
 authority.checkImportCancelRequest(cancel,vector('delegation'),1n,false);authority.checkImportControlCaller('Cancel',source,active.body.scope,{...caller,connectionOwnerAccount:'other',selectedCommitsAvailable:false});
 authority.checkImportRetryReplay(Uint8Array.of(1),Uint8Array.of(1));assert.throws(()=>authority.checkImportRetryReplay(Uint8Array.of(1),Uint8Array.of(2)),expected('OperationIdReused'));
});

test('alpha33 parent and delegation revocation are independent',()=>{
 const d=vector('delegation'),p=vector('permission');
 for(const id of [d.body.cancellationId,p.body.cancellationId]){
  assert.throws(()=>authority.checkImportRevocations(d,p,[id]),expected('Revoked'));
  authority.checkImportRevocations(d,p,[]);
 }
});

function emptyFor(o){return create(api.ImportResultManifestV1Schema,{formatVersion:1,logicalJobId:o.body.logicalJobId,retryLineageId:o.body.retryLineageId});}
