import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fromBinary,toBinary} from '@bufbuild/protobuf';
import * as nat from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import * as imp from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import * as native from '../packages/typescript/dist/v1alpha2/native-witness.js';
import * as imported from '../packages/typescript/dist/v1alpha2/import-authority.js';
import {verifyWitnessSet} from '../packages/typescript/dist/v1alpha2/witness-trust.js';
import {SignedHostedWitnessSetV1Schema} from '../packages/typescript/dist/common/hosted_witness_pb.js';
const f=JSON.parse(readFileSync(new URL('./fixtures/foreign-dependencies-alpha34.json',import.meta.url)));
const bytes=h=>new Uint8Array(Buffer.from(h,'hex'));
const wire=(name,schema=f.wire_vectors[name].schema===nat.NativePublicProofBundleV1Schema.typeName?nat.NativePublicProofBundleV1Schema:imp.ImportPublicProofBundleV1Schema)=>fromBinary(schema,bytes(f.wire_vectors[name].wire_hex));
async function check(name,carrier){const roles=f.negative.find(v=>v.id===name)?.roles;if(roles&&!roles.startsWith('import_')){for(const p of wire(name).landingWitnesses)imported.verifyLandingKeyRoles(p,roles==='known'?[bytes(f.keys.job.public_key_hex)]:[],roles==='forbidden'?[bytes(f.keys.job.public_key_hex)]:[]);}if(carrier==='native'){if(name==='job_signed_landing')await nativeWitnesses(wire(name));else await native.validatePublicNativeBundle(wire(name));}else if(carrier==='import'){if(roles?.startsWith('import_'))await importWitnesses(wire(name),roles);else imported.validatePublicBundle(wire(name));}else await native.validateNativeWitnessCarriers(wire('import_stage'),wire(name));}
for(const v of f.positive)test(`foreign closure PASS ${v.id}`,()=>check(v.id,v.carrier));
for(const v of f.negative)test(`foreign REJECT then PASS ${v.id}`,async()=>{
 await assert.rejects(()=>check(v.carrier==='dispatch'?v.control:v.id,v.carrier),{reason:v.expected});
 await check(v.control,v.carrier==='dispatch'?'native':v.carrier);
});
test('foreign native references retain witness verification',async()=>{
 const selected=wire('mixed_set',SignedHostedWitnessSetV1Schema);
 const set=await verifyWitnessSet(selected,{authority:'https://weft.example.test',rootId:'descriptor-root-1',rootPublicKey:bytes(f.keys.root.public_key_hex),rootEpoch:1n,nowUnixMillis:1200001n,clockFloorUnixMillis:1000000n,knownJobKeys:[bytes(f.keys.job.public_key_hex)]});
 for(const v of f.positive.filter(v=>v.carrier==='native'))await native.verifyNativeBundleWitnesses(wire(v.id),set,1200001n);
});

// Executable staged receiver contract model. Repository transactions and native
// model authorization are downstream; the Rust native corpus checks their codecs.
import {decode,encode} from '../packages/typescript/dist/v1alpha2/_collaboration-msgpack.js';
import {SignedRecordSchema} from '../packages/typescript/dist/v1alpha2/common_pb.js';
import {blake3} from '@noble/hashes/blake3.js';
import {canonicalHybridV1,equal,reject,join,utf8} from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
const pinned=JSON.parse(readFileSync(new URL('./fixtures/import-authority-host-witness-v1.json',import.meta.url)));
const independent=fromBinary(imp.ImportPublicProofBundleV1Schema,bytes(pinned.wire_vectors.complete_export.wire_hex));
const nativeId=(format,data)=>{const size=new Uint8Array(8);new DataView(size.buffer).setBigUint64(0,BigInt(data.length),true);return blake3(join(utf8.encode(format),size,Uint8Array.of(0),data));};
const pin={authority:'https://weft.example.test',rootId:'descriptor-root-1',publicKey:bytes(f.keys.root.public_key_hex),epoch:1n};
async function nativeWitnesses(b,forbiddenLandingKeys=[]){const set=await verifyWitnessSet(wire('mixed_set',SignedHostedWitnessSetV1Schema),{authority:pin.authority,rootId:pin.rootId,rootPublicKey:pin.publicKey,rootEpoch:1n,nowUnixMillis:1200001n,clockFloorUnixMillis:1000000n,knownJobKeys:[bytes(f.keys.job.public_key_hex)]});await native.verifyNativeBundleWitnesses(b,set,1200001n,forbiddenLandingKeys);}
async function importWitnesses(b,roles){
 const result=await imported.verifyImportBundleWitnesses(b,pin,undefined,1200001n,()=>({identity:independent.delegations[0].body.identity,ownerPublicKey:bytes(f.keys.owner.public_key_hex),ownerChainDigest:imported.ownerChainDigest(independent.ownerChain),authorityExpiresAtSeconds:2000n,effectiveFromUnixSeconds:0n,effectiveUntilUnixSeconds:undefined,forbiddenJobKeys:roles?[]:['owner','device','root','witness'].map(k=>bytes(f.keys[k].public_key_hex)),forbiddenLandingKeys:roles==='import_forbidden'?[bytes(f.keys.device.public_key_hex)]:[],knownJobAssociations:roles==='import_known'?[{key:bytes(f.keys.device.public_key_hex),logicalJobId:independent.delegations[0].body.logicalJobId}]:[]}),bundle=>{
   // Independently pinned accepted owner/policy context for this fixed corpus.
   assert.deepEqual(bundle.ownerGenesis,independent.ownerGenesis);
   assert.deepEqual(bundle.ownerHistories,independent.ownerHistories);
   assert.deepEqual(bundle.policies,independent.policies);
 });
 assert.equal(result.evidence,'witnessed');
}
class Receiver {
 rows=new Map();stages=new Set();targets=new Set();
 async stage(name){
  const descriptor=f.stages.find(s=>s.id===name),bundle=wire(name);
  if(descriptor.origin===imp.ForeignDependencyOrigin.IMPORT)await importWitnesses(bundle);else await nativeWitnesses(bundle);
  const pending=[];
  for(const name of descriptor.originals){
   const record=wire(name,SignedRecordSchema);await imported.verifyNativeRecord(record,record.format);
   const op=decode(record.canonicalRecord),thread=new Uint8Array(op.thread);let job;
   if(op.body.kind==='integration'){assert.ok(bundle.landingWitnesses.some(p=>p.execution&&equal(imported.signedNativeDigest(p.execution),imported.signedNativeDigest(record))));}
   else if(descriptor.origin===imp.ForeignDependencyOrigin.IMPORT&&op.body.canonical?.author?.kind!=='local_key'){
    assert.ok(bundle.authorityWitnesses.some(p=>p.original&&equal(imported.signedNativeDigest(p.original),imported.signedNativeDigest(record))));
   }else if(descriptor.origin===imp.ForeignDependencyOrigin.IMPORT){
    job=bundle.delegations[0].body.jobPublicKey;
    assert.ok(equal(new Uint8Array(op.publisher),job));
    const frontier=imported.frontierDigest({formatVersion:1,threadId:thread,operationIds:[nativeId(record.format,record.canonicalRecord)]});
    const content=imported.contentDigest({formatVersion:1,canonicalCapture:encode(op.body.canonical.result)});
    assert.ok(bundle.operations.some(p=>equal(p.body.genesisDigest,thread)&&equal(p.body.resultingFrontierDigest,frontier)&&equal(p.body.resultingContentDigest,content)),'P3-bound exact frontier/content');
   }else assert.ok(bundle.authorityWitnesses.some(p=>p.original&&equal(imported.signedNativeDigest(p.original),imported.signedNativeDigest(record))));
   const statement=bundle.statements.find(s=>{
    if(s.body.purpose===2)return bundle.authorityWitnesses.some(p=>p.original&&equal(imported.signedNativeDigest(p.original),imported.signedNativeDigest(record))&&equal(canonicalHybridV1(imp.ImportAuthorityWitnessV1Schema,p),s.body.canonicalPayload));
    if(s.body.purpose===4)return bundle.landingWitnesses.some(p=>p.execution&&equal(imported.signedNativeDigest(p.execution),imported.signedNativeDigest(record))&&equal(canonicalHybridV1(imp.HostedLandingWitnessV1Schema,p),s.body.canonicalPayload));
    if(s.body.purpose===3&&job)return bundle.operations.some(o=>equal(o.body.genesisDigest,thread)&&bundle.manifests.some(m=>equal(canonicalHybridV1(imp.ImportPublicationWitnessV1Schema,imported.publicationPayload(o,m)),s.body.canonicalPayload)));
    return false;
   });assert.ok(statement,'original admission marker');
   pending.push([Buffer.from(imported.signedNativeDigest(record)).toString('hex'),{origin:descriptor.origin,record,thread,job,admissionPurpose:statement.body.purpose,admissionOrder:statement.body.admissionOrder,stage:name,spool:bundle.ownerGenesis.genesis.spoolUuid,authority:bundle.witnessSet.body.deploymentAuthority}]);
  }
  for(const [digest,row]of pending)this.rows.set(digest,row);this.stages.add(name);
 }
 async installPrefix(name,catalog=f.prefixes,visiting=[]){
  if(this.stages.has(name))return;
  const selected=catalog.find(p=>p.id===name)??reject('Scope');
  const key=[selected.carrier,selected.thread_genesis_digest,selected.signed_native_digest,selected.cutoff].join(':');
  if(visiting.includes(key))reject('Scope');
  if(visiting.length>catalog.length)reject('Bounds');visiting.push(key);
  const bundle=wire(name);
  for(const ref of bundle.foreignDependencies){
   const foreign=catalog.find(p=>p.thread_genesis_digest===Buffer.from(ref.threadGenesisDigest).toString('hex')&&BigInt(p.cutoff)===ref.prefixAdmissionOrder&&p.signed_native_digest===Buffer.from(ref.signedNativeDigest).toString('hex'))??reject('Scope');
   await this.installPrefix(foreign.id,catalog,visiting);
  }
  await this.install(name,selected.carrier);await this.stage(name);visiting.pop();
 }
 async install(name,carrier){
  const b=wire(name);if(carrier==='native')await nativeWitnesses(b);else await importWitnesses(b);
  for(const stage of this.stages){if(f.stages.find(s=>s.id===stage).origin===imp.ForeignDependencyOrigin.IMPORT)await importWitnesses(wire(stage));else await nativeWitnesses(wire(stage));}
  for(const ref of b.foreignDependencies){const row=this.rows.get(Buffer.from(ref.signedNativeDigest).toString('hex'));if(!row||row.origin!==ref.origin||!equal(row.thread,ref.threadGenesisDigest)||row.admissionOrder!==ref.prefixAdmissionOrder||!equal(row.spool,b.ownerGenesis.genesis.spoolUuid)||row.authority!==b.witnessSet.body.deploymentAuthority)reject('Scope');
   const records=[...b.authorityWitnesses.flatMap(p=>p.dependencies),...b.landingWitnesses.flatMap(p=>[p.sourceOperation,...p.reviewEvidence])];
   const original=records.find(r=>equal(imported.signedNativeDigest(r),ref.signedNativeDigest));if(!original||!equal(toBinary(SignedRecordSchema,original),toBinary(SignedRecordSchema,row.record)))reject('Scope');await imported.verifyNativeRecord(row.record,row.record.format);}
  for(const p of b.landingWitnesses){
   const requestKey=p.request.signature.publicKey;
   imported.verifyLandingKeyRoles(p,[bytes(f.keys.job.public_key_hex)]);
   const source=decode(p.sourceOperation.canonicalRecord),digest=Buffer.from(imported.signedNativeDigest(p.sourceOperation)).toString('hex');
   const author=source.body.canonical?.author;
   if(author?.kind==='local_key'){const row=this.rows.get(digest);if(!row?.job||!equal(row.job,new Uint8Array(source.publisher)))reject('ImportPermission');}
   else if(author?.kind==='account'){
    const admitted=[...this.stages].map(n=>wire(n)).some(stage=>stage.authorityWitnesses.some(a=>a.original&&equal(imported.signedNativeDigest(a.original),imported.signedNativeDigest(p.sourceOperation))));
    if(!admitted||this.rows.get(digest)?.admissionPurpose!==2)reject('Scope');
   }else if(source.body.kind==='integration'){
    if(this.rows.get(digest)?.admissionPurpose!==4||![...this.stages].map(n=>wire(n)).some(stage=>stage.landingWitnesses.some(a=>a.execution&&equal(imported.signedNativeDigest(a.execution),imported.signedNativeDigest(p.sourceOperation)))))reject('Scope');
   }else reject('Scope');
  }
  this.targets.add(name);
 }
}
for(const v of f.positive)test(`staged receiver PASS ${v.id}`,async()=>{const r=new Receiver();await r.stage(v.stage);await r.install(v.id,v.carrier);assert.equal(r.targets.size,1);});
for(const v of f.receiver_negative)test(`staged receiver REJECT then PASS ${v.id}`,async()=>{
 const descriptor=f.positive.find(p=>p.id===v.control)??f.prefixes.find(p=>p.id===v.control),r=new Receiver();
 const stage=v.prefix_setup??descriptor.stage;
 if(v.prefix_setup)await r.installPrefix(stage);else if(!v.omit_stage)await r.stage(stage);
 if(v.unbind)for(const row of r.rows.values())row.job=undefined;
 if(v.unadmit)for(const row of r.rows.values())if(row.admissionPurpose===v.unadmit)row.admissionPurpose=0;
 if(v.row_mismatch)for(const row of r.rows.values()){
  if(v.row_mismatch==='origin')row.origin=imp.ForeignDependencyOrigin.NATIVE;
  if(v.row_mismatch==='thread')row.thread=new Uint8Array(32);
  if(v.row_mismatch==='spool')row.spool=new Uint8Array(16);
  if(v.row_mismatch==='authority')row.authority='https://other.example.test';
  if(v.row_mismatch==='order')row.admissionOrder++;
  if(v.row_mismatch==='bytes')row.record.signatures[0].signature[0]^=1;
 }
 await assert.rejects(()=>r.install(v.control,descriptor.carrier),{reason:v.expected});
 await r.stage(stage);await r.install(v.control,descriptor.carrier);assert.ok(r.targets.has(v.control));
});

test('prefix staging bidirectional fresh receiver',async()=>{const r=new Receiver();for(const root of f.fresh_receiver.roots)await r.installPrefix(root);assert.deepEqual([...r.stages],f.fresh_receiver.expected_prefixes);});
test('prefix staging genuine cycle REJECT then PASS',async()=>{const r=new Receiver(),catalog=f.prefixes.filter(p=>f.cycle_negative.prefixes.includes(p.id));await assert.rejects(()=>r.installPrefix(f.cycle_negative.root,catalog),{reason:'Scope'});await r.installPrefix(f.cycle_negative.control);});

test('native witnesses apply forbidden landing keys',async()=>{
 const b=wire('import_tip_native_fast_forward');
 await assert.rejects(()=>nativeWitnesses(b,[bytes(f.keys.device.public_key_hex)]),{reason:'KeyRole'});
 await nativeWitnesses(b);
});

test('LocalKey cutoff ignores later claim and resolution in both install orders',async()=>{
 const original=wire('local_cutoff_original',SignedRecordSchema),prefix=wire('local_cutoff_prefix'),history=wire('local_cutoff_history'),carrier=wire('local_cutoff_dependent');
 await importWitnesses(carrier);
 const order=carrier.statements.find(s=>s.body.purpose===2).body.admissionOrder;
 assert.equal(order,236n);
 assert.ok(equal(carrier.foreignDependencies[0].signedNativeDigest,imported.signedNativeDigest(original)));
 for(const histories of [[prefix,history],[history,prefix]]){
  for(const installed of histories){
   await nativeWitnesses(installed);
   assert.equal(native.localWorkCutoff(installed,original,order),carrier.foreignDependencies[0].prefixAdmissionOrder);
  }
 }
 assert.throws(()=>native.localWorkCutoff(history,original,204n),{reason:'Scope'});
 assert.throws(()=>native.localWorkCutoff(history,original,237n),{reason:'Scope'});
 assert.equal(native.localWorkCutoff(history,original,238n),238n);
});
