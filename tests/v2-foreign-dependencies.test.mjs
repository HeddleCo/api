import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fromBinary} from '@bufbuild/protobuf';
import * as nat from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import * as imp from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import * as native from '../packages/typescript/dist/v1alpha2/native-witness.js';
import * as imported from '../packages/typescript/dist/v1alpha2/import-authority.js';
import {verifyWitnessSet} from '../packages/typescript/dist/v1alpha2/witness-trust.js';
import {SignedHostedWitnessSetV1Schema} from '../packages/typescript/dist/common/hosted_witness_pb.js';
const f=JSON.parse(readFileSync(new URL('./fixtures/foreign-dependencies-alpha34.json',import.meta.url)));
const bytes=h=>new Uint8Array(Buffer.from(h,'hex'));
const wire=(name,schema=f.wire_vectors[name].schema===nat.NativePublicProofBundleV1Schema.typeName?nat.NativePublicProofBundleV1Schema:imp.ImportPublicProofBundleV1Schema)=>fromBinary(schema,bytes(f.wire_vectors[name].wire_hex));
async function check(name,carrier){if(carrier==='native')await native.validatePublicNativeBundle(wire(name));else if(carrier==='import')imported.validatePublicBundle(wire(name));else await native.validateNativeWitnessCarriers(wire('import_stage'),wire(name));}
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
import {equal,reject,join,utf8} from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
const pinned=JSON.parse(readFileSync(new URL('./fixtures/import-authority-host-witness-v1.json',import.meta.url)));
const independent=fromBinary(imp.ImportPublicProofBundleV1Schema,bytes(pinned.wire_vectors.complete_export.wire_hex));
const nativeId=(format,data)=>{const size=new Uint8Array(8);new DataView(size.buffer).setBigUint64(0,BigInt(data.length),true);return blake3(join(utf8.encode(format),size,Uint8Array.of(0),data));};
const pin={authority:'https://weft.example.test',rootId:'descriptor-root-1',publicKey:bytes(f.keys.root.public_key_hex),epoch:1n};
async function nativeWitnesses(b){const set=await verifyWitnessSet(wire('mixed_set',SignedHostedWitnessSetV1Schema),{authority:pin.authority,rootId:pin.rootId,rootPublicKey:pin.publicKey,rootEpoch:1n,nowUnixMillis:1200001n,clockFloorUnixMillis:1000000n,knownJobKeys:[bytes(f.keys.job.public_key_hex)]});await native.verifyNativeBundleWitnesses(b,set,1200001n);}
async function importWitnesses(b){
 const result=await imported.verifyImportBundleWitnesses(b,pin,undefined,1200001n,()=>({identity:independent.delegations[0].body.identity,ownerPublicKey:bytes(f.keys.owner.public_key_hex),ownerChainDigest:imported.ownerChainDigest(independent.ownerChain),authorityExpiresAtSeconds:2000n,effectiveFromUnixSeconds:0n,effectiveUntilUnixSeconds:undefined,forbiddenJobKeys:['owner','device','root','witness'].map(k=>bytes(f.keys[k].public_key_hex)),knownJobAssociations:[]}),bundle=>{
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
  if(descriptor.origin===1)await importWitnesses(bundle);else await nativeWitnesses(bundle);
  const pending=[];
  for(const name of descriptor.originals){
   const record=wire(name,SignedRecordSchema);await imported.verifyNativeRecord(record,record.format);
   const op=decode(record.canonicalRecord),thread=new Uint8Array(op.thread);let job;
   if(descriptor.origin===1&&op.body.canonical?.author?.kind!=='local_key'){
    assert.ok(bundle.authorityWitnesses.some(p=>p.original&&equal(imported.signedNativeDigest(p.original),imported.signedNativeDigest(record))));
   }else if(descriptor.origin===1){
    job=bundle.delegations[0].body.jobPublicKey;
    assert.ok(equal(new Uint8Array(op.publisher),job));
    const frontier=imported.frontierDigest({formatVersion:1,threadId:thread,operationIds:[nativeId(record.format,record.canonicalRecord)]});
    const content=imported.contentDigest({formatVersion:1,canonicalCapture:encode(op.body.canonical.result)});
    assert.ok(bundle.operations.some(p=>equal(p.body.genesisDigest,thread)&&equal(p.body.resultingFrontierDigest,frontier)&&equal(p.body.resultingContentDigest,content)),'P3-bound exact frontier/content');
   }else assert.ok(bundle.authorityWitnesses.some(p=>p.original&&equal(imported.signedNativeDigest(p.original),imported.signedNativeDigest(record))));
   pending.push([Buffer.from(imported.signedNativeDigest(record)).toString('hex'),{origin:descriptor.origin,record,thread,job}]);
  }
  for(const [digest,row]of pending)this.rows.set(digest,row);this.stages.add(name);
 }
 async install(name,carrier){
  const b=wire(name);if(carrier==='native')await nativeWitnesses(b);else await importWitnesses(b);
  for(const stage of this.stages){if(f.stages.find(s=>s.id===stage).origin===1)await importWitnesses(wire(stage));else await nativeWitnesses(wire(stage));}
  for(const ref of b.foreignDependencies){const row=this.rows.get(Buffer.from(ref.signedNativeDigest).toString('hex'));if(!row||row.origin!==ref.origin||!equal(row.thread,ref.threadGenesisDigest))reject('Scope');}
  for(const p of b.landingWitnesses){
   const requestKey=p.request.signature.publicKey;
   if(equal(requestKey,bytes(f.keys.job.public_key_hex)))reject('KeyRole');
   const source=decode(p.sourceOperation.canonicalRecord),digest=Buffer.from(imported.signedNativeDigest(p.sourceOperation)).toString('hex');
   const author=source.body.canonical?.author;
   if(author?.kind==='local_key'){const row=this.rows.get(digest);if(!row?.job||!equal(row.job,new Uint8Array(source.publisher)))reject('ImportPermission');}
   else if(author?.kind==='account'){
    const admitted=[...this.stages].map(n=>wire(n)).some(stage=>stage.authorityWitnesses.some(p=>p.original&&equal(imported.signedNativeDigest(p.original),imported.signedNativeDigest(b.landingWitnesses[0].sourceOperation))));
    if(!admitted)reject('Scope');
   }else if(source.body.kind==='integration'){
    if(![...this.stages].map(n=>wire(n)).some(stage=>stage.landingWitnesses.some(p=>p.execution&&equal(imported.signedNativeDigest(p.execution),imported.signedNativeDigest(b.landingWitnesses[0].sourceOperation)))))reject('Scope');
   }else reject('Scope');
  }
  this.targets.add(name);
 }
}
for(const v of f.positive)test(`staged receiver PASS ${v.id}`,async()=>{const r=new Receiver();await r.stage(v.stage);await r.install(v.id,v.carrier);assert.equal(r.targets.size,1);});
for(const v of f.receiver_negative)test(`staged receiver REJECT unchanged then PASS ${v.id}`,async()=>{
 const descriptor=f.positive.find(p=>p.id===v.control),r=new Receiver();if(!v.omit_stage)await r.stage(descriptor.stage);
 if(v.unbind)for(const row of r.rows.values())row.job=undefined;
 const counts=[r.rows.size,r.stages.size,r.targets.size];
 await assert.rejects(()=>r.install(v.id==='job_signed_landing'?v.id:v.control,descriptor.carrier),{reason:v.expected});
 assert.deepEqual([r.rows.size,r.stages.size,r.targets.size],counts);
 await r.stage(descriptor.stage);await r.install(v.control,descriptor.carrier);assert.equal(r.targets.size,1);
});
