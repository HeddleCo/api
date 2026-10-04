import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fromBinary } from '@bufbuild/protobuf';
import { ownerChainDigest, signedNativeDigest } from '../packages/typescript/dist/v1alpha2/import-authority.js';
import * as api from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import * as imp from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import { SignedHostedWitnessSetV1Schema } from '../packages/typescript/dist/common/hosted_witness_pb.js';
import { StartThreadRequestSchema } from '../packages/typescript/dist/v1alpha2/thread_pb.js';
import { ThreadGenesisRecordSchema } from '../packages/typescript/dist/v1alpha2/sync_pb.js';
import { canonicalHybridV1, signingDigest, equal } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
import { verifyWitnessSet } from '../packages/typescript/dist/v1alpha2/witness-trust.js';
import { signNativeGenesisAuthority, verifyNativeGenesisAuthority, validatePublicNativeBundle, verifyNativeBundleWitnesses, validateNativeWitnessCarriers } from '../packages/typescript/dist/v1alpha2/native-witness.js';
const f=JSON.parse(readFileSync(new URL('./fixtures/native-host-witness-v1.json',import.meta.url),'utf8'));
const bytes=h=>new Uint8Array(Buffer.from(h,'hex'));
const wire=(name,schema=api.NativePublicProofBundleV1Schema)=>fromBinary(schema,bytes(f.wire_vectors[name].wire_hex));
async function verify(b){const selected=wire(b.witnessSet?.body?.generation===51n?'retired_set':'current_set',SignedHostedWitnessSetV1Schema);const now=selected.body.issuedAtUnixMillis+1n;const set=await verifyWitnessSet(selected,{authority:'https://weft.example.test',rootId:'descriptor-root-1',rootPublicKey:bytes(f.keys.root.public_key_hex),rootEpoch:1n,nowUnixMillis:now,clockFloorUnixMillis:1000000n,knownJobKeys:[]});await verifyNativeBundleWitnesses(b,set,now);}
for(const name of f.positive)test(`native positive ${name}`,async()=>{await verify(wire(name));});
test('bindings select distinct retained owner chains',()=>{
  const b=wire('distinct_owner_chains'),selected=b.genesisWitnesses.map(p=>Buffer.from(p.binding.body.ownerChainDigest).toString('hex'));
  assert.equal(b.ownerChains.length,2);assert.equal(selected.length,2);assert.notEqual(selected[0],selected[1]);
  for(const digest of selected)assert.ok(b.ownerChains.some(c=>Buffer.from(ownerChainDigest(c)).toString('hex')===digest));
  const missing=wire('missing_selected_owner_chain');assert.equal(missing.ownerChains.length,1);
  assert.deepEqual(missing.genesisWitnesses,b.genesisWitnesses);assert.deepEqual(missing.statements,b.statements);
});
test('post-landing capture retains its exact execution dependency without purpose 2',()=>{
  const b=wire('post_landing_capture'),execution=b.landingWitnesses[0].execution;
  assert.ok(b.authorityWitnesses.some(p=>p.dependencies.some(r=>equal(signedNativeDigest(r),signedNativeDigest(execution)))));
  assert.ok(b.authorityWitnesses.every(p=>!equal(signedNativeDigest(p.original),signedNativeDigest(execution))));
});
for(const [name,v] of Object.entries(f.canonical_vectors))test(`native canonical parity ${name}`,()=>{const schema=Object.values(api).find(s=>s?.typeName===v.schema);const value=fromBinary(schema,bytes(v.wire_hex));assert.deepEqual(canonicalHybridV1(schema,value),bytes(v.canonical_hex));assert.deepEqual(signingDigest(v.domain,schema,value),bytes(v.digest_hex));});
for(const v of f.negative)test(`native negative ${v.id}`,async()=>{
  if(v.gate==='import'){const control=wire(v.control,imp.ImportPublicProofBundleV1Schema);await validateNativeWitnessCarriers(control,undefined);await assert.rejects(()=>validateNativeWitnessCarriers(wire(v.id,imp.ImportPublicProofBundleV1Schema),undefined),{reason:v.expected});}
  else if(v.gate==='dispatch'){await verify(wire(v.control));await assert.rejects(()=>validateNativeWitnessCarriers(wire('import_complete',imp.ImportPublicProofBundleV1Schema),wire(v.control)),{reason:v.expected});}
  else{await verify(wire(v.control));await assert.rejects(()=>verify(wire(v.id)),{reason:v.expected});}
});
test('StartThread and relay retain exact creator envelope and second signature',async()=>{const start=wire('start_request',StartThreadRequestSchema),record=wire('thread_genesis_record',ThreadGenesisRecordSchema);assert.deepEqual(start.threadGenesis,record.genesis);assert.deepEqual(start.creatorAuthority,record.creatorAuthority);assert.deepEqual(start.nativeGenesisAuthority,record.nativeGenesisAuthority);await verifyNativeGenesisAuthority(start.nativeGenesisAuthority,start.threadGenesis,start.creatorAuthority);});
