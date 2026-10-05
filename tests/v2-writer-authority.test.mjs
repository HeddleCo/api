import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fromBinary } from '@bufbuild/protobuf';
import { NativeGenesisWitnessV1Schema } from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import { verifyNativeGenesisAuthority } from '../packages/typescript/dist/v1alpha2/native-witness.js';
const f=JSON.parse(readFileSync(new URL('./fixtures/writer-authority-alpha35.json',import.meta.url)));
const raw=h=>new Uint8Array(Buffer.from(h,'hex'));
const wire=(name,schema=NativeGenesisWitnessV1Schema)=>fromBinary(schema,raw(f.vectors[name].wire_hex));
const genesis=async name=>{const p=wire(name);await verifyNativeGenesisAuthority(p.binding,p.originalGenesis,p.creatorAuthorityEnvelope);};
test('cowriter StartThread',async()=>{await genesis('cowriter_start_thread');});
for(const v of f.negative.filter(v=>v.gate==='genesis'))test(`${v.id} REJECT then PASS`,async()=>{
  await assert.rejects(()=>genesis(v.id),{reason:v.expected});await genesis(v.control);
});
