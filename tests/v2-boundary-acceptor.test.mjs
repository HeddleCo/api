import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fromBinary } from '@bufbuild/protobuf';
import { NativePublicProofBundleV1Schema } from '../packages/typescript/dist/v1alpha2/native_witness_pb.js';
import { ImportPublicProofBundleV1Schema, ImportGenesisWitnessV1Schema, ImportAuthorityWitnessV1Schema } from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import { validatePublicNativeBundle } from '../packages/typescript/dist/v1alpha2/native-witness.js';
import { validatePublicBundle, verifyWitnessPayload } from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { canonicalHybridV1, equal, verifySignature } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
import { statementSigningDigest } from '../packages/typescript/dist/v1alpha2/witness-trust.js';
const f=JSON.parse(readFileSync(new URL('./fixtures/boundary-acceptor-alpha36.json',import.meta.url)));
async function validate(kind,name){
 const b=fromBinary(kind==='native'?NativePublicProofBundleV1Schema:ImportPublicProofBundleV1Schema,Buffer.from(f.vectors[name].wire_hex,'hex'));
 for(const signed of b.statements)await verifySignature(Buffer.from(f.keys.witness.public_key_hex,'hex'),statementSigningDigest(signed.body),signed.signature);
 if(kind==='native')return validatePublicNativeBundle(b);
 for(const {body:s} of b.statements){
  if(s.purpose===1)await verifyWitnessPayload(s,{kind:'genesis',payload:b.genesisWitnesses.find(p=>equal(canonicalHybridV1(ImportGenesisWitnessV1Schema,p),s.canonicalPayload))});
  if(s.purpose===2)await verifyWitnessPayload(s,{kind:'authority',payload:b.authorityWitnesses.find(p=>equal(canonicalHybridV1(ImportAuthorityWitnessV1Schema,p),s.canonicalPayload))});
 }
 validatePublicBundle(b);
}
for(const kind of ['native','import'])for(const purpose of [1,2]){
 const prefix=`${kind}_p${purpose}`;
 test(`${prefix} boundary original revoked accepts`,async()=>{
  await validate(kind,prefix+'_control');await validate(kind,prefix+'_original_revoked');
 });
 for(const [mode,reason] of [['acceptor_revoked','Revoked'],['acceptor_mint_revoked','Revoked'],['forged_acceptor','Signature'],['account_mismatch','GenesisBinding'],['owner_impersonation','Root'],['ordinary_revoked','Revoked']])test(`${prefix} ${kind==='import'&&purpose===1&&mode==='ordinary_revoked'?'ordinary delegated authority unchanged':'boundary guard '+mode}`,async()=>{
  if(kind==='import'&&purpose===1&&mode==='ordinary_revoked'){await validate(kind,prefix+'_'+mode);return;}
  await assert.rejects(()=>validate(kind,prefix+'_'+mode),{reason});await validate(kind,prefix+'_control');
 });
}
