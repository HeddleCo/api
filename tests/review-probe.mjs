// Reviewer probes adapted to mandatory manifest/resolver inputs; signed recipes unchanged.
import { readFileSync } from "node:fs";
import * as api from "../packages/typescript/dist/v1alpha2/index.js";
import * as common from "../packages/typescript/dist/common/index.js";
import * as authority from '../packages/typescript/dist/v1alpha2/import-authority.js';
import assert from 'node:assert/strict';
import { create, toBinary } from '@bufbuild/protobuf';
import { sign as nodeSign, createPrivateKey } from 'node:crypto';
import { hash, utf8 } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
const fixture = JSON.parse(readFileSync(new URL("./fixtures/import-authority-host-witness-v1.json", import.meta.url)));
const bytes=v=>new Uint8Array(Buffer.from(v,'hex'));
const schemaFor=name=>(name.includes('.common.')?common:api)[`${name.split('.').at(-1)}Schema`];
function vector(name){const v=fixture.signed_vectors[name]??fixture.wire_vectors[name];return authority.strictDecode(schemaFor(v.schema),bytes(v.wire_hex));}
function ownerContext(now=1100n){return {identity:vector('identity'),ownerPublicKey:bytes(fixture.keys.owner.public_key_hex),ownerChainDigest:bytes(fixture.context.owner_chain_digest_hex),authorityExpiresAtSeconds:2000n,nowUnixSeconds:now,forbiddenJobKeys:['owner','device','witness','next_witness','root'].map(n=>bytes(fixture.keys[n].public_key_hex)),knownJobAssociations:[]};}
const pin={authority:fixture.context.authority,rootId:fixture.context.root_id,publicKey:bytes(fixture.keys.root.public_key_hex),epoch:1n};
const policy=(b)=>{const p=vector('signed_policy');if(b.policies.length!==1||!Buffer.from(toBinary(common.SignedPolicyChainV1Schema??schemaFor(fixture.signed_vectors.signed_policy?.schema??fixture.wire_vectors.signed_policy.schema),b.policies[0])).equals(Buffer.from(toBinary(schemaFor(fixture.signed_vectors.signed_policy?.schema??fixture.wire_vectors.signed_policy.schema),p))))throw new authority.HybridContractError('Signature');};
const reason=async p=>{try{const r=await p;return 'OK '+JSON.stringify([r.ownerCheckTimeUnixSeconds].map(String));}catch(e){return e.reason??String(e);}};
// P1: live aggregate
{
 const b=vector('aggregate_over'),d=b.delegations[0],parent=b.memberPermission;
 const t=d.body.notBeforeUnixSeconds;
 const verified=await authority.verifyImportDelegation(d,b.memberPermission??parent,ownerContext(t));
 const total=d.body.scope.maxResultBytes;
 const seedHex=Object.values(fixture.keys).find(k=>Buffer.from(bytes(k.public_key_hex)).equals(Buffer.from(d.body.jobPublicKey))).seed_hex;
 const key=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(seedHex,'hex')]),format:'der',type:'pkcs8'});
 let sum=0n;const before=create(api.ImportResultManifestV1Schema,{...b.terminalManifest,slots:[]});let index=0;
 for(const o of b.operations){o.body.resultBytes=total;const input=hash(utf8.encode(authority.OPERATION_DOMAIN),authority.canonicalHybridV1(api.DelegatedImportOperationV1Schema,o.body));o.jobSignature.signature=new Uint8Array(nodeSign(null,Buffer.from(input),key));if(index++===0){await authority.verifyNewImportOperation(o,verified,t,before);const slot=b.terminalManifest.slots.find(s=>s.refName===o.body.refName);slot.resultBytes=total;slot.signedOperationDigest=authority.signedOperationDigest(o);before.slots.push(slot);}else{await assert.rejects(authority.verifyNewImportOperation(o,verified,t,before),e=>e.reason==='Scope');}sum+=total;}
 console.log(`PROBE TS live: ${b.operations.length} ops each == total ${total} second refused Scope by verifyNewImportOperation; requested sum ${sum}`);
}
// P2: owner facts
{
 const b=vector('current_export');
 const run=(expiry,effectiveFrom=0n)=>authority.verifyImportBundleWitnesses(b,pin,undefined,1200000n,time=>({...ownerContext(time),authorityExpiresAtSeconds:expiry,effectiveFromUnixSeconds:effectiveFrom,effectiveUntilUnixSeconds:undefined}),policy);
 await run(2000n);await assert.rejects(run(2000n,1200n),e=>e.reason==='Scope');await assert.rejects(run(1299n),e=>e.reason==='Scope');
 console.log('PROBE TS authenticated owner interval/expiry: Scope -> OK');
}
