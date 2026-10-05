// Additive maintenance generator: existing signed and wire vectors stay exact.
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createPrivateKey, sign } from 'node:crypto';
import { clone, create, fromBinary, toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as common from '../packages/typescript/dist/common/index.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { hash, keyId, join, u32, integer, sized, utf8 } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
const hex=b=>Buffer.from(b).toString('hex'),bytes=h=>new Uint8Array(Buffer.from(h,'hex')),raw=(n,len=32)=>new Uint8Array(len).fill(n),str=s=>utf8.encode(s);
export function addEffectiveOwnerExpiryVectors(f){
 const key=n=>bytes(f.keys[n].public_key_hex),privateKey=n=>createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),bytes(f.keys[n].seed_hex)]),format:'der',type:'pkcs8'});
 const sig=(n,input)=>new Uint8Array(sign(null,input,privateKey(n))),auth=(n,input)=>({signerKeyId:keyId(key(n)),signature:sig(n,input)});
 const schema=n=>(n.includes('.common.')?common:api)[n.split('.').at(-1)+'Schema'];
 const v=n=>{const r=f.signed_vectors[n]??f.wire_vectors[n];return fromBinary(schema(r.schema),bytes(r.wire_hex));};
 const wire=(n,s,value)=>{f.wire_vectors[n]={schema:s.typeName,wire_hex:hex(toBinary(s,value))};return value;};
 function signed(n,bs,b,ss,field,k,domain){const input=a.signingDigest(domain,bs,b),signature=auth(k,input),value=create(ss,{body:b,[field]:signature});f.signed_vectors[n]={schema:ss.typeName,body_schema:bs.typeName,wire_hex:hex(toBinary(ss,value)),canonical_hex:hex(a.canonicalHybridV1(bs,b)),signing_input_hex:hex(input),domain,public_key_hex:hex(key(k)),signature_hex:hex(signature.signature)};return value;}
 // #346: genuine deferred root and ClaimDeferredHuman, co-signed by old/new
 // authority and next guardians. Before/after endpoints are separately retained.
 const oldRoot=v('owner_history').root.root,guardians=oldRoot.recoveryPolicy.guardians;
 const encKey=n=>join(u32(1),sized(key(n))),recovery=join(u32(oldRoot.recoveryPolicy.threshold),u32(guardians.length),...guardians.map(g=>join(u32(g.kind),u32(g.key.algorithm),sized(g.key.publicKey))),integer(604800n));
 const deadline=1150n,withoutId=join(u32(1),sized(oldRoot.accountUuid),encKey('owner'),recovery,raw(1,1),sized(raw(0xf4)),integer(deadline,true)),id=hash(str('heddle-owner-root-v1'),withoutId),canonical=join(u32(1),sized(id),withoutId.subarray(4)),rootHash=hash(str('heddle-owner-root-v1'),canonical);
 const root=create(api.OwnerRootSchema,{...oldRoot,ownerId:id,claimableDeferredHuman:true,claimableUntilUnixSeconds:deadline,nonce:raw(0xf4)}),guardianNames=guardians.map(g=>Object.keys(f.keys).find(n=>hex(key(n))===hex(g.key.publicKey)));
 const signedRoot=create(api.SignedOwnerRootSchema,{root,authorityProof:auth('owner',rootHash),recoveryKeyProofs:guardianNames.map(n=>auth(n,rootHash))});
 const before=wire('alpha31_deferred_history',api.OwnerHistorySchema,create(api.OwnerHistorySchema,{root:signedRoot,stateHash:rootHash}));
 const transition=create(api.OwnerKeyTransitionSchema,{formatVersion:1,ownerId:id,previousStateHash:rootHash,sequence:1n,kind:4,nextAuthorityKey:{algorithm:1,publicKey:key('rotated_owner')},nextRecoveryPolicy:root.recoveryPolicy,validFromUnixSeconds:1100n,previousKeyValidUntilUnixSeconds:1100n,nonce:raw(0xf5)}),transitionCanonical=join(u32(1),sized(id),sized(rootHash),integer(1n),u32(4),encKey('rotated_owner'),recovery,integer(1100n,true),integer(1100n,true),sized(transition.nonce)),claimHash=hash(str('heddle-owner-key-transition-v1'),transitionCanonical);
 const claim=create(api.SignedOwnerKeyTransitionSchema,{transition,authorizations:[auth('owner',claimHash)],nextAuthorityKeyProof:auth('rotated_owner',claimHash),nextRecoveryKeyProofs:guardianNames.map(n=>auth(n,claimHash))});wire('alpha31_claim',api.SignedOwnerKeyTransitionSchema,claim);
 const after=wire('alpha31_claimed_history',api.OwnerHistorySchema,create(api.OwnerHistorySchema,{root:signedRoot,acceptedTransitions:[claim],stateHash:claimHash}));
 const expiryVectors=[];
 for(const [name,history,deferred,now,start,end,k,expected] of [['claimed_after_deadline',after,false,1200,1200,1900,'rotated_owner','OK'],['unclaimed_after_deadline',before,true,1200,1200,1900,'owner','Scope'],['historical_before_claim',before,true,1050,1000,1140,'owner','OK'],['historical_after_claim',after,false,1120,1100,1900,'rotated_owner','OK']]){
  const identity=clone(api.ImportIdentityV1Schema,v('identity'));identity.ownerId=id;identity.ownerStateHash=history.stateHash;
  const chain=create(api.ImportOwnerChainV1Schema,{spoolGenesisDigest:identity.spoolGenesisDigest,ownerStateHashes:[identity.ownerStateHash]});wire('alpha31_chain_'+name,api.ImportOwnerChainV1Schema,chain);
  const body=clone(api.ImportJobDelegationV1Schema,v('delegation').body);body.identity=identity;body.delegatingPublicKey=key(k);body.parentPermissionDigest=raw(0);body.ownerChainDigest=a.ownerChainDigest(chain);body.notBeforeUnixSeconds=BigInt(start);body.expiresAtUnixSeconds=BigInt(end);
  signed('alpha31_expiry_'+name,api.ImportJobDelegationV1Schema,body,api.SignedImportJobDelegationV1Schema,'delegatingSignature',k,a.DELEGATION_DOMAIN);
  expiryVectors.push({id:name,history:deferred?'alpha31_deferred_history':'alpha31_claimed_history',delegation:'alpha31_expiry_'+name,chain:'alpha31_chain_'+name,owner_key:k,deferred,claimable_until:1150,now_seconds:now,expected,control:'claimed_after_deadline'});
 }
 f.effective_owner_expiry_vectors={root_canonical_hex:hex(canonical),root_digest_hex:hex(rootHash),claim_canonical_hex:hex(transitionCanonical),claim_digest_hex:hex(claimHash),vectors:expiryVectors};
}
