// Additive maintenance generator: existing signed and wire vectors stay exact.
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createPrivateKey, sign } from 'node:crypto';
import { clone, create, fromBinary, toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as common from '../packages/typescript/dist/common/index.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
import * as w from '../packages/typescript/dist/v1alpha2/witness-trust.js';
import { hash, keyId, join, u32, integer, sized, utf8 } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
const hex=b=>Buffer.from(b).toString('hex'),bytes=h=>new Uint8Array(Buffer.from(h,'hex')),raw=(n,len=32)=>new Uint8Array(len).fill(n),str=s=>utf8.encode(s);
export function addAlpha31Vectors(f){
 const key=n=>bytes(f.keys[n].public_key_hex),privateKey=n=>createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),bytes(f.keys[n].seed_hex)]),format:'der',type:'pkcs8'});
 const sig=(n,input)=>new Uint8Array(sign(null,input,privateKey(n))),auth=(n,input)=>({signerKeyId:keyId(key(n)),signature:sig(n,input)});
 const schema=n=>(n.includes('.common.')?common:api)[n.split('.').at(-1)+'Schema'];
 const v=n=>{const r=f.signed_vectors[n]??f.wire_vectors[n];return fromBinary(schema(r.schema),bytes(r.wire_hex));};
 const wire=(n,s,value)=>{f.wire_vectors[n]={schema:s.typeName,wire_hex:hex(toBinary(s,value))};return value;};
 function signed(n,bs,b,ss,field,k,domain){const input=a.signingDigest(domain,bs,b),signature=auth(k,input),value=create(ss,{body:b,[field]:signature});f.signed_vectors[n]={schema:ss.typeName,body_schema:bs.typeName,wire_hex:hex(toBinary(ss,value)),canonical_hex:hex(a.canonicalHybridV1(bs,b)),signing_input_hex:hex(input),domain,public_key_hex:hex(key(k)),signature_hex:hex(signature.signature)};return value;}
 function set(n,b,k='root'){const input=w.setSigningBytes(b),signature=sig(k,input),value=create(common.SignedHostedWitnessSetV1Schema,{body:b,bodyDigest:hash(input),rootSignature:signature});f.signed_vectors[n]={schema:common.SignedHostedWitnessSetV1Schema.typeName,body_schema:common.HostedWitnessSetV1Schema.typeName,wire_hex:hex(toBinary(common.SignedHostedWitnessSetV1Schema,value)),canonical_hex:hex(a.canonicalHybridV1(common.HostedWitnessSetV1Schema,b)),signing_input_hex:hex(input),domain:w.SET_DOMAIN,public_key_hex:hex(key(k)),signature_hex:hex(signature)};return value;}
 const bundle=v('complete_renewed_export');bundle.historyProofs=['genesis_proof','genesis_dev_proof','publication_proof','renewed_publication_proof'].map(v);
 wire('alpha31_bundle',api.ImportPublicProofBundleV1Schema,bundle);
 const negative=[];
 function bad(id,mutate,expected,extra={}){const b=clone(api.ImportPublicProofBundleV1Schema,bundle);mutate(b);const name='alpha31_bundle_'+id;wire(name,api.ImportPublicProofBundleV1Schema,b);negative.push({id,bundle:name,expected,control:'alpha31_bundle',...extra});}
 bad('corrupted_witness_signature',b=>b.statements[0].signature[0]^=1,'Signature');
 bad('corrupted_statement',b=>b.statements[0].body.originalSignaturesDigest[0]^=1,'Signature');
 bad('unknown_root',b=>{const body=clone(common.HostedWitnessSetV1Schema,b.witnessSet.body);body.descriptorRootId='unknown-root';b.witnessSet=set('alpha31_unknown_root_set',body,'wrong_root');},'Root');
 bad('mismatched_root',b=>{const body=clone(common.HostedWitnessSetV1Schema,b.witnessSet.body);body.descriptorRootId='descriptor-root-other';b.witnessSet=set('alpha31_mismatched_root_set',body);},'Root');
 bad('wrong_root_key',b=>b.witnessSet=set('alpha31_wrong_root_key_set',b.witnessSet.body,'wrong_root'),'Signature');
 const highBody=clone(common.HostedWitnessSetV1Schema,bundle.witnessSet.body);highBody.generation=13n;
 const high=clone(api.ImportPublicProofBundleV1Schema,bundle);high.witnessSet=set('alpha31_high_set',highBody);wire('alpha31_high_bundle',api.ImportPublicProofBundleV1Schema,high);
 bad('high_water_rollback',()=>{},'HighWater',{snapshot_bundle:'alpha31_high_bundle',control:'alpha31_high_bundle'});
 bad('missing_inclusion_proof',b=>b.historyProofs=[],'Proof');
 bad('reordered_history',b=>b.delegations.reverse(),'RenewalFork');
 bad('reordered_publications',b=>b.operations.reverse(),'Transition');
 bad('stale_epoch',()=>{},'StaleContext',{snapshot_bundle:'alpha31_bundle',pin_epoch:0});
 const replacementBody=clone(common.HostedWitnessSetV1Schema,bundle.witnessSet.body);replacementBody.descriptorRootId='descriptor-root-2';replacementBody.generation=14n;
 const replacement=clone(api.ImportPublicProofBundleV1Schema,bundle);replacement.witnessSet=set('alpha31_replacement_set',replacementBody,'wrong_root');wire('alpha31_replacement_bundle',api.ImportPublicProofBundleV1Schema,replacement);
 bad('replacement_carries_high_water',b=>{const body=clone(common.HostedWitnessSetV1Schema,replacementBody);body.generation=11n;b.witnessSet=set('alpha31_replacement_rollback_set',body,'wrong_root');},'HighWater',{snapshot_bundle:'alpha31_high_bundle',replacement:true,control:'alpha31_replacement_bundle'});
 bad('replacement_preserves_seal',b=>{const body=clone(common.HostedWitnessSetV1Schema,replacementBody);body.entries.find(e=>e.state===2).archiveRoot=raw(0xfa);b.witnessSet=set('alpha31_replacement_bad_seal',body,'wrong_root');},'Transition',{snapshot_bundle:'alpha31_high_bundle',replacement:true,control:'alpha31_replacement_bundle'});
 bad('clock_rollback',()=>{},'StaleContext',{snapshot_bundle:'alpha31_bundle',snapshot_clock:1350001});
 // Exercise purpose 2 and 4 through the same composition, with exact archived paths.
 const all=clone(api.ImportPublicProofBundleV1Schema,bundle);all.authorityWitnesses=['authority_admission_payload','ownership_admission_payload','resolution_admission_payload'].map(v);all.landingWitnesses=[v('landing_payload')];all.statements.push(...['authority_admission','ownership_admission','resolution_admission','landing_statement'].map(v));all.historyProofs.push(...['authority_proof','ownership_proof','resolution_proof','landing_proof'].map(v));wire('alpha31_all_purposes_bundle',api.ImportPublicProofBundleV1Schema,all);
 f.import_bundle_vectors={positive:['alpha31_bundle','alpha31_all_purposes_bundle'],negative,now_ms:1350000,owner_times:[1100,1200]};
 // #345: exact signed S request, publication S -> S', definitive refusal, new signature.
 const old=v('renew_request_zero'),fresh=clone(api.RenewImportJobRequestSchema,v('renew_request_partial'));
 const parentBody=clone(api.ImportMemberPermissionV1Schema,v('renewed_permission').body);parentBody.nonce=raw(0xf2);
 const parent=signed('alpha31_fresh_permission',api.ImportMemberPermissionV1Schema,parentBody,api.SignedImportMemberPermissionV1Schema,'ownerSignature','owner',a.PERMISSION_DOMAIN);
 const child=clone(api.ImportJobDelegationV1Schema,fresh.renewal.body.replacement.body);child.delegationId=raw(0xf3,16);child.jobPublicKey=key('competing_job');child.jobKeyId=keyId(child.jobPublicKey);child.parentPermissionDigest=a.signedPermissionDigest(parent);
 const delegation=signed('alpha31_fresh_delegation',api.ImportJobDelegationV1Schema,child,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device',a.DELEGATION_DOMAIN);
 const renewalBody=clone(api.ImportJobRenewalV1Schema,fresh.renewal.body);renewalBody.replacement=delegation;
 fresh.renewal=signed('alpha31_fresh_renewal',api.ImportJobRenewalV1Schema,renewalBody,api.SignedImportJobRenewalV1Schema,'delegatingSignature','device',a.RENEWAL_DOMAIN);fresh.clientOperationId='alpha31-new-after-stale-manifest';fresh.proof.memberPermission=parent;fresh.proof.memberPermissions=[v('permission'),parent].sort((x,y)=>Buffer.compare(a.signedPermissionDigest(x),a.signedPermissionDigest(y)));wire('alpha31_fresh_renew_request',api.RenewImportJobRequestSchema,fresh);
 f.stale_manifest_vectors={frozen_request:'renew_request_zero',signed_state:'job_state_empty',publication:'operation_main',fresh_read:'job_state_partial',refusal:{classification:'StaleManifest',definitive:true,settled:false,request_wire_hex:hex(toBinary(api.RenewImportJobRequestSchema,old))},fresh_request:'alpha31_fresh_renew_request',negative:[{id:'refused_bytes_not_settled',expected:'StaleManifest'},{id:'old_candidate_revalidated',expected:'StaleManifest'}]};
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
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){const path=new URL('../tests/fixtures/import-authority-host-witness-v1.json',import.meta.url),f=JSON.parse(readFileSync(path));addAlpha31Vectors(f);writeFileSync(path,JSON.stringify(f,null,2)+'\n');console.log('alpha.31 signed vectors appended; prior entries untouched');}
