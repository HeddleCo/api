// Maintenance-only generator. Tests read the checked-in artifact and NEVER
// regenerate expected bytes/signatures. Review every fixture change as contract.
// Published codecs: heddle 0.28.7 / heddle-api 0.31.0-alpha.19.
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { writeFileSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { create, clone, fromBinary, toBinary, getOption } from '@bufbuild/protobuf';
import { encode, decode } from '../packages/typescript/dist/v1alpha2/_collaboration-msgpack.js';
import { SignedRecordSchema, RecordSignatureSchema } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import { ThreadControlAuthoritySchema } from '../packages/typescript/dist/v1alpha2/identity_pb.js';
import { LandThreadRequestSchema } from '../packages/typescript/dist/v1alpha2/thread_pb.js';
import { unarySigningBytes } from '../packages/typescript/dist/signing.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { delegationPreparation, frontierDigest, contentDigest, boundaryOctetsDigest, publicationPayload, signedNativeDigest, authorityEnvelopeDigest, originalSignaturesDigest } from '../packages/typescript/dist/v1alpha2/import-authority.js';
import * as api from '../packages/typescript/dist/v1alpha2/import_authority_pb.js';
import { CommitImportJobRequestSchema, ImportSourceRequestSchema } from '../packages/typescript/dist/v1alpha2/integration_pb.js';
import { MutationResponseSchema } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import * as common from '../packages/typescript/dist/common/hosted_witness_pb.js';
import { canonicalThreadGenesis, threadGenesisId } from '../packages/typescript/dist/v1alpha2/thread-genesis.js';
import { IntegrationService, SyncService } from "../packages/typescript/dist/v1alpha2/services_pb.js";
import { ProtocolCompatibilitySchema, MandatoryProtocolFeatureSchema, rpc_contract } from '../packages/typescript/dist/common/contract_pb.js';
import * as owner from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import { canonicalHybridV1, signingDigest, signedPermissionDigest, signedGenesisDigest, signedDelegationDigest, signedOperationDigest, manifestDigest } from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { setSigningBytes, witnessId, statementSigningDigest, leafDigest, merkleRoot, purposeDomain } from '../packages/typescript/dist/v1alpha2/witness-trust.js';
import { hash, keyId, join, u32, integer, sized, utf8, compare } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
const hex=v=>Buffer.from(v).toString('hex'),raw=(n,s=32)=>new Uint8Array(s).fill(n),str=s=>utf8.encode(s);
const keys=Object.fromEntries(['owner','device','job','renew_job','witness','next_witness','root','wrong_root','guardian_a','guardian_b','direct_job','competing_job'].map((name,i)=>{const seed=raw(i+1),privateKey=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'}),publicKey=new Uint8Array(createPublicKey(privateKey).export({format:'der',type:'spki'}).subarray(-32));return [name,{seed,privateKey,publicKey}];}));
const sig=(name,input)=>new Uint8Array(sign(null,input,keys[name].privateKey));
const auth=(name,input)=>({signerKeyId:keyId(keys[name].publicKey),signature:sig(name,input)});
const artifact={format_version:1,messages:[...Object.values(common),...Object.values(api),CommitImportJobRequestSchema,ImportSourceRequestSchema,ProtocolCompatibilitySchema].filter(v=>v?.kind==='message').map(v=>v.typeName).sort(),descriptors:[],enums:[],protocol:{version:2,feature:1,gated_methods:[...IntegrationService.methods,...SyncService.methods].filter(m=>getOption(m,rpc_contract).mandatoryFeatures.includes(1)).map(m=>`/${m.parent.typeName}/${m.name}`).sort()},keys:Object.fromEntries(Object.entries(keys).map(([n,k])=>[n,{seed_hex:hex(k.seed),public_key_hex:hex(k.publicKey)}])),signed_vectors:{},wire_vectors:{},commitment_vectors:{},raw_commitment_vectors:{},negative_vectors:[],trees:[],retry_scenarios:[]};
for(const schema of [...Object.values(common),...Object.values(api),CommitImportJobRequestSchema,ImportSourceRequestSchema,ProtocolCompatibilitySchema].filter(v=>v?.kind==='message'))artifact.descriptors.push({name:schema.typeName,fields:schema.fields.map(f=>({name:f.name,number:f.number,type:f.message?.typeName??f.enum?.typeName??String(f.scalar),list:f.fieldKind==='list'}))});
for(const schema of [...Object.values(common),...Object.values(api),MandatoryProtocolFeatureSchema].filter(v=>v?.kind==='enum'))artifact.enums.push({name:schema.typeName,values:schema.values.map(v=>({name:v.name,number:v.number}))});
function wire(name,schema,value){artifact.wire_vectors[name]={schema:schema.typeName,wire_hex:hex(toBinary(schema,value))};return value;}
function signed(name,bodySchema,body,signedSchema,signatureField,key,domain){const input=signingDigest(domain,bodySchema,body),signature=auth(key,input),value=create(signedSchema,{body,[signatureField]:signature});artifact.signed_vectors[name]={schema:signedSchema.typeName,body_schema:bodySchema.typeName,wire_hex:hex(toBinary(signedSchema,value)),canonical_hex:hex(canonicalHybridV1(bodySchema,body)),signing_input_hex:hex(input),domain,public_key_hex:hex(keys[key].publicKey),signature_hex:hex(signature.signature)};return value;}
function commitment(name,schema,value,domain){const canonical=canonicalHybridV1(schema,value),digest=hash(str(domain),canonical);artifact.commitment_vectors[name]={schema:schema.typeName,wire_hex:hex(toBinary(schema,value)),domain,canonical_hex:hex(canonical),preimage_hex:hex(join(str(domain),canonical)),digest_hex:hex(digest)};return value;}
function nativeId(format,canonical){const size=new Uint8Array(8);new DataView(size.buffer).setBigUint64(0,BigInt(canonical.length),true);return blake3(join(str(format),size,raw(0,1),canonical));}
execFileSync('cargo',['build','--locked','--manifest-path',new URL('./hybrid-native/Cargo.toml',import.meta.url).pathname],{stdio:'inherit'});
const nativeCodec=resolve(process.env.CARGO_TARGET_DIR??'tools/hybrid-native/target','debug/hybrid-native-conformance');
const codecCall=(args,input)=>execFileSync(nativeCodec,args,{input:hex(input),encoding:'utf8'}).trim();
const nativeEncode=(format,value)=>new Uint8Array(Buffer.from(codecCall(['encode',format],encode(value)),'hex'));
const nativeGenesis=(value,creator)=>new Uint8Array(Buffer.from(codecCall(['encode','heddle-thread-genesis-v1'],canonicalThreadGenesis(value,creator)),'hex'));
function native(format,value,signers=['device']){const canonicalRecord=nativeEncode(format,value);return create(SignedRecordSchema,{format,canonicalRecord,signatures:signers.map(name=>({publicKey:keys[name].publicKey,signature:sig(name,join(str(format),raw(0,1),canonicalRecord))})).sort((a,b)=>compare(a.publicKey,b.publicKey))});}
const seedText=readFileSync(new URL('../tests/fixtures/synthetic-initial-base-v2.txt',import.meta.url),'utf8'),state=decode(new Uint8Array(Buffer.from(seedText.split('canonical=')[1].split('\n')[0],'hex')));
const child=JSON.parse(codecCall(['child-state'],encode(state))),baseStateId=new Uint8Array(Buffer.from(child.base_id_hex,'hex')),stateId=new Uint8Array(Buffer.from(child.id_hex,'hex'));
const capture={state:Array.from(Buffer.from(child.state_hex,'hex')),source_targets:null,visibility:null};
const content=commitment('content',api.ImportContentV1Schema,create(api.ImportContentV1Schema,{formatVersion:1,canonicalCapture:nativeEncode('capture',capture)}),'heddle-import-content-v1');
// Portable existing owner records, using their unchanged canonical contract.
const guardians=['guardian_a','guardian_b'].sort((a,b)=>compare(keyId(keys[a].publicKey),keyId(keys[b].publicKey)));
const encodedKey=name=>join(u32(1),sized(keys[name].publicKey));
const recovery=join(u32(2),u32(2),...guardians.map(name=>join(u32(1),encodedKey(name))),integer(604800n));
const rootWithoutId=join(u32(1),sized(raw(0x21,16)),encodedKey('owner'),recovery,raw(0,1),sized(raw(0x22)),integer(0n,true));
const ownerId=hash(str('heddle-owner-root-v1'),rootWithoutId);
const rootCanonical=join(u32(1),sized(ownerId),rootWithoutId.subarray(4)),stateHash=hash(str('heddle-owner-root-v1'),rootCanonical);
const root=create(owner.OwnerRootSchema,{formatVersion:1,ownerId,accountUuid:raw(0x21,16),authorityKey:{algorithm:1,publicKey:keys.owner.publicKey},recoveryPolicy:{threshold:2,guardians:guardians.map(n=>({kind:1,key:{algorithm:1,publicKey:keys[n].publicKey}}))},nonce:raw(0x22)});
const signedRoot=create(owner.SignedOwnerRootSchema,{root,authorityProof:auth('owner',stateHash),recoveryKeyProofs:guardians.map(n=>auth(n,stateHash))});
wire('owner_history',owner.OwnerHistorySchema,create(owner.OwnerHistorySchema,{root:signedRoot,stateHash}));
artifact.owner_root_canonical_hex=hex(rootCanonical);artifact.owner_root_signing_digest_hex=hex(stateHash);
const spoolUuid=raw(0x23,16),spoolBody=join(sized(spoolUuid),encodedKey('owner')),spoolDigest=hash(str('heddle-spool-owner-genesis-v1'),spoolBody);
const spoolGenesis=wire('spool_owner_genesis',owner.SignedSpoolOwnerGenesisSchema,create(owner.SignedSpoolOwnerGenesisSchema,{genesis:{spoolUuid,ownerPublicKey:{algorithm:1,publicKey:keys.owner.publicKey}},ownerSignature:auth('owner',hash(keys.owner.publicKey,spoolUuid))}));
const identity=wire('identity',api.ImportIdentityV1Schema,create(api.ImportIdentityV1Schema,{spoolUuid,spoolGenesisDigest:spoolDigest,ownerId,ownerAccountUuid:root.accountUuid,ownerStateHash:stateHash}));
const chain=wire('owner_chain',api.ImportOwnerChainV1Schema,create(api.ImportOwnerChainV1Schema,{spoolGenesisDigest:spoolDigest,ownerStateHashes:[stateHash]}));
const chainDigest=signingDigest('heddle-import-owner-chain-v1',api.ImportOwnerChainV1Schema,chain);
artifact.context={identity_wire_hex:hex(toBinary(api.ImportIdentityV1Schema,identity)),owner_chain_digest_hex:hex(chainDigest),authority_expires_at_seconds:2000,now_seconds:1100,now_ms:1100000,authority:'https://weft.example.test',root_id:'descriptor-root-1',root_epoch:1,clock_floor_ms:1000000,logical_job_id_hex:hex(raw(0x24,16)),retry_lineage_id_hex:hex(raw(0x25,16))};
// Existing signed policy v2: fields 1-10 hash, then field 11 in signature.
const policyCanonical=join(u32(1),sized(spoolUuid),sized(raw(0)),integer(0n),integer(1n),u32(0),u32(0),raw(0,1),u32(2),sized(str('max_audience')),u32(1),sized(str('revoked_key_ids')),u32(2),sized(ownerId),sized(stateHash),integer(0n));
const policyStateHash=hash(str('heddle-spool-signed-policy-v2'),policyCanonical);
const policyBody=create(owner.SignedPolicyBodySchema,{formatVersion:1,spoolUuid,expectedHead:{stateHash:raw(0),sequence:0n},sequence:1n,policy:{revokedKeyIds:[]},mergePolicies:[{settingKey:'max_audience',semantics:1},{settingKey:'revoked_key_ids',semantics:2}],ownerId,ownerStateHash:stateHash,policyStateHash});
const policySignatureCanonical=join(policyCanonical,sized(policyStateHash)),policySignatureInput=hash(str('heddle-spool-signed-policy-signature-v2'),policySignatureCanonical);
const policy=wire('signed_policy',owner.SignedSpoolPolicyRecordSchema,create(owner.SignedSpoolPolicyRecordSchema,{body:policyBody,ownerSignature:auth('owner',policySignatureInput)}));
artifact.policy={canonical_hex:hex(policyCanonical),state_hash_hex:hex(policyStateHash),signature_canonical_hex:hex(policySignatureCanonical),signature_input_hex:hex(policySignatureInput)};
const logicalJobId=raw(0x24,16),retryLineageId=raw(0x25,16),genesisRecords={},envelopes={};
const branchLimits=['dev','main'].map((name,i)=>{const envelope=str(`exact-creator-authority-envelope:${name}`),canonical=nativeGenesis({spoolId:'23232323-2323-2323-2323-232323232323',baseStateId,name,intent:'Import this exact branch',owner:{kind:'account',accountId:'21212121-2121-2121-2121-212121212121'},nonce:raw(0x2a+i,16)},keys.device.publicKey),genesisDigest=threadGenesisId(canonical),signature=sig('device',join(str('heddle-thread-genesis-v1\0'),canonical));genesisRecords[name]={canonical,signature,genesisDigest};envelopes[name]=envelope;return create(api.ImportBranchLimitV1Schema,{refName:`refs/heads/${name}`,hashAlgorithm:1,refMode:1,pinnedCommitOid:raw(0x30+i,20),genesisDigest,targetThreadId:genesisDigest,expectedFrontierDigest:frontierDigest(commitment(`expected_frontier_${name}`,api.ImportFrontierV1Schema,create(api.ImportFrontierV1Schema,{formatVersion:1,threadId:genesisDigest}),'heddle-import-frontier-v1')),slotId:0n,maxResultBytes:1000n});});
const scope=wire('scope',api.ImportPermissionScopeV1Schema,create(api.ImportPermissionScopeV1Schema,{provider:'github',sourceUrl:'https://github.com/heddleco/example.git',branches:branchLimits,destinationVersion:raw(0x41),optionsDigest:hash(str('heddle-import-conversion-options-v1'),sized(str('git-converter/1.0')),sized(new Uint8Array())),converterVersion:'git-converter/1.0',maxOperations:2,maxResultBytes:2000n}));
const permissionBody=create(api.ImportMemberPermissionV1Schema,{formatVersion:1,identity,logicalJobId,retryLineageId,subjectPublicKey:keys.device.publicKey,purpose:1,scope,notBeforeUnixSeconds:1000n,expiresAtUnixSeconds:1300n,cancellationId:raw(0x50),ownerChainDigest:chainDigest,nonce:raw(0x51)});
const permission=signed('permission',api.ImportMemberPermissionV1Schema,permissionBody,api.SignedImportMemberPermissionV1Schema,'ownerSignature','owner','heddle-import-member-permission-v1');
const permissionDigest=signedPermissionDigest(permission),genesisProofs={};
for(const name of Object.keys(envelopes))envelopes[name]=join(str('heddle-signed-import-member-permission-v1\0'),canonicalHybridV1(api.SignedImportMemberPermissionV1Schema,permission));
const renewedPermissionBody=clone(api.ImportMemberPermissionV1Schema,permissionBody);renewedPermissionBody.notBeforeUnixSeconds=1200n;renewedPermissionBody.expiresAtUnixSeconds=1900n;renewedPermissionBody.nonce=raw(0x81);renewedPermissionBody.scope.branches=renewedPermissionBody.scope.branches.filter(b=>b.refName.endsWith('dev'));renewedPermissionBody.scope.maxOperations=1;renewedPermissionBody.scope.maxResultBytes=1000n;
const renewedPermission=signed('renewed_permission',api.ImportMemberPermissionV1Schema,renewedPermissionBody,api.SignedImportMemberPermissionV1Schema,'ownerSignature','owner','heddle-import-member-permission-v1');
for(const [name,g] of Object.entries(genesisRecords)){const body=create(api.ImportGenesisAuthorityV1Schema,{formatVersion:1,identity,genesisDigest:g.genesisDigest,originalCreatorSignature:g.signature,creatorPublicKey:keys.device.publicKey,creatorAuthorityEnvelopeDigest:hash(envelopes[name]),parentPermissionDigest:permissionDigest,ownerChainDigest:chainDigest});genesisProofs[name]=signed(`genesis_${name}`,api.ImportGenesisAuthorityV1Schema,body,api.SignedImportGenesisAuthorityV1Schema,'creatorSignature','device','heddle-import-genesis-authority-v1');}
artifact.originals=Object.fromEntries(Object.entries(genesisRecords).map(([n,g])=>[n,{canonical_hex:hex(g.canonical),signature_hex:hex(g.signature),envelope_hex:hex(envelopes[n]),genesis_digest_hex:hex(g.genesisDigest)}]));
const delegationBody=create(api.ImportJobDelegationV1Schema,{formatVersion:1,identity,delegationId:raw(0x52,16),logicalJobId,retryLineageId,jobPublicKey:keys.job.publicKey,jobKeyId:keyId(keys.job.publicKey),delegatingPublicKey:keys.device.publicKey,parentPermissionDigest:permissionDigest,ownerChainDigest:chainDigest,purpose:1,scope,branchManifest:scope.branches.map(b=>({limit:b,genesisAuthorityDigest:signedGenesisDigest(genesisProofs[b.refName.split('/').at(-1)])})),notBeforeUnixSeconds:1000n,expiresAtUnixSeconds:1300n,cancellationId:raw(0x53),predecessorDelegationDigest:raw(0)});
const delegation=signed('delegation',api.ImportJobDelegationV1Schema,delegationBody,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device','heddle-import-job-delegation-v1');
// api#321: exact frozen preparation and browser-completed Commit vectors.
const preparation=wire('commit_preparation',api.PrepareImportJobResponseSchema,create(api.PrepareImportJobResponseSchema,{
 proposal:commitment('preparation',api.ImportJobPreparationV1Schema,delegationPreparation(delegationBody),'heddle-import-job-preparation-v1'),
 preparedAtUnixSeconds:1000n,reservationExpiresAtUnixSeconds:4600n,maxValidityDurationSeconds:300n,clockSkewAllowanceSeconds:100n,
}));
artifact.commit_vectors={passing:['delegation'],negative:[]};
const commitSigned=(name,body)=>signed(name,api.ImportJobDelegationV1Schema,body,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device','heddle-import-job-delegation-v1');
function commitNegative(id,body,expected,check,extra={}){
 const value=commitSigned(`commit_${id}`,body);
 artifact.commit_vectors.negative.push({id,delegation:`commit_${id}`,expected,first_failing_check:check,control:'delegation',...extra});
 return value;
}
function mutateLeaf(value,field){
 if(field.fieldKind==='enum'||field.scalar===13)value[field.localName]++;
 else if(field.scalar===12){value[field.localName]=value[field.localName].slice();value[field.localName][0]^=1;}
 else if(field.scalar===9)value[field.localName]+='-changed';
 else value[field.localName]+=1n;
}
function frozenLeaves(schema,value,path=[]){
 return schema.fields.flatMap(field=>{
  const next=[...path,field.localName],v=value[field.localName];
  if(field.fieldKind==='message')return frozenLeaves(field.message,v,next);
  if(field.fieldKind==='list')return v.flatMap((item,i)=>frozenLeaves(field.message,item,[...next,i]));
  return [{path:next,field}];
 });
}
for(const {path,field} of frozenLeaves(api.ImportJobPreparationV1Schema,preparation.proposal)){
 const body=clone(api.ImportJobDelegationV1Schema,delegationBody);let target=body;
 for(const part of path.slice(0,-1))target=target[part];mutateLeaf(target,field);
 commitNegative(`frozen_${path.join('_')}`,body,'PreparedFields',`frozen.${path.join('.')}`);
}
for(const field of api.ImportBranchLimitV1Schema.fields){
 const body=clone(api.ImportJobDelegationV1Schema,delegationBody);mutateLeaf(body.branchManifest[0].limit,field);
 commitNegative(`frozen_manifest_${field.name}`,body,'PreparedFields',`frozen.branch_manifest.limit.${field.name}`);
}
for(const [id,mutate] of [
 ['branch_removed',b=>b.scope.branches.pop()],['branch_reordered',b=>b.scope.branches.reverse()],
 ['manifest_removed',b=>b.branchManifest.pop()],['manifest_reordered',b=>b.branchManifest.reverse()],
]){const b=clone(api.ImportJobDelegationV1Schema,delegationBody);mutate(b);commitNegative(`frozen_${id}`,b,'PreparedFields',`frozen.${id}`);}
// Rebind every signed genesis reference when a case gets a different parent.
function commitParentInputs(name,parentBody,childBody=delegationBody){
 const parent=signed(`commit_${name}_parent`,api.ImportMemberPermissionV1Schema,parentBody,api.SignedImportMemberPermissionV1Schema,'ownerSignature','owner','heddle-import-member-permission-v1');
 const body=clone(api.ImportJobDelegationV1Schema,childBody),geneses=[];
 body.parentPermissionDigest=signedPermissionDigest(parent);
 const envelope=join(str('heddle-signed-import-member-permission-v1\0'),canonicalHybridV1(api.SignedImportMemberPermissionV1Schema,parent));
 for(const [i,m] of body.branchManifest.entries()){
  const branch=m.limit.refName.split('/').at(-1),g=clone(api.ImportGenesisAuthorityV1Schema,genesisProofs[branch].body);
  g.parentPermissionDigest=body.parentPermissionDigest;g.creatorAuthorityEnvelopeDigest=hash(envelope);
  const genesisName=`commit_${name}_genesis_${branch}`;
  const proof=signed(genesisName,api.ImportGenesisAuthorityV1Schema,g,api.SignedImportGenesisAuthorityV1Schema,'creatorSignature','device','heddle-import-genesis-authority-v1');
  geneses.push(genesisName);body.branchManifest[i].genesisAuthorityDigest=signedGenesisDigest(proof);
 }
 return {body,inputs:{parent:`commit_${name}_parent`,geneses}};
}
// Duration and early-start violate only host bounds, not parent containment.
const wideParent=clone(api.ImportMemberPermissionV1Schema,permissionBody);wideParent.notBeforeUnixSeconds=800n;wideParent.expiresAtUnixSeconds=1400n;
const wideCommit=commitParentInputs('wide',wideParent);
commitSigned('commit_wide_control',wideCommit.body);
for(const [id,start,end] of [['duration',1000n,1301n],['too_early',899n,1199n],['too_late',1201n,1300n],['expired',1000n,1100n],['empty',1200n,1199n]]){
 const useWide=['duration','too_early'].includes(id),b=clone(api.ImportJobDelegationV1Schema,useWide?wideCommit.body:delegationBody);
 b.notBeforeUnixSeconds=start;b.expiresAtUnixSeconds=end;
 commitNegative(`window_${id}`,b,'ValidityBounds',`window.${id}`,useWide?{...wideCommit.inputs,control:'commit_wide_control'}:{});
}
const future=clone(api.ImportJobDelegationV1Schema,delegationBody);future.notBeforeUnixSeconds=1200n;
const futureDelegation=commitSigned('commit_future_within_skew',future);artifact.commit_vectors.passing.push('commit_future_within_skew');
commitNegative('parent_absent',delegationBody,'ImportPermission','parent.required',{parent:null});
// Child and genesis stay mutually consistent; only the supplied signed parent differs.
const equivalentParent=clone(api.ImportMemberPermissionV1Schema,permissionBody);equivalentParent.nonce=raw(0x90);
signed('commit_equivalent_parent',api.ImportMemberPermissionV1Schema,equivalentParent,api.SignedImportMemberPermissionV1Schema,'ownerSignature','owner','heddle-import-member-permission-v1');
commitNegative('parent_ref',delegationBody,'Scope','parent.exact_signed_digest',{parent:'commit_equivalent_parent',control_parent:'permission'});
const narrowParent=clone(api.ImportMemberPermissionV1Schema,permissionBody);narrowParent.scope.maxResultBytes=1999n;narrowParent.scope.branches[0].maxResultBytes=999n;
const narrow=commitParentInputs('narrow',narrowParent);
// The negative's child retains its frozen larger scope; its control fits the same parent.
const narrowControl=clone(api.ImportJobDelegationV1Schema,narrow.body);narrowControl.scope=clone(api.ImportPermissionScopeV1Schema,narrowParent.scope);
narrowControl.branchManifest.forEach((m,i)=>m.limit=narrowControl.scope.branches[i]);
commitSigned('commit_narrow_control',narrowControl);
const narrowPreparation=clone(api.PrepareImportJobResponseSchema,preparation);narrowPreparation.proposal=delegationPreparation(narrowControl);
wire('commit_narrow_preparation',api.PrepareImportJobResponseSchema,narrowPreparation);
commitNegative('parent_amplification',narrow.body,'Scope','parent.non_amplification',{...narrow.inputs,control:'commit_narrow_control',control_preparation:'commit_narrow_preparation'});
const badGenesis=clone(api.ImportJobDelegationV1Schema,delegationBody);badGenesis.branchManifest[0].genesisAuthorityDigest=raw(0x91);
commitNegative('genesis_digest',badGenesis,'GenesisBinding','genesis.exact_signed_digest');
const substitutedGenesis=clone(api.ImportJobDelegationV1Schema,delegationBody);substitutedGenesis.branchManifest[0].genesisAuthorityDigest=signedGenesisDigest(genesisProofs.main);
commitNegative('genesis_branch',substitutedGenesis,'GenesisBinding','genesis.prepared_branch');
const invalidSignature=clone(api.SignedImportJobDelegationV1Schema,delegation);invalidSignature.delegatingSignature.signature[0]^=1;
wire('commit_bad_signature',api.SignedImportJobDelegationV1Schema,invalidSignature);
artifact.commit_vectors.negative.push({id:'bad_signature',delegation:'commit_bad_signature',expected:'Signature',first_failing_check:'delegation.signature',control:'delegation'});
// Keep owner, parent and child current on both sides of the exclusive reservation boundary.
const reservationParent=clone(api.ImportMemberPermissionV1Schema,permissionBody);reservationParent.expiresAtUnixSeconds=4900n;
const reservation=commitParentInputs('reservation',reservationParent);reservation.body.notBeforeUnixSeconds=4500n;reservation.body.expiresAtUnixSeconds=4800n;
commitSigned('commit_reservation',reservation.body);
artifact.commit_vectors.negative.push({id:'reservation_expired',delegation:'commit_reservation',expected:'Expired',first_failing_check:'reservation.exclusive_expiry',...reservation.inputs,now_seconds:4600,authority_expires_at_seconds:5000,control:'commit_reservation',control_now_seconds:4599});

const directOriginals=[],directGenes=[],directEnvelopes=[];
const directBody=clone(api.ImportJobDelegationV1Schema,delegationBody);directBody.delegatingPublicKey=keys.owner.publicKey;directBody.parentPermissionDigest=raw(0);directBody.jobPublicKey=keys.direct_job.publicKey;directBody.jobKeyId=keyId(keys.direct_job.publicKey);directBody.logicalJobId=raw(0x54,16);directBody.delegationId=raw(0x55,16);
directBody.scope.branches=directBody.scope.branches.map((b,i)=>{const next=clone(api.ImportBranchLimitV1Schema,b),canonical=nativeGenesis({spoolId:'23232323-2323-2323-2323-232323232323',baseStateId,name:b.refName,intent:'Direct owner import',owner:{kind:'account',accountId:'21212121-2121-2121-2121-212121212121'},nonce:raw(0x7d+i,16)},keys.owner.publicKey);next.genesisDigest=threadGenesisId(canonical);next.targetThreadId=next.genesisDigest;const g=create(api.ImportGenesisAuthorityV1Schema,{formatVersion:1,identity,genesisDigest:next.genesisDigest,originalCreatorSignature:sig('owner',join(str('heddle-thread-genesis-v1\0'),canonical)),creatorPublicKey:keys.owner.publicKey,creatorAuthorityEnvelopeDigest:hash(str('direct active owner authority')),parentPermissionDigest:raw(0),ownerChainDigest:chainDigest});const proof=signed(`direct_genesis_${i}`,api.ImportGenesisAuthorityV1Schema,g,api.SignedImportGenesisAuthorityV1Schema,'creatorSignature','owner','heddle-import-genesis-authority-v1');directOriginals.push(create(SignedRecordSchema,{format:'heddle-thread-genesis-v1',canonicalRecord:canonical,signatures:[{publicKey:keys.owner.publicKey,signature:g.originalCreatorSignature}]}));directGenes.push(proof);directEnvelopes.push(str('direct active owner authority'));directBody.branchManifest[i]=create(api.ImportBranchManifestV1Schema,{limit:next,genesisAuthorityDigest:signedGenesisDigest(proof)});return next;});
signed('direct_owner',api.ImportJobDelegationV1Schema,directBody,api.SignedImportJobDelegationV1Schema,'delegatingSignature','owner','heddle-import-job-delegation-v1');
const converted={};
for(const b of branchLimits){const name=b.refName.split('/').at(-1),operation=native('heddle-thread-operation-v1',{version:1,thread:Array.from(b.targetThreadId),parents:[],publisher:Array.from(keys.job.publicKey),body:{kind:'capture',canonical:{result:capture,author:{kind:'local_key'}}}},['job']);converted[name]=operation;commitment(`result_frontier_${name}`,api.ImportFrontierV1Schema,create(api.ImportFrontierV1Schema,{formatVersion:1,threadId:b.targetThreadId,operationIds:[nativeId(operation.format,operation.canonicalRecord)]}),'heddle-import-frontier-v1');wire(`converted_${name}`,SignedRecordSchema,operation);}
function operationBody(b,d,physical=raw(0x56,16)){return create(api.DelegatedImportOperationV1Schema,{formatVersion:1,spoolUuid,spoolGenesisDigest:spoolDigest,logicalJobId:d.body.logicalJobId,retryLineageId:d.body.retryLineageId,physicalOperationId:physical,delegationDigest:signedDelegationDigest(d),refName:b.refName,slotId:b.slotId,hashAlgorithm:b.hashAlgorithm,observedCommitOid:b.pinnedCommitOid,genesisDigest:b.genesisDigest,targetThreadId:b.targetThreadId,expectedFrontierDigest:b.expectedFrontierDigest,resultingFrontierDigest:new Uint8Array(Buffer.from(artifact.commitment_vectors[`result_frontier_${b.refName.split('/').at(-1)}`].digest_hex,'hex')),resultingContentDigest:contentDigest(content),resultBytes:BigInt(content.canonicalCapture.length),optionsDigest:d.body.scope.optionsDigest,converterVersion:d.body.scope.converterVersion});}
const operations=Object.fromEntries(scope.branches.map(b=>{const n=b.refName.split('/').at(-1),body=operationBody(b,delegation);return [n,signed(`operation_${n}`,api.DelegatedImportOperationV1Schema,body,api.SignedDelegatedImportOperationV1Schema,'jobSignature','job','heddle-delegated-import-operation-v1')];}));
signed('commit_future_operation',api.DelegatedImportOperationV1Schema,operationBody(scope.branches[1],futureDelegation),api.SignedDelegatedImportOperationV1Schema,'jobSignature','job','heddle-delegated-import-operation-v1');
const committedSlot=o=>({refName:o.body.refName,slotId:o.body.slotId,signedOperationDigest:signedOperationDigest(o),resultingFrontierDigest:o.body.resultingFrontierDigest,resultBytes:o.body.resultBytes});
const partialManifest=wire('partial_manifest',api.ImportResultManifestV1Schema,create(api.ImportResultManifestV1Schema,{formatVersion:1,logicalJobId,retryLineageId,slots:[committedSlot(operations.main)]}));
const nextBody=clone(api.ImportJobDelegationV1Schema,delegationBody);nextBody.delegationId=raw(0x59,16);nextBody.cancellationId=raw(0x5c);nextBody.parentPermissionDigest=signedPermissionDigest(renewedPermission);nextBody.jobPublicKey=keys.renew_job.publicKey;nextBody.jobKeyId=keyId(keys.renew_job.publicKey);nextBody.predecessorDelegationDigest=signedDelegationDigest(delegation);nextBody.notBeforeUnixSeconds=1200n;nextBody.expiresAtUnixSeconds=1800n;nextBody.scope.branches=nextBody.scope.branches.filter(b=>b.refName.endsWith('dev'));nextBody.scope.maxOperations=1;nextBody.scope.maxResultBytes=1000n;nextBody.branchManifest=nextBody.branchManifest.filter(b=>b.limit.refName.endsWith('dev'));
const next=signed('renewed_delegation',api.ImportJobDelegationV1Schema,nextBody,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device','heddle-import-job-delegation-v1');
const renewalBody=create(api.ImportJobRenewalV1Schema,{formatVersion:1,predecessorDelegationDigest:signedDelegationDigest(delegation),expectedAuthorityEpoch:1n,committedManifestDigest:manifestDigest(partialManifest),replacement:next});
const renewal=signed('renewal',api.ImportJobRenewalV1Schema,renewalBody,api.SignedImportJobRenewalV1Schema,'delegatingSignature','device','heddle-import-job-renewal-v1');
const competingBody=clone(api.ImportJobDelegationV1Schema,nextBody);competingBody.delegationId=raw(0x5b,16);competingBody.jobPublicKey=keys.competing_job.publicKey;competingBody.jobKeyId=keyId(keys.competing_job.publicKey);
const competing=signed('competing_delegation',api.ImportJobDelegationV1Schema,competingBody,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device','heddle-import-job-delegation-v1');
const competingRenewal=clone(api.ImportJobRenewalV1Schema,renewalBody);competingRenewal.replacement=competing;
signed('competing_renewal',api.ImportJobRenewalV1Schema,competingRenewal,api.SignedImportJobRenewalV1Schema,'delegatingSignature','device','heddle-import-job-renewal-v1');
const renewedOperation=signed('renewed_operation_dev',api.DelegatedImportOperationV1Schema,operationBody(nextBody.scope.branches[0],next,raw(0x5a,16)),api.SignedDelegatedImportOperationV1Schema,'jobSignature','renew_job','heddle-delegated-import-operation-v1');
const terminalManifest=wire('terminal_manifest',api.ImportResultManifestV1Schema,create(api.ImportResultManifestV1Schema,{formatVersion:1,logicalJobId,retryLineageId,slots:[committedSlot(renewedOperation),committedSlot(operations.main)]}));
const publication=wire('publication',api.ImportPublicationWitnessV1Schema,create(api.ImportPublicationWitnessV1Schema,{formatVersion:1,signedOperationDigest:signedOperationDigest(operations.main),delegationDigest:signedDelegationDigest(delegation),logicalJobId,retryLineageId,physicalOperationId:operations.main.body.physicalOperationId,refName:operations.main.body.refName,slotId:0n,hashAlgorithm:1,observedCommitOid:operations.main.body.observedCommitOid,expectedFrontierDigest:operations.main.body.expectedFrontierDigest,resultingFrontierDigest:operations.main.body.resultingFrontierDigest,terminalManifestDigest:manifestDigest(partialManifest)}));
const statements=[];
function statement(name,purpose,payload,transaction=0x60,authority=signedDelegationDigest(delegation),originalSignatures=hash(operations.main.jobSignature.signature),observed=1100000n,boundaryAcceptance){const body=create(common.HostedWitnessStatementV1Schema,{formatVersion:1,executorId:witnessId(keys.witness.publicKey),purpose,spoolUuid,spoolGenesisDigest:spoolDigest,ownerId,ownerStateHash:stateHash,policyStateHash,policySequence:1n,basis:boundaryAcceptance?2:1,boundaryAcceptance,publisherKeyId:keyId(keys.device.publicKey),authorityDigest:authority,originalSignaturesDigest:originalSignatures,hostTransactionId:raw(transaction,16),admissionOrder:BigInt(transaction),observedAtUnixMillis:observed,canonicalPayload:payload});const input=statementSigningDigest(body),signature=sig('witness',input),value=create(common.SignedHostedWitnessStatementV1Schema,{body,signature});artifact.signed_vectors[name]={schema:common.SignedHostedWitnessStatementV1Schema.typeName,body_schema:common.HostedWitnessStatementV1Schema.typeName,wire_hex:hex(toBinary(common.SignedHostedWitnessStatementV1Schema,value)),canonical_hex:hex(canonicalHybridV1(common.HostedWitnessStatementV1Schema,body)),signing_input_hex:hex(input),domain:purposeDomain(purpose),public_key_hex:hex(keys.witness.publicKey),signature_hex:hex(signature)};return value;}
const originalGeneses=Object.fromEntries(Object.entries(genesisRecords).map(([name,g])=>[name,create(SignedRecordSchema,{format:'heddle-thread-genesis-v1',canonicalRecord:g.canonical,signatures:[{publicKey:keys.device.publicKey,signature:g.signature}]})]));
// api#327: caller choices, complete initial submission and signed ref fallback.
artifact.submission_vectors={changed_preparations:[],commit_negatives:[],ref_negatives:[],scope_refusals:[]};
const destination={id:'23232323-2323-2323-2323-232323232323'};
const config=wire('import_configuration',api.GetImportConfigurationResponseSchema,create(api.GetImportConfigurationResponseSchema,{
 converters:[{converterVersion:scope.converterVersion,optionsEncoding:'heddle-import-options-empty-v1',canonicalOptions:[new Uint8Array()],defaultOptions:new Uint8Array()}],
 limits:{maxBranches:256,maxOperations:256,maxResultBytes:1n<<30n,maxBranchResultBytes:1n<<30n},
}));
const prepareRequest=wire('prepare_request',api.PrepareImportJobRequestSchema,create(api.PrepareImportJobRequestSchema,{clientOperationId:'prepare-327',destination,identity,proposedScope:scope,retryLineageId}));
const emptyTokenRequest=clone(api.PrepareImportJobRequestSchema,prepareRequest);emptyTokenRequest.proposedScope.destinationVersion=new Uint8Array();wire('prepare_issue_token',api.PrepareImportJobRequestSchema,emptyTokenRequest);
for(const {path,field} of frozenLeaves(api.ImportPermissionScopeV1Schema,scope)){
 const changed=clone(api.PrepareImportJobResponseSchema,preparation);let target=changed.proposal.scope;
 for(const part of path.slice(0,-1))target=target[part];mutateLeaf(target,field);
 const name=`prepare_changed_${path.join('_')}`;wire(name,api.PrepareImportJobResponseSchema,changed);
 artifact.submission_vectors.changed_preparations.push({id:path.join('.'),response:name,expected:'PreparedFields',control:'commit_preparation'});
}
const initialProof=create(api.ImportPublicProofBundleV1Schema,{formatVersion:1,ownerGenesis:spoolGenesis,ownerHistories:[create(owner.OwnerHistorySchema,{root:signedRoot,stateHash})],memberPermission:permission,memberPermissions:[permission],genesisAuthorities:Object.values(genesisProofs),delegations:[delegation],originalGeneses:Object.values(originalGeneses),creatorAuthorityEnvelopes:Object.values(envelopes),ownerChain:chain});
const commitRequest=wire('commit_request',CommitImportJobRequestSchema,create(CommitImportJobRequestSchema,{clientOperationId:'commit-327',destination,proof:initialProof,source:{connection:{id:'26262626-2626-2626-2626-262626262626'},providerRepositoryId:'327',cloneUrl:scope.sourceUrl,name:'heddleco/example',private:true,installationId:'123'},initialBaseState:new Uint8Array(Buffer.from(seedText.split('canonical=')[1].split('\n')[0],'hex'))}));
const withoutBase=clone(CommitImportJobRequestSchema,commitRequest);withoutBase.initialBaseState=new Uint8Array();wire('commit_hosted_base',CommitImportJobRequestSchema,withoutBase);
const publicSource=clone(CommitImportJobRequestSchema,commitRequest);publicSource.source={...publicSource.source,connection:undefined,providerRepositoryId:scope.sourceUrl,private:false,installationId:''};wire('commit_public_source',CommitImportJobRequestSchema,publicSource);
for(const [id,mutate,expected] of [
 ['missing_source',r=>r.source=undefined,'SourceSelection'],
 ['source_url',r=>r.source.cloneUrl='https://other.example.test/repo.git','SourceSelection'],
 ['unconnected_installation',r=>r.source.installationId='123','SourceSelection'],
 ['unconnected_repository',r=>{r.source.connection=undefined;r.source.installationId='';r.source.private=false;},'SourceSelection'],
 ['missing_installation',r=>r.source.installationId='','SourceSelection'],
 ['base_too_large',r=>r.initialBaseState=raw(0,4097),'Bounds'],
 ['missing_original',r=>r.proof.originalGeneses.pop(),'GenesisBinding'],
 ['reordered_originals',r=>r.proof.originalGeneses.reverse(),'GenesisBinding'],
 ['envelope_substitution',r=>r.proof.creatorAuthorityEnvelopes[0]=str('different exact envelope'),'GenesisBinding'],
 ['renewal_as_commit',r=>r.proof.delegations[0].body.predecessorDelegationDigest=raw(1),'Canonical'],
]){const control=id==='unconnected_installation'?'commit_public_source':'commit_request';const r=clone(CommitImportJobRequestSchema,id==='unconnected_installation'?publicSource:commitRequest);mutate(r);const name=`submission_${id}`;wire(name,CommitImportJobRequestSchema,r);artifact.submission_vectors.commit_negatives.push({id,request:name,expected,control});}
const privateSource=clone(CommitImportJobRequestSchema,publicSource);privateSource.source.private=true;
wire('submission_private_without_connection',CommitImportJobRequestSchema,privateSource);
artifact.submission_vectors.commit_negatives.push({id:'private_without_connection',request:'submission_private_without_connection',expected:'SourceSelection',control:'commit_public_source'});
wire('commit_response',MutationResponseSchema,create(MutationResponseSchema,{receipt:{clientOperationId:commitRequest.clientOperationId,outcome:{case:'pendingOperation',value:{spool:destination,id:'25252525-2525-2525-2525-252525252525'}}}}));
wire('import_source_misuse',ImportSourceRequestSchema,create(ImportSourceRequestSchema,{clientOperationId:'commit-327',destination,source:commitRequest.source,initialBaseState:commitRequest.initialBaseState}));
for(const [id,mutate,reason] of [
 ['converter',s=>s.converterVersion='unsupported/1',2],
 ['options',s=>s.optionsDigest=raw(0x91),3],
 ['budget',s=>s.maxOperations=3,4],
 ['destination',s=>s.destinationVersion=raw(0x92),5],
 ['invalid_scope',s=>s.optionsDigest=new Uint8Array(),1],
]){const s=clone(api.ImportPermissionScopeV1Schema,scope);mutate(s);const name=`scope_refusal_${id}`;wire(name,api.ImportPermissionScopeV1Schema,s);const limits=clone(api.GetImportConfigurationResponseSchema,config);limits.limits.maxOperations=2;wire('import_configuration_tight',api.GetImportConfigurationResponseSchema,limits);artifact.submission_vectors.scope_refusals.push({id,scope:name,reason,configuration:id==='budget'?'import_configuration_tight':'import_configuration',control:'scope'});wire(`prepare_refusal_${id}`,api.PrepareImportJobResponseSchema,create(api.PrepareImportJobResponseSchema,{refusal:{reason,field:'proposed_scope'}}));}
const observeScope=clone(api.ImportPermissionScopeV1Schema,scope);for(const b of observeScope.branches){b.refMode=2;b.pinnedCommitOid=new Uint8Array();b.refDisclosure=1;}
wire('scope_observe_disclosed',api.ImportPermissionScopeV1Schema,observeScope);
// Direct-owner pair avoids independent member-parent containment masking disclosure.
for(const [name,disclosure] of [['observe',1],['observe_undisclosed',0]]){
 const b=clone(api.ImportJobDelegationV1Schema,directBody);
 b.scope.branches.forEach(branch=>{branch.refMode=2;branch.pinnedCommitOid=new Uint8Array();branch.refDisclosure=1;});
 b.scope.branches[0].refDisclosure=disclosure;
 b.branchManifest.forEach((m,i)=>m.limit=b.scope.branches[i]);
 const child=signed(`submission_${name}_delegation`,api.ImportJobDelegationV1Schema,b,api.SignedImportJobDelegationV1Schema,'delegatingSignature','owner','heddle-import-job-delegation-v1');
 wire(`submission_${name}_preparation`,api.PrepareImportJobResponseSchema,create(api.PrepareImportJobResponseSchema,{...preparation,proposal:delegationPreparation(b)}));
 const proof=create(api.ImportPublicProofBundleV1Schema,{formatVersion:1,ownerGenesis:spoolGenesis,ownerHistories:initialProof.ownerHistories,genesisAuthorities:directGenes,delegations:[child],originalGeneses:directOriginals,creatorAuthorityEnvelopes:directEnvelopes,ownerChain:chain});
 wire(`submission_${name}_request`,CommitImportJobRequestSchema,create(CommitImportJobRequestSchema,{...commitRequest,proof}));
}
const undisclosed=clone(api.ImportPermissionScopeV1Schema,observeScope);undisclosed.branches[0].refDisclosure=0;wire('scope_observe_undisclosed',api.ImportPermissionScopeV1Schema,undisclosed);
artifact.submission_vectors.ref_negatives.push({id:'observe_without_disclosure',scope:'scope_observe_undisclosed',expected:'RefDisclosure',control:'scope_observe_disclosed'});
const genesisPayload=wire('genesis_payload',api.ImportGenesisWitnessV1Schema,create(api.ImportGenesisWitnessV1Schema,{formatVersion:1,binding:genesisProofs.main,originalGenesis:originalGeneses.main,creatorAuthorityEnvelope:envelopes.main}));
commitment('genesis_payload',api.ImportGenesisWitnessV1Schema,genesisPayload,'heddle-import-genesis-witness-payload-v1');
statements.push(statement('genesis_admission',1,canonicalHybridV1(api.ImportGenesisWitnessV1Schema,genesisPayload),0x60,signedGenesisDigest(genesisProofs.main),originalSignaturesDigest([originalGeneses.main])));
const devGenesisPayload=wire('genesis_dev_payload',api.ImportGenesisWitnessV1Schema,create(api.ImportGenesisWitnessV1Schema,{formatVersion:1,binding:genesisProofs.dev,originalGenesis:originalGeneses.dev,creatorAuthorityEnvelope:envelopes.dev}));
commitment('genesis_dev_payload',api.ImportGenesisWitnessV1Schema,devGenesisPayload,'heddle-import-genesis-witness-payload-v1');
const devGenesisAdmission=statement('genesis_dev_admission',1,canonicalHybridV1(api.ImportGenesisWitnessV1Schema,devGenesisPayload),0x6b,signedGenesisDigest(genesisProofs.dev),originalSignaturesDigest([originalGeneses.dev]));
const attachment=create(owner.MintRootAttachmentSchema,{formatVersion:1,accountUuid:root.accountUuid,ownerStateHash:stateHash,ownerKey:{algorithm:1,publicKey:keys.owner.publicKey},mintRootKey:{algorithm:1,publicKey:keys.device.publicKey},notBeforeUnixSeconds:1000n,expiresAtUnixSeconds:2000n,nonce:raw(0x86)});
const attachmentCanonical=join(u32(1),sized(root.accountUuid),sized(stateHash),integer(0n),encodedKey('owner'),encodedKey('device'),integer(1000n,true),integer(2000n,true),sized(raw(0x86)));
const signedAttachment=create(owner.SignedOwnerMintRootAttachmentSchema,{attachment,ownerSignature:auth('owner',hash(str('heddle-mint-root-attachment-v1'),attachmentCanonical))});
const envelope=toBinary(ThreadControlAuthoritySchema,create(ThreadControlAuthoritySchema,{format:1,owner:{root:signedRoot,stateHash},mintRootPublicKey:keys.device.publicKey,mintRootAssociation:{case:'ownerMintRootAttachment',value:signedAttachment},sealedBiscuit:new Uint8Array(readFileSync(new URL('../tests/fixtures/hybrid-native-biscuit-v1.binpb',import.meta.url)))}));
artifact.native_authority={wire_hex:hex(envelope),owner_attachment_canonical_hex:hex(attachmentCanonical),owner_attachment_signing_digest_hex:hex(hash(str('heddle-mint-root-attachment-v1'),attachmentCanonical)),native_state_id_hex:hex(stateId),native_base_state_id_hex:hex(baseStateId)};
const sourceAuthor={kind:'account',spool:spoolUuid,actor:{principal_id:root.accountUuid,agent_id:null},authority_digest:Array.from(nativeId('heddle-thread-control-authority-v1',envelope)),authority:envelope};
const source=native('heddle-thread-operation-v1',{version:1,thread:Array.from(branchLimits[1].targetThreadId),parents:[],publisher:Array.from(keys.device.publicKey),body:{kind:'capture',canonical:{result:capture,author:sourceAuthor}}});
const control=native('heddle-thread-operation-v1',{version:1,thread:Array.from(branchLimits[1].targetThreadId),parents:[],publisher:Array.from(keys.device.publicKey),body:{kind:'metadata',canonical:Array.from(nativeEncode('heddle-thread-control-v1',{version:1,spool:spoolUuid,actor:sourceAuthor.actor,authority_digest:sourceAuthor.authority_digest,authority_envelope:Array.from(envelope),client_operation_id:raw(0x82,16),occurred_at_ms:1100000n,control:{kind:'name',value:'Imported branch'}}))}});
const localGenesisCanonical=nativeGenesis({spoolId:'23232323-2323-2323-2323-232323232323',baseStateId,name:'Local ownership fixture',intent:'Explicit claim and resolution',owner:{kind:'local_key',publicKey:keys.owner.publicKey},nonce:raw(0x87,16)},keys.owner.publicKey),localGenesis=create(SignedRecordSchema,{format:'heddle-thread-genesis-v1',canonicalRecord:localGenesisCanonical,signatures:[{publicKey:keys.owner.publicKey,signature:sig('owner',join(str('heddle-thread-genesis-v1\0'),localGenesisCanonical))}]}),localThread=threadGenesisId(localGenesisCanonical);
const localSource=native('heddle-thread-operation-v1',{version:1,thread:Array.from(localThread),parents:[],publisher:Array.from(keys.owner.publicKey),body:{kind:'capture',canonical:{result:capture,author:{kind:'local_key'}}}},['owner']);
const claim=native('heddle-thread-ownership-claim-v1',{version:1,thread:Array.from(localThread),prior_local_key:Array.from(keys.owner.publicKey),accepting_publisher:Array.from(keys.device.publicKey),acceptance:sourceAuthor,source_frontier:[Array.from(nativeId(localSource.format,localSource.canonicalRecord))]},['owner','device']);
const otherClaim=clone(SignedRecordSchema,claim);otherClaim.canonicalRecord=nativeEncode('heddle-thread-ownership-claim-v1',{...decode(claim.canonicalRecord),source_frontier:[]});otherClaim.signatures=otherClaim.signatures.map(x=>create(RecordSignatureSchema,{publicKey:x.publicKey,signature:sig(hex(x.publicKey)===hex(keys.owner.publicKey)?'owner':'device',join(str(claim.format),raw(0,1),otherClaim.canonicalRecord))}));
const claims=[claim,otherClaim].sort((a,b)=>compare(signedNativeDigest(a),signedNativeDigest(b)));
const resolution=native('heddle-thread-ownership-resolution-v1',{version:1,spool:spoolUuid,thread:Array.from(localThread),winning_claim:Array.from(nativeId(claim.format,claim.canonicalRecord)),conflicting_claims:claims.map(c=>Array.from(nativeId(c.format,c.canonicalRecord))).sort((a,b)=>compare(a,b)),frontier:[Array.from(nativeId(localSource.format,localSource.canonicalRecord))],local_owner:Array.from(keys.owner.publicKey),accepting_publisher:Array.from(keys.device.publicKey),acceptance:sourceAuthor,occurred_at_ms:1100000n},['owner','device']);
const authorityPayloads=[];
for(const [name,kind,original,deps] of [['authority_admission',1,control,[source]],['ownership_admission',2,claim,[localGenesis,localSource].sort((a,b)=>compare(signedNativeDigest(a),signedNativeDigest(b)))],['resolution_admission',3,resolution,[localGenesis,localSource,...claims].sort((a,b)=>compare(signedNativeDigest(a),signedNativeDigest(b)))]]){const payload=wire(`${name}_payload`,api.ImportAuthorityWitnessV1Schema,create(api.ImportAuthorityWitnessV1Schema,{formatVersion:1,kind,original,dependencies:deps,authorityEnvelope:envelope}));authorityPayloads.push(payload);commitment(`${name}_payload`,api.ImportAuthorityWitnessV1Schema,payload,'heddle-import-authority-witness-payload-v1');statements.push(statement(name,2,canonicalHybridV1(api.ImportAuthorityWitnessV1Schema,payload),0x64+kind,authorityEnvelopeDigest(envelope),originalSignaturesDigest([original,...deps])));}
const publicationStatement=statement('publication_statement',3,canonicalHybridV1(api.ImportPublicationWitnessV1Schema,publication));statements.push(publicationStatement);
const renewedPublication=wire('renewed_publication',api.ImportPublicationWitnessV1Schema,publicationPayload(renewedOperation,terminalManifest));
const renewedStatement=statement('renewed_publication_statement',3,canonicalHybridV1(api.ImportPublicationWitnessV1Schema,renewedPublication),0x69,signedDelegationDigest(next),hash(renewedOperation.jobSignature.signature),1250000n);statements.push(renewedStatement);
const requestBody=toBinary(LandThreadRequestSchema,create(LandThreadRequestSchema,{clientOperationId:'83838383-8383-8383-8383-838383838383',thread:{spool:{id:'23232323-2323-2323-2323-232323232323'},id:{value:branchLimits[1].targetThreadId}},source:{spool:{id:'23232323-2323-2323-2323-232323232323'},revision:{case:'state',value:{value:stateId}}},expectedTarget:{spool:{id:'23232323-2323-2323-2323-232323232323'},revision:{case:'state',value:{value:baseStateId}}},target:{spool:{id:'23232323-2323-2323-2323-232323232323'},id:{value:branchLimits[0].targetThreadId}},expectedPolicyVersion:policyStateHash}));
const request=create(api.HostedLandingRequestProofV1Schema,{formatVersion:1,signingIdentity:`principal:device-key:${hex(keys.device.publicKey)}`,methodPath:'/heddle.api.v1alpha2.ThreadService/LandThread',timestampMillis:1100000n,nonce:raw(0x84,16),requestBody});const requestInput=await unarySigningBytes(request.signingIdentity,request.methodPath,request.timestampMillis,request.nonce,requestBody);request.signature=create(RecordSignatureSchema,{publicKey:keys.device.publicKey,signature:sig('device',requestInput)});
const review=native('heddle-thread-operation-v1',{version:1,thread:Array.from(branchLimits[1].targetThreadId),parents:[],publisher:Array.from(keys.device.publicKey),body:{kind:'metadata',canonical:Array.from(nativeEncode('heddle-thread-control-v1',{version:1,spool:spoolUuid,actor:sourceAuthor.actor,authority_digest:sourceAuthor.authority_digest,authority_envelope:Array.from(envelope),client_operation_id:raw(0x88,16),occurred_at_ms:1100000n,control:{kind:'review',value:{id:raw(0x89,16),source:Array.from(stateId),target:Array.from(baseStateId),policy_version:Array.from(policyStateHash),kind:'approval',explanation:'Approve this exact source and target',revokes:null,expires_at_unix_seconds:null}}}))}});
const initiatingRequestPreimage=join(requestInput,request.signature.signature),initiatingRequestId=nativeId('weft-hosted-landing-request-proof-v1',initiatingRequestPreimage);
artifact.native_request_proof={domain:'weft-hosted-landing-request-proof-v1',unary_input_hex:hex(requestInput),original_signature_hex:hex(request.signature.signature),canonical_hex:hex(initiatingRequestPreimage),id_hex:hex(initiatingRequestId)};
const integration=nativeEncode('heddle-hosted-integration-v1',{version:1,spool:spoolUuid,spool_genesis:Array.from(spoolDigest),executor:Array.from(keys.witness.publicKey),source_thread:Array.from(branchLimits[1].targetThreadId),source_operation:Array.from(nativeId(source.format,source.canonicalRecord)),source_revision:Array.from(stateId),target_thread:Array.from(branchLimits[0].targetThreadId),expected_target_frontier:[],result:capture,initiating_request_proof:Array.from(initiatingRequestId),review_policy_version:Array.from(policyStateHash),review_evidence:[Array.from(nativeId(review.format,review.canonicalRecord))],executed_at_ms:1100000n});
const execution=native('heddle-thread-operation-v1',{version:1,thread:Array.from(branchLimits[0].targetThreadId),parents:[],publisher:Array.from(keys.witness.publicKey),body:{kind:'integration',canonical:Array.from(integration)}},['witness']);
const landingPayload=wire('landing_payload',api.HostedLandingWitnessV1Schema,create(api.HostedLandingWitnessV1Schema,{formatVersion:1,execution,request,sourceOperation:source,reviewEvidence:[review],authorityEnvelope:envelope}));commitment('landing_payload',api.HostedLandingWitnessV1Schema,landingPayload,'heddle-hosted-landing-witness-payload-v1');
statements.push(statement('landing_statement',4,canonicalHybridV1(api.HostedLandingWitnessV1Schema,landingPayload),0x63,authorityEnvelopeDigest(envelope),originalSignaturesDigest([execution,source,review],[request.signature])));
// Boundary evidence is generated through the published native codecs. Its
// acceptance signs the complete manifest and exact intent IDs; receipts name it.
function boundaryEvidence(name,original,kind,creatorEnvelope){
  const id=nativeId(original.format,original.canonicalRecord),thread=kind==='AccountGenesis'?id:new Uint8Array(decode(original.canonicalRecord).thread),authorityDigest=kind==='AccountGenesis'?nativeId('heddle-thread-genesis-authority-v1',creatorEnvelope):new Uint8Array(sourceAuthor.authority_digest);
  const manifest=nativeEncode('heddle-original-publication-manifest-v1',{version:1,entries:[{subject:{[kind==='AccountGenesis'?'Genesis':'Source']:Array.from(id)},thread:Array.from(thread),publisher:Array.from(keys.device.publicKey),authority:{spool:spoolUuid,actor:sourceAuthor.actor,authority_digest:Array.from(kind==='AccountGenesis'?nativeId('heddle-thread-control-authority-v1',creatorEnvelope):authorityDigest)}}]});
  const intent=nativeEncode('heddle-original-publication-intent-v1',{spool:spoolUuid,spool_genesis:Array.from(spoolDigest),thread:Array.from(thread),revision:Array.from(stateId),inventory:Array.from(hash(manifest)),sharing_policy:Array.from(policyStateHash),source:Array.from(keys.device.publicKey),destination:Array.from(keys.witness.publicKey),client_operation_id:raw(name.endsWith('dev')?0x92:name.endsWith('main')?0x91:0x93,16)});
  const acceptance=native('heddle-original-boundary-acceptance-v1',{version:1,publication_intent:Array.from(nativeId('heddle-original-publication-intent-v1',intent)),originals_manifest:Array.from(nativeId('heddle-original-publication-manifest-v1',manifest)),original_account:root.accountUuid,kinds:[kind],accepting_publisher:Array.from(keys.device.publicKey),accepting_author:sourceAuthor});
  const acceptanceId=nativeId(acceptance.format,acceptance.canonicalRecord),basis={BoundaryAcceptance:{acceptance:Array.from(acceptanceId)}};
  const receipt=kind==='AccountGenesis'?native('heddle-thread-genesis-admission-v2',{version:2,basis,spool:spoolUuid,spool_genesis:Array.from(spoolDigest),thread:Array.from(thread),owner:root.accountUuid,creator:Array.from(keys.device.publicKey),authority_digest:Array.from(authorityDigest),executor:Array.from(keys.witness.publicKey),admitted_at_ms:1100000n},['witness']):native('heddle-thread-authority-admission-v3',{version:3,basis,spool:spoolUuid,spool_genesis:Array.from(spoolDigest),thread:Array.from(thread),subject:{Operation:Array.from(id)},actor:sourceAuthor.actor,publisher:Array.from(keys.device.publicKey),authority_digest:Array.from(authorityDigest),executor:Array.from(keys.witness.publicKey),admitted_at_ms:1100000n},['witness']);
  const binding=create(common.HostedWitnessBoundaryAcceptanceV1Schema,{formatVersion:1,acceptanceId,signedAcceptanceDigest:signedNativeDigest(acceptance),originalsManifestDigest:boundaryOctetsDigest('heddle-boundary-originals-manifest-v1',manifest),publicationIntentDigest:boundaryOctetsDigest('heddle-boundary-publication-intent-v1',intent),originalReceiptDigests:[signedNativeDigest(receipt)]});
  const evidence=wire(name,api.ImportBoundaryAcceptanceV1Schema,create(api.ImportBoundaryAcceptanceV1Schema,{binding,signedAcceptance:acceptance,originalsManifest:manifest,publicationIntent:intent,originalReceipts:[receipt]}));
  commitment(name+'_binding',common.HostedWitnessBoundaryAcceptanceV1Schema,binding,'heddle-hosted-boundary-acceptance-binding-v1');
  return evidence;
}
const boundaryMain=boundaryEvidence('boundary_main',originalGeneses.main,'AccountGenesis',envelopes.main),boundaryDev=boundaryEvidence('boundary_dev',originalGeneses.dev,'AccountGenesis',envelopes.dev),boundarySource=boundaryEvidence('boundary_source',source,'Source',envelope);
const boundaryGenesis=wire('boundary_genesis_payload',api.ImportGenesisWitnessV1Schema,create(api.ImportGenesisWitnessV1Schema,{...genesisPayload,boundaryAcceptance:boundaryMain}));
const boundaryGenesisStatement=statement('boundary_genesis_statement',1,canonicalHybridV1(api.ImportGenesisWitnessV1Schema,boundaryGenesis),0x94,signedGenesisDigest(genesisProofs.main),originalSignaturesDigest([originalGeneses.main]),1100000n,boundaryMain.binding);statements.push(boundaryGenesisStatement);
const boundaryDevPayload=wire('boundary_dev_genesis_payload',api.ImportGenesisWitnessV1Schema,create(api.ImportGenesisWitnessV1Schema,{...devGenesisPayload,boundaryAcceptance:boundaryDev}));statements.push(statement('boundary_dev_genesis_statement',1,canonicalHybridV1(api.ImportGenesisWitnessV1Schema,boundaryDevPayload),0x95,signedGenesisDigest(genesisProofs.dev),originalSignaturesDigest([originalGeneses.dev]),1100000n,boundaryDev.binding));
const boundaryDependencies=[boundarySource.signedAcceptance,...boundarySource.originalReceipts].sort((a,b)=>compare(signedNativeDigest(a),signedNativeDigest(b)));
const boundaryAuthority=wire('boundary_authority_payload',api.ImportAuthorityWitnessV1Schema,create(api.ImportAuthorityWitnessV1Schema,{formatVersion:1,kind:1,original:source,dependencies:boundaryDependencies,authorityEnvelope:envelope,boundaryAcceptances:[boundarySource]}));
const boundaryAuthorityStatement=statement('boundary_authority_statement',2,canonicalHybridV1(api.ImportAuthorityWitnessV1Schema,boundaryAuthority),0x96,authorityEnvelopeDigest(envelope),originalSignaturesDigest([source,...boundaryDependencies]),1100000n,boundarySource.binding);statements.push(boundaryAuthorityStatement);
artifact.boundary_vectors={passing:[{statement:'boundary_genesis_statement',payload:'boundary_genesis_payload',kind:'genesis'},{statement:'boundary_dev_genesis_statement',payload:'boundary_dev_genesis_payload',kind:'genesis'},{statement:'boundary_authority_statement',payload:'boundary_authority_payload',kind:'authority'}],negative:[]};
for(const name of ['acceptance_swapped_between_originals','manifest_mismatch','intent_mismatch','receipt_from_another_acceptance','missing_binding']){
  const p=clone(api.ImportGenesisWitnessV1Schema,boundaryGenesis),e=p.boundaryAcceptance;
  if(name==='acceptance_swapped_between_originals')p.boundaryAcceptance=clone(api.ImportBoundaryAcceptanceV1Schema,boundaryDev);
  if(name==='manifest_mismatch'){e.originalsManifest=boundaryDev.originalsManifest;e.binding.originalsManifestDigest=boundaryOctetsDigest('heddle-boundary-originals-manifest-v1',e.originalsManifest);}
  if(name==='intent_mismatch'){e.publicationIntent=boundaryDev.publicationIntent;e.binding.publicationIntentDigest=boundaryOctetsDigest('heddle-boundary-publication-intent-v1',e.publicationIntent);}
  if(name==='receipt_from_another_acceptance'){e.originalReceipts=boundaryDev.originalReceipts;e.binding.originalReceiptDigests=e.originalReceipts.map(signedNativeDigest);}
  const payload=wire(name+'_payload',api.ImportGenesisWitnessV1Schema,p),binding=name==='missing_binding'?undefined:p.boundaryAcceptance.binding;
  const bad=statement(name+'_statement',1,canonicalHybridV1(api.ImportGenesisWitnessV1Schema,payload),0x97,signedGenesisDigest(genesisProofs.main),originalSignaturesDigest([originalGeneses.main]),1100000n,binding);
  if(name==='missing_binding'){
    bad.body.basis=2;const input=statementSigningDigest(bad.body);bad.signature=sig('witness',input);
    const v=artifact.signed_vectors[name+'_statement'];v.wire_hex=hex(toBinary(common.SignedHostedWitnessStatementV1Schema,bad));v.canonical_hex=hex(canonicalHybridV1(common.HostedWitnessStatementV1Schema,bad.body));v.signing_input_hex=hex(input);v.signature_hex=hex(bad.signature);
  }
  artifact.boundary_vectors.negative.push({name,statement:name+'_statement',payload:name+'_payload',expected:'BoundaryAcceptance',control_statement:'boundary_genesis_statement',control_payload:'boundary_genesis_payload',first_failing_check:({acceptance_swapped_between_originals:'native_receipt_original_subject',manifest_mismatch:'signed_acceptance_native_manifest_id',intent_mismatch:'signed_acceptance_native_intent_id',receipt_from_another_acceptance:'native_receipt_acceptance_id',missing_binding:'required_statement_binding'})[name]});
}
// Acceptance/receipt dependencies cannot be admitted without exact sidecars.
const missingDependency=clone(api.ImportAuthorityWitnessV1Schema,boundaryAuthority);missingDependency.boundaryAcceptances=[];wire('boundary_dependency_missing_payload',api.ImportAuthorityWitnessV1Schema,missingDependency);
const missingDependencyStatement=statement('boundary_dependency_missing_statement',2,canonicalHybridV1(api.ImportAuthorityWitnessV1Schema,missingDependency),0x98,authorityEnvelopeDigest(envelope),originalSignaturesDigest([source,...boundaryDependencies]));
artifact.boundary_vectors.dependency_negative={statement:'boundary_dependency_missing_statement',payload:'boundary_dependency_missing_payload',expected:'BoundaryAcceptance'};
// Complete native receipt collections; shared clients check commitments only.
const boundaryArchiveProofNames=[];
function receiptSet(evidence,receipts){
  const e=clone(api.ImportBoundaryAcceptanceV1Schema,evidence);
  e.originalReceipts=receipts.sort((a,b)=>compare(signedNativeDigest(a),signedNativeDigest(b)));
  e.binding.originalReceiptDigests=e.originalReceipts.map(signedNativeDigest);
  return e;
}
function combinedBoundary(name,parts){
  const e=clone(api.ImportBoundaryAcceptanceV1Schema,parts[0]);
  const entries=parts.flatMap(p=>decode(p.originalsManifest).entries);
  entries.sort((a,b)=>{const ak=Object.keys(a.subject)[0],bk=Object.keys(b.subject)[0];return ak.localeCompare(bk)||compare(new Uint8Array(a.subject[ak]),new Uint8Array(b.subject[bk]));});
  e.originalsManifest=nativeEncode('heddle-original-publication-manifest-v1',{version:1,entries});
  const a=decode(e.signedAcceptance.canonicalRecord);
  a.originals_manifest=Array.from(nativeId('heddle-original-publication-manifest-v1',e.originalsManifest));
  a.kinds=parts.includes(boundarySource)?['AccountGenesis','Source']:['AccountGenesis'];
  e.signedAcceptance=native('heddle-original-boundary-acceptance-v1',a);
  e.binding.acceptanceId=nativeId(e.signedAcceptance.format,e.signedAcceptance.canonicalRecord);
  e.binding.signedAcceptanceDigest=signedNativeDigest(e.signedAcceptance);
  e.binding.originalsManifestDigest=boundaryOctetsDigest('heddle-boundary-originals-manifest-v1',e.originalsManifest);
  const receipts=parts.flatMap(p=>p.originalReceipts).map(r=>{const b=decode(r.canonicalRecord);b.basis.BoundaryAcceptance.acceptance=Array.from(e.binding.acceptanceId);return native(r.format,b,['witness']);});
  const result=receiptSet(e,receipts);
  wire(name,api.ImportBoundaryAcceptanceV1Schema,result);
  commitment(name+'_binding',common.HostedWitnessBoundaryAcceptanceV1Schema,result.binding,'heddle-hosted-boundary-acceptance-binding-v1');
  return result;
}
function archiveBoundary(name,payload,kind,binding,negative){
  const schema=kind==='genesis'?api.ImportGenesisWitnessV1Schema:api.ImportAuthorityWitnessV1Schema;
  wire(name+'_payload',schema,payload);
  commitment(name+'_payload',schema,payload,kind==='genesis'?'heddle-import-genesis-witness-payload-v1':'heddle-import-authority-witness-payload-v1');
  const digest=kind==='genesis'?signedGenesisDigest(genesisProofs.main):authorityEnvelopeDigest(envelope);
  const originals=kind==='genesis'?[payload.originalGenesis]:[payload.original,...payload.dependencies];
  statements.push(statement(name+'_statement',kind==='genesis'?1:2,canonicalHybridV1(schema,payload),0xa0+boundaryArchiveProofNames.length,digest,originalSignaturesDigest(originals),1100000n,binding));
  boundaryArchiveProofNames.push(name+'_proof');
  const v={name,statement:name+'_statement',payload:name+'_payload',kind};
  if(negative)artifact.boundary_vectors.native_negative.push({...v,error:negative});
  else artifact.boundary_vectors.passing.push(v);
}
artifact.boundary_vectors.native_negative=[];
for(const [size,parts] of [[2,[boundaryMain,boundaryDev]],[3,[boundaryMain,boundaryDev,boundarySource]]]){
  const e=combinedBoundary('boundary_set_'+size,parts);
  archiveBoundary('boundary_complete_'+size,create(api.ImportGenesisWitnessV1Schema,{...genesisPayload,boundaryAcceptance:e}),'genesis',e.binding);
  const bySubject=parts.map(p=>e.originalReceipts.find(r=>r.format===p.originalReceipts[0].format&&hex(decode(r.canonicalRecord).thread)===hex(decode(p.originalReceipts[0].canonicalRecord).thread)));
  for(const change of ['omission','duplicate','substitution','extra']){
    let receipts=[...bySubject];
    const duplicateBody=decode(receipts[0].canonicalRecord);duplicateBody.admitted_at_ms+=1;
    const duplicate=native(receipts[0].format,duplicateBody,['witness']);
    if(change==='omission')receipts.pop();
    if(change==='duplicate')receipts[1]=duplicate;
    if(change==='extra')receipts.push(duplicate);
    if(change==='substitution'){
      const b=decode(receipts[receipts.length-1].canonicalRecord);
      if(size===2)b.thread=Array.from(nativeId(localGenesis.format,localGenesis.canonicalRecord));
      else b.subject={Operation:Array.from(nativeId(control.format,control.canonicalRecord))};
      receipts[receipts.length-1]=native(receipts[receipts.length-1].format,b,['witness']);
    }
    const bad=receiptSet(e,receipts);
    archiveBoundary('boundary_'+change+'_'+size,create(api.ImportGenesisWitnessV1Schema,{...genesisPayload,boundaryAcceptance:bad}),'genesis',bad.binding,change==='duplicate'?'duplicate receipt subject':change==='substitution'?'receipt subject outside selected originals':'complete per-original receipt selection');
  }
}
function multipleAcceptances(name,acceptances,negative,enclosing=boundarySource){
  const dependencies=acceptances.flatMap(e=>[e.signedAcceptance,...e.originalReceipts]).sort((a,b)=>compare(signedNativeDigest(a),signedNativeDigest(b)));
  const sorted=[...acceptances].sort((a,b)=>compare(a.binding.acceptanceId,b.binding.acceptanceId));
  const p=create(api.ImportAuthorityWitnessV1Schema,{...boundaryAuthority,dependencies,boundaryAcceptances:sorted});
  archiveBoundary(name,p,'authority',enclosing.binding,negative);
}
multipleAcceptances('boundary_multiple_dependencies',[boundaryMain,boundaryDev,boundarySource]);
// A distinct source acceptance sorts after a dependency acceptance. The
// enclosing binding, rather than list position, must choose source authority.
function sourceAcceptanceWithIntent(nonce){
  const e=clone(api.ImportBoundaryAcceptanceV1Schema,boundarySource);
  const intent=decode(e.publicationIntent);intent.client_operation_id=raw(nonce,16);
  e.publicationIntent=nativeEncode('heddle-original-publication-intent-v1',intent);
  const a=decode(e.signedAcceptance.canonicalRecord);
  a.publication_intent=Array.from(nativeId('heddle-original-publication-intent-v1',e.publicationIntent));
  e.signedAcceptance=native('heddle-original-boundary-acceptance-v1',a);
  e.binding.acceptanceId=nativeId(e.signedAcceptance.format,e.signedAcceptance.canonicalRecord);
  e.binding.signedAcceptanceDigest=signedNativeDigest(e.signedAcceptance);
  e.binding.publicationIntentDigest=boundaryOctetsDigest('heddle-boundary-publication-intent-v1',e.publicationIntent);
  const r=decode(e.originalReceipts[0].canonicalRecord);r.basis.BoundaryAcceptance.acceptance=Array.from(e.binding.acceptanceId);
  return receiptSet(e,[native(e.originalReceipts[0].format,r,['witness'])]);
}
const laterSource=sourceAcceptanceWithIntent(0xb4);
multipleAcceptances('boundary_enclosing_not_first',[boundaryMain,laterSource],undefined,laterSource);

const two=combinedBoundary('boundary_dependency_set', [boundaryMain,boundaryDev]);
const firstReceipt=decode(two.originalReceipts.find(r=>hex(decode(r.canonicalRecord).thread)===hex(decode(boundaryMain.originalReceipts[0].canonicalRecord).thread)).canonicalRecord);
firstReceipt.admitted_at_ms+=1;
const mainReceipt=two.originalReceipts.find(r=>hex(decode(r.canonicalRecord).thread)===hex(firstReceipt.thread));
multipleAcceptances('boundary_invalid_dependency_acceptance',[boundarySource,receiptSet(two,[mainReceipt,native(mainReceipt.format,firstReceipt,['witness'])])],'duplicate receipt subject');
// Closed finding #5 keeps its exact pre-source_ref legacy negative input.
const legacyInput=JSON.parse(readFileSync(new URL('../tests/fixtures/hybrid-native-old-parentless-v1.json',import.meta.url),'utf8'));
wire('legacy_hosted_import',SignedRecordSchema,fromBinary(SignedRecordSchema,Buffer.from(legacyInput.legacy_wire_hex,'hex')));
const boundaryArchived=statements.splice(10);
statements.push(devGenesisAdmission,...boundaryArchived);
const leaves=statements.map(s=>leafDigest(s.body.purpose,canonicalHybridV1(common.HostedWitnessStatementV1Schema,s.body),s.signature)).sort(compare),archiveRoot=merkleRoot(leaves);
function proof(index,a){if(a.length===1)return [];let k=1;while(k*2<a.length)k*=2;return index<k?[...proof(index,a.slice(0,k)),merkleRoot(a.slice(k))]:[...proof(index-k,a.slice(k)),merkleRoot(a.slice(0,k))];}
for(let n of [0,1,2,3,5]){const a=n<=3?leaves.slice(0,n):[...leaves.slice(0,3),hash(str('additional archived exact statement 1')),hash(str('additional archived exact statement 2'))].sort(compare);artifact.trees.push({count:n,leaves_hex:a.map(hex),root_hex:hex(merkleRoot(a)),paths:a.map((_,i)=>({index:i,siblings_hex:proof(i,a).map(hex)}))});}
const proofNames=['genesis_proof','authority_proof','ownership_proof','resolution_proof','publication_proof','renewed_publication_proof','landing_proof','boundary_genesis_proof','boundary_dev_genesis_proof','boundary_authority_proof','genesis_dev_proof',...boundaryArchiveProofNames];
for(const [i,s] of statements.entries()){const leaf=leafDigest(s.body.purpose,canonicalHybridV1(common.HostedWitnessStatementV1Schema,s.body),s.signature),index=leaves.findIndex(x=>hex(x)===hex(leaf));wire(proofNames[i],common.HostedWitnessHistoryProofV1Schema,create(common.HostedWitnessHistoryProofV1Schema,{executorId:s.body.executorId,purpose:s.body.purpose,leafIndex:BigInt(index),leafCount:BigInt(leaves.length),siblings:proof(index,leaves)}));}
function member(name,state=1){return create(common.HostedWitnessEntryV1Schema,{executorId:witnessId(keys[name].publicKey),publicKey:keys[name].publicKey,role:1,state,purposes:[1,2,3,4],activeFromUnixMillis:name==='next_witness'?1300000n:0n,activeUntilUnixMillis:2000000n});}
function signedSet(name,body,key='root'){const input=setSigningBytes(body),signature=sig(key,input),value=create(common.SignedHostedWitnessSetV1Schema,{body,bodyDigest:hash(input),rootSignature:signature});artifact.signed_vectors[name]={schema:common.SignedHostedWitnessSetV1Schema.typeName,body_schema:common.HostedWitnessSetV1Schema.typeName,wire_hex:hex(toBinary(common.SignedHostedWitnessSetV1Schema,value)),canonical_hex:hex(canonicalHybridV1(common.HostedWitnessSetV1Schema,body)),signing_input_hex:hex(input),domain:'heddle-hosted-witness-set-v1\0',public_key_hex:hex(keys[key].publicKey),signature_hex:hex(signature)};return value;}
const setBody=create(common.HostedWitnessSetV1Schema,{formatVersion:1,deploymentAuthority:artifact.context.authority,descriptorRootId:artifact.context.root_id,generation:10n,issuedAtUnixMillis:1000000n,validUntilUnixMillis:1300000n,currentExecutorId:witnessId(keys.witness.publicKey),entries:[member('witness')]});
const currentSet=signedSet('current_set',setBody);const newerBody=clone(common.HostedWitnessSetV1Schema,setBody);newerBody.generation=11n;newerBody.issuedAtUnixMillis=1000100n;signedSet('newer_set',newerBody);
const retiredBody=clone(common.HostedWitnessSetV1Schema,setBody);retiredBody.generation=12n;retiredBody.issuedAtUnixMillis=1300000n;retiredBody.validUntilUnixMillis=1600000n;retiredBody.currentExecutorId=witnessId(keys.next_witness.publicKey);const retired=member('witness',2);retired.activeUntilUnixMillis=1300000n;retired.archiveRoot=archiveRoot;retired.archiveLeafCount=BigInt(leaves.length);retiredBody.entries=[retired,member('next_witness')].sort((a,b)=>compare(a.executorId,b.executorId));const retiredSet=signedSet('retired_set',retiredBody);
const revokedBody=clone(common.HostedWitnessSetV1Schema,retiredBody);revokedBody.generation=13n;revokedBody.issuedAtUnixMillis=1300100n;const revoked=revokedBody.entries.find(v=>v.state===2);revoked.state=3;revoked.revokedAtUnixMillis=1300100n;signedSet('revoked_set',revokedBody);
function negative(id,type,value,schema,expected,extra={}){artifact.negative_vectors.push({id,type,wire_hex:value?hex(toBinary(schema,value)):null,expected,control:type==='set'?(extra.previous??'current_set'):type==='statement'?'publication_statement':type==='renewal'?'renewal':'operation_main',...extra});}
negative('forged_wrong_root','set',signedSet('wrong_root_set',setBody,'wrong_root'),common.SignedHostedWitnessSetV1Schema,'Signature');
const invalid=clone(common.HostedWitnessSetV1Schema,setBody);invalid.entries[0].archiveRoot=raw(0x8a);negative('root_signed_invalid_current_set','set',signedSet('semantic_invalid_set',invalid),common.SignedHostedWitnessSetV1Schema,'Semantic');
const jobSet=clone(common.HostedWitnessSetV1Schema,setBody);jobSet.entries=[member('job')];jobSet.currentExecutorId=witnessId(keys.job.publicKey);negative('job_key_as_witness','set',signedSet('job_witness_set',jobSet),common.SignedHostedWitnessSetV1Schema,'JobAsWitness');
const roleSet=clone(common.HostedWitnessSetV1Schema,setBody);roleSet.entries[0].role=2;negative('encoded_job_role_as_witness','set',signedSet('wrong_role_set',roleSet),common.SignedHostedWitnessSetV1Schema,'JobAsWitness');
negative('set_rollback_below_persisted_high_water','set',currentSet,common.SignedHostedWitnessSetV1Schema,'HighWater',{previous:'newer_set'});
const forgedOld=statement('backdated_new_statement',3,canonicalHybridV1(api.ImportPublicationWitnessV1Schema,publication),0x62);negative('retired_seed_backdating_new_leaf','statement',forgedOld,common.SignedHostedWitnessStatementV1Schema,'Proof',{set:'retired_set',proof:'publication_proof',now_ms:1350000,new_work:false});
negative('retired_key_cannot_admit_new_work','statement',publicationStatement,common.SignedHostedWitnessStatementV1Schema,'Expired',{set:'retired_set',proof:'publication_proof',now_ms:1350000,new_work:true});
negative('revoked_key_rejects_exact_history','statement',publicationStatement,common.SignedHostedWitnessStatementV1Schema,'Revoked',{set:'revoked_set',proof:'publication_proof',now_ms:1350000,new_work:false});
const wrongScope=clone(api.DelegatedImportOperationV1Schema,operations.main.body);wrongScope.targetThreadId=raw(0x73);negative('delegation_target_scope_violation','operation',signed('scope_violation',api.DelegatedImportOperationV1Schema,wrongScope,api.SignedDelegatedImportOperationV1Schema,'jobSignature','job','heddle-delegated-import-operation-v1'),api.SignedDelegatedImportOperationV1Schema,'Scope');
negative('expired_delegation','new_operation',operations.main,api.SignedDelegatedImportOperationV1Schema,'Expired',{now_seconds:1300});
const forkBody=clone(api.ImportJobDelegationV1Schema,nextBody);forkBody.logicalJobId=raw(0x74,16);forkBody.delegatingPublicKey=keys.owner.publicKey;forkBody.parentPermissionDigest=raw(0);const fork=signed('fork_delegation',api.ImportJobDelegationV1Schema,forkBody,api.SignedImportJobDelegationV1Schema,'delegatingSignature','owner','heddle-import-job-delegation-v1');const forkRenewal=clone(api.ImportJobRenewalV1Schema,renewalBody);forkRenewal.replacement=fork;negative('renewal_forks_logical_job','renewal',signed('fork_renewal',api.ImportJobRenewalV1Schema,forkRenewal,api.SignedImportJobRenewalV1Schema,'delegatingSignature','owner','heddle-import-job-renewal-v1'),api.SignedImportJobRenewalV1Schema,'RenewalFork',{now_seconds:1200,member:false});
const wideParentBody=clone(api.ImportMemberPermissionV1Schema,renewedPermissionBody);wideParentBody.scope.maxOperations=2;
const renewalWideParent=signed('wide_permission',api.ImportMemberPermissionV1Schema,wideParentBody,api.SignedImportMemberPermissionV1Schema,'ownerSignature','owner','heddle-import-member-permission-v1');
const widened=clone(api.ImportJobDelegationV1Schema,nextBody);widened.scope.maxOperations=2;widened.parentPermissionDigest=signedPermissionDigest(renewalWideParent);const wide=signed('wide_delegation',api.ImportJobDelegationV1Schema,widened,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device','heddle-import-job-delegation-v1');const wideRenewal=clone(api.ImportJobRenewalV1Schema,renewalBody);wideRenewal.replacement=wide;negative('renewal_resets_result_budget','renewal',signed('wide_renewal',api.ImportJobRenewalV1Schema,wideRenewal,api.SignedImportJobRenewalV1Schema,'delegatingSignature','device','heddle-import-job-renewal-v1'),api.SignedImportJobRenewalV1Schema,'RenewalFork',{now_seconds:1200,parent:'wide_permission'});
// Correct signatures in other domains still supply NO typed import permission.
artifact.unrelated_permissions=[];
for(const version of [1,3]){
 const domain=`heddle-owner-capability-v${version}`,selector=join(sized(spoolUuid),u32(1),sized(str('example')),raw(0,1));
 const subject=join(u32(1),sized(raw(0x77,16)),raw(1,1),encodedKey('device'));
 const timeline=join(raw(1,1),sized(root.accountUuid),raw(1,1),sized(raw(0x78)),sized(raw(0x79)),u32(1),sized(branchLimits[0].genesisDigest),sized(raw(0x7b)));
 const bodyWithoutId=join(u32(version),sized(ownerId),sized(stateHash),sized(new Uint8Array()),subject,u32(1),selector,u32(version===1?1:2),...(version===3?[timeline]:[]),integer(1000n,true),integer(1900n,true),sized(raw(0x7c)));
 const id=hash(str(domain),bodyWithoutId),canonical=join(bodyWithoutId,sized(id)),input=hash(str(domain),canonical);
 const capability=create(owner.OwnerCapabilitySchema,{formatVersion:version,ownerId,issuerStateHash:stateHash,subject:{kind:1,principalId:raw(0x77,16),key:{algorithm:1,publicKey:keys.device.publicKey}},grants:[{spool:{rootSpoolUuid:spoolUuid,pathSegments:['example']},action:version===1?1:2,...(version===3?{timelineAcceptance:{principalAccountUuid:root.accountUuid,credentialIdentity:{identity:{case:'serverIssued',value:{credentialId:raw(0x78)}}},effectivePopKeySha256:raw(0x79),credentialClass:1,threadId:branchLimits[0].genesisDigest,originSha256:raw(0x7b)}}:{})}],notBeforeUnixSeconds:1000n,expiresAtUnixSeconds:1900n,nonce:raw(0x7c),capabilityId:id});
 artifact.unrelated_permissions.push({format:version===1?'PURGE-v1':'timeline-acceptance-v3',schema:owner.SignedOwnerCapabilitySchema.typeName,wire_hex:hex(toBinary(owner.SignedOwnerCapabilitySchema,create(owner.SignedOwnerCapabilitySchema,{capability,signature:auth('owner',input)}))),canonical_hex:hex(canonical),signing_input_hex:hex(input),signature_hex:hex(sig('owner',input)),public_key_hex:hex(keys.owner.publicKey),expected:'ImportPermission'});
}
const roleInput=hash(str('ordinary-online-role-control'),str('Developer'));
artifact.unrelated_permissions.push({format:'ordinary-Developer-role',canonical_hex:hex(str('Developer')),signing_input_hex:hex(roleInput),signature_hex:hex(sig('owner',roleInput)),public_key_hex:hex(keys.owner.publicKey),expected:'ImportPermission'});

wire('lookup_request',api.GetHostedWitnessHistoryProofRequestSchema,create(api.GetHostedWitnessHistoryProofRequestSchema,{executorId:witnessId(keys.witness.publicKey),statementLeafDigest:leafDigest(publicationStatement.body.purpose,canonicalHybridV1(common.HostedWitnessStatementV1Schema,publicationStatement.body),publicationStatement.signature)}));
const p=artifact.wire_vectors.publication_proof;wire('lookup_response',api.GetHostedWitnessHistoryProofResponseSchema,create(api.GetHostedWitnessHistoryProofResponseSchema,{proof:create(common.HostedWitnessHistoryProofV1Schema,{executorId:publicationStatement.body.executorId,purpose:3,leafIndex:BigInt(leaves.findIndex(l=>hex(l)===hex(leafDigest(3,canonicalHybridV1(common.HostedWitnessStatementV1Schema,publicationStatement.body),publicationStatement.signature)))),leafCount:BigInt(leaves.length),siblings:proof(leaves.findIndex(l=>hex(l)===hex(leafDigest(3,canonicalHybridV1(common.HostedWitnessStatementV1Schema,publicationStatement.body),publicationStatement.signature))),leaves)})}));
artifact.retry_scenarios=[{id:'two_concurrent_renewals_and_paused_old_worker',route:'crates/weft-hosted/src/server/hosted/integration_v2/import_retry.rs::native_retry_import_source',initial_epoch:1,committed_manifest:'partial_manifest',events:[{action:'activate_renewal',certificate:'renewal',expected_epoch:1,result:'OK',epoch_after:2},{action:'activate_renewal',certificate:'competing_renewal',expected_epoch:1,result:'StaleContext',epoch_after:2},{action:'publish_paused_worker',operation:'operation_dev',expected_epoch:1,result:'StaleContext',epoch_after:2},{action:'publish',operation:'renewed_operation_dev',expected_epoch:2,result:'OK',epoch_after:2}],final_manifest:'terminal_manifest',committed_slot_count:2},{id:'commit_success_response_loss_retry_fresh_fetch',route:'crates/weft-hosted/src/server/hosted/integration_v2/import_retry.rs::native_retry_import_source',physical_retry_operation_id_hex:hex(raw(0x7a,16)),logical_job_id_hex:hex(logicalJobId),retry_original_operation_hex:hex(retryLineageId),original_operation:'operation_main',receipt:'publication_statement',manifest:'partial_manifest',events:['commit','lose_response','retry','fresh_fetch'],expected_replay:true,committed_slot_count:1}];
const completedManifest=wire('completed_slot_manifest',api.ImportResultManifestV1Schema,create(api.ImportResultManifestV1Schema,{formatVersion:1,logicalJobId,retryLineageId,slots:[committedSlot(operations.dev)]}));
const completedRenewal=clone(api.ImportJobRenewalV1Schema,renewalBody);completedRenewal.committedManifestDigest=manifestDigest(completedManifest);signed('completed_slot_renewal',api.ImportJobRenewalV1Schema,completedRenewal,api.SignedImportJobRenewalV1Schema,'delegatingSignature','device','heddle-import-job-renewal-v1');
const originalTerminal=wire('publication_wins_manifest',api.ImportResultManifestV1Schema,create(api.ImportResultManifestV1Schema,{formatVersion:1,logicalJobId,retryLineageId,slots:[committedSlot(operations.dev),committedSlot(operations.main)]}));
const emptyManifest=wire('empty_manifest',api.ImportResultManifestV1Schema,create(api.ImportResultManifestV1Schema,{formatVersion:1,logicalJobId,retryLineageId}));const racingRenewal=clone(api.ImportJobRenewalV1Schema,renewalBody);racingRenewal.committedManifestDigest=manifestDigest(emptyManifest);signed('publication_wins_renewal',api.ImportJobRenewalV1Schema,racingRenewal,api.SignedImportJobRenewalV1Schema,'delegatingSignature','device','heddle-import-job-renewal-v1');
artifact.retry_scenarios.push({id:'publication_wins_unchanged_epoch_manifest_cas',initial_epoch:1,renewal:'publication_wins_renewal',before_manifest:'empty_manifest',after_manifest:'partial_manifest',publication:'operation_main',now_seconds:1250,expected:'StaleManifest',epoch_after:1});
wire('renewal_preparation',api.PrepareImportJobResponseSchema,create(api.PrepareImportJobResponseSchema,{proposal:delegationPreparation(nextBody),reservationExpiresAtUnixSeconds:4800n,preparedAtUnixSeconds:1200n,maxValidityDurationSeconds:700n,clockSkewAllowanceSeconds:100n,renewalState:{formatVersion:1,logicalJobId,retryLineageId,activePredecessor:delegation,authorityEpoch:1n,committedManifest:partialManifest}}));
const exportBundle=wire('complete_renewed_export',api.ImportPublicProofBundleV1Schema,create(api.ImportPublicProofBundleV1Schema,{formatVersion:1,ownerGenesis:spoolGenesis,ownerHistories:[artifact.wire_vectors.owner_history?create(owner.OwnerHistorySchema,{root:signedRoot,stateHash}):null],memberPermissions:[permission,renewedPermission].sort((a,b)=>compare(signedPermissionDigest(a),signedPermissionDigest(b))),genesisAuthorities:Object.values(genesisProofs),delegations:[delegation,next],renewals:[renewal],operations:[operations.main,renewedOperation],terminalManifest,manifests:[partialManifest,terminalManifest].sort((a,b)=>compare(manifestDigest(a),manifestDigest(b))),witnessSet:retiredSet,policies:[policy],statements:[statements[0],devGenesisAdmission,publicationStatement,renewedStatement],genesisWitnesses:[genesisPayload,devGenesisPayload],originalGeneses:Object.values(originalGeneses),creatorAuthorityEnvelopes:[envelopes.main],ownerChain:chain}));
for(const [name,chars] of [['root_id_boundary',128],['root_id_over_boundary',129]]){const b=clone(common.HostedWitnessSetV1Schema,setBody);b.descriptorRootId='é'.repeat(chars);signedSet(name,b);}
for(const [name,schema,v,domain] of [['owner_chain',api.ImportOwnerChainV1Schema,chain,'heddle-import-owner-chain-v1'],['partial_manifest',api.ImportResultManifestV1Schema,partialManifest,'heddle-import-result-manifest-v1'],['terminal_manifest',api.ImportResultManifestV1Schema,terminalManifest,'heddle-import-result-manifest-v1'],['publication',api.ImportPublicationWitnessV1Schema,publication,'heddle-import-publication-payload-v1']])commitment(name,schema,v,domain);
const missingOwner=clone(api.ImportAuthorityWitnessV1Schema,authorityPayloads[1]);missingOwner.original.signatures=missingOwner.original.signatures.filter(s=>hex(s.publicKey)!==hex(keys.owner.publicKey));wire('missing_owner_payload',api.ImportAuthorityWitnessV1Schema,missingOwner);statement('witness_without_owner',2,canonicalHybridV1(api.ImportAuthorityWitnessV1Schema,missingOwner),0x70,authorityEnvelopeDigest(envelope),originalSignaturesDigest([missingOwner.original,...missingOwner.dependencies]));
const missingJob=clone(api.SignedDelegatedImportOperationV1Schema,operations.main);missingJob.jobSignature.signature=publicationStatement.signature;wire('witness_without_job',api.SignedDelegatedImportOperationV1Schema,missingJob);
// 2026-10-04 owner decisions: all scenarios are shared by Rust and TypeScript.
artifact.amendment_vectors={permission_negatives:[],cancel_negatives:[],preflight:[],recovery:[],lineage:[]};
for(const [name,mutate,expected] of [
 ['full_scope',p=>p.scope=scope,'CommittedSlot'],
 ['reused_nonce',p=>p.nonce=permissionBody.nonce,'ImportPermission'],
 ['changed_cancel',p=>p.cancellationId=raw(0x99),'ImportPermission'],
]){
 const p=clone(api.ImportMemberPermissionV1Schema,renewedPermissionBody);mutate(p);
 const parent=signed(`renewal_parent_${name}`,api.ImportMemberPermissionV1Schema,p,api.SignedImportMemberPermissionV1Schema,'ownerSignature','owner','heddle-import-member-permission-v1');
 const d=clone(api.ImportJobDelegationV1Schema,nextBody);d.parentPermissionDigest=signedPermissionDigest(parent);
 const replacement=signed(`renewal_child_${name}`,api.ImportJobDelegationV1Schema,d,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device','heddle-import-job-delegation-v1');
 const r=clone(api.ImportJobRenewalV1Schema,renewalBody);r.replacement=replacement;
 signed(`renewal_${name}`,api.ImportJobRenewalV1Schema,r,api.SignedImportJobRenewalV1Schema,'delegatingSignature','device','heddle-import-job-renewal-v1');
 artifact.amendment_vectors.permission_negatives.push({id:name,parent:`renewal_parent_${name}`,renewal:`renewal_${name}`,expected});
}
// Reusing exact still-valid parent bytes is not new permission issuance.
const reuseBody=clone(api.ImportJobDelegationV1Schema,nextBody);reuseBody.delegationId=raw(0xdc,16);reuseBody.jobPublicKey=keys.competing_job.publicKey;reuseBody.jobKeyId=keyId(keys.competing_job.publicKey);reuseBody.predecessorDelegationDigest=signedDelegationDigest(next);reuseBody.notBeforeUnixSeconds=1350n;
const reuseChild=signed('reused_parent_delegation',api.ImportJobDelegationV1Schema,reuseBody,api.SignedImportJobDelegationV1Schema,'delegatingSignature','device','heddle-import-job-delegation-v1');
signed('reused_parent_renewal',api.ImportJobRenewalV1Schema,create(api.ImportJobRenewalV1Schema,{formatVersion:1,predecessorDelegationDigest:signedDelegationDigest(next),expectedAuthorityEpoch:2n,committedManifestDigest:manifestDigest(partialManifest),replacement:reuseChild}),api.SignedImportJobRenewalV1Schema,'delegatingSignature','device','heddle-import-job-renewal-v1');
const cancel=create(api.CancelImportJobRequestSchema,{clientOperationId:'cancel-328',destination,logicalJobId,cancellationId:delegationBody.cancellationId,expectedAuthorityEpoch:1n});
wire('cancel_active',api.CancelImportJobRequestSchema,cancel);
for(const [name,mutate,epoch,cancelled,expected] of [
 ['parent_selector',r=>r.cancellationId=permissionBody.cancellationId,1n,false,'Scope'],
 ['mismatch',r=>r.cancellationId=raw(0xaa),1n,false,'Scope'],
 ['stale_epoch',r=>{},2n,false,'StaleContext'],
 ['stale_selector',r=>r.expectedAuthorityEpoch=2n,2n,false,'Scope'],
 ['terminal',r=>{r.expectedAuthorityEpoch=2n;r.cancellationId=nextBody.cancellationId;},2n,true,'Revoked'],
]){const r=clone(api.CancelImportJobRequestSchema,cancel);mutate(r);wire(`cancel_${name}`,api.CancelImportJobRequestSchema,r);artifact.amendment_vectors.cancel_negatives.push({id:name,request:`cancel_${name}`,active:['stale_selector','terminal'].includes(name)?'renewed_delegation':'delegation',epoch:Number(epoch),cancelled,expected});}
const cancelChanged=clone(api.CancelImportJobRequestSchema,cancel);cancelChanged.cancellationId=raw(0xbb);wire('cancel_changed_replay',api.CancelImportJobRequestSchema,cancelChanged);
const beforePublication=wire('empty_manifest',api.ImportResultManifestV1Schema,create(api.ImportResultManifestV1Schema,{formatVersion:1,logicalJobId,retryLineageId}));
const emptyState=wire('recovery_empty_state',api.ImportJobCasStateV1Schema,create(api.ImportJobCasStateV1Schema,{formatVersion:1,logicalJobId,retryLineageId,activePredecessor:delegation,authorityEpoch:1n,committedManifest:beforePublication}));
const emptyRenewal=clone(api.ImportJobRenewalV1Schema,renewalBody);emptyRenewal.committedManifestDigest=manifestDigest(beforePublication);
signed('recovery_empty_renewal',api.ImportJobRenewalV1Schema,emptyRenewal,api.SignedImportJobRenewalV1Schema,'delegatingSignature','device','heddle-import-job-renewal-v1');
artifact.amendment_vectors.recovery.push({id:'expired_before_publication',state:'recovery_empty_state',renewal:'recovery_empty_renewal',now:1350});
wire('recovery_partial_state',api.ImportJobCasStateV1Schema,create(api.ImportJobCasStateV1Schema,{...emptyState,committedManifest:partialManifest}));
artifact.amendment_vectors.recovery.push({id:'expired_after_partial',state:'recovery_partial_state',renewal:'renewal',now:1350});
for(const [id,now,preflight,host] of [['behind_at_skew',900,'OK','Expired'],['behind_inside',999,'OK','Expired'],['beyond_skew',899,'Expired','Expired'],['at_prepare',1000,'OK','OK'],['at_expiry',1300,'ValidityBounds','ValidityBounds']])artifact.amendment_vectors.preflight.push({id,now,preflight,host});
const wrongReceipt=create(MutationResponseSchema,{receipt:{clientOperationId:commitRequest.clientOperationId,outcome:{case:'pendingOperation',value:{spool:destination,id:'27272727-2727-2727-2727-272727272727'}}}});
wire('commit_wrong_lineage_response',MutationResponseSchema,wrongReceipt);
artifact.amendment_vectors.lineage.push({id:'reserved_first_id',lineage_hex:hex(retryLineageId),operation_id:'25252525-2525-2525-2525-252525252525',occupied:false,expected:'OK'},{id:'collision',lineage_hex:hex(retryLineageId),occupied:true,expected:'OperationIdReused'},{id:'nil',lineage_hex:hex(raw(0,16)),occupied:false,expected:'Canonical'});
for(const [name,v] of Object.entries(artifact.signed_vectors)){const domains={SignedImportMemberPermissionV1:'heddle-signed-import-member-permission-v1',SignedImportGenesisAuthorityV1:'heddle-signed-import-genesis-authority-v1',SignedImportJobDelegationV1:'heddle-signed-import-job-delegation-v1',SignedDelegatedImportOperationV1:'heddle-signed-delegated-import-operation-v1'};const domain=domains[v.schema.split('.').at(-1)];if(domain){const schema=api[v.schema.split('.').at(-1)+'Schema'],value=(await import('@bufbuild/protobuf')).fromBinary(schema,new Uint8Array(Buffer.from(v.wire_hex,'hex')));commitment(`signed_${name}`,schema,value,domain);}}
const checks={forged_wrong_root:'root_signature',root_signed_invalid_current_set:'current_entry_has_no_archive_seal',job_key_as_witness:'known_job_key_role',encoded_job_role_as_witness:'witness_role_enum',set_rollback_below_persisted_high_water:'persisted_generation_high_water',retired_seed_backdating_new_leaf:'exact_retirement_leaf_inclusion',retired_key_cannot_admit_new_work:'current_issuance_window',revoked_key_rejects_exact_history:'revoked_tombstone',delegation_target_scope_violation:'exact_operation_target_scope',expired_delegation:'new_operation_validity_window',renewal_forks_logical_job:'logical_job_lineage',renewal_resets_result_budget:'remaining_operation_budget'};
for(const v of artifact.negative_vectors)v.first_failing_check=checks[v.id];
function rawCommitment(name,domain,canonical){artifact.raw_commitment_vectors[name]={domain,canonical_hex:hex(canonical),preimage_hex:hex(join(str(domain),canonical)),digest_hex:hex(hash(str(domain),canonical))};}
rawCommitment('conversion_options','heddle-import-conversion-options-v1',join(sized(str(scope.converterVersion)),sized(new Uint8Array())));
rawCommitment('device_key_id','heddle-key-v1',join(u32(1),keys.device.publicKey));
rawCommitment('witness_selector','heddle-hosted-witness-key-v1\0',keys.witness.publicKey);
rawCommitment('authority_envelope','heddle-hosted-authority-envelope-v1',sized(envelope));
artifact.first_failing_checks={unrelated_permissions:'permission_format_selection',completed_slot_renewal:'committed_slot_exclusion',paused_worker:'authority_epoch_and_active_delegation_fence',publication_wins:'committed_manifest_digest_cas',legacy_hosted_import:'hybrid_import_dispatch',root_id_over_boundary:'root_id_utf8_byte_bound'};
writeFileSync(new URL('../tests/fixtures/import-authority-host-witness-v1.json',import.meta.url),JSON.stringify(artifact,null,2)+'\n');
console.log(`Frozen ${artifact.messages.length} messages, ${Object.keys(artifact.signed_vectors).length} signed byte vectors, ${artifact.negative_vectors.length} witness/operation negatives, ${artifact.commit_vectors.negative.length} Commit negatives, ${artifact.trees.length} trees, ${artifact.retry_scenarios.length} retry scenarios.`);
