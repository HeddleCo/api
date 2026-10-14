// Deterministic test builder: real signed candidate jobs, never a size estimate.
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { clone, create, fromBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as a from '../packages/typescript/dist/v1alpha2/import-authority.js';
import { hash, keyId, join, utf8 } from '../packages/typescript/dist/v1alpha2/_hybrid-codec.js';
import { canonicalThreadGenesis, threadGenesisId } from '../packages/typescript/dist/v1alpha2/thread-genesis.js';
export const base=JSON.parse(readFileSync(new URL('./fixtures/import-authority-host-witness-v1.json',import.meta.url)));
export const bytes=h=>new Uint8Array(Buffer.from(h,'hex'));
export const vector=n=>{const v=base.signed_vectors[n]??base.wire_vectors[n];return fromBinary(api[v.schema.split('.').at(-1)+'Schema'],bytes(v.wire_hex));};
const privateKeys=Object.fromEntries(['owner','device'].map(k=>[k,createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),bytes(base.keys[k].seed_hex)]),format:'der',type:'pkcs8'})]));
const signed=(schema,wrapper,body,field,key,domain)=>create(wrapper,{body,[field]:{signerKeyId:keyId(bytes(base.keys[key].public_key_hex)),signature:sign(null,a.signingDigest(domain,schema,body),privateKeys[key])}});
export function selection(count,worst=false){
 return Array.from({length:count},(_,i)=>{
  const prefix='refs/heads/b'+String(i).padStart(4,'0')+'/';
  const tail=1024-Buffer.byteLength(prefix),refName=worst?prefix+'é'.repeat(Math.floor(tail/2))+'a'.repeat(tail%2):prefix+'tip';
  const nonce=new Uint8Array(16);new DataView(nonce.buffer).setUint32(12,i+1);
  const canonicalRecord=canonicalThreadGenesis({spoolId:'23232323-2323-2323-2323-232323232323',baseStateId:vector('scope').branches[0].expectedFrontierDigest,name:'branch-'+i,intent:'Import this exact branch',owner:{kind:'account',accountId:'21212121-2121-2121-2121-212121212121'},nonce},bytes(base.keys.device.public_key_hex));
  const original=create(api.SignedRecordSchema,{format:'heddle-thread-genesis-v1',canonicalRecord,signatures:[{publicKey:bytes(base.keys.device.public_key_hex),signature:sign(null,join(utf8.encode('heddle-thread-genesis-v1\0'),canonicalRecord),privateKeys.device)}]});
  const limit=clone(api.ImportBranchLimitV1Schema,vector('scope').branches[0]);limit.refName=refName;limit.hashAlgorithm=2;limit.pinnedCommitOid=new Uint8Array(32).fill(255);limit.genesisDigest=threadGenesisId(canonicalRecord);limit.targetThreadId=limit.genesisDigest;limit.slotId=(1n<<64n)-1n;
  return {limit,original};
 });
}
export function buildJob(branches,materials,worst=false){
 const scope=vector('scope');scope.branches=[...branches];scope.maxOperations=256;scope.maxResultBytes=(1n<<64n)-1n;
 if(worst){scope.sourceUrl='https://example.test/'+'a'.repeat(2048-'https://example.test/'.length);scope.provider='public-git';scope.converterVersion='c'.repeat(128);scope.optionsDigest=a.conversionOptionsDigest(scope.converterVersion,vector('import_configuration').converters[0].canonicalOptions[0]);}
 const jobSeed=hash(join(utf8.encode('partition-job\0'),branches[0].genesisDigest));
 const jobPrivate=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),jobSeed]),format:'der',type:'pkcs8'});
 const jobPublic=new Uint8Array(createPublicKey(jobPrivate).export({format:'der',type:'spki'}).subarray(-32));
 const parent=vector('permission').body;parent.scope=clone(api.ImportPermissionScopeV1Schema,scope);parent.logicalJobId=jobSeed.slice(0,16);parent.retryLineageId=jobSeed.slice(16);
 const permission=signed(api.ImportMemberPermissionV1Schema,api.SignedImportMemberPermissionV1Schema,parent,'ownerSignature','owner',a.PERMISSION_DOMAIN);
 const envelope=join(utf8.encode('heddle-signed-import-member-permission-v1\0'),a.canonicalHybridV1(api.SignedImportMemberPermissionV1Schema,permission));
 const originals=branches.map(b=>clone(api.SignedRecordSchema,materials.find(m=>m.limit.refName===b.refName).original));
 const bindings=branches.map((b,i)=>{const body=clone(api.ImportGenesisAuthorityV1Schema,vector('genesis_dev').body);body.genesisDigest=b.genesisDigest;body.originalCreatorSignature=originals[i].signatures[0].signature;body.parentPermissionDigest=a.signedPermissionDigest(permission);body.creatorAuthorityEnvelopeDigest=hash(envelope);return signed(api.ImportGenesisAuthorityV1Schema,api.SignedImportGenesisAuthorityV1Schema,body,'creatorSignature','device',a.GENESIS_DOMAIN);});
 const body=vector('delegation').body;body.logicalJobId=parent.logicalJobId;body.retryLineageId=parent.retryLineageId;body.delegationId=hash(jobSeed).slice(0,16);body.jobPublicKey=jobPublic;body.jobKeyId=keyId(jobPublic);body.scope=scope;body.parentPermissionDigest=a.signedPermissionDigest(permission);body.branchManifest=branches.map((b,i)=>create(api.ImportBranchManifestV1Schema,{limit:b,genesisAuthorityDigest:a.signedGenesisDigest(bindings[i])}));
 const delegation=signed(api.ImportJobDelegationV1Schema,api.SignedImportJobDelegationV1Schema,body,'delegatingSignature','device',a.DELEGATION_DOMAIN);
 const proof=vector('commit_request').proof;proof.formatVersion=2;proof.memberPermission=permission;proof.delegations=[delegation];proof.genesisAuthorities=bindings;proof.originalGeneses=originals;proof.creatorAuthorityEnvelopes=[envelope];return proof;
}
export function ownerContext(){return {identity:vector('identity'),ownerPublicKey:bytes(base.keys.owner.public_key_hex),ownerChainDigest:bytes(base.context.owner_chain_digest_hex),authorityExpiresAtSeconds:2000n,nowUnixSeconds:1100n,forbiddenJobKeys:[],knownJobAssociations:[]};}
export function commitInputs(proof){
 const request=vector('commit_request');request.proof=proof;
 const scope=proof.delegations[0].body.scope;
 const source=vector('source_public_github');source.cloneUrl=scope.sourceUrl;source.providerRepositoryId='';source.connection=undefined;source.installationId='';source.hashAlgorithm=2;source.refs=scope.branches.map(b=>create(api.ProviderRefSchema,{name:b.refName,kind:1,hashAlgorithm:2,headOid:Buffer.from(b.pinnedCommitOid).toString('hex')}));request.source=source;
 const configuration=vector('import_configuration');configuration.importProofBundleFormatVersion=2;configuration.limits.maxBranches=a.MAX_BRANCHES;configuration.limits.maxResultBytes=scope.maxResultBytes;configuration.converters[0].converterVersion=scope.converterVersion;configuration.defaultConverterVersion=scope.converterVersion;
 const prepared=vector('commit_preparation');prepared.proposal=a.delegationPreparation(proof.delegations[0].body);
 return {request,source,configuration,prepared};
}
