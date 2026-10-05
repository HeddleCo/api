import { blake3 } from "@noble/hashes/blake3.js";
import { ForeignReferences } from "./_foreign-dependencies.js";
import { clone, create, toBinary } from "@bufbuild/protobuf";
import * as api from "./native_witness_pb.js";
import { ForeignDependencyOrigin, ImportIdentityV1Schema, ImportOwnerChainV1Schema, ImportAuthorityWitnessV1Schema, HostedLandingWitnessV1Schema, type ImportIdentityV1, type ImportPublicProofBundleV1 } from "./import_authority_pb.js";
import { SignedRecordSchema, type SignedRecord } from "./common_pb.js";
import type { HostedWitnessStatementV1 } from "../common/hosted_witness_pb.js";
import { canonicalHybridV1, signingDigest, hash, keyId, equal, compare, width, reject, HybridContractError, verifySignature, join } from "./_hybrid-codec.js";
import { decodeWriterAuthority, verifyWriterAccountBinding, checkWitnessWriter } from "./writer-authority.js";
import { threadGenesisId, type ThreadGenesisSigner } from "./thread-genesis.js";
import { decode, type Value } from "./_collaboration-msgpack.js";
import { verifyLandingKeyRoles, verifyNativeRecord, originalSignaturesDigest, ownerChainDigest, matchWitnessBoundary, requireBoundaryOriginal, verifyWitnessPayload, validatePublicBundle, requirePolicyHistory } from "./import-authority.js";
import { resolveWitnessStatement, verifyWitnessInclusion, leafDigest, statementSigningDigest, type VerifiedWitnessSet } from "./witness-trust.js";

export const NATIVE_GENESIS_DOMAIN = "heddle-native-genesis-authority-v1";
export const signedNativeGenesisAuthorityDigest = (v:api.SignedNativeGenesisAuthorityV1) => signingDigest("heddle-signed-native-genesis-authority-v1",api.SignedNativeGenesisAuthorityV1Schema,v);
function map(v:Value|undefined):{[key:string]:Value} {
  if (!v || typeof v!=="object" || Array.isArray(v) || v instanceof Uint8Array) reject("Canonical");
  return v;
}
function octets(v:Value|undefined,n:number):Uint8Array {
  if(v instanceof Uint8Array){width(v,n);return v;}
  if(!Array.isArray(v)||v.length!==n||v.some(b=>typeof b!=="number"||!Number.isInteger(b)||b<0||b>255))reject("Canonical");
  return Uint8Array.from(v as number[]);
}
function uuid(v:Value|undefined):Uint8Array {
  if(typeof v!=="string"||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v))reject("Canonical");
  return Uint8Array.from(v.replaceAll("-","").match(/../g)!,b=>parseInt(b,16));
}
function selectors(r:SignedRecord){try{return map(decode(r.canonicalRecord));}catch{reject("Canonical");}}
/** Signature and exact native selectors. Native model/owner capability verification
 * with independently selected context is still required before mutation. */
export async function verifyNativeGenesisAuthority(signed:api.SignedNativeGenesisAuthorityV1,original:SignedRecord,envelope:Uint8Array):Promise<void> {
  signed=clone(api.SignedNativeGenesisAuthorityV1Schema,signed);original=structuredClone(original);envelope=envelope.slice();
  const b=signed.body??reject("GenesisBinding"),id=b.identity??reject("Canonical");
  if(b.formatVersion!==1)reject("Version");
  for(const v of [id.spoolUuid,id.ownerAccountUuid]){width(v,16);if(!v.some(Boolean))reject("Canonical");}
  for(const v of [id.spoolGenesisDigest,id.ownerId,id.ownerStateHash,b.genesisDigest,b.originalSignaturesDigest,b.creatorPublicKey,b.creatorAuthorityEnvelopeDigest,b.ownerChainDigest,b.publisherKeyId])width(v,32);
  if(envelope.length>65536)reject("Bounds");
  await verifyNativeRecord(original,"heddle-thread-genesis-v1");
  const g=selectors(original),owner=map(g.owner);
  if(g.version!==1||!equal(uuid(g.spool),id.spoolUuid)||!equal(octets(g.creator,32),b.creatorPublicKey)||original.signatures.length!==1||!equal(original.signatures[0]!.publicKey,b.creatorPublicKey)||!equal(threadGenesisId(original.canonicalRecord),b.genesisDigest)||!equal(originalSignaturesDigest([original]),b.originalSignaturesDigest)||!equal(hash(envelope),b.creatorAuthorityEnvelopeDigest)||!equal(keyId(b.creatorPublicKey),b.publisherKeyId))reject("GenesisBinding");
  if(b.ownerKind===1){if(!envelope.length)reject("GenesisBinding");verifyWriterAccountBinding(decodeWriterAuthority(envelope),octets(owner.account,16),id.ownerAccountUuid,id.ownerId);}
  else if(b.ownerKind===2){if(!equal(octets(owner.local_key,32),b.creatorPublicKey)||envelope.length)reject("GenesisBinding");}
  else reject("GenesisBinding");
  const sig=signed.creatorSignature??reject("Signature");if(!equal(sig.signerKeyId,keyId(b.creatorPublicKey)))reject("Signature");
  await verifySignature(b.creatorPublicKey,signingDigest(NATIVE_GENESIS_DOMAIN,api.NativeGenesisAuthorityV1Schema,b),sig.signature);
}
/** Freeze original and authority first, then request the second creator signature.
 * The caller selects/verifies the identity and owner chain before this helper. */
export async function signNativeGenesisAuthority(original:SignedRecord,envelope:Uint8Array,identity:ImportIdentityV1,chain:import("./import_authority_pb.js").ImportOwnerChainV1,signer:ThreadGenesisSigner):Promise<api.SignedNativeGenesisAuthorityV1> {
  original=structuredClone(original);envelope=envelope.slice();identity=clone(ImportIdentityV1Schema,identity);chain=clone(ImportOwnerChainV1Schema,chain);
  const key=signer.publicKey.slice(),g=selectors(original),owner=map(g.owner);
  const body=create(api.NativeGenesisAuthorityV1Schema,{formatVersion:1,identity,ownerKind:owner.account!==undefined?1:2,genesisDigest:threadGenesisId(original.canonicalRecord),originalSignaturesDigest:originalSignaturesDigest([original]),creatorPublicKey:key,creatorAuthorityEnvelopeDigest:hash(envelope),ownerChainDigest:ownerChainDigest(chain),publisherKeyId:keyId(key)});
  const signature=await signer.sign(signingDigest(NATIVE_GENESIS_DOMAIN,api.NativeGenesisAuthorityV1Schema,body));
  const signed=create(api.SignedNativeGenesisAuthorityV1Schema,{body,creatorSignature:{signerKeyId:keyId(key),signature}});
  await verifyNativeGenesisAuthority(signed,original,envelope);return signed;
}
export async function verifyNativeGenesisPayload(s:HostedWitnessStatementV1,p:api.NativeGenesisWitnessV1):Promise<void> {
  s=structuredClone(s);p=clone(api.NativeGenesisWitnessV1Schema,p);
  if(p.formatVersion!==1||p.kind!==2)reject("Version");
  const binding=p.binding??reject("GenesisBinding"),original=p.originalGenesis??reject("Canonical");
  await verifyNativeGenesisAuthority(binding,original,p.creatorAuthorityEnvelope);
  const b=binding.body!,id=b.identity!;
  await matchWitnessBoundary(s,p.boundaryAcceptance?[p.boundaryAcceptance]:[]);
  if((s.basis===2)!==!!p.boundaryAcceptance)reject("BoundaryAcceptance");
  if(p.boundaryAcceptance)requireBoundaryOriginal(p.boundaryAcceptance,original);
  if(s.purpose!==1||!equal(s.spoolUuid,id.spoolUuid)||!equal(s.spoolGenesisDigest,id.spoolGenesisDigest)||(s.basis===1&&(!equal(s.ownerId,id.ownerId)||!equal(s.ownerStateHash,id.ownerStateHash)||s.ownershipTransferSequence!==id.ownershipTransferSequence))||!equal(s.canonicalPayload,canonicalHybridV1(api.NativeGenesisWitnessV1Schema,p))||!equal(s.authorityDigest,signedNativeGenesisAuthorityDigest(binding))||!equal(s.originalSignaturesDigest,b.originalSignaturesDigest)||!equal(s.publisherKeyId,b.publisherKeyId))reject("Scope");
  if(s.canonicalPayload.length>65536)reject("Bounds");
}
const authorityDigest=(p:import("./import_authority_pb.js").ImportAuthorityWitnessV1)=>signingDigest("heddle-import-authority-witness-payload-v1",ImportAuthorityWitnessV1Schema,p);
function sorted<T>(values:T[],digest:(v:T)=>Uint8Array){values.forEach((v,i)=>{if(i&&compare(digest(values[i-1]!),digest(v))>=0)reject("Canonical");});}
function thread(r:SignedRecord){return r.format==="heddle-thread-genesis-v1"?threadGenesisId(r.canonicalRecord):octets(selectors(r).thread,32);}
function requiresAuthority(r:SignedRecord){
  if(r.format!=="heddle-thread-operation-v1")return true;
  const body=map(selectors(r).body);
  if(body.kind==="integration")return false;
  if(body.kind==="capture")return map(map(body.canonical).author).kind!=="local_key";
  if(body.kind==="local_integration"){
    const bytes=body.canonical;
    if(!(bytes instanceof Uint8Array)&&(!Array.isArray(bytes)||bytes.some(b=>typeof b!=="number"||!Number.isInteger(b)||b<0||b>255)))reject("Canonical");
    try{return map(map(decode(Uint8Array.from(bytes as Uint8Array|number[]))).author).kind!=="local_key";}
    catch{reject("Canonical");}
  }
  return true;
}
/** Reference completeness and original signatures. This cannot enroll an owner,
 * authenticate a carried set or replace native causal/authority verification. */
export async function validatePublicNativeBundle(b:api.NativePublicProofBundleV1):Promise<void> {
  b=clone(api.NativePublicProofBundleV1Schema,b);
  if(b.formatVersion!==1)reject("Version");
  if(toBinary(api.NativePublicProofBundleV1Schema,b).length>1048576||b.ownerHistories.length>64||b.ownershipTransfers.length>64||!b.ownerChains.length||b.ownerChains.length>64||b.policies.length>256||!b.genesisWitnesses.length||b.genesisWitnesses.length>256||b.authorityWitnesses.length>256||b.landingWitnesses.length>256||b.statements.length>1024||b.historyProofs.length>1024)reject("Bounds");
  const foreign=new ForeignReferences(b.foreignDependencies,ForeignDependencyOrigin.NATIVE);
  const owner=b.ownerGenesis?.genesis??reject("Canonical"),chain=b.ownerChains[0]??reject("Canonical");
  sorted(b.ownerChains,ownerChainDigest);
  if(!b.witnessSet)reject("Canonical");
  for(const c of b.ownerChains)if(!equal(c.spoolGenesisDigest,chain.spoolGenesisDigest)||c.ownerStateHashes.some(h=>!b.ownerHistories.some(o=>equal(o.stateHash,h)))||c.transferAuditHashes.some(h=>!b.ownershipTransfers.some(t=>equal(t.auditRecordHash,h))))reject("Scope");
  sorted(b.genesisWitnesses,p=>signedNativeGenesisAuthorityDigest(p.binding??reject("GenesisBinding")));
  sorted(b.authorityWitnesses,authorityDigest);sorted(b.landingWitnesses,p=>signingDigest("heddle-hosted-landing-witness-payload-v1",HostedLandingWitnessV1Schema,p));sorted(b.statements,s=>statementSigningDigest(s.body??reject("Canonical")));
  const requireStatement=(purpose:number,payload:Uint8Array)=>{if(b.statements.filter(s=>s.body?.purpose===purpose&&equal(s.body.canonicalPayload,payload)).length!==1)reject("Scope");};
  const exact=(a:SignedRecord|undefined,r:SignedRecord)=>!!a&&equal(toBinary(SignedRecordSchema,a),toBinary(SignedRecordSchema,r));
  const requireNativeDependency=async(original:SignedRecord)=>{
    if(!b.genesisWitnesses.some(g=>g.originalGenesis&&equal(threadGenesisId(g.originalGenesis.canonicalRecord),thread(original)))){await foreign.verify(original);return;}
    if(requiresAuthority(original)){
      const p=b.authorityWitnesses.find(p=>exact(p.original,original))??reject("Scope");
      requireStatement(2,canonicalHybridV1(ImportAuthorityWitnessV1Schema,p));
    }else if(map(selectors(original).body).kind==="integration"){
      const p=b.landingWitnesses.find(p=>exact(p.execution,original))??reject("Scope");
      requireStatement(4,canonicalHybridV1(HostedLandingWitnessV1Schema,p));
    }else{
      // Local captures and LocalKey integrations retain native proof and the
      // thread's exact hosted ownership claim, never an authority/landing receipt.
      // This is reference closure only. Native authorization must bind publisher
      // to genesis.owner.local_key and enforce the selected signed cutoff.
      await verifyNativeRecord(original,"heddle-thread-operation-v1");
      const p=b.authorityWitnesses.find(p=>p.kind===2&&p.original&&equal(thread(p.original),thread(original)))??reject("Scope");
      requireStatement(2,canonicalHybridV1(ImportAuthorityWitnessV1Schema,p));
    }
  };
  for(const p of b.genesisWitnesses){
    const g=p.binding?.body??reject("GenesisBinding"),id=g.identity??reject("Canonical");
    await verifyNativeGenesisAuthority(p.binding!,p.originalGenesis??reject("Canonical"),p.creatorAuthorityEnvelope);
    if(!equal(id.spoolUuid,owner.spoolUuid)||!equal(id.spoolGenesisDigest,chain.spoolGenesisDigest)||!b.ownerChains.some(c=>equal(ownerChainDigest(c),g.ownerChainDigest))||!b.ownerHistories.some(h=>equal(h.stateHash,id.ownerStateHash)&&h.root?.root&&equal(h.root.root.ownerId,id.ownerId)&&equal(h.root.root.accountUuid,id.ownerAccountUuid)))reject("Scope");
    if(g.ownerKind===2&&!b.authorityWitnesses.some(a=>a.kind===2&&a.original&&equal(thread(a.original),g.genesisDigest)))reject("Scope");
    requireStatement(1,canonicalHybridV1(api.NativeGenesisWitnessV1Schema,p));
  }
  for(const p of b.authorityWitnesses){
    requireStatement(2,canonicalHybridV1(ImportAuthorityWitnessV1Schema,p));
    if(!requiresAuthority(p.original??reject("Canonical")))reject("Scope");
    const subjectThread=thread(p.original??reject("Canonical"));
    if(!b.genesisWitnesses.some(g=>g.originalGenesis&&equal(threadGenesisId(g.originalGenesis.canonicalRecord),subjectThread)))reject("Scope");
    for(const original of [...(p.original?[p.original]:[]),...p.dependencies]){
      if(["heddle-thread-genesis-v1","heddle-thread-operation-v1","heddle-thread-ownership-claim-v1","heddle-thread-ownership-resolution-v1"].includes(original.format)){
        const t=thread(original);
        if(!b.genesisWitnesses.some(g=>g.originalGenesis&&equal(threadGenesisId(g.originalGenesis.canonicalRecord),t))){await foreign.verify(original);continue;}
        if(original.format==="heddle-thread-genesis-v1"&&!b.genesisWitnesses.some(g=>g.originalGenesis&&equal(toBinary(SignedRecordSchema,g.originalGenesis),toBinary(SignedRecordSchema,original))))reject("Scope");
        if(original.format!=="heddle-thread-genesis-v1"&&original!==p.original)await requireNativeDependency(original);
      }else if(!["heddle-original-boundary-acceptance-v1","heddle-thread-genesis-admission-v2","heddle-thread-authority-admission-v3"].includes(original.format))reject("Version");
    }
  }
  for(const p of b.landingWitnesses){
    requireStatement(4,canonicalHybridV1(HostedLandingWitnessV1Schema,p));
    const execution=p.execution??reject("Canonical");
    if(execution.format!=="heddle-thread-operation-v1"||map(selectors(execution).body).kind!=="integration")reject("Scope");
    if(!b.genesisWitnesses.some(g=>g.originalGenesis&&equal(threadGenesisId(g.originalGenesis.canonicalRecord),thread(execution))))reject("Scope");
    for(const original of [...(p.sourceOperation?[p.sourceOperation]:[]),...p.reviewEvidence]){
      await requireNativeDependency(original);
    }
  }
  for(const signed of b.statements){
    const s=signed.body??reject("Canonical");
    if(!equal(s.spoolUuid,owner.spoolUuid)||!equal(s.spoolGenesisDigest,chain.spoolGenesisDigest)||!b.ownerHistories.some(h=>equal(h.stateHash,s.ownerStateHash)&&h.root?.root&&equal(h.root.root.ownerId,s.ownerId)))reject("Scope");
    requirePolicyHistory(b.policies,s.spoolUuid,s.policySequence,s.policyStateHash);
    if(s.purpose===1){const p=b.genesisWitnesses.find(p=>equal(canonicalHybridV1(api.NativeGenesisWitnessV1Schema,p),s.canonicalPayload))??reject("Scope");await verifyNativeGenesisPayload(s,p);checkWitnessWriter(s,p.creatorAuthorityEnvelope,b.ownerHistories,b.policies);}
    else if(s.purpose===2){const p=b.authorityWitnesses.find(p=>equal(canonicalHybridV1(ImportAuthorityWitnessV1Schema,p),s.canonicalPayload))??reject("Scope");await verifyWitnessPayload(s,{kind:"authority",payload:p});checkWitnessWriter(s,p.authorityEnvelope,b.ownerHistories,b.policies);}
    else if(s.purpose===4){const p=b.landingWitnesses.find(p=>equal(canonicalHybridV1(HostedLandingWitnessV1Schema,p),s.canonicalPayload))??reject("Scope");await verifyWitnessPayload(s,{kind:"landing",payload:p});checkWitnessWriter(s,p.authorityEnvelope,b.ownerHistories,b.policies);}
    else reject("Version");
  }
  foreign.finish();
}
/** All statements resolve separately, including exact retirement proofs. */
export async function verifyNativeBundleWitnesses(b:api.NativePublicProofBundleV1,set:VerifiedWitnessSet,now:bigint,forbiddenLandingKeys:Uint8Array[]=[]):Promise<void> {
  b=clone(api.NativePublicProofBundleV1Schema,b);await validatePublicNativeBundle(b);
  for(const p of b.landingWitnesses)verifyLandingKeyRoles(p,set.knownJobKeys,forbiddenLandingKeys);
  // The opaque verified snapshot, rather than the carrier, selects trust.
  if(!b.witnessSet?.body||!equal(b.witnessSet.bodyDigest,set.digest)||!equal(signingDigest("heddle-hosted-witness-set-v1\0",(await import("../common/hosted_witness_pb.js")).HostedWitnessSetV1Schema,b.witnessSet.body),set.digest))reject("StaleContext");
  for(const signed of b.statements){
    try { await resolveWitnessStatement(set,signed,undefined,false,now);continue; }
    catch(error){if(!(error instanceof HybridContractError)||error.reason!=="Proof")throw error;}
    const s=signed.body??reject("Canonical"),entry=set.body.entries.find(e=>equal(e.executorId,s.executorId))??reject("Root");
    const leaf=leafDigest(s.purpose,canonicalHybridV1((await import("../common/hosted_witness_pb.js")).HostedWitnessStatementV1Schema,s),signed.signature);
    const proof=b.historyProofs.find(p=>{if(p.purpose!==s.purpose)return false;try{verifyWitnessInclusion(leaf,p,entry);return true;}catch{return false;}})??reject("Proof");
    await resolveWitnessStatement(set,signed,proof,false,now);
  }
}
/** Select a LocalKey proof cutoff from independently verified native history.
 * Native causal/owner checks remain required; the order comes from the exact
 * authenticated dependent statement. */
export function localWorkCutoff(b:api.NativePublicProofBundleV1,original:SignedRecord,dependentAdmissionOrder:bigint):bigint {
  const subject=thread(original),orders:bigint[]=[],claims:Uint8Array[]=[],resolutions:SignedRecord[]=[];
  let genesisCount=0;
  for(const signed of b.statements){
    const s=signed.body??reject("Canonical");
    if(s.admissionOrder>dependentAdmissionOrder)continue;
    if(s.purpose===1){for(const p of b.genesisWitnesses){const binding=p.binding?.body??reject("Canonical");if(equal(binding.genesisDigest,subject)&&equal(s.canonicalPayload,canonicalHybridV1(api.NativeGenesisWitnessV1Schema,p))){if(binding.ownerKind!==2)reject("Scope");genesisCount++;orders.push(s.admissionOrder);}}}
    else if(s.purpose===2){for(const p of b.authorityWitnesses){if(![2,3].includes(p.kind)||!equal(s.canonicalPayload,canonicalHybridV1(ImportAuthorityWitnessV1Schema,p)))continue;const r=p.original??reject("Canonical");if(!equal(thread(r),subject))continue;orders.push(s.admissionOrder);if(p.kind===2)claims.push(nativeOriginalId(r));else resolutions.push(r);}}
  }
  if(genesisCount!==1)reject("Scope");
  if(resolutions.length===0){if(claims.length!==1)reject("Scope");}
  else if(resolutions.length===1){const r=selectors(resolutions[0]!);claims.sort(compare);const conflicts=r.conflicting_claims;if(!Array.isArray(conflicts)||claims.length!==conflicts.length||claims.some((c,i)=>!equal(c,octets(conflicts[i],32)))||!claims.some(c=>equal(c,octets(r.winning_claim,32))))reject("Scope");}
  else reject("Scope");
  const cutoff=orders.reduce((a,b)=>a>b?a:b,0n);if(cutoff===0n)reject("Scope");return cutoff;
}
function nativeOriginalId(r:SignedRecord):Uint8Array {
  const size=new Uint8Array(8);new DataView(size.buffer).setBigUint64(0,BigInt(r.canonicalRecord.length),true);
  return blake3(join(new TextEncoder().encode(r.format),size,Uint8Array.of(0),r.canonicalRecord));
}
/** Explicit transport arms, never delegation-less fallback. */
export async function validateNativeWitnessCarriers(imported:ImportPublicProofBundleV1|undefined,native:api.NativePublicProofBundleV1|undefined):Promise<void> {
  if(imported&&native)reject("Protocol");if(imported)await validatePublicBundle(imported);else if(native)await validatePublicNativeBundle(native);
}
