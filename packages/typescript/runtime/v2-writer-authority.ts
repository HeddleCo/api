import { blake3 } from "@noble/hashes/blake3.js";
import { clone, toBinary } from "@bufbuild/protobuf";
import { ThreadControlAuthoritySchema, type ThreadControlAuthority } from "./identity_pb.js";
import { SignedOwnerMintRootAttachmentSchema, type SignedOwnerMintRootAttachment, type OwnerHistory, type SignedSpoolPolicyRecord, type ResourceTransferAuditRecord } from "./owner_records_pb.js";
import { HostedWitnessBoundaryAcceptanceV1Schema, HostedWitnessStatementV1Schema, type HostedWitnessStatementV1 } from "../common/hosted_witness_pb.js";
import { strictDecode, canonicalHybridV1, join, utf8, equal, keyId, reject, width, verifySignature } from "./_hybrid-codec.js";
import { mintRootAttachmentSigningDigest } from "./owner-certificates.js";
import { signedNativeDigest, requirePolicyHistory, verifyWitnessPayload, type WitnessPayload } from "./import-authority.js";
import { verifyNativeGenesisPayload } from "./native-witness.js";
import { NativeGenesisWitnessV1Schema, type NativeGenesisWitnessV1 } from "./native_witness_pb.js";
import { ImportGenesisWitnessV1Schema, ImportAuthorityWitnessV1Schema, HostedLandingWitnessV1Schema, type ImportBoundaryAcceptanceV1, type ImportIdentityV1, type HostedLandingWitnessV1, type ImportAuthorityWitnessV1 } from "./import_authority_pb.js";
import { decode, type Value } from "./_collaboration-msgpack.js";
import type { RecordSignature } from "./common_pb.js";

export function decodeWriterAuthority(envelope:Uint8Array):ThreadControlAuthority {
  const a=strictDecode(ThreadControlAuthoritySchema,envelope,65536);
  if(a.format!==1)reject("Version");return a;
}
/** Account/root binding only; native owner-history and Biscuit verification is mandatory. */
export function verifyWriterAccountBinding(a:ThreadControlAuthority,actorAccount:Uint8Array,spoolAccount:Uint8Array,spoolOwnerId:Uint8Array):void {
  width(actorAccount,16);width(spoolAccount,16);width(spoolOwnerId,32);
  if(!actorAccount.some(Boolean))reject("Canonical");
  const root=a.owner?.root?.root??reject("Root");width(root.accountUuid,16);width(root.ownerId,32);
  if(!equal(root.accountUuid,actorAccount))reject("GenesisBinding");
  if(equal(actorAccount,spoolAccount)&&!equal(root.ownerId,spoolOwnerId))reject("Root");
}
export function checkWriterKeys(a:ThreadControlAuthority,publisherKeyId:Uint8Array,revokedKeyIds:readonly Uint8Array[]):void {
  width(publisherKeyId,32);width(a.mintRootPublicKey,32);
  if(revokedKeyIds.some(id=>equal(id,publisherKeyId)||equal(id,keyId(a.mintRootPublicKey))))reject("Revoked");
}
/** Reference checks only: caller authenticates the selected policy, Spool history,
 * original payload and acceptance signatures before admission. */
export function checkWitnessWriter(s:HostedWitnessStatementV1,envelope:Uint8Array,histories:OwnerHistory[],policies:SignedSpoolPolicyRecord[],spoolAccount:Uint8Array,coSigners:readonly RecordSignature[]=[],boundary?:ImportBoundaryAcceptanceV1):void {
  validateOwnerHistories(histories);
  requirePolicyHistory(policies,s.spoolUuid,s.policySequence,s.policyStateHash);
  const revoked=policies.find(p=>p.body&&equal(p.body.spoolUuid,s.spoolUuid)&&p.body.sequence===s.policySequence&&equal(p.body.policyStateHash,s.policyStateHash))?.body?.policy?.revokedKeyIds??[];
  if(s.basis===2){
    // Preserve original provenance bindings; only the signed acceptor is cut.
    // P1 retains its existing genesis provenance verifier (import: delegated).
    if(s.purpose!==1){const original=decodeWriterAuthority(envelope);verifyWriterAccountBinding(original,original.owner?.root?.root?.accountUuid??reject("Root"),spoolAccount,s.ownerId);}
    const e=boundary??reject("BoundaryAcceptance"),binding=e.binding??reject("BoundaryAcceptance"),selected=s.boundaryAcceptance??reject("BoundaryAcceptance");
    if(!equal(canonicalHybridV1(HostedWitnessBoundaryAcceptanceV1Schema,binding),canonicalHybridV1(HostedWitnessBoundaryAcceptanceV1Schema,selected)))reject("BoundaryAcceptance");
    const signed=e.signedAcceptance??reject("BoundaryAcceptance");
    if(signed.format!=="heddle-original-boundary-acceptance-v1")reject("Version");
    if(!signed.canonicalRecord.length||signed.canonicalRecord.length>65536)reject("Bounds");
    if(!equal(acceptingId(signed.format,signed.canonicalRecord),binding.acceptanceId)||!equal(signedNativeDigest(signed),binding.signedAcceptanceDigest))reject("BoundaryAcceptance");
    const acceptance=acceptingSelectors(signed.canonicalRecord),publisher=acceptingOctets(acceptance.accepting_publisher,32);
    if(signed.signatures.length!==1||!equal(signed.signatures[0]!.publicKey,publisher))reject("Signature");
    const author=acceptingMap(acceptance.accepting_author),actor=acceptingMap(author.actor);
    if(author.kind!=="account"||!equal(acceptingOctets(author.spool,16),s.spoolUuid))reject("Scope");
    const authority=acceptingOctets(author.authority),digest=acceptingOctets(author.authority_digest,32);
    if(!equal(acceptingId("heddle-thread-control-authority-v1",authority),digest))reject("GenesisBinding");
    const current=decodeWriterAuthority(authority);
    verifyWriterAccountBinding(current,acceptingOctets(actor.principal_id,16),spoolAccount,s.ownerId);
    checkWriterKeys(current,keyId(publisher),revoked);return;
  }
  if(revoked.some(id=>equal(id,s.publisherKeyId))||coSigners.some(s=>revoked.some(id=>equal(id,keyId(s.publicKey)))))reject("Revoked");
  if(!envelope.length){if(s.purpose!==1)reject("Bounds");return;}
  const a=decodeWriterAuthority(envelope);
  verifyWriterAccountBinding(a,a.owner?.root?.root?.accountUuid??reject("Root"),spoolAccount,s.ownerId);
  checkWriterKeys(a,s.publisherKeyId,revoked);
}

function acceptingId(format:string,bytes:Uint8Array):Uint8Array {
  const n=new Uint8Array(8);new DataView(n.buffer).setBigUint64(0,BigInt(bytes.length),true);
  return blake3(join(utf8.encode(format),n,Uint8Array.of(0),bytes));
}
function acceptingSelectors(bytes:Uint8Array):{[key:string]:Value} {
  try{return acceptingMap(decode(bytes));}catch{reject("Canonical");}
}
function acceptingMap(v:Value|undefined):{[key:string]:Value} {
  if(!v||typeof v!=="object"||Array.isArray(v)||v instanceof Uint8Array)reject("Canonical");return v;
}
function acceptingOctets(v:Value|undefined,n?:number):Uint8Array {
  if(v instanceof Uint8Array){if(n!==undefined)width(v,n);return v;}
  if(!Array.isArray(v)||v.some(b=>typeof b!=="number"||!Number.isInteger(b)||b<0||b>255))reject("Canonical");
  const bytes=Uint8Array.from(v as number[]);if(n!==undefined)width(bytes,n);return bytes;
}

export function validateOwnerHistories(histories:readonly OwnerHistory[]):void {
  histories.forEach((h,i)=>{width(h.stateHash,32);if(histories.slice(0,i).some(prev=>equal(prev.stateHash,h.stateHash)))reject("Canonical");});
}
/** Select from signed identities/transfers; native verification authenticates them. */
export function spoolAccountForStatement(s:HostedWitnessStatementV1,identities:readonly ImportIdentityV1[],transfers:readonly ResourceTransferAuditRecord[]):Uint8Array {
  let account:Uint8Array|undefined;
  for(const id of identities.filter(id=>equal(id.spoolUuid,s.spoolUuid)&&equal(id.spoolGenesisDigest,s.spoolGenesisDigest)&&equal(id.ownerId,s.ownerId)&&id.ownershipTransferSequence===s.ownershipTransferSequence)){
    if(account&&!equal(account,id.ownerAccountUuid))reject("Root");account=id.ownerAccountUuid;
  }
  for(const t of transfers){const h=t.transfer?.acceptance?.signedHandoff?.handoff;if(h&&equal(h.resourceUuid,s.spoolUuid)&&h.transferSequence===s.ownershipTransferSequence){if(account&&!equal(account,h.destinationOwnerUuid))reject("Root");account=h.destinationOwnerUuid;}}
  const result=account??reject("Root");width(result,16);return result;
}
/** Receiver-mandatory after native token and request-proof verification. */
export function verifyLandingActorBinding(p:HostedLandingWitnessV1,verifiedTokenSubject:Uint8Array,verifiedTokenSubjectKey:Uint8Array,verifiedRequestProofKey:Uint8Array,spoolAccount:Uint8Array,spoolOwnerId:Uint8Array):void {
  width(verifiedRequestProofKey,32);const key=p.request?.signature?.publicKey??reject("Signature");
  if(!equal(key,verifiedRequestProofKey)||!equal(verifiedTokenSubjectKey,verifiedRequestProofKey))reject("KeyRole");
  verifyWriterAccountBinding(decodeWriterAuthority(p.authorityEnvelope),verifiedTokenSubject,spoolAccount,spoolOwnerId);
}
/** Account resolved from the verified native operation author or claim acceptance. */
export function verifyAuthorityActorBinding(p:ImportAuthorityWitnessV1,verifiedAuthorOrClaimAccount:Uint8Array,spoolAccount:Uint8Array,spoolOwnerId:Uint8Array):void {
  verifyWriterAccountBinding(decodeWriterAuthority(p.authorityEnvelope),verifiedAuthorOrClaimAccount,spoolAccount,spoolOwnerId);
}
export interface RetainedMintRootIssuer { readonly kind:"retained-mint-root-issuer" }
type IssuerFacts={accountUuid:Uint8Array;stateHash:Uint8Array;sequence:bigint;publicKey:Uint8Array};
const issuers=new WeakMap<RetainedMintRootIssuer,IssuerFacts>();
/** Precondition: native verification authenticated this complete OwnerHistory. */
export function retainedMintRootIssuer(verifiedHistory:OwnerHistory,stateHash:Uint8Array,sequence:bigint):RetainedMintRootIssuer {
  width(stateHash,32);const root=verifiedHistory.root?.root??reject("Root");
  let publicKey=root.authorityKey?.publicKey??reject("Root"),endpoint=verifiedHistory.stateHash;
  verifiedHistory.acceptedTransitions.forEach((s,i)=>{
    const t=s.transition??reject("Root");if(t.sequence!==BigInt(i)+1n)reject("Root");
    if(t.sequence<=sequence)publicKey=t.nextAuthorityKey?.publicKey??reject("Root");
    else {if(t.kind===2)reject("Root");if(t.sequence===sequence+1n)endpoint=t.previousStateHash;}
  });
  if(sequence<0n||sequence>BigInt(verifiedHistory.acceptedTransitions.length)||!equal(endpoint,stateHash))reject("Root");
  width(publicKey,32);const result:RetainedMintRootIssuer=Object.freeze({kind:"retained-mint-root-issuer"});
  issuers.set(result,{accountUuid:root.accountUuid.slice(),stateHash:endpoint.slice(),sequence,publicKey:publicKey.slice()});return result;
}
export interface AdmittedMintRootAttachment { readonly kind:"admitted-mint-root-attachment" }
const admissions=new WeakMap<AdmittedMintRootAttachment,SignedOwnerMintRootAttachment>();
/** Resolve witness trust/signature/retirement BEFORE calling. This helper matches
 * payload commitments and verifies original signatures, then extracts the bytes. */
export async function admittedOwnerMintRootAttachment(authenticatedStatement:HostedWitnessStatementV1,payload:WitnessPayload|{kind:"native-genesis";payload:NativeGenesisWitnessV1}):Promise<AdmittedMintRootAttachment> {
  authenticatedStatement=clone(HostedWitnessStatementV1Schema,authenticatedStatement);
  payload=payload.kind==="native-genesis"?{kind:payload.kind,payload:clone(NativeGenesisWitnessV1Schema,payload.payload)}:payload.kind==="genesis"?{kind:payload.kind,payload:clone(ImportGenesisWitnessV1Schema,payload.payload)}:payload.kind==="authority"?{kind:payload.kind,payload:clone(ImportAuthorityWitnessV1Schema,payload.payload)}:{kind:payload.kind,payload:clone(HostedLandingWitnessV1Schema,payload.payload)};
  const envelope=payload.kind==="native-genesis"?payload.payload.creatorAuthorityEnvelope:payload.kind==="genesis"?payload.payload.creatorAuthorityEnvelope:payload.payload.authorityEnvelope;
  // Snapshot the attachment before asynchronous verification can yield.
  const a=decodeWriterAuthority(envelope),association=a.mintRootAssociation;
  if(association.case!=="ownerMintRootAttachment")reject("Root");
  const signed=clone(SignedOwnerMintRootAttachmentSchema,association.value);
  if(payload.kind==="native-genesis")await verifyNativeGenesisPayload(authenticatedStatement,payload.payload);
  else await verifyWitnessPayload(authenticatedStatement,payload);
  const result:AdmittedMintRootAttachment=Object.freeze({kind:"admitted-mint-root-attachment"});admissions.set(result,signed);return result;
}
/** Strict untrusted certificate boundary with opaque derived facts/admission. */
export async function verifyRetainedWriterAttachment(attachmentBytes:Uint8Array,mintRootPublicKey:Uint8Array,issuer:RetainedMintRootIssuer,admitted:AdmittedMintRootAttachment,nowUnixSeconds:bigint):Promise<void> {
  const signed=strictDecode(SignedOwnerMintRootAttachmentSchema,attachmentBytes,65536),facts=issuers.get(issuer)??reject("Root"),inventory=admissions.get(admitted)??reject("Root");
  await verifyRetainedOwnerMintRootAttachment(signed,mintRootPublicKey.slice(),facts,inventory,nowUnixSeconds);
}
async function verifyRetainedOwnerMintRootAttachment(signed:SignedOwnerMintRootAttachment,mintRootPublicKey:Uint8Array,e:IssuerFacts,admitted:SignedOwnerMintRootAttachment,nowUnixSeconds:bigint):Promise<void> {
  const bytes=toBinary(SignedOwnerMintRootAttachmentSchema,signed);
  if(!equal(toBinary(SignedOwnerMintRootAttachmentSchema,admitted),bytes))reject("Root");
  const a=signed.attachment??reject("Canonical"),owner=a.ownerKey??reject("Canonical"),mint=a.mintRootKey??reject("Canonical");
  if(!equal(a.accountUuid,e.accountUuid)||!equal(a.ownerStateHash,e.stateHash)||a.ownerSequence!==e.sequence||!equal(owner.publicKey,e.publicKey)||!equal(mint.publicKey,mintRootPublicKey))reject("Root");
  if(nowUnixSeconds<a.notBeforeUnixSeconds||nowUnixSeconds>=a.expiresAtUnixSeconds)reject("Expired");
  let digest:Uint8Array;try{digest=mintRootAttachmentSigningDigest(a);}catch{reject("Canonical");}
  const signature=signed.ownerSignature??reject("Signature");if(!equal(signature.signerKeyId,keyId(owner.publicKey)))reject("Signature");
  await verifySignature(e.publicKey.slice(),digest,signature.signature);
}
