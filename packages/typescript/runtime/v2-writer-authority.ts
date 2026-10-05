import { toBinary } from "@bufbuild/protobuf";
import { ThreadControlAuthoritySchema, type ThreadControlAuthority } from "./identity_pb.js";
import { SignedOwnerMintRootAttachmentSchema, type SignedOwnerMintRootAttachment, type OwnerHistory, type SignedSpoolPolicyRecord } from "./owner_records_pb.js";
import type { HostedWitnessStatementV1 } from "../common/hosted_witness_pb.js";
import { strictDecode, equal, keyId, reject, width, verifySignature } from "./_hybrid-codec.js";
import { mintRootAttachmentSigningDigest } from "./owner-certificates.js";
import { requirePolicyHistory } from "./import-authority.js";

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
/** Reference checks only: caller authenticates the selected policy and Spool history. */
export function checkWitnessWriter(s:HostedWitnessStatementV1,envelope:Uint8Array,histories:OwnerHistory[],policies:SignedSpoolPolicyRecord[]):void {
  requirePolicyHistory(policies,s.spoolUuid,s.policySequence,s.policyStateHash);
  const revoked=policies.find(p=>p.body&&equal(p.body.spoolUuid,s.spoolUuid)&&p.body.sequence===s.policySequence&&equal(p.body.policyStateHash,s.policyStateHash))?.body?.policy?.revokedKeyIds??[];
  if(revoked.some(id=>equal(id,s.publisherKeyId)))reject("Revoked");
  if(!envelope.length){if(s.purpose!==1)reject("Bounds");return;}
  const a=decodeWriterAuthority(envelope),spool=histories.find(h=>equal(h.stateHash,s.ownerStateHash)&&h.root?.root&&equal(h.root.root.ownerId,s.ownerId))?.root?.root??reject("Root");
  verifyWriterAccountBinding(a,a.owner?.root?.root?.accountUuid??reject("Root"),spool.accountUuid,s.ownerId);
  checkWriterKeys(a,s.publisherKeyId,revoked);
}
/** Issuer facts MUST come from the actor's independently verified owner history.
 * Recover clears issuerRetainedMintAuthority for all prior issuers; Rotate preserves it. */
export interface RetainedMintRootExpectation {
  accountUuid:Uint8Array;mintRootPublicKey:Uint8Array;issuerStateHash:Uint8Array;
  issuerSequence:bigint;issuerPublicKey:Uint8Array;issuerRetainedMintAuthority:boolean;
  /** Host durable inventory at issuance; exact authenticated P1/P2/P4 attachments at a receiver. */
  admittedAttachments:readonly SignedOwnerMintRootAttachment[];nowUnixSeconds:bigint;
}
export async function verifyRetainedOwnerMintRootAttachment(signed:SignedOwnerMintRootAttachment,e:RetainedMintRootExpectation):Promise<void> {
  // Snapshot all inputs before signature verification yields to caller code.
  const bytes=toBinary(SignedOwnerMintRootAttachmentSchema,signed);
  signed=strictDecode(SignedOwnerMintRootAttachmentSchema,bytes,65536);
  if(!e.issuerRetainedMintAuthority||!e.admittedAttachments.some(a=>equal(toBinary(SignedOwnerMintRootAttachmentSchema,a),bytes)))reject("Root");
  const a=signed.attachment??reject("Canonical"),owner=a.ownerKey??reject("Canonical"),mint=a.mintRootKey??reject("Canonical");
  if(!equal(a.accountUuid,e.accountUuid)||!equal(a.ownerStateHash,e.issuerStateHash)||a.ownerSequence!==e.issuerSequence||!equal(owner.publicKey,e.issuerPublicKey)||!equal(mint.publicKey,e.mintRootPublicKey))reject("Root");
  if(e.nowUnixSeconds<a.notBeforeUnixSeconds||e.nowUnixSeconds>=a.expiresAtUnixSeconds)reject("Expired");
  let digest:Uint8Array;try{digest=mintRootAttachmentSigningDigest(a);}catch{reject("Canonical");}
  const signature=signed.ownerSignature??reject("Signature");if(!equal(signature.signerKeyId,keyId(owner.publicKey)))reject("Signature");
  await verifySignature(e.issuerPublicKey.slice(),digest,signature.signature);
}
