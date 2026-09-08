import { clone, create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { SignedRecordSchema, RecordRefSchema, type RecordRef, type SignedRecord } from "./common_pb.js";
import { EndpointKind, type EndpointRef } from "./stream_pb.js";
import { BeginPairingRequestSchema, CompletePairingRequestSchema, PairingInitiationBindingSchema,
  BrowserPairingCompletionBindingSchema, BrowserPairingApprovalBindingSchema,
  type BrowserPairingApprovalBinding, type BeginPairingRequest, type CompletePairingRequest } from "./identity_pb.js";
const utf8 = new TextEncoder();
const INITIATION = "heddle.pairing-initiation.v2";
const COMPLETION = "heddle.browser-pairing-completion.v1";
export interface PairingSigner { publicKey: Uint8Array; sign(bytes: Uint8Array): Promise<Uint8Array> }
function equal(a: Uint8Array, b: Uint8Array) { return a.length === b.length && a.every((byte, index) => byte === b[index]); }
function joined(a: Uint8Array, b: Uint8Array) { const value = new Uint8Array(a.length + b.length); value.set(a); value.set(b, a.length); return value; }
function host(value: EndpointRef) { if (value.kind !== EndpointKind.WEFT || value.publicKey.length !== 32) throw new Error("Pairing requires the observed Weft endpoint"); }
function operation(value: string) { if (!value || utf8.encode(value).length > 256) throw new Error("Invalid pairing operation identity"); }
function reference(value: RecordRef) { if (value.spool || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value.id) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(value.id)) throw new Error("Invalid browser pairing reference"); }
function approval(value: BrowserPairingApprovalBinding) {
  if (value.formatVersion !== 1 || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value.accountId) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(value.accountId)
    || [value.rootPublicKey, value.subjectPublicKey, value.credentialDigest, value.pairingChallenge].some(bytes => bytes.length !== 32)
    || value.notBeforeUnixSeconds <= 0n || value.expiresAtUnixSeconds <= value.notBeforeUnixSeconds) throw new Error("Invalid browser pairing approval");
}
async function verify(record: SignedRecord, format: string, publicKey: Uint8Array) {
  if (record.format !== format || record.signatures.length !== 1 || publicKey.length !== 32 || !equal(record.signatures[0].publicKey, publicKey) || record.signatures[0].signature.length !== 64) throw new Error("Invalid browser pairing signer");
  const key = await crypto.subtle.importKey("raw", publicKey as BufferSource, "Ed25519", false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", key, record.signatures[0].signature as BufferSource, joined(utf8.encode(format + "\0"), record.canonicalRecord) as BufferSource)) throw new Error("Invalid browser pairing signature");
}
async function signed(format: string, canonicalRecord: Uint8Array, signer: PairingSigner) {
  const publicKey = signer.publicKey.slice();
  const signature = (await signer.sign(joined(utf8.encode(format + "\0"), canonicalRecord))).slice();
  const record = create(SignedRecordSchema, { format, canonicalRecord, signatures: [{ publicKey, signature }] });
  await verify(record, format, publicKey); return record;
}
/** Browser pairing proves a credential key. It does not invent an Iroh endpoint
 * or an independent mint issuer. Fresh exact RPC PoP remains mandatory. */
export async function signBrowserPairingInitiation(observedHost: EndpointRef, clientOperationId: string, nowUnixSeconds: bigint, signer: PairingSigner): Promise<BeginPairingRequest> {
  host(observedHost); operation(clientOperationId);
  if (nowUnixSeconds <= 0n || nowUnixSeconds > (1n << 63n) - 601n || signer.publicKey.length !== 32) throw new Error("Invalid pairing key or lifetime");
  const binding = create(PairingInitiationBindingSchema, { host: observedHost, clientOperationId, receiver: { case: "browser", value: {} }, subjectPublicKey: signer.publicKey.slice(), notBeforeUnixSeconds: nowUnixSeconds, expiresAtUnixSeconds: nowUnixSeconds + 600n });
  const canonical = toBinary(PairingInitiationBindingSchema, binding);
  const subjectPossession = await signed(INITIATION, canonical, signer);
  return create(BeginPairingRequestSchema, { clientOperationId, receiver: { case: "browser", value: {} }, subjectPublicKey: binding.subjectPublicKey, subjectPossession });
}
/** Use only the exact currently observed approval. Approval still requires the
 * original parent Biscuit and the receiver's new request-bound possession. */
export async function signBrowserPairingCompletion(observedHost: EndpointRef, clientOperationId: string, pairing: RecordRef, observedApproval: BrowserPairingApprovalBinding, nowUnixSeconds: bigint, signer: PairingSigner): Promise<CompletePairingRequest> {
  host(observedHost); operation(clientOperationId); reference(pairing); approval(observedApproval);
  if (!equal(observedApproval.subjectPublicKey, signer.publicKey) || nowUnixSeconds < observedApproval.notBeforeUnixSeconds || nowUnixSeconds >= observedApproval.expiresAtUnixSeconds) throw new Error("Browser pairing approval key or lifetime mismatch");
  const binding = create(BrowserPairingCompletionBindingSchema, { host: observedHost, clientOperationId, pairing: clone(RecordRefSchema, pairing), approval: clone(BrowserPairingApprovalBindingSchema, observedApproval) });
  const canonical = toBinary(BrowserPairingCompletionBindingSchema, binding);
  const record = await signed(COMPLETION, canonical, signer);
  return create(CompletePairingRequestSchema, { clientOperationId, pairing: binding.pairing, proof: { case: "browserPossession", value: record } });
}
/** Verify against an externally supplied host and current public approval;
 * trusting the values inside the signed record itself would prove nothing. */
export async function verifyBrowserPairingCompletion(request: CompletePairingRequest, observedHost: EndpointRef, observedApproval: BrowserPairingApprovalBinding, nowUnixSeconds: bigint): Promise<void> {
  host(observedHost); operation(request.clientOperationId); approval(observedApproval);
  if (!request.pairing) throw new Error("Missing browser pairing reference"); reference(request.pairing);
  const record = request.proof.case === "browserPossession" ? request.proof.value : undefined;
  if (!record || record.canonicalRecord.length > 2048) throw new Error("Invalid browser completion format or size");
  const binding = fromBinary(BrowserPairingCompletionBindingSchema, record.canonicalRecord);
  const expected = create(BrowserPairingCompletionBindingSchema, { host: observedHost, clientOperationId: request.clientOperationId, pairing: request.pairing, approval: observedApproval });
  if (!equal(toBinary(BrowserPairingCompletionBindingSchema, expected), record.canonicalRecord) || nowUnixSeconds < observedApproval.notBeforeUnixSeconds || nowUnixSeconds >= observedApproval.expiresAtUnixSeconds || !binding.approval) throw new Error("Browser completion differs from current approval or lifetime");
  await verify(record, COMPLETION, observedApproval.subjectPublicKey);
}
