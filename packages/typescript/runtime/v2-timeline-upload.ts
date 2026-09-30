/** Shared bounds for the hosted v1 timeline input. Servers must also reject
 * unknown protobuf fields before a decoder discards them. */
import { toBinary } from "@bufbuild/protobuf";
import { sha256 } from "@noble/hashes/sha2.js";
import { OperationRecord_State } from "./common_pb.js";
import {
  TimelineOriginCredentialClass, UploadTimelineEventKind, UploadTimelineTool,
  UploadRunSummarySchema, UploadTimelineEventSchema,
  UploadScrubbedTimelineRequestSchema,
  type TimelineOriginCredentialIdentity, type TimelineOriginEndorsement, type TimelineAdmissionAcceptance,
  type UploadRunSummary, type UploadTimelineEvent, type UploadScrubbedTimelineRequest,
  type RegisterTimelineOriginRequest,
} from "./timeline_upload_pb.js";

export const MAX_TIMELINE_REQUEST_BYTES = 256 * 1024;
export const MAX_TIMELINE_EVENT_BYTES = 2 * 1024;
export const MAX_TIMELINE_SNAPSHOT_BYTES = 4 * 1024;
export const MAX_TIMELINE_EVENTS = 64;
export const MAX_TIMELINE_ORIGIN_BISCUIT_BYTES = 64 * 1024;
export const MAX_TIMELINE_OWNER_BUNDLE_BYTES = 64 * 1024;
/** Check lengths before fully decoding untrusted protobuf bytes. */
export function validateTimelineRawSize(raw: Uint8Array, kind: "request" | "event" | "snapshot"): void {
  const limit = kind === "request" ? MAX_TIMELINE_REQUEST_BYTES
    : kind === "event" ? MAX_TIMELINE_EVENT_BYTES : MAX_TIMELINE_SNAPSHOT_BYTES;
  if (raw.length > limit) throw new Error(`Invalid hosted timeline ${kind} size`);
}
export const ORIGIN_DOMAIN = "heddle-timeline-run-origin-v3";
export const DERIVATION_PATH_DOMAIN = "heddle-timeline-derivation-path-v1";
export const ACCEPTANCE_DOMAIN = "heddle-timeline-run-acceptance-v1";
export const UPLOAD_DOMAIN = "heddle-timeline-upload-v1";
const encoder = new TextEncoder();
const MAX_POSITION = (1n << 63n) - 1n;
const validState = new Set([OperationRecord_State.QUEUED, OperationRecord_State.RUNNING,
  OperationRecord_State.COMPLETED, OperationRecord_State.FAILED, OperationRecord_State.CANCELED,
  OperationRecord_State.WAITING_FOR_HUMAN, OperationRecord_State.PAUSED]);
const validKind = new Set([UploadTimelineEventKind.RUN_STARTED, UploadTimelineEventKind.TURN_STARTED,
  UploadTimelineEventKind.TURN_FINISHED, UploadTimelineEventKind.TOOL_STARTED,
  UploadTimelineEventKind.TOOL_FINISHED, UploadTimelineEventKind.PROMPT_SUBMITTED,
  UploadTimelineEventKind.RUN_FINISHED, UploadTimelineEventKind.RUN_FAILED]);
const validTool = new Set([UploadTimelineTool.BASH, UploadTimelineTool.EDIT, UploadTimelineTool.READ,
  UploadTimelineTool.WRITE, UploadTimelineTool.GREP, UploadTimelineTool.GLOB,
  UploadTimelineTool.TASK, UploadTimelineTool.OTHER]);

function requireField(ok: boolean, field: string): asserts ok {
  if (!ok) throw new Error(`Invalid hosted timeline ${field}`);
}
export function validCanonicalUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![\s\S])/.test(value);
}
export function validRunId(value: string): boolean {
  return /^[A-Za-z0-9_-]{1,128}(?![\s\S])/.test(value);
}
export function validAgentLabel(value: string): boolean {
  return /^[A-Za-z0-9._:-]{1,64}(?![\s\S])/.test(value);
}
export function validVerifiedAgentId(value: string, agent: boolean): boolean {
  return agent ? value === "" || validAgentLabel(value) : value === "";
}

export function validateUploadSummary(value: UploadRunSummary): void {
  requireField(toBinary(UploadRunSummarySchema, value).length <= MAX_TIMELINE_SNAPSHOT_BYTES, "snapshot size");
  requireField(validState.has(value.state), "snapshot state");
  requireField(value.harness === "claude-code" || value.harness === "codex" || value.harness === "other", "snapshot harness");
}

export function validateUploadEvent(value: UploadTimelineEvent, nowMicros: bigint): void {
  requireField(value.position >= 0n && value.position <= MAX_POSITION, "event position");
  requireField(validKind.has(value.kind), "event kind");
  const at = value.recordedAt;
  requireField(at !== undefined && at.seconds >= -62135596800n && at.seconds <= 253402300799n
    && Number.isInteger(at.nanos) && at.nanos >= 0 && at.nanos < 1_000_000_000
    && at.nanos % 1000 === 0
    && at.seconds * 1_000_000n + BigInt(at.nanos / 1000) <= nowMicros + 300_000_000n, "recorded_at");
  const toolKind = value.kind === UploadTimelineEventKind.TOOL_STARTED || value.kind === UploadTimelineEventKind.TOOL_FINISHED;
  requireField((value.toolName !== undefined) === toolKind, "tool_name presence");
  if (value.toolName !== undefined) requireField(validTool.has(value.toolName), "tool_name");
  requireField(toBinary(UploadTimelineEventSchema, value).length <= MAX_TIMELINE_EVENT_BYTES, "event size");
}

function validateOriginFields(value: TimelineOriginEndorsement): void {
  requireField(value.deploymentPublicKey.length === 32, "deployment key");
  requireField(validCanonicalUuid(value.spoolId), "origin spool");
  requireField(value.threadId.length === 32, "origin thread");
  requireField(validRunId(value.runId), "origin run");
  requireField(validCanonicalUuid(value.principalId), "origin principal");
  requireField(value.credentialClass === TimelineOriginCredentialClass.DIRECT_HUMAN
    || value.credentialClass === TimelineOriginCredentialClass.AGENT, "origin credential class");
  requireField(value.effectivePopKeySha256.length === 32, "origin actor digest");
  requireField(value.credentialIdentity !== undefined, "origin credential identity");
  validateTimelineCredentialIdentity(value.credentialIdentity);
  requireField(value.credentialIdentity.identity.case !== "offlineDerived"
    || value.credentialClass === TimelineOriginCredentialClass.AGENT, "offline origin class");
  requireField(value.uploaderDevicePublicKey.length === 32, "origin uploader key");
}
export function validateTimelineCredentialIdentity(value: TimelineOriginCredentialIdentity): void {
  const identity = value.identity;
  if (identity.case === "serverIssued") {
    requireField(identity.value.credentialId.length >= 1 && identity.value.credentialId.length <= 128,
      "issued credential ID");
  } else if (identity.case === "offlineDerived") {
    requireField(identity.value.issuedAncestorCredentialId.length >= 1
      && identity.value.issuedAncestorCredentialId.length <= 128, "issued ancestor credential ID");
    requireField(identity.value.terminalRevocationId.length === 64, "terminal revocation ID");
    requireField(identity.value.derivationPathSha256.length === 32, "derivation path digest");
  } else {
    throw new Error("Invalid hosted timeline credential identity variant");
  }
}
export function validateTimelineOrigin(value: TimelineOriginEndorsement): void {
  validateOriginFields(value);
  requireField(value.signature.length === 64, "origin signature");
}

function validateOriginBiscuit(origin: TimelineOriginEndorsement, biscuit: Uint8Array, requiredForOffline: boolean): void {
  const variant = origin.credentialIdentity!.identity.case;
  if (variant === "serverIssued") requireField(biscuit.length === 0, "issued origin biscuit");
  else requireField(biscuit.length <= MAX_TIMELINE_ORIGIN_BISCUIT_BYTES
    && (!requiredForOffline || biscuit.length > 0), "offline origin biscuit");
}

function validateAcceptanceFields(value: TimelineAdmissionAcceptance): void {
  requireField(value.originSha256.length === 32, "acceptance origin digest");
  requireField(value.uploaderDevicePublicKey.length === 32, "acceptance uploader key");
  requireField(value.deploymentPublicKey.length === 32, "acceptance deployment key");
  requireField(value.requestSha256.length === 32, "acceptance request digest");
  requireField(value.firstPosition >= 0n && value.firstPosition <= MAX_POSITION, "acceptance position");
  requireField(Number.isInteger(value.eventCount) && value.eventCount >= 0 && value.eventCount <= MAX_TIMELINE_EVENTS, "acceptance event count");
  const authority = value.authority;
  requireField(authority.case === "principalCredentialId"
    ? authority.value.length >= 1 && authority.value.length <= 128
    : authority.case === "ownerDerivedCapability"
      ? authority.value.length >= 1 && authority.value.length <= MAX_TIMELINE_OWNER_BUNDLE_BYTES : false, "acceptance authority");
}
export function validateTimelineAcceptance(value: TimelineAdmissionAcceptance): void {
  validateAcceptanceFields(value);
  requireField(value.signature.length === 64, "acceptance signature");
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}
function binding(thread: RegisterTimelineOriginRequest["thread"], run: RegisterTimelineOriginRequest["run"], origin: TimelineOriginEndorsement): void {
  requireField(thread !== undefined && thread.spool !== undefined && validCanonicalUuid(thread.spool.id), "spool UUID");
  requireField(thread.id !== undefined && thread.id.value.length === 32, "thread ID");
  requireField(run !== undefined && run.spool !== undefined && run.spool.id === thread.spool.id && validRunId(run.id), "run ID/spool");
  requireField(origin.spoolId === thread.spool.id && same(origin.threadId, thread.id.value)
    && origin.runId === run.id, "origin binding");
}

export function validateTimelineRegistration(value: RegisterTimelineOriginRequest): void {
  requireField(validCanonicalUuid(value.clientOperationId), "client operation ID");
  requireField(value.origin !== undefined, "origin");
  validateTimelineOrigin(value.origin);
  validateOriginBiscuit(value.origin, value.originCredentialBiscuit, true);
  binding(value.thread, value.run, value.origin);
}

export function validateTimelineUpload(value: UploadScrubbedTimelineRequest, nowMicros: bigint): void {
  requireField(toBinary(UploadScrubbedTimelineRequestSchema, value).length <= MAX_TIMELINE_REQUEST_BYTES, "request size");
  requireField(validCanonicalUuid(value.clientOperationId), "client operation ID");
  requireField(value.canonicalizationVersion === 1, "canonicalization version");
  requireField(value.firstPosition >= 0n && value.firstPosition <= MAX_POSITION, "first position");
  requireField(value.events.length <= MAX_TIMELINE_EVENTS, "event count");
  requireField(value.events.length > 0 || value.snapshot !== undefined, "run-only snapshot");
  if (value.snapshot !== undefined) validateUploadSummary(value.snapshot);
  value.events.forEach((event, index) => {
    validateUploadEvent(event, nowMicros);
    requireField(event.position === value.firstPosition + BigInt(index), "event sequence");
  });
  requireField(value.origin !== undefined, "origin");
  validateTimelineOrigin(value.origin);
  validateOriginBiscuit(value.origin, value.originCredentialBiscuit, false);
  binding(value.thread, value.run, value.origin);
  if (value.acceptance !== undefined) {
    const acceptance = value.acceptance;
    validateTimelineAcceptance(acceptance);
    requireField(same(acceptance.originSha256, timelineOriginDigest(value.origin)), "acceptance origin");
    requireField(same(acceptance.uploaderDevicePublicKey, value.origin.uploaderDevicePublicKey)
      && same(acceptance.deploymentPublicKey, value.origin.deploymentPublicKey), "acceptance binding");
    requireField(acceptance.firstPosition === value.firstPosition && acceptance.eventCount === value.events.length, "acceptance range");
    requireField(same(acceptance.requestSha256, logicalDigestBytes(value)), "acceptance request digest");
  }
}

function counted(bytes: Uint8Array): Uint8Array {
  const result = new Uint8Array(4 + bytes.length);
  new DataView(result.buffer).setUint32(0, bytes.length);
  result.set(bytes, 4);
  return result;
}
function join(parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}
function domain(value: string): Uint8Array { return join([encoder.encode(value), new Uint8Array(1)]); }
/** Raw Biscuit revocation IDs in order, including issued authority and terminal. */
export function timelineDerivationPathSha256(revocationIds: Uint8Array[]): Uint8Array {
  requireField(revocationIds.length >= 2 && revocationIds.length <= MAX_TIMELINE_ORIGIN_BISCUIT_BYTES / 64
    && revocationIds.every((id) => id.length === 64), "derivation path IDs");
  return sha256(join([domain(DERIVATION_PATH_DOMAIN), u32(revocationIds.length), ...revocationIds]));
}
/** Servers resolve this against their persisted, exact verified registration. */
export function validateTimelineUploadProvenance(value: UploadScrubbedTimelineRequest,
  exactVerifiedRegistrationBinding: boolean): void {
  requireField(value.origin !== undefined, "origin");
  validateOriginBiscuit(value.origin, value.originCredentialBiscuit,
    value.origin.credentialIdentity?.identity.case === "offlineDerived" && !exactVerifiedRegistrationBinding);
}
function u64(value: bigint): Uint8Array {
  const result = new Uint8Array(8);
  new DataView(result.buffer).setBigUint64(0, value);
  return result;
}
function i64(value: bigint): Uint8Array {
  const result = new Uint8Array(8);
  new DataView(result.buffer).setBigInt64(0, value);
  return result;
}
function u32(value: number): Uint8Array {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value);
  return result;
}
export function timelineCredentialIdentitySigningBytes(value: TimelineOriginCredentialIdentity): Uint8Array {
  validateTimelineCredentialIdentity(value);
  const identity = value.identity;
  if (identity.case === "serverIssued") return join([Uint8Array.of(1), counted(identity.value.credentialId)]);
  if (identity.case === "offlineDerived") return join([Uint8Array.of(2),
    counted(identity.value.issuedAncestorCredentialId), counted(identity.value.terminalRevocationId),
    counted(identity.value.derivationPathSha256)]);
  throw new Error("Invalid hosted timeline credential identity variant");
}
export function timelineOriginSigningBytes(value: TimelineOriginEndorsement): Uint8Array {
  validateOriginFields(value);
  return join([domain(ORIGIN_DOMAIN), counted(value.deploymentPublicKey), counted(encoder.encode(value.spoolId)),
    counted(value.threadId), counted(encoder.encode(value.runId)), counted(encoder.encode(value.principalId)),
    Uint8Array.of(value.credentialClass), counted(value.effectivePopKeySha256),
    timelineCredentialIdentitySigningBytes(value.credentialIdentity!),
    counted(value.uploaderDevicePublicKey)]);
}
export function timelineOriginDigest(value: TimelineOriginEndorsement): Uint8Array {
  validateTimelineOrigin(value);
  return sha256(join([timelineOriginSigningBytes(value), value.signature]));
}
export function timelineAcceptanceSigningBytes(value: TimelineAdmissionAcceptance): Uint8Array {
  validateAcceptanceFields(value);
  const authority = value.authority;
  requireField(authority.case === "principalCredentialId" || authority.case === "ownerDerivedCapability", "acceptance authority");
  const tag = authority.case === "principalCredentialId" ? 1 : 2;
  return join([domain(ACCEPTANCE_DOMAIN), counted(value.originSha256), counted(value.uploaderDevicePublicKey),
    counted(value.deploymentPublicKey), counted(value.requestSha256), u64(value.firstPosition), u32(value.eventCount),
    Uint8Array.of(tag), counted(authority.value)]);
}

function logicalDigestBytes(value: UploadScrubbedTimelineRequest): Uint8Array {
  const thread = value.thread!, run = value.run!, origin = value.origin!;
  const parts = [domain(UPLOAD_DOMAIN), counted(encoder.encode(value.clientOperationId)),
    counted(encoder.encode(thread.spool!.id)), counted(thread.id!.value), counted(encoder.encode(run.id)),
    u32(value.canonicalizationVersion), u64(value.runRevision), Uint8Array.of(value.snapshot === undefined ? 0 : 1)];
  if (value.snapshot !== undefined) parts.push(u32(value.snapshot.state), counted(encoder.encode(value.snapshot.harness)));
  parts.push(u32(value.events.length));
  for (const event of value.events) {
    parts.push(u64(event.position), u32(event.kind), i64(event.recordedAt!.seconds), u32(event.recordedAt!.nanos),
      Uint8Array.of(event.toolName === undefined ? 0 : 1));
    if (event.toolName !== undefined) parts.push(u32(event.toolName));
  }
  parts.push(counted(timelineOriginDigest(origin)), u64(value.firstPosition));
  return sha256(join(parts));
}

/** Digest of the exact logical request, independent of acceptance and fresh
 * method-bound transport proof. */
export function timelineLogicalRequestDigest(value: UploadScrubbedTimelineRequest, nowMicros: bigint): Uint8Array {
  validateTimelineUpload(value, nowMicros);
  return logicalDigestBytes(value);
}
