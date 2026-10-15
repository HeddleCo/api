import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { BinaryReader } from "@bufbuild/protobuf/wire";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  ReadObjectsRequestSchema, ReadObjectsResponseSchema, ImmutableObjectSnapshotSchema,
  type ImmutableObjectId, type ImmutableObjectLimits, type ImmutableObjectSnapshot,
  type ImmutableObjectRange, type ReadObjectsRequest, type ReadObjectsResponse,
  type OpenObjectSnapshotRequest, type OpenObjectSnapshotResponse, OpenObjectSnapshotRequestSchema, OpenObjectSnapshotResponseSchema,
} from "./immutable_objects_pb.js";

export const DEFAULT_MAX_CACHE_TTL_SECONDS = 60;
export const MAX_SNAPSHOT_WIRE_BYTES = 512 * 1024;
export const MAX_REQUEST_WIRE_BYTES = 64 * 1024;
export const OBJECT_LIMITS = Object.freeze({ maxBatchObjects: 512, maxResponseBytes: 4 * 1024 * 1024,
  maxChunkBytes: 512 * 1024, maxInFlightBatches: 4, maxInventoryObjects: 4096, maxSnapshotBytes: 256n * 1024n * 1024n });
export class ObjectContractError extends Error {
  constructor(readonly reason: "Limits" | "Malformed" | "Binding" | "Unavailable" | "Expired" | "Integrity") {
    super(`Immutable object contract: ${reason}`); this.name = "ObjectContractError";
  }
}
const fail = (reason: ObjectContractError["reason"]): never => { throw new ObjectContractError(reason); };
const eq = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((v, i) => v === b[i]);
const u32 = (n: number): boolean => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
const u64 = (n: bigint): boolean => typeof n === "bigint" && n >= 0n && n <= 0xffffffffffffffffn;
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const be32 = (n: number): Uint8Array => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
const be64 = (n: bigint): Uint8Array => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n); return b; };
const hex = (b: Uint8Array): string => Array.from(b, v => v.toString(16).padStart(2, "0")).join("");
function uuid(b: Uint8Array): string {
  const s = hex(b); return `${s.slice(0,8)}-${s.slice(8,12)}-${s.slice(12,16)}-${s.slice(16,20)}-${s.slice(20)}`;
}
export function validateObjectLimits(l: ImmutableObjectLimits): void {
  for (const key of ["maxBatchObjects", "maxResponseBytes", "maxChunkBytes", "maxInFlightBatches", "maxInventoryObjects"] as const)
    if (!u32(l[key]) || l[key] === 0 || l[key] > OBJECT_LIMITS[key]) fail("Limits");
  if (!u64(l.maxSnapshotBytes) || l.maxSnapshotBytes === 0n || l.maxSnapshotBytes > OBJECT_LIMITS.maxSnapshotBytes
    || l.maxChunkBytes > l.maxResponseBytes) fail("Limits");
}
export function validateObjectId(id: ImmutableObjectId): void {
  if ((id.kind !== 1 && id.kind !== 2) || id.algorithm !== "blake3" || id.digest.length !== 32) fail("Malformed");
}
export function validateObjectSnapshot(s: ImmutableObjectSnapshot): void {
  const l = s.limits ?? fail("Limits"); validateObjectLimits(l);
  if (s.inventory.length === 0 || s.inventory.length > l.maxInventoryObjects) fail("Limits");
  if (s.formatVersion !== 1 || s.userId.length !== 16 || s.spoolId.length !== 16
    || !s.userId.some(Boolean) || !s.spoolId.some(Boolean)
    || [s.hostPublicKey, s.principalSha256, s.threadId, s.stateId, s.viewDigest].some(b => b.length !== 32)) fail("Malformed");
  const root = s.rootTree ?? fail("Malformed"); validateObjectId(root);
  if (root.kind !== 1) fail("Malformed");
  if (![s.authorizationEpoch, s.visibilityEpoch, s.authorizedAtUnixSeconds, s.expiresAtUnixSeconds].every(u64)) fail("Malformed");
  if (!u32(s.maxCacheTtlSeconds) || s.maxCacheTtlSeconds === 0 || s.expiresAtUnixSeconds <= s.authorizedAtUnixSeconds
    || s.expiresAtUnixSeconds - s.authorizedAtUnixSeconds > BigInt(s.maxCacheTtlSeconds)) fail("Limits");
  let previous = "", total = 0n, foundRoot = false;
  for (const e of s.inventory) {
    const id = e.id ?? fail("Malformed"); validateObjectId(id);
    const key = `${id.kind}${hex(id.digest)}`;
    if (key <= previous) fail("Malformed"); previous = key;
    if (!u64(e.decodedLength)) fail("Limits");
    total += e.decodedLength; if (total > l.maxSnapshotBytes) fail("Limits");
    foundRoot ||= id.kind === root.kind && eq(id.digest, root.digest);
  }
  if (!foundRoot) fail("Malformed");
  if (toBinary(ImmutableObjectSnapshotSchema, s).length > MAX_SNAPSHOT_WIRE_BYTES) fail("Limits");
}
/** Explicit fixed-width v1 transcript; independent of protobuf serialization. */
export function objectAuthorityBinding(s: ImmutableObjectSnapshot): Uint8Array {
  validateObjectSnapshot(s);
  const h = sha256.create(); h.update(utf8("heddle-object-authority-v1\0"));
  for (const b of [s.hostPublicKey, s.userId, s.principalSha256, s.spoolId, s.threadId, s.stateId, s.viewDigest]) h.update(b);
  for (const n of [s.authorizationEpoch, s.visibilityEpoch]) h.update(be64(n));
  h.update(s.rootTree!.digest); h.update(be32(s.inventory.length));
  for (const e of s.inventory) { h.update(new Uint8Array([e.id!.kind])); h.update(e.id!.digest); h.update(be64(e.decodedLength)); }
  const l = s.limits!;
  for (const n of [l.maxBatchObjects, l.maxResponseBytes, l.maxChunkBytes, l.maxInFlightBatches, l.maxInventoryObjects]) h.update(be32(n));
  for (const n of [l.maxSnapshotBytes, s.authorizedAtUnixSeconds, s.expiresAtUnixSeconds]) h.update(be64(n));
  h.update(be32(s.maxCacheTtlSeconds)); return h.digest();
}
/** Requires a host-authenticated snapshot and separate user/principal/session matching. */
export function validateObjectReadRequest(s: ImmutableObjectSnapshot, r: ReadObjectsRequest, now: bigint): void {
  const binding = objectAuthorityBinding(s);
  if (!eq(r.authorityBinding, binding) || !r.thread?.id || !eq(r.thread.id.value, s.threadId)
    || r.thread.spool?.id !== uuid(s.spoolId)) fail("Binding");
  if (!u64(now) || now < s.authorizedAtUnixSeconds || now >= s.expiresAtUnixSeconds) fail("Expired");
  const l = s.limits!;
  if (!r.objects.length || r.objects.length > l.maxBatchObjects || !r.sessionHandle.length || r.sessionHandle.length > 256) fail("Limits");
  const seen = new Set<string>();
  for (const range of r.objects) {
    const id = range.id ?? fail("Malformed"); validateObjectId(id);
    const key = `${id.kind}${hex(id.digest)}`; if (seen.has(key)) fail("Malformed"); seen.add(key);
    const e = s.inventory.find(e => e.id?.kind === id.kind && eq(e.id.digest, id.digest)) ?? fail("Unavailable");
    if (!u64(range.offset) || !u32(range.length) || range.length > l.maxChunkBytes
      || (range.length === 0 && e.decodedLength !== 0n) || range.offset + BigInt(range.length) > e.decodedLength) fail("Limits");
  }
  if (toBinary(ReadObjectsRequestSchema, r).length > MAX_REQUEST_WIRE_BYTES) fail("Limits");
}
/** Check every delivered prefix, including cache hits, against the original request. */
export function validateObjectReadResponse(s: ImmutableObjectSnapshot, r: ReadObjectsRequest, response: ReadObjectsResponse, now: bigint): void {
  validateObjectReadRequest(s, r, now);
  if (!eq(response.authorityBinding, r.authorityBinding)) fail("Binding");
  const n = response.chunks.length;
  if (!n || n > r.objects.length || response.nextObjectIndex !== n || response.complete !== (n === r.objects.length)) fail("Integrity");
  for (let i = 0; i < n; i++) {
    const c = response.chunks[i]!, range = r.objects[i]!, id = range.id!;
    const e = s.inventory.find(e => e.id?.kind === id.kind && eq(e.id.digest, id.digest))!;
    if (!c.id || c.id.kind !== id.kind || c.id.algorithm !== id.algorithm || !eq(c.id.digest, id.digest)
      || c.codec !== "identity" || c.offset !== range.offset || c.decodedLength !== e.decodedLength
      || c.data.length !== range.length || !eq(c.chunkSha256, sha256(c.data))) fail("Integrity");
  }
  if (toBinary(ReadObjectsResponseSchema, response).length > s.limits!.maxResponseBytes) fail("Limits");
}
export function objectCacheKey(binding: Uint8Array, range: ImmutableObjectRange): Uint8Array {
  if (binding.length !== 32) fail("Binding");
  const id = range.id ?? fail("Malformed"); validateObjectId(id);
  if (!u64(range.offset) || !u32(range.length) || range.length > OBJECT_LIMITS.maxChunkBytes) fail("Limits");
  const h = sha256.create(); h.update(utf8("heddle-object-cache-v1\0")); h.update(binding);
  h.update(new Uint8Array([id.kind])); h.update(id.digest); h.update(utf8("identity\0"));
  h.update(be64(range.offset)); h.update(be32(range.length)); return h.digest();
}
/** Wire byte caps run before protobuf decoding and allocation. */
export function decodeObjectReadRequest(bytes: Uint8Array): ReadObjectsRequest {
  if (bytes.length > MAX_REQUEST_WIRE_BYTES) fail("Limits");
  preflightCount(bytes, 4, OBJECT_LIMITS.maxBatchObjects);
  try { return fromBinary(ReadObjectsRequestSchema, bytes, { readUnknownFields: false }); } catch { return fail("Malformed"); }
}
export function decodeObjectReadResponse(bytes: Uint8Array, limits: ImmutableObjectLimits): ReadObjectsResponse {
  validateObjectLimits(limits); if (bytes.length > limits.maxResponseBytes) fail("Limits");
  preflightCount(bytes, 2, limits.maxBatchObjects);
  try { return fromBinary(ReadObjectsResponseSchema, bytes, { readUnknownFields: false }); } catch { return fail("Malformed"); }
}

export function decodeObjectSnapshot(bytes: Uint8Array): ImmutableObjectSnapshot {
  if (bytes.length > MAX_SNAPSHOT_WIRE_BYTES) fail("Limits");
  preflightCount(bytes, 12, OBJECT_LIMITS.maxInventoryObjects);
  let snapshot: ImmutableObjectSnapshot;
  try { snapshot = fromBinary(ImmutableObjectSnapshotSchema, bytes, { readUnknownFields: false }); } catch { return fail("Malformed"); }
  validateObjectSnapshot(snapshot); return snapshot;
}

/** Bind opening to the exact native revision and explicitly requested limits. */
export function validateObjectOpenResponse(request: OpenObjectSnapshotRequest, response: OpenObjectSnapshotResponse, now: bigint): void {
  validateObjectOpenRequest(request);
  const s = response.snapshot ?? fail("Malformed"), binding = objectAuthorityBinding(s);
  const requested = request.limits!;
  const accepted = s.limits!;
  for (const key of ["maxBatchObjects", "maxResponseBytes", "maxChunkBytes", "maxInFlightBatches", "maxInventoryObjects", "maxSnapshotBytes"] as const)
    if (accepted[key] > requested[key]) fail("Limits");
  if (toBinary(OpenObjectSnapshotResponseSchema, response).length > MAX_SNAPSHOT_WIRE_BYTES
    || !response.sessionHandle.length || response.sessionHandle.length > 256) fail("Limits");
  if (!eq(response.authorityBinding, binding) || !request.thread?.id || !eq(request.thread.id.value, s.threadId)
    || request.thread.spool?.id !== uuid(s.spoolId) || request.revision?.spool?.id !== uuid(s.spoolId)
    || request.revision?.revision.case !== "state" || !eq(request.revision.revision.value.value, s.stateId)) fail("Binding");
  if (!u64(now) || now < s.authorizedAtUnixSeconds || now >= s.expiresAtUnixSeconds) fail("Expired");
}

/** Validate selection and ceilings before authority resolution or object I/O. */
export function validateObjectOpenRequest(request: OpenObjectSnapshotRequest): void {
  validateObjectLimits(request.limits ?? fail("Limits"));
  if (toBinary(OpenObjectSnapshotRequestSchema, request).length > MAX_REQUEST_WIRE_BYTES) fail("Limits");
  const thread = request.thread ?? fail("Malformed"), spool = thread.spool?.id ?? fail("Malformed");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(spool)
    || spool === "00000000-0000-0000-0000-000000000000" || thread.id?.value.length !== 32) fail("Malformed");
  const revision = request.revision ?? fail("Malformed");
  if (revision.spool?.id !== spool) fail("Binding");
  if (revision.revision.case !== "state" || revision.revision.value.value.length !== 32) fail("Malformed");
}

// Cap repeated empty messages before allocation, using the existing wire reader.
function preflightCount(bytes: Uint8Array, field: number, maximum: number): void {
  const reader = new BinaryReader(bytes); let count = 0;
  try {
    while (reader.pos < reader.len) {
      const [tag, wire] = reader.tag();
      if (tag === field && ++count > maximum) fail("Limits");
      reader.skip(wire, tag);
    }
  } catch (error) { if (error instanceof ObjectContractError) throw error; fail("Malformed"); }
}
