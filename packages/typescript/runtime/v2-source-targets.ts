import type { RevisionRef, ThreadRef } from "./common_pb.js";
import { SourceTargetResolution_Status as Status, type SourceTargetResolution, type SourceTargetResolutionEvent, type SourceTargetResolutionKey } from "./collaboration_pb.js";
import { StreamDataKind } from "./stream_pb.js";

const invalid = (): never => { throw new Error("Invalid source target resolution"); };
function spool(id?: string): string {
  if (!id || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return invalid();
  return id.toLowerCase();
}
function hash(bytes?: Uint8Array): string {
  if (!bytes || bytes.length !== 32) return invalid();
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}
function thread(value?: ThreadRef): string[] {
  return [spool(value?.spool?.id), hash(value?.id?.value)];
}
function revision(value?: RevisionRef): string[] {
  const owner = spool(value?.spool?.id);
  const ref = value?.revision;
  if (ref?.case === "state") return [owner, "state", hash(ref.value.value)];
  if (ref?.case === "gitCommitOid" && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(ref.value)) return [owner, "git", ref.value];
  return invalid();
}

/** Canonical map identity within one endpoint/query. This is not an authority
 * token. Keep the selected revision in the value, so capture replaces one key. */
export function sourceTargetResolutionKey(key?: SourceTargetResolutionKey): string {
  const target = hash(key?.reference?.targetId);
  const binding = key?.reference?.binding;
  if (binding?.case === "viewedThread" && binding.value === true) {
    return JSON.stringify([target, "viewed", ...thread(key?.viewedThread)]);
  }
  if (key?.viewedThread) return invalid();
  if (binding?.case === "namedThread") return JSON.stringify([target, "named", ...thread(binding.value)]);
  if (binding?.case === "pinnedRevision") {
    const ref = revision(binding.value.revision);
    const origin = binding.value.thread ? thread(binding.value.thread) : [];
    if (origin.length && origin[0] !== ref[0]) return invalid();
    return JSON.stringify([target, "pinned", ref, origin]);
  }
  return invalid();
}

/** Validate before mutating the staged map. Callers commit it with their stream
 * checkpoint and clear it with its containing collaboration/context section. */
export function applySourceTargetResolution(
  map: Map<string, SourceTargetResolution>, event: SourceTargetResolutionEvent, kind: StreamDataKind,
): void {
  if (event.change.case === "remove") {
    if (kind !== StreamDataKind.REMOVE) return invalid();
    map.delete(sourceTargetResolutionKey(event.change.value));
    return;
  }
  if (event.change.case !== "upsert" || (kind !== StreamDataKind.SNAPSHOT && kind !== StreamDataKind.UPSERT)) return invalid();
  const value = event.change.value;
  const key = sourceTargetResolutionKey(value.key);
  if (value.status === Status.UNAVAILABLE) {
    if (value.computedFor || value.location) return invalid();
  } else {
    const computed = revision(value.computedFor);
    const binding = value.key!.reference!.binding;
    const scope = binding.case === "viewedThread" ? thread(value.key?.viewedThread)
      : binding.case === "namedThread" ? thread(binding.value)
      : binding.case === "pinnedRevision" ? revision(binding.value.revision) : invalid();
    if (computed[0] !== scope[0]) return invalid();
    if (binding.case === "pinnedRevision" && JSON.stringify(computed) !== JSON.stringify(scope)) return invalid();
    if (value.status === Status.RESOLVED) {
      const location = value.location;
      if (!location || JSON.stringify(revision(location.revision)) !== JSON.stringify(computed)) return invalid();
      const owner = thread(location.thread);
      if (owner[0] !== computed[0]) return invalid();
      const expected = binding.case === "pinnedRevision" ? binding.value.thread : binding.case === "namedThread" ? binding.value : value.key?.viewedThread;
      if (expected && JSON.stringify(owner) !== JSON.stringify(thread(expected))) return invalid();
      if (!location.path || location.path.includes("\\") || /[\x00-\x1f\x7f]/.test(location.path)
        || location.path.split("/").some(part => !part || part === "." || part === "..")) return invalid();
      const { startLine, endLine } = location;
      if ((startLine === undefined) !== (endLine === undefined)) return invalid();
      if (startLine !== undefined && (!Number.isInteger(startLine) || !Number.isInteger(endLine)
        || startLine < 1 || endLine! < startLine || endLine! > 0xffffffff)) return invalid();
    } else if ((value.status !== Status.AMBIGUOUS && value.status !== Status.DELETED) || value.location) return invalid();
  }
  map.set(key, structuredClone(value));
}
