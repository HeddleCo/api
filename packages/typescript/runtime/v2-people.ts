/** Scoped lookup over host-trusted, current identity and membership data. */
import { create } from "@bufbuild/protobuf";
import { HandleKind, SuggestPrincipalsResponseSchema, SuggestedPrincipalSchema } from "./identity_pb.js";
import type { SuggestPrincipalsRequest, SuggestPrincipalsResponse, SuggestedPrincipal } from "./identity_pb.js";

export const MAX_SUGGESTED_PRINCIPALS = 20;
export type PeopleCandidate = {
  person: SuggestedPrincipal;
  spoolIds: readonly string[];
  isAgent: boolean;
  isPublic: boolean;
  handleVisible: boolean;
};
/** Derived by the host, including inherited membership. Public read is insufficient.
 * membersReadableSpoolIds requires member-only MEMBERS-section read, even
 * without a request spool. handleVisible excludes caller-hidden handles.
 * rateLimitAllowed is the account budget decision already debited for this attempt. */
export type PeopleContext = { callerSpoolIds: readonly string[]; membersReadableSpoolIds: readonly string[]; rateLimitAllowed: boolean };
export const normalizedPeoplePrefix = (value: string): string => value.normalize("NFC").toLowerCase();
const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);
const controls = /\p{Cc}/u;
const edgeWhitespace = /^\p{White_Space}|\p{White_Space}$/u;

/** Same ordering as Rust UTF-8 string comparison, including non-BMP scalars. */
export function comparePeopleHandles(a: SuggestedPrincipal, b: SuggestedPrincipal): number {
  const x = bytes(a.handle), y = bytes(b.handle);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    if (x[i] !== y[i]) return x[i] - y[i];
  }
  return x.length - y.length;
}

export function validateSuggestPrincipalsRequest(request: SuggestPrincipalsRequest, context: PeopleContext): void {
  if (!context.rateLimitAllowed) throw new Error("RateLimited: suggestion account limit exceeded");
  if (request.spool && (!request.spool.id || !context.callerSpoolIds.includes(request.spool.id))) {
    throw new Error("Scope: uniform unknown/non-member spool refusal");
  }
  const prefix = normalizedPeoplePrefix(request.prefix);
  if (edgeWhitespace.test(request.prefix) || controls.test(request.prefix) || bytes(request.prefix).length > 256 ||
    bytes(prefix).length > 256 || [...prefix].length < 2 || [...prefix].length > 64) {
    throw new Error("Prefix: requires 2..64 scalars and at most 256 UTF-8 bytes");
  }
}

/** Public rows must have exactly the ID-free schema, including at JS boundaries. */
export function validateSuggestedPrincipal(person: SuggestedPrincipal): void {
  const allowed = new Set(["$typeName", "handle", "displayName", "kind"]);
  if (Object.keys(person).some(key => !allowed.has(key)) || !person.handle || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(person.handle) || bytes(person.handle).length > 256 ||
    edgeWhitespace.test(person.handle) || controls.test(person.handle) || bytes(person.displayName).length > 1024 ||
    controls.test(person.displayName) || ![HandleKind.NATIVE, HandleKind.GITHUB, HandleKind.GITLAB].includes(person.kind)) {
    throw new Error("Metadata: invalid public people metadata");
  }
}

/** Hosts query co-member indexes plus one exact public handle; never a global scan. */
export function suggestPrincipals(request: SuggestPrincipalsRequest, candidates: readonly PeopleCandidate[], context: PeopleContext): SuggestPrincipalsResponse {
  validateSuggestPrincipalsRequest(request, context);
  const prefix = normalizedPeoplePrefix(request.prefix);
  const members: SuggestedPrincipal[] = [], exact: SuggestedPrincipal[] = [];
  for (const candidate of candidates) {
    if (candidate.isAgent) continue;
    if (!candidate.handleVisible || !candidate.person.handle) continue;
    const shared = candidate.spoolIds.some(id => context.callerSpoolIds.includes(id) && context.membersReadableSpoolIds.includes(id) && (!request.spool || request.spool.id === id));
    const handle = normalizedPeoplePrefix(candidate.person.handle);
    if (shared && (handle.startsWith(prefix) || normalizedPeoplePrefix(candidate.person.displayName).startsWith(prefix))) {
      validateSuggestedPrincipal(candidate.person);
      members.push(candidate.person);
    } else if (candidate.isPublic && handle === prefix) {
      validateSuggestedPrincipal(candidate.person);
      exact.push(candidate.person);
    }
  }
  members.push(...exact.sort(comparePeopleHandles).slice(0, 1));
  const seen = new Set<string>();
  const principals = members.sort(comparePeopleHandles).filter(person => {
    if (seen.has(person.handle)) return false;
    seen.add(person.handle);
    return true;
  }).slice(0, MAX_SUGGESTED_PRINCIPALS).map(person => create(SuggestedPrincipalSchema, {
    handle: person.handle, displayName: person.displayName, kind: person.kind,
  }));
  return create(SuggestPrincipalsResponseSchema, { principals });
}

export function validateSuggestPrincipalsResponse(response: SuggestPrincipalsResponse, request: SuggestPrincipalsRequest, candidates: readonly PeopleCandidate[], context: PeopleContext): void {
  response.principals.forEach(validateSuggestedPrincipal);
  const expected = suggestPrincipals(request, candidates, context).principals;
  if (Object.keys(response).some(key => !["$typeName", "principals"].includes(key)) ||
    response.principals.length !== expected.length || response.principals.some((p, i) =>
    p.handle !== expected[i].handle || p.displayName !== expected[i].displayName || p.kind !== expected[i].kind)) {
    throw new Error("Projection: suggestion violates scoped people projection");
  }
}
