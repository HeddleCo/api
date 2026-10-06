import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { create, toBinary, fromBinary } from "@bufbuild/protobuf";
import { SuggestPrincipalsRequestSchema, SuggestPrincipalsResponseSchema, SuggestedPrincipalSchema } from "../packages/typescript/dist/v1alpha2/identity_pb.js";
import { ApprovalGroupViewSchema } from "../packages/typescript/dist/v1alpha2/administration_pb.js";
import { SpoolEventSchema } from "../packages/typescript/dist/v1alpha2/views_pb.js";
import { suggestPrincipals, validateSuggestPrincipalsResponse } from "../packages/typescript/dist/v1alpha2/people.js";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/people-suggestions.json", import.meta.url)));
const candidate = p => ({ person: create(SuggestedPrincipalSchema, { handle: p.handle, displayName: p.display_name, kind: p.kind }), spoolIds: p.spool_ids, isAgent: p.is_agent, isPublic: p.is_public, handleVisible: p.handle_visible });
for (const v of fixture.cases) {
  test(v.name, () => {
    const request = create(SuggestPrincipalsRequestSchema, { prefix: v.prefix, spool: v.spool === null ? undefined : { id: v.spool } });
    const candidates = (v.replacement_candidates ?? fixture.candidates).map(candidate);
    const context = { callerSpoolIds: v.caller_spool_ids, membersReadableSpoolIds: v.members_readable_spool_ids, rateLimitAllowed: v.rate_limit_allowed };
    const run = () => suggestPrincipals(request, candidates, context);
    if (v.error) { assert.throws(run, new RegExp(`^Error: ${v.error}:`)); return; }
    const response = run();
    assert.deepEqual(response.principals.map(p => p.handle), v.expected);
    validateSuggestPrincipalsResponse(response, request, candidates, context);
    assert.deepEqual(fromBinary(SuggestPrincipalsResponseSchema, toBinary(SuggestPrincipalsResponseSchema, response)), response);
    const leaked = create(SuggestPrincipalsResponseSchema, { principals: [...response.principals, candidate(fixture.candidates[2]).person] });
    assert.throws(() => validateSuggestPrincipalsResponse(leaked, request, candidates, context), /Projection:/);
  });
}
test("no ID leak in public people or group projection", () => {
  assert.deepEqual(SuggestedPrincipalSchema.fields.map(f => [f.name, f.number]), [["handle", 1], ["display_name", 2], ["kind", 3]]);
  assert.deepEqual(SuggestPrincipalsResponseSchema.fields.map(f => [f.name, f.message?.typeName]), [["principals", SuggestedPrincipalSchema.typeName]]);
  assert.deepEqual(ApprovalGroupViewSchema.fields.map(f => f.name), ["ref", "version", "name", "description", "member_role", "resolved_members", "role_member_handles", "explicit_member_handles", "resolved_member_count", "role_member_count", "explicit_member_count"]);
  assert.equal(ApprovalGroupViewSchema.fields.find(f => f.name === "resolved_members").message, SuggestedPrincipalSchema);
  assert.equal(SpoolEventSchema.fields.find(f => f.name === "approval_group").message, ApprovalGroupViewSchema);
});
test("runtime IDs and unknown protobuf fields are refused", () => {
  const request = create(SuggestPrincipalsRequestSchema, { prefix: "ad", spool: { id: "shared" } });
  const context = { callerSpoolIds: ["shared"], membersReadableSpoolIds: ["shared"], rateLimitAllowed: true };
  const candidates = fixture.candidates.map(candidate);
  for (const extra of [{ principalId: "private-account-id" }, { accountId: "private-account-id" }, { $unknown: [{ no: 99, wireType: 2, data: new Uint8Array([1]) }] }]) {
    const response = suggestPrincipals(request, candidates, context);
    Object.assign(response.principals[0], extra);
    assert.throws(() => validateSuggestPrincipalsResponse(response, request, candidates, context), /Metadata:/);
  }
});

test("response envelope rejects runtime account IDs", () => {
  const request = create(SuggestPrincipalsRequestSchema, { prefix: "ad" });
  const context = { callerSpoolIds: ["shared"], membersReadableSpoolIds: ["shared"], rateLimitAllowed: true };
  const candidates = fixture.candidates.map(candidate);
  const response = suggestPrincipals(request, candidates, context);
  response.accountId = "private-account-id";
  assert.throws(() => validateSuggestPrincipalsResponse(response, request, candidates, context), /Projection:/);
});
