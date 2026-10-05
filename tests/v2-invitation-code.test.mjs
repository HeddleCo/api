import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { TimestampSchema } from "@bufbuild/protobuf/wkt";
import {
  InvitationState, GetInvitationCodeRequestSchema, GetInvitationCodeResponseSchema, InvitationRecordSchema,
} from "../packages/typescript/dist/v1alpha2/administration_pb.js";
import {
  GetSignupInvitationCodeRequestSchema, GetSignupInvitationCodeResponseSchema, SignupInvitationSchema,
} from "../packages/typescript/dist/v1alpha2/identity_pb.js";
import * as services from "../packages/typescript/dist/v1alpha2/services_pb.js";
import {
  validateInvitationCodeResponse, validateSignupInvitationCodeResponse,
} from "../packages/typescript/dist/v1alpha2/invitation-code.js";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/invitation-code-reads.json", import.meta.url)));
const timestamp = (t) => t === null ? undefined : create(TimestampSchema, { seconds: BigInt(t.seconds), nanos: t.nanos });

function check(v) {
  const context = { callerSubject: v.caller, creatorSubject: v.creator, now: timestamp(v.now) };
  const state = { redeemed: v.redeemed, revoked: v.revoked, expiresAt: timestamp(v.expires_at) };
  if (v.runtime_seconds) {
    context.now.seconds = v.runtime_seconds[0];
    state.expiresAt.seconds = v.runtime_seconds[1];
  }
  const bytes = Uint8Array.from(Buffer.from(v.secret_hex, "hex"));
  for (const [validate, responseSchema, invitationSchema] of [
    [validateInvitationCodeResponse, GetInvitationCodeResponseSchema, InvitationRecordSchema],
    [validateSignupInvitationCodeResponse, GetSignupInvitationCodeResponseSchema, SignupInvitationSchema],
  ]) {
    const invitation = invitationSchema === InvitationRecordSchema ? {
      state: v.revoked ? InvitationState.REVOKED : v.redeemed ? InvitationState.ACCEPTED : InvitationState.PENDING,
      recipient: { case: "email", value: "recipient@example.test" }, expiresAt: state.expiresAt,
    } : state;
    const run = () => validate(create(responseSchema, { redemptionSecret: bytes }), create(invitationSchema, invitation), context);
    if (v.error === null) assert.doesNotThrow(run, v.name);
    else assert.throws(run, new RegExp(`^Error: ${v.error}:`), v.name);
  }
}

test("non-creator reads are refused even for other admins or empty codes", () => {
  const denied = fixture.cases.filter(v => v.error === "Creator");
  assert.equal(denied.length, 6);
  denied.forEach(check);
});

test("reads after redeem, revoke or expiry must be empty", () => {
  const terminal = fixture.cases.filter(v => /^(redeemed|revoked|expired)_/.test(v.name));
  assert.equal(terminal.length, 8);
  terminal.forEach(check);
});

test("shared vectors cover repeated reads, legacy codes and timestamp validation", () => {
  assert.equal(fixture.cases.length, 22);
  fixture.cases.forEach(check);
});

test("missing or non-string subjects cannot satisfy creator equality", () => {
  for (const subject of [undefined, null, 1]) {
    check({ ...fixture.cases[0], caller: subject, creator: subject, error: "Creator" });
  }
});

test("timestamps must use bigint seconds, preventing lexical expiry comparisons", () => {
  for (const seconds of [["10", "9"], [10, 9]]) {
    check({ ...fixture.cases[0], runtime_seconds: seconds, error: "Expiry" });
  }
});

test("code responses round-trip original bytes and the empty terminal shape", () => {
  for (const schema of [GetInvitationCodeResponseSchema, GetSignupInvitationCodeResponseSchema]) {
    for (const wireHex of [fixture.secret_wire_hex, fixture.empty_wire_hex]) {
      const wire = Uint8Array.from(Buffer.from(wireHex, "hex"));
      const decoded = fromBinary(schema, wire);
      assert.deepEqual(toBinary(schema, decoded), wire);
      assert.equal(Buffer.from(decoded.redemptionSecret).toString("hex"), wireHex === "" ? "" : "0001feff");
    }
  }
});

test("every service projection excludes codes except top-level create and creator reads", () => {
  const allowed = new Set(["CreateInvitationResponse", "CreateSignupInvitationResponse", "GetInvitationCodeResponse", "GetSignupInvitationCodeResponse"]
    .map(name => `heddle.api.v1alpha2.${name}`));
  function walk(schema, root, seen = new Set()) {
    if (seen.has(schema.typeName)) return;
    seen.add(schema.typeName);
    for (const field of schema.fields) {
      if (field.name === "redemption_secret") {
        assert.equal(schema.typeName, root, `code leaked into ${root} through ${schema.typeName}`);
        assert.ok(allowed.has(root), `code leaked into ${root}`);
      }
      if (field.message) walk(field.message, root, seen);
    }
  }
  let count = 0;
  const roots = new Set();
  for (const service of Object.values(services).filter(s => s.kind === "service")) {
    for (const method of service.methods) {
      count++;
      if (method.output.fields.some(f => f.name === "redemption_secret")) roots.add(method.output.typeName);
      walk(method.output, method.output.typeName);
    }
  }
  assert.ok(count >= 174);
  assert.deepEqual(roots, allowed);
  for (const schema of [GetInvitationCodeRequestSchema, GetSignupInvitationCodeRequestSchema]) {
    assert.deepEqual(schema.fields.map(f => [f.name, f.number, f.message?.typeName]), [["invitation", 1, "heddle.api.v1alpha2.RecordRef"]]);
  }
  for (const schema of [GetInvitationCodeResponseSchema, GetSignupInvitationCodeResponseSchema]) {
    assert.deepEqual(schema.fields.map(f => [f.name, f.number, f.scalar]), [["redemption_secret", 1, 12]]);
  }
});

test("alpha.38 terminal states and non-link invites never disclose codes", () => {
  const states = JSON.parse(readFileSync(new URL("./fixtures/invitation-code-states.json", import.meta.url)));
  assert.equal(states.cases.length, 22);
  const context = { callerSubject: "creator", creatorSubject: "creator", now: create(TimestampSchema, { seconds: 1n }) };
  for (const v of states.cases) {
    const invitation = create(InvitationRecordSchema, { state: v.state, expiresAt: create(TimestampSchema, { seconds: 2n }),
      recipient: v.recipient_kind === "none" ? undefined : { case: v.recipient_kind === "account_id" ? "accountId" : v.recipient_kind, value: v.recipient },
    });
    const response = create(GetInvitationCodeResponseSchema, { redemptionSecret: Uint8Array.from(Buffer.from(v.secret_hex, "hex")) });
    const run = () => validateInvitationCodeResponse(response, invitation, context);
    if (v.error) assert.throws(run, new RegExp(`^Error: ${v.error}:`), v.name);
    else assert.doesNotThrow(run, v.name);
  }
});
