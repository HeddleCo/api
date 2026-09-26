import test from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  InvitationResolutionSchema,
  InvitationResolution_Status as Status,
} from "../packages/typescript/dist/v1alpha2/administration_pb.js";
import { PublicOwnerSchema } from "../packages/typescript/dist/v1alpha2/common_pb.js";
import { validateInvitationResolution } from "../packages/typescript/dist/v1alpha2/invitation.js";

test("invitation preview retains public inviter and delegated agent label", () => {
  const preview = create(InvitationResolutionSchema, {
    status: Status.AVAILABLE,
    inviter: create(PublicOwnerSchema, { handle: "mara", displayName: "Mara" }),
    inviterViaAgentLabel: "build-bot",
  });
  const decoded = fromBinary(InvitationResolutionSchema, toBinary(InvitationResolutionSchema, preview));
  assert.equal(decoded.inviter?.handle, "mara");
  assert.equal(decoded.inviter?.displayName, "Mara");
  assert.equal(decoded.inviterViaAgentLabel, "build-bot");
  validateInvitationResolution(decoded);

  assert.throws(() => validateInvitationResolution({ ...decoded, inviter: undefined }), /agent label/);
  assert.throws(() => validateInvitationResolution({ ...decoded,
    inviter: create(PublicOwnerSchema, { displayName: "Heddle Support" }) }), /public handle/);
});

test("UNAVAILABLE preview has one non-disclosing shape", () => {
  const unavailable = create(InvitationResolutionSchema, { status: Status.UNAVAILABLE });
  validateInvitationResolution(unavailable);
  assert.throws(() => validateInvitationResolution({ ...unavailable,
    inviterViaAgentLabel: "build-bot" }), /UNAVAILABLE/);
  assert.throws(() => validateInvitationResolution({ ...unavailable,
    inviter: create(PublicOwnerSchema, { handle: "mara" }) }), /UNAVAILABLE/);
});
