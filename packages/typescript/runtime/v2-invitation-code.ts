/** Creator-only code response checks. Authenticated host subjects and current
 * transactional state are required; a projection never establishes access. */
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { InvitationState } from "./administration_pb.js";
import type { GetInvitationCodeResponse, InvitationRecord } from "./administration_pb.js";
import type { GetSignupInvitationCodeResponse, SignupInvitation } from "./identity_pb.js";

/** Trusted host context, never request fields. Clients may use independently
 * known state to check disclosure, never to authorize a read. */
export interface InvitationCodeReadContext {
  callerSubject: string;
  creatorSubject: string;
  now: Timestamp;
}

export function validateSignupInvitationCodeResponse(
  response: GetSignupInvitationCodeResponse,
  invitation: SignupInvitation,
  context: InvitationCodeReadContext,
): void {
  validateCodeResponse(response.redemptionSecret, invitation, context);
}

export function validateInvitationCodeResponse(
  response: GetInvitationCodeResponse,
  invitation: InvitationRecord,
  context: InvitationCodeReadContext,
  inviterRole: number,
): void {
  validateCreator(context);
  if (inviterRole !== 3) throw new Error("Authority: invitation code read requires current inviter admin authority");
  const nonLink = invitation.recipient.case !== "email" || invitation.recipient.value === "";
  validateCodeResponse(response.redemptionSecret, {
    redeemed: invitation.state !== InvitationState.PENDING,
    revoked: nonLink,
    expiresAt: invitation.expiresAt,
  }, context);
}

function validTimestamp(time: Timestamp): boolean {
  return typeof time.seconds === "bigint" && time.seconds >= -62135596800n && time.seconds <= 253402300799n &&
    Number.isInteger(time.nanos) && time.nanos >= 0 && time.nanos < 1000000000;
}

function validateCodeResponse(
  secret: Uint8Array,
  invitation: Pick<SignupInvitation, "redeemed" | "revoked" | "expiresAt">,
  context: InvitationCodeReadContext,
): void {
  validateCreator(context);
  const expiry = invitation.expiresAt;
  if (expiry === undefined || !validTimestamp(expiry) || !validTimestamp(context.now)) {
    throw new Error("Expiry: invitation code read requires valid current time and finite expiry");
  }
  const expired = context.now.seconds > expiry.seconds ||
    (context.now.seconds === expiry.seconds && context.now.nanos >= expiry.nanos);
  if (secret.length !== 0 && (invitation.redeemed || invitation.revoked || expired)) {
    throw new Error("NotPending: terminal invitation code response must be empty");
  }
}

function validateCreator(context: InvitationCodeReadContext): void {
  if (typeof context.callerSubject !== "string" || typeof context.creatorSubject !== "string" ||
      context.callerSubject === "" || context.creatorSubject === "" ||
      context.callerSubject !== context.creatorSubject) {
    throw new Error("Creator: invitation code read requires the original creator");
  }
}
