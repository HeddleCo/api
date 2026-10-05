/** Creator-only code response checks. Authenticated host subjects and current
 * transactional state are required; a projection never establishes access. */
import type { Timestamp } from "@bufbuild/protobuf/wkt";
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
): void {
  validateCodeResponse(response.redemptionSecret, invitation, context);
}

function validTimestamp(time: Timestamp): boolean {
  return time.seconds >= -62135596800n && time.seconds <= 253402300799n &&
    Number.isInteger(time.nanos) && time.nanos >= 0 && time.nanos < 1000000000;
}

function validateCodeResponse(
  secret: Uint8Array,
  invitation: SignupInvitation | InvitationRecord,
  context: InvitationCodeReadContext,
): void {
  if (context.callerSubject === "" || context.creatorSubject === "" ||
      context.callerSubject !== context.creatorSubject) {
    throw new Error("Creator: invitation code read requires the original creator");
  }
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
