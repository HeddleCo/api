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
  _response: GetSignupInvitationCodeResponse,
  _invitation: SignupInvitation,
  _context: InvitationCodeReadContext,
): void {}

export function validateInvitationCodeResponse(
  _response: GetInvitationCodeResponse,
  _invitation: InvitationRecord,
  _context: InvitationCodeReadContext,
): void {}
