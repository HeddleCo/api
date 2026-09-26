import { InvitationResolution_Status as Status, type InvitationResolution } from "./administration_pb.js";

/** Validate a capability preview before displaying its public inviter. The
 * server checks the secret and resolves the public identity at read time. */
export function validateInvitationResolution(response: InvitationResolution): void {
  if (response.status === Status.UNAVAILABLE &&
      (response.spool !== undefined || response.spoolName !== "" || response.role !== 0 ||
       response.expiresAt !== undefined || response.inviter !== undefined ||
       response.inviterViaAgentLabel !== "")) {
    throw new Error("UNAVAILABLE invitation resolution contains disclosed details");
  }
  if (response.inviter !== undefined && response.inviter.handle === "") {
    throw new Error("inviter requires an already-public handle");
  }
  if (response.inviterViaAgentLabel !== "" && !response.inviter?.handle) {
    throw new Error("agent label requires an inviter handle");
  }
}
