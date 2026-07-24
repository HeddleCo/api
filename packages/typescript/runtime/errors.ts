import { ErrorReason } from "./errors_pb.js";

export function errorReasonRetryable(reason: ErrorReason): boolean {
  return (
    reason === ErrorReason.RATE_LIMITED ||
    reason === ErrorReason.QUOTA_EXCEEDED ||
    reason === ErrorReason.TRANSIENT
  );
}
