import {
  create,
  fromBinary,
  toBinary,
  type MessageInitShape,
  type MessageShape,
} from "@bufbuild/protobuf";
import {
  AccountBillingLockReason,
  AccountBillingLockSchema,
  ErrorDetailSchema,
  ErrorReason,
} from "./errors_pb.js";

export const ACCOUNT_BILLING_LOCK_POLICY_ID = "account_locked_billing";

/** Build the structured policy detail hosts attach to FAILED_PRECONDITION. */
export function accountBillingLockErrorDetail(
  resource: string,
  billingLock: MessageInitShape<typeof AccountBillingLockSchema>,
): MessageShape<typeof ErrorDetailSchema> {
  const rule = billingLock.reason === AccountBillingLockReason.OVER_FREE_CAP_WITHOUT_PAID_PLAN
    ? "over_free_cap_without_paid_plan"
    : "account_billing_lock";
  return create(ErrorDetailSchema, {
    reason: ErrorReason.POLICY_DENIED,
    resource,
    context: {
      case: "policy",
      value: {
        policyId: ACCOUNT_BILLING_LOCK_POLICY_ID,
        rule,
        humanVerificationCanOverride: false,
        billingLock,
      },
    },
  });
}

/** Extract the lock only from the matching typed policy denial. */
export function accountBillingLockFromErrorDetail(
  detail: MessageShape<typeof ErrorDetailSchema>,
): MessageShape<typeof AccountBillingLockSchema> | undefined {
  if (
    detail.reason !== ErrorReason.POLICY_DENIED ||
    detail.context.case !== "policy" ||
    detail.context.value.policyId !== ACCOUNT_BILLING_LOCK_POLICY_ID
  ) return undefined;
  return detail.context.value.billingLock;
}

/** Encode a complete account billing-lock ErrorDetail for transport. */
export function encodeAccountBillingLockErrorDetail(
  resource: string,
  billingLock: MessageInitShape<typeof AccountBillingLockSchema>,
): Uint8Array {
  return toBinary(ErrorDetailSchema, accountBillingLockErrorDetail(resource, billingLock));
}

/** Decode a transported ErrorDetail and return its typed lock when present. */
export function decodeAccountBillingLockErrorDetail(
  encoded: Uint8Array,
): MessageShape<typeof AccountBillingLockSchema> | undefined {
  return accountBillingLockFromErrorDetail(fromBinary(ErrorDetailSchema, encoded));
}

export function errorReasonRetryable(reason: ErrorReason): boolean {
  return (
    reason === ErrorReason.RATE_LIMITED ||
    reason === ErrorReason.QUOTA_EXCEEDED ||
    reason === ErrorReason.TRANSIENT
  );
}
