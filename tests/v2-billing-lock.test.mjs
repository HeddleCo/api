import test from "node:test";
import assert from "node:assert/strict";
import {
  ACCOUNT_BILLING_LOCK_POLICY_ID,
  accountBillingLockErrorDetail,
  decodeAccountBillingLockErrorDetail,
  encodeAccountBillingLockErrorDetail,
} from "../packages/typescript/dist/common/errors.js";
import {
  AccountBillingLockAllowedAction,
  AccountBillingLockReason,
  ErrorReason,
} from "../packages/typescript/dist/common/errors_pb.js";

test("TypeScript billing-lock helpers preserve every typed status field", () => {
  const lock = {
    reason: AccountBillingLockReason.OVER_FREE_CAP_WITHOUT_PAID_PLAN,
    lockedAt: { seconds: 1_795_000_000n, nanos: 123_000_000 },
    deleteAfter: { seconds: 1_805_368_000n, nanos: 456_000_000 },
    usedBytes: 6_500_000_001n,
    capBytes: 5_000_000_000n,
    allowedActions: [
      AccountBillingLockAllowedAction.MANAGE_BILLING,
      AccountBillingLockAllowedAction.LIST_SPOOLS,
      AccountBillingLockAllowedAction.DELETE_SPOOL,
      AccountBillingLockAllowedAction.DELETE_ACCOUNT,
      AccountBillingLockAllowedAction.EXPORT_DATA,
    ],
  };
  const resource = "account/00000000-0000-0000-0000-000000000237";
  const detail = accountBillingLockErrorDetail(resource, lock);
  assert.equal(detail.reason, ErrorReason.POLICY_DENIED);
  assert.equal(detail.resource, resource);
  assert.equal(detail.context.case, "policy");
  assert.equal(detail.context.value.policyId, ACCOUNT_BILLING_LOCK_POLICY_ID);
  assert.equal(detail.context.value.humanVerificationCanOverride, false);

  const decoded = decodeAccountBillingLockErrorDetail(
    encodeAccountBillingLockErrorDetail(resource, lock),
  );
  assert.deepEqual(decoded, detail.context.value.billingLock);
  assert.equal(decoded.lockedAt.seconds, lock.lockedAt.seconds);
  assert.equal(decoded.deleteAfter.seconds, lock.deleteAfter.seconds);
  assert.equal(decoded.usedBytes, lock.usedBytes);
  assert.equal(decoded.capBytes, lock.capBytes);
  assert.deepEqual(decoded.allowedActions, lock.allowedActions);
});
