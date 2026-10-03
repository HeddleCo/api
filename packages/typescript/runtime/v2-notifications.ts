/** Portable delivery gates. Hosts must validate before settings replacement or
 * capability-authorized unsubscribe, then independently check authority,
 * destination verification and expectedVersion. These gates complement remaining
 * stored-settings validation: hosts must also check timezone, selectors,
 * duplicate overrides and input budgets. */
import { toBinary } from '@bufbuild/protobuf';
import { CallFailureCode, ErrorReason } from '../common/errors_pb.js';
import {
  NotificationPreferencesSchema, NotificationRule_Channel as Channel,
  NotificationRule_Delivery as Delivery,
  type NotificationRule, type NotificationPreferences,
  type SetNotificationPreferencesRequest, type UnsubscribeNotificationsRequest,
} from './activity_pb.js';

export const MAX_EFFECTIVE_DELIVERIES = 4096;
export const MAX_NOTIFICATION_PREFERENCES_BYTES = 1024 * 1024;
export const LOCKED_EMAIL_KINDS: readonly string[] = ['account_security', 'security_surface'];
export type NotificationValidationReason = 'InvalidRule' | 'DigestRequiresEmail' |
  'LockedEmail' | 'InvalidDigestInterval' | 'UnsubscribeDelivery' | 'ProjectionTooLarge';

export class NotificationValidationError extends Error {
  readonly code: CallFailureCode;
  readonly reason: ErrorReason;
  constructor(readonly violation: NotificationValidationReason) {
    super(violation);
    this.name = 'NotificationValidationError';
    this.code = violation === 'LockedEmail' ? CallFailureCode.FAILED_PRECONDITION :
      violation === 'ProjectionTooLarge' ? CallFailureCode.RESOURCE_EXHAUSTED : CallFailureCode.INVALID_ARGUMENT;
    this.reason = violation === 'LockedEmail' ? ErrorReason.POLICY_DENIED :
      violation === 'ProjectionTooLarge' ? ErrorReason.QUOTA_EXCEEDED : ErrorReason.FIELD_INVALID;
  }
}

/** Wildcard OFF rules that include locked email are rejected atomically.
 * After enum validation, the email lock takes precedence over email-only DIGEST. */
export function validateNotificationRule(rule: NotificationRule): void {
  if (![Channel.UNSPECIFIED, Channel.IN_APP, Channel.EMAIL, Channel.PUSH].includes(rule.channel) ||
      ![Delivery.IMMEDIATE, Delivery.DIGEST, Delivery.DISABLED].includes(rule.delivery)) {
    throw new NotificationValidationError('InvalidRule');
  }
  const matchesLocked = rule.kind === '' || rule.kind === '*' || LOCKED_EMAIL_KINDS.includes(rule.kind);
  if (matchesLocked && [Channel.EMAIL, Channel.UNSPECIFIED].includes(rule.channel) &&
      rule.delivery !== Delivery.IMMEDIATE) {
    throw new NotificationValidationError('LockedEmail');
  }
  if (rule.delivery === Delivery.DIGEST && rule.channel !== Channel.EMAIL) {
    throw new NotificationValidationError('DigestRequiresEmail');
  }
}

export function validateNotificationPreferencesWrite(request: SetNotificationPreferencesRequest): void {
  if (!request.preferences) throw new NotificationValidationError('InvalidRule');
  const { digestInterval, digestOverrides, rules } = request.preferences;
  if (digestInterval) validateDigestInterval(digestInterval);
  for (const override of digestOverrides) {
    if (!override.digestInterval) throw new NotificationValidationError('InvalidDigestInterval');
    validateDigestInterval(override.digestInterval);
  }
  for (const rule of rules) validateNotificationRule(rule);
}

function validateDigestInterval(interval: { seconds: bigint; nanos: number }): void {
  if (interval.nanos !== 0 || ![0n, 3600n, 86400n, 604800n].includes(interval.seconds)) {
    throw new NotificationValidationError('InvalidDigestInterval');
  }
}

export function validateUnsubscribeNotifications(request: UnsubscribeNotificationsRequest): void {
  for (const rule of request.rules) {
    validateNotificationRule(rule);
    if (rule.delivery !== Delivery.DISABLED) throw new NotificationValidationError('UnsubscribeDelivery');
  }
}

/** Includes stored settings and selector lengths in the byte cap. */
export function validateNotificationPreferencesBound(preferences: NotificationPreferences): void {
  if (preferences.effectiveDelivery.length > MAX_EFFECTIVE_DELIVERIES ||
      toBinary(NotificationPreferencesSchema, preferences).length > MAX_NOTIFICATION_PREFERENCES_BYTES) {
    throw new NotificationValidationError('ProjectionTooLarge');
  }
}
