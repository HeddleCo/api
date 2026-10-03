/** Portable delivery gates. Hosts must validate before settings replacement or
 * capability-authorized unsubscribe, then independently check authority,
 * destination verification and expectedVersion. */
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
  'LockedEmail' | 'UnsubscribeDelivery' | 'ProjectionTooLarge';

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

/** Wildcard OFF rules that include locked email are rejected atomically. */
export function validateNotificationRule(rule: NotificationRule): void {
  if (![Channel.UNSPECIFIED, Channel.IN_APP, Channel.EMAIL, Channel.PUSH].includes(rule.channel) ||
      ![Delivery.IMMEDIATE, Delivery.DIGEST, Delivery.DISABLED].includes(rule.delivery)) {
    throw new NotificationValidationError('InvalidRule');
  }
  if (rule.delivery === Delivery.DIGEST && rule.channel !== Channel.EMAIL) {
    throw new NotificationValidationError('DigestRequiresEmail');
  }
  const matchesLocked = rule.kind === '' || rule.kind === '*' || LOCKED_EMAIL_KINDS.includes(rule.kind);
  if (matchesLocked && [Channel.EMAIL, Channel.UNSPECIFIED].includes(rule.channel) &&
      rule.delivery !== Delivery.IMMEDIATE) {
    throw new NotificationValidationError('LockedEmail');
  }
}

export function validateNotificationPreferencesWrite(request: SetNotificationPreferencesRequest): void {
  if (!request.preferences) throw new NotificationValidationError('InvalidRule');
  for (const rule of request.preferences.rules) validateNotificationRule(rule);
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
