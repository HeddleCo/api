/** Portable delivery gates. Hosts must validate before settings replacement or
 * capability-authorized unsubscribe, then independently check authority,
 * destination verification and expectedVersion. These gates complement remaining
 * stored-settings validation: hosts must also check timezone, selectors,
 * duplicate overrides and input budgets. */
import { create, toBinary } from '@bufbuild/protobuf';
import { CallFailureCode, ErrorReason } from '../common/errors_pb.js';
import {
  EffectiveDeliverySchema, EffectiveDelivery_Source as Source,
  NotificationPreferencesSchema, NotificationRule_Channel as Channel,
  NotificationRule_Delivery as Delivery,
  type EffectiveDelivery, type NotificationRule, type NotificationPreferences,
  type SetNotificationPreferencesRequest, type UnsubscribeNotificationsRequest,
} from './activity_pb.js';

export const MAX_EFFECTIVE_DELIVERIES = 4096;
export const MAX_NOTIFICATION_PREFERENCES_BYTES = 1024 * 1024;
export const LOCKED_EMAIL_KINDS: readonly string[] = ['account_security', 'security_surface'];
export type NotificationValidationReason = 'InvalidRule' | 'DigestRequiresEmail' |
  'LockedEmail' | 'InvalidDigestInterval' | 'UnsubscribeDelivery' | 'ProjectionTooLarge' | 'InvalidAncestry' | 'InvalidSource';

export class NotificationValidationError extends Error {
  readonly code: CallFailureCode;
  readonly reason: ErrorReason;
  constructor(readonly violation: NotificationValidationReason) {
    super(violation);
    this.name = 'NotificationValidationError';
    this.code = ['LockedEmail', 'InvalidAncestry'].includes(violation) ? CallFailureCode.FAILED_PRECONDITION :
      violation === 'ProjectionTooLarge' ? CallFailureCode.RESOURCE_EXHAUSTED : CallFailureCode.INVALID_ARGUMENT;
    this.reason = ['LockedEmail', 'InvalidAncestry'].includes(violation) ? ErrorReason.POLICY_DENIED :
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

/** Write gate with the host-resolved shared system-root identity. */
export function validateNotificationPreferencesWriteForSystemRoot(
  request: SetNotificationPreferencesRequest, systemRoot: { id: string },
): void {
  validateNotificationPreferencesWrite(request);
  if (request.preferences?.rules.some(rule => rule.spool?.id === systemRoot.id)) {
    throw new NotificationValidationError('InvalidRule');
  }
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

/** Hosts with a 64-node ancestor bound pass 64 instead. Includes event spool. */
export const MAX_NOTIFICATION_ANCESTORS = 128;
export interface NotificationAncestor {
  spool: { id: string };
  readable: boolean;
  systemRoot: boolean;
}

/** Trusted host-loaded, complete parent chain; never from client input. */
function validateAncestry(cell: EffectiveDelivery, ancestors: readonly NotificationAncestor[], limit: number): void {
  if (![64, MAX_NOTIFICATION_ANCESTORS].includes(limit) || ancestors.length > limit ||
      cell.spool?.id !== ancestors[0]?.spool.id || ancestors.some((level, i) =>
        level.spool.id === '' || ancestors.slice(0, i).some(other => other.spool.id === level.spool.id) ||
        (level.systemRoot && (i === 0 || i + 1 !== ancestors.length)))) {
    throw new NotificationValidationError('InvalidAncestry');
  }
  if (ancestors[0] && !ancestors[0].readable) throw new NotificationValidationError('InvalidSource');
}

/** Shared routing/read projection. Host supplies defaults, effective cadence and
 * complete ancestry (including unreadable levels). The system root is optional,
 * last and transparent. Host must verify parent links and completeness first. */
export function resolveNotificationDelivery(
  rules: readonly NotificationRule[], cell: EffectiveDelivery, ancestors: readonly NotificationAncestor[],
  ancestorLimit: number, defaultDelivery: Delivery, digestEnabled: boolean,
): EffectiveDelivery {
  validateAncestry(cell, ancestors, ancestorLimit);
  if (![Channel.IN_APP, Channel.EMAIL, Channel.PUSH].includes(cell.channel) ||
      ['', '*'].includes(cell.kind) || !['', 'human', 'agent'].includes(cell.actorOrigin) ||
      ![Delivery.IMMEDIATE, Delivery.DIGEST, Delivery.DISABLED].includes(defaultDelivery) ||
      (defaultDelivery === Delivery.DIGEST && cell.channel !== Channel.EMAIL)) {
    throw new NotificationValidationError('InvalidRule');
  }
  for (const rule of rules) {
    validateNotificationRule(rule);
    if (ancestors.some(level => level.systemRoot && rule.spool?.id === level.spool.id)) {
      throw new NotificationValidationError('InvalidRule');
    }
  }
  let delivery = defaultDelivery;
  let source: Source = Source.DEFAULT;
  let sourceSpool: { id: string } | undefined;
  let selected = false;
  for (const [i, level] of ancestors.entries()) {
    if (level.systemRoot) continue;
    const rule = bestNotificationRule(rules, cell, level.spool.id);
    if (rule) {
      delivery = rule.delivery;
      source = i === 0 ? Source.RULE : Source.INHERITED;
      sourceSpool = i > 0 && level.readable ? level.spool : undefined;
      selected = true;
      break;
    }
  }
  if (!selected) {
    const account = bestNotificationRule(rules, cell, undefined);
    if (account) {
      delivery = account.delivery;
      source = cell.spool ? Source.ACCOUNT : Source.RULE;
    }
  }
  const locked = cell.channel === Channel.EMAIL && LOCKED_EMAIL_KINDS.includes(cell.kind);
  if (locked) delivery = Delivery.IMMEDIATE;
  else if (delivery === Delivery.DIGEST && !digestEnabled) delivery = Delivery.DISABLED;
  return create(EffectiveDeliverySchema, {
    kind: cell.kind, spool: cell.spool, actorOrigin: cell.actorOrigin, channel: cell.channel,
    delivery, source, locked, sourceSpool,
  });
}

function bestNotificationRule(
  rules: readonly NotificationRule[], cell: EffectiveDelivery, spoolId: string | undefined,
): NotificationRule | undefined {
  let best: NotificationRule | undefined;
  let previous = -1;
  for (const rule of rules) {
    const exactKind = !['', '*'].includes(rule.kind);
    const exactChannel = rule.channel !== Channel.UNSPECIFIED;
    const exactOrigin = !['', 'any'].includes(rule.actorOrigin);
    if (rule.spool?.id !== spoolId || (exactKind && rule.kind !== cell.kind) ||
        (exactChannel && rule.channel !== cell.channel) || (exactOrigin && rule.actorOrigin !== cell.actorOrigin)) continue;
    const score = Number(exactKind) * 4 + Number(exactChannel) * 2 + Number(exactOrigin);
    if (score > previous) { best = rule; previous = score; }
  }
  return best;
}

/** Checks provenance/disclosure; hosts also compare with the resolved result. */
export function validateEffectiveDeliverySource(
  cell: EffectiveDelivery, ancestors: readonly NotificationAncestor[], ancestorLimit: number,
): void {
  validateAncestry(cell, ancestors, ancestorLimit);
  const valid = [Source.RULE, Source.DEFAULT].includes(cell.source) ? !cell.sourceSpool :
    cell.source === Source.ACCOUNT ? !!cell.spool && !cell.sourceSpool :
    cell.source === Source.INHERITED ? !!cell.spool && ancestors.slice(1).some(level =>
      !level.systemRoot && (cell.sourceSpool ? level.readable && cell.sourceSpool.id === level.spool.id : !level.readable)) : false;
  if (!valid) throw new NotificationValidationError('InvalidSource');
}

/** Choose scopes before expanding matrices; rule-free descendants never enter. */
export function notificationProjectionScopes(
  request: import('./views_pb.js').ObserveNotificationsRequest, rules: readonly NotificationRule[], readable: readonly { id: string }[],
): ({ id: string } | undefined)[] {
  const spool = request.effectiveDeliverySpool;
  if (spool) {
    if (!request.includePreferences || !spool.id || !readable.some(s => s.id === spool.id)) throw new NotificationValidationError('InvalidSource');
    return [spool];
  }
  const scopes: ({ id: string } | undefined)[] = [undefined];
  for (const rule of rules) {
    if (rule.spool && readable.some(s => s.id === rule.spool?.id) && !scopes.some(s => s?.id === rule.spool?.id)) scopes.push(rule.spool);
  }
  return scopes;
}

/** Host loads stored state/current readability under the commit lock/CAS, and
 * validates storage budgets after preserving hidden selectors. */
export function replaceNotificationPreferences(
  stored: NotificationPreferences, request: SetNotificationPreferencesRequest, readable: readonly { id: string }[],
): NotificationPreferences {
  validateNotificationPreferencesWrite(request);
  const next = create(NotificationPreferencesSchema, request.preferences!);
  const hidden = (spool: { id: string } | undefined) => !!spool && !readable.some(s => s.id === spool.id);
  if (next.rules.some(rule => hidden(rule.spool)) || next.digestOverrides.some(item => !item.spool || hidden(item.spool))) throw new NotificationValidationError('InvalidSource');
  if (!request.clearUnreadableScopes) {
    next.rules = [...next.rules, ...stored.rules.filter(rule => hidden(rule.spool))];
    next.digestOverrides = [...next.digestOverrides, ...stored.digestOverrides.filter(item => hidden(item.spool))];
  }
  return create(NotificationPreferencesSchema, { ...next, effectiveDelivery: [], nextDigestAt: undefined,
    digestOverrides: next.digestOverrides.map(item => ({ ...item, nextDigestAt: undefined })) });
}

/** Invitation binding authorizes delivery without membership. Decline to a
 * departed inviter MUST route at account scope, never InvalidSource. */
export function resolveInvitationNotificationDelivery(
  rules: readonly NotificationRule[], cell: EffectiveDelivery, ancestors: readonly NotificationAncestor[],
  ancestorLimit: number, defaultDelivery: Delivery, digestEnabled: boolean,
): EffectiveDelivery {
  if (!['spool_invitation', 'spool_invitation_declined'].includes(cell.kind)) throw new NotificationValidationError('InvalidRule');
  if (cell.spool && ancestors[0] && !ancestors[0].readable) {
    return resolveNotificationDelivery(rules, create(EffectiveDeliverySchema, { ...cell, spool: undefined }), [], ancestorLimit, defaultDelivery, digestEnabled);
  }
  return resolveNotificationDelivery(rules, cell, ancestors, ancestorLimit, defaultDelivery, digestEnabled);
}
