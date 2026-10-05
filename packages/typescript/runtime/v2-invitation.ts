import { InvitationResolution_Status as Status, type InvitationResolution } from "./administration_pb.js";
import { create } from '@bufbuild/protobuf';
import { CallFailureSchema, ErrorDetailSchema, CallFailureCode, ErrorReason } from '../common/errors_pb.js';
import { InvitationState, type InvitationRecord } from './administration_pb.js';
import { type CreateInvitationRequest, type CreateInvitationResponse } from './administration_pb.js';

export const SPOOL_INVITATION = 'spool_invitation';
export const SPOOL_INVITATION_DECLINED = 'spool_invitation_declined';
export type InvitationViolation = 'RecipientRequired' | 'InvalidEmail' | 'InvalidHandle' |
  'InvalidAccountId' | 'HandleNotFound' | 'Unauthenticated' | 'Unavailable' | 'Lifecycle' | 'InvalidRecord' | 'HumanSessionRequired' | 'InviterAuthorityLost';

export class InvitationError extends Error {
  readonly code: CallFailureCode;
  readonly reason: ErrorReason;
  readonly field: string;
  constructor(readonly violation: InvitationViolation) {
    super(violation === 'HandleNotFound' ? 'no such user' :
      violation === 'Unavailable' ? 'invitation unavailable' : violation);
    this.name = 'InvitationError';
    this.code = ['HandleNotFound', 'Unavailable'].includes(violation) ? CallFailureCode.NOT_FOUND :
      violation === 'Unauthenticated' ? CallFailureCode.UNAUTHENTICATED :
      violation === 'HumanSessionRequired' ? CallFailureCode.PERMISSION_DENIED :
      ['Lifecycle', 'InviterAuthorityLost'].includes(violation) ? CallFailureCode.FAILED_PRECONDITION : CallFailureCode.INVALID_ARGUMENT;
    this.reason = violation === 'HumanSessionRequired' ? ErrorReason.INVITATION_HUMAN_SESSION_REQUIRED :
      violation === 'InviterAuthorityLost' ? ErrorReason.INVITATION_INVITER_AUTHORITY_LOST :
      violation === 'HandleNotFound' ? ErrorReason.INVITATION_HANDLE_NOT_FOUND :
      violation === 'Unavailable' ? ErrorReason.RESOURCE_NOT_FOUND :
      violation === 'Unauthenticated' ? ErrorReason.CREDENTIAL_MISSING :
      violation === 'Lifecycle' ? ErrorReason.LIFECYCLE_STATE :
      violation === 'RecipientRequired' ? ErrorReason.FIELD_REQUIRED : ErrorReason.FIELD_INVALID;
    this.field = violation === 'RecipientRequired' ? 'invitation.recipient' :
      violation === 'InvalidEmail' ? 'invitation.email' :
      ['InvalidHandle', 'HandleNotFound'].includes(violation) ? 'invitation.handle' :
      violation === 'InvalidAccountId' ? 'invitation.account_id' :
      violation === 'Unauthenticated' ? '' : 'invitation';
  }
  failure() {
    return create(CallFailureSchema, { code: this.code, message: this.message,
      error: create(ErrorDetailSchema, { reason: this.reason, field: this.field }) });
  }
}

const utf8 = new TextEncoder();
const asciiLower = (value: string) => value.replace(/[A-Z]/g, c => c.toLowerCase());
// Match Rust str::trim / char::is_whitespace (Unicode White_Space), including
// U+0085 and excluding U+FEFF; JavaScript's trim/\s use a different set.
const trimWhitespace = (value: string) => value.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, '');
const accountUuid = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** Input shape only. Hosts must reuse their canonical handle grammar/provider lookup. */
export function normalizeInvitationRecipient(record: InvitationRecord): InvitationRecord['recipient'] {
  const recipient = record.recipient;
  if (recipient.case === undefined) throw new InvitationError('RecipientRequired');
  const bound = recipient.case === 'email' ? 320 : recipient.case === 'handle' ? 256 : 36;
  if (recipient.value.length > bound || utf8.encode(recipient.value).length > bound) {
    throw new InvitationError(recipient.case === 'email' ? 'InvalidEmail' :
      recipient.case === 'handle' ? 'InvalidHandle' : 'InvalidAccountId');
  }
  const value = asciiLower(trimWhitespace(recipient.value));
  switch (recipient.case) {
    case 'email': {
      const parts = value.split('@');
      if (parts.length !== 2 || parts.some(p => p === '') ||
          /[\p{White_Space}\p{Cc}]/u.test(value)) throw new InvitationError('InvalidEmail');
      return { case: 'email', value };
    }
    case 'handle':
      if (value === '' || /[\p{White_Space}\p{Cc}/@#]/u.test(value)) {
        throw new InvitationError('InvalidHandle');
      }
      return { case: 'handle', value };
    case 'accountId':
      if (!accountUuid.test(recipient.value)) throw new InvitationError('InvalidAccountId');
      return { case: 'accountId', value: asciiLower(recipient.value) };
  }
}

/** SERVER ONLY, after spool-admin authorization. Resolver uses public directory
 * eligibility/coordinates/rate budget. Return value is private storage, NEVER a
 * handle response field. Host also validates that explicit UUIDs name humans. */
export function resolveInvitationRecipient(record: InvitationRecord,
  resolvePublicHandle: (handle: string) => string | undefined): string | undefined {
  const recipient = normalizeInvitationRecipient(record);
  if (recipient.case === 'email') return undefined;
  if (recipient.case === 'accountId') return recipient.value;
  if (recipient.case === 'handle') {
    const id = resolvePublicHandle(recipient.value);
    if (!id || !accountUuid.test(id)) throw new InvitationError('HandleNotFound');
    return asciiLower(id);
  }
  throw new InvitationError('RecipientRequired');
}

/** Host additionally checks refs, future expiry, authorization and quotas. */
export function validateCreateInvitation(record: InvitationRecord): void {
  normalizeInvitationRecipient(record);
  if (record.version.length !== 0 || ![1, 2, 3].includes(record.role) || record.state !== InvitationState.UNSPECIFIED ||
      record.createdAt || record.updatedAt || record.inviter || record.inviterViaAgentLabel !== '' ||
      record.spoolName !== '' || record.spoolAddress) throw new InvitationError('InvalidRecord');
}

/** Reject replacing a handle with its private UUID or emitting an in-app link. */
export function validateCreateInvitationResponse(request: CreateInvitationRequest, response: CreateInvitationResponse): void {
  const input = request.invitation, output = response.invitation;
  if (!input || !output) throw new InvitationError('InvalidRecord');
  const recipient = normalizeInvitationRecipient(input);
  const actual = normalizeInvitationRecipient(output);
  if (recipient.case !== actual.case || recipient.value !== actual.value || output.state !== InvitationState.PENDING ||
      input.ref?.id !== output.ref?.id || input.ref?.spool?.id !== output.ref?.spool?.id || input.role !== output.role ||
      input.expiresAt?.seconds !== output.expiresAt?.seconds || input.expiresAt?.nanos !== output.expiresAt?.nanos ||
      (recipient.case === 'email') === (response.redemptionSecret.length === 0) ||
      (output.inviter !== undefined && output.inviter.handle === '') ||
      (output.inviterViaAgentLabel !== '' && !output.inviter?.handle)) throw new InvitationError('InvalidRecord');
  validateInvitationRecordProjection(output, recipient);
}

export type InvitationResponseAction = 'accept' | 'decline';
export type InvitationResponsePlan = {
  state: InvitationState; changed: boolean; grantRole: boolean; notificationKind?: string;
};
type Time = { seconds: bigint; nanos: number };

export function effectiveInvitationState(record: InvitationRecord, now: Time): InvitationState {
  if (![1, 2, 3, 4, 5].includes(record.state)) throw new InvitationError('Lifecycle');
  const expiry = record.expiresAt;
  if (record.state === InvitationState.PENDING && expiry &&
      (expiry.seconds < now.seconds || (expiry.seconds === now.seconds && expiry.nanos <= now.nanos))) {
    return InvitationState.EXPIRED;
  }
  return record.state;
}

/** Trusted stored binding + VERIFIED caller account, never caller-selected IDs.
 * Recheck before receipt replay. Accept/Decline require a human session.
 * Host serializes races and atomically commits state, grant, attention, receipt,
 * notification/outbox. This function plans effects; it performs no durable write. */
export function planInvitationResponse(record: InvitationRecord, storedRecipientAccount: string | undefined,
  authenticatedAccount: string | undefined, action: InvitationResponseAction, now: Time, humanSession: boolean, inviterRole: number): InvitationResponsePlan {
  if (!authenticatedAccount) throw new InvitationError('Unauthenticated');
  if (!humanSession) throw new InvitationError('HumanSessionRequired');
  if (!storedRecipientAccount || !accountUuid.test(authenticatedAccount) ||
      !accountUuid.test(storedRecipientAccount) || asciiLower(authenticatedAccount) !== asciiLower(storedRecipientAccount) ||
      !['handle', 'accountId'].includes(record.recipient.case ?? '')) throw new InvitationError('Unavailable');
  if (action !== 'accept' && action !== 'decline') throw new InvitationError('InvalidRecord');
  if (action === 'accept') validateInviterAuthority(record.role, inviterRole);
  const state = effectiveInvitationState(record, now);
  const target = action === 'accept' ? InvitationState.ACCEPTED : InvitationState.DECLINED;
  if (state === target) return { state, changed: false, grantRole: false };
  if (state !== InvitationState.PENDING) throw new InvitationError('Lifecycle');
  return { state: target, changed: true, grantRole: action === 'accept',
    notificationKind: action === 'decline' ? SPOOL_INVITATION_DECLINED : undefined };
}

/** Validate a capability preview before displaying its public inviter. The
 * server checks the secret and resolves the public identity at read time. */
export function validateInvitationResolution(response: InvitationResolution): void {
  if (response.status === Status.UNAVAILABLE &&
      (response.spool !== undefined || response.spoolName !== "" || response.role !== 0 ||
       response.expiresAt !== undefined || response.inviter !== undefined ||
       response.inviterViaAgentLabel !== "")) {
    throw new Error("UNAVAILABLE invitation resolution contains disclosed details");
  }
  if (response.inviter !== undefined && (response.inviter.handle === "" || accountUuid.test(response.inviter.handle))) {
    throw new Error("inviter requires an already-public handle");
  }
  if (response.inviterViaAgentLabel !== "" && !response.inviter?.handle) {
    throw new Error("agent label requires an inviter handle");
  }
}

/** Trusted current effective role/ceilings under the host transition lock.
 * Use for Accept AND Redeem before replay and to auto-revoke pending invites. */
export function validateInviterAuthority(offeredRole: number, inviterRole: number): void {
  if (![1, 2, 3].includes(offeredRole) || ![1, 2, 3].includes(inviterRole) || inviterRole < offeredRole) {
    throw new InvitationError('InviterAuthorityLost');
  }
}

/** Original stored recipient arm, never the private resolved account binding. */
export function validateInvitationRecordProjection(record: InvitationRecord, original: InvitationRecord['recipient']): void {
  const actual = normalizeInvitationRecipient(record);
  if (actual.case !== original.case || actual.value !== original.value ||
      ![1, 2, 3].includes(record.role) || ![1, 2, 3, 4, 5].includes(record.state)) throw new InvitationError('InvalidRecord');
  try { validateInvitationResolution({ inviter: record.inviter, inviterViaAgentLabel: record.inviterViaAgentLabel } as InvitationResolution); }
  catch { throw new InvitationError('InvalidRecord'); }
}

export function validateSpoolInvitationProjection(event: import('./views_pb.js').SpoolEvent, original: InvitationRecord['recipient']): void {
  if (event.payload.case === 'invitation') validateInvitationRecordProjection(event.payload.value, original);
}
export function validateNotificationInvitationProjection(record: import('./activity_pb.js').NotificationRecord, original: InvitationRecord['recipient']): void {
  if (record.invitation) validateInvitationRecordProjection(record.invitation, original);
}
export function validateAttentionInvitationProjection(item: import('./activity_pb.js').AttentionItem, original: InvitationRecord['recipient']): void {
  if (item.invitation) validateInvitationRecordProjection(item.invitation, original);
}
