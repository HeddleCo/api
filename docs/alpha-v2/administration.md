# Spool invitations and People

This is the normative alpha.38 API contract for hosts and clients. This API
repository ships protobufs, route/signing metadata, portable Rust/TypeScript
gates and vectors. Hosts implement storage, authentication, transactions and
delivery; the helpers do not implement weft handlers. The
[canonical identity model](https://github.com/HeddleCo/weft/blob/integration/docs/IDENTITY_RESOURCE_AUTHORIZATION_MODEL.md)
governs account rooting and delegation.

## Typed recipients and disclosure

`SpoolService.CreateInvitation` takes `CreateInvitationRequest` with
`client_operation_id = 1` and `invitation = 2`. `InvitationRecord.recipient`
is a required oneof: `email = 8`, `handle = 9`, or `account_id = 10`.
The old string tag 3 is reserved, with no compatibility path. Old revoked and
redeemed booleans at tags 6/7 are also reserved; use `state` instead. Create
accepts only ref, recipient, role and optional future expires_at. All version,
state, timestamps, inviter and spool display fields MUST be unset on create.
Unknown/unspecified roles are invalid.

Email is trimmed and ASCII-lowercased: maximum 320 UTF-8 bytes before trimming,
one `@`, nonempty local/domain parts, no internal whitespace/control characters.
Email invitations remain link invitations even for registered mailboxes. The
account arm is an explicit human UUID already supplied by the caller. The host
MUST validate that it identifies a human, never an independent agent principal;
hide unknown/private account eligibility with `NOT_FOUND / RESOURCE_NOT_FOUND`.

Handles are at most 256 UTF-8 bytes before trimming; reject empty input,
internal whitespace/control characters and `/`, `@`, or discriminator `#`.
Reuse `weft_base::handle::parse_canonical_text` and the account-management
grammar: native `mara`, GitHub `gh:Mara`, or host-qualified `gitlab.com:Mara`.
Trim and ASCII-lowercase lookup coordinates; never confusable-fold, guess an
email or reinterpret a UUID-looking handle as an account arm. Portable helpers
validate shape; the host owns grammar and provider/directory validation.

The host MUST authorize spool administration and quotas before resolving a
handle. Reuse `IdentityService.ResolveHandles`' publicly claimed-account
eligibility, exact lookup/query shape and shared enumeration/rate budget.
AVAILABLE, HELD, RESERVED, CONFUSABLE, tombstoned, absent and otherwise
unresolvable handles all return the same envelope:

```
CallFailure.code = CALL_FAILURE_CODE_NOT_FOUND (5)
CallFailure.message = "no such user"
CallFailure.error.reason = ERROR_REASON_INVITATION_HANDLE_NOT_FOUND (302)
CallFailure.error.field = "invitation.handle"
CallFailure.error.resource = ""
CallFailure.error.context = absent
```

**Exact disclosure:** an authorized inviter learns only whether the supplied
handle currently resolves to a publicly claimed account. This is a subset of
ResolveHandles' existing public status/profile disclosure. Create MUST NOT
expose the resolved UUID, email, provider subject, private lifecycle, credential
readiness, delivery, membership or another invitation. Do not add private
eligibility distinctions to publicly identical outcomes: a publicly claimed
binding can be stored while its account is locked/disabled; its own sign-in
policy controls later action. Handles the directory withholds stay unresolvable.
Malformed input returns `INVALID_ARGUMENT / FIELD_INVALID`, field
`invitation.handle`, without lookup. Unauthorized callers receive only the
existing spool authorization failure, with no handle-dependent result.

Resolve and store the private human account binding transactionally once.
Handle removal/rename/reassignment MUST NOT retarget it. Return only the
original normalized recipient arm. A handle is never replaced/supplemented
with its account UUID in create, invitation observations, inbox, receipts,
notification text or errors before acceptance. Explicit account-ID inputs may
echo that same supplied ID. After Accept/Redeem, member/grant records expose the
accepted human principal by design under ordinary spool authorization. This
privacy rule does not suppress that membership identity. InvitationRecord itself
continues to preserve the original recipient arm in every lifecycle state.

`CreateInvitationResponse` has `receipt = 1`, `invitation = 2`, and
`redemption_secret = 3`. Only email invitations receive a secret. Account and
handle invitations MUST have an empty secret and no link capability. Stored
secrets never enter reads. The create result is a PENDING creation snapshot;
use observations for current lifecycle state. `validate_create_invitation_response` /
`validateCreateInvitationResponse` check this split and recipient preservation
against the original request.
Hosts MUST run these gates or equivalent validation before emitting a response,
including operation-receipt replay. Validating after receipt by a client cannot
undo a UUID already disclosed on the wire.

## Signed-in Accept and Decline

`SpoolService.AcceptInvitation(AcceptInvitationRequest) -> MutationResponse`
and `SpoolService.DeclineInvitation(DeclineInvitationRequest) -> MutationResponse`
take only `client_operation_id = 1` and `invitation = 2` (`RecordRef`). They
require authenticated-principal Tier-1 proof of possession, durable receipts,
client-operation-ID retries, caller-bound authorization and hidden existence.
There is no secret, OAuth-only gate, owner signature or existing membership
prerequisite. Accept AND Decline REQUIRE a verified human session. Agent,
service and delegated credentials MUST refuse with `PERMISSION_DENIED /
INVITATION_HUMAN_SESSION_REQUIRED (204)`, field `invitation`, before invitation
lookup/state/receipt replay, even when delegated by the recipient. Agents are
delegations of a user, not people; they cannot make this human membership choice.

Compare the verified caller account with the stored recipient binding, never
the current handle owner or caller-selected principal. Recheck active auth and
this comparison BEFORE state inspection and BEFORE receipt replay, on every
retry. Missing credentials use `UNAUTHENTICATED / CREDENTIAL_MISSING`.
Signed-in foreign callers, nonexistent invites and email-only invites uniformly
use `NOT_FOUND / RESOURCE_NOT_FOUND`, field `invitation`, message
`invitation unavailable`, empty resource and absent context. Neither the
inviter nor a spool administrator bypasses recipient matching.

Accept AND email Redeem MUST recheck the original human inviter's CURRENT
authority to grant the offered role under the transition lock, before grant or
receipt replay. Administrator invitations require ADMINISTRATOR; other roles
require at least the offered role, including current credential/grant ceilings.
Removed, expired, revoked or insufficient authority refuses with
`FAILED_PRECONDITION / INVITATION_INVITER_AUTHORITY_LOST (205)`, field `invitation`,
empty resource/context and no inviter identity. Accepted retries cannot recreate
a grant and still recheck authority. Decline does not require inviter authority.
Hosts MUST auto-revoke affected PENDING invitations when the inviter loses this
authority (grant removal/downgrade/expiry, inherited authority or credential
revocation), serializing with acceptance. Commit REVOKED/version/time, attention
DISMISSED and stream updates atomically; no grant. If loss is detected before
that worker commits, Accept/Redeem still return the typed authority-lost refusal.
`validate_inviter_authority` / `validateInviterAuthority` supply the shared gate;
trusted effective roles are host-loaded, never request fields.

Accept atomically commits ACCEPTED and grants the offered role once. An active
grant already meeting or exceeding that role remains unchanged, including its
expiry. Otherwise create/upgrade to the offered role with no grant expiry;
never revive an expired stronger role. Preserve `include_descendants` on every
existing-row conflict; a new grant sets it false. Invitation expiry limits
acceptance, not membership. Acceptance never grants owner/purge
authority. A retry MUST NOT recreate a subsequently revoked grant. Decline
commits DECLINED without a grant and emits one `spool_invitation_declined`
notification to the original human inviter, including if they have left the
spool. That notification permits only its invitation-scoped projection.
Normatively, if the inviter cannot currently read the spool, resolve
`spool_invitation_declined` at ACCOUNT scope with no event Spool/ancestor chain.
MUST NOT return InvalidSource or require spool-read authorization for this
required effect. Account preferences, suppression and ordinary outbox semantics
apply, so leaving the spool cannot make Decline impossible or roll it back.

Serialize Accept/Decline/Redeem/Revoke/expiry races. Commit state/version/time,
grant, attention update, receipt and required notification/outbox in one
transaction, rolling back if a required effect fails. Deduplicate notifications
by invitation plus transition, not only operation ID. Same operation ID and
same bytes replay the receipt AFTER reauthorization; changed bytes return
OPERATION_ID_REUSED. A fresh operation ID against a matching terminal state
returns a successful no-op receipt, preserving version/time and producing no
grant or notification effects.

## State machine and email links

`InvitationState`: UNSPECIFIED=0, PENDING=1, ACCEPTED=2, DECLINED=3,
REVOKED=4, EXPIRED=5. UNSPECIFIED is create input only, never a read state.

| Current | Event | Result and effect |
| --- | --- | --- |
| PENDING | Account/handle Accept | ACCEPTED; grant once; attention ACTED_ON |
| PENDING | Account/handle Decline | DECLINED; notify inviter once; attention ACTED_ON |
| PENDING | Email Redeem | ACCEPTED; grant once |
| PENDING | Authorized Revoke with matching version | REVOKED; attention DISMISSED |
| PENDING | Server time >= expires_at | EXPIRED; attention DISMISSED |
| ACCEPTED | Authorized matching Accept or email Redeem retry | Success, no effects |
| DECLINED | Authorized matching Decline retry | Success, no effects |
| REVOKED | Authorized matching Revoke retry | Success, no effects |
| Any terminal | Conflicting lifecycle command | FAILED_PRECONDITION / LIFECYCLE_STATE |

No terminal state reopens. Use a fresh ID for another invitation. At the exact
expiry instant (seconds/nanos), pending cannot be accepted, declined or
redeemed; project EXPIRED before the expiry worker persists it. Accepted and
declined never later expire. Missing expiry means no deadline. Hosts validate
Timestamp bounds. Effective expiry does not fabricate a committed version or
update time: these remain the last stored commit until the expiration
transaction updates them and emits the ordinary terminal stream update.
Revoke retains spool-admin authorization and CAS: a stale
expected_version returns VERSION_CONFLICT; exact receipt retries reauthorize.
Same-state Revoke under a fresh operation ID requires the current version.

`RedeemInvitation` remains email-only, using a link secret or the existing
verified matching OAuth-email flow. It uses the same ACCEPTED transaction,
grant and retry rules. Retain verified recipient-email/account matching;
possession of a forwarded preview secret does not let another account redeem.
Persist the accepting human account privately for matching accepted retries.
It MUST NOT redeem account/handle invitations by secret
guessing or handle re-resolution. Anonymous `ResolveInvitation` remains an
email-link preview: wrong secret, non-email, declined, expired, revoked or
unavailable all return the byte-identical UNAVAILABLE projection. Valid pending
email links project AVAILABLE; accepted links project REDEEMED. Existing public
inviter and timing protections apply. Email link capabilities still expire at
expires_at: an accepted record remains ACCEPTED, but its expired anonymous link
preview is UNAVAILABLE and an expired secret cannot authorize receipt replay.
Email links have no in-app Decline in
this release.

## Inbox and delivery

Reuse `ObserveNotifications` / `NotificationEvent.notification`,
`ObserveAttention` / `AttentionEvent.item`, `EntityRef.invitation`,
`ActionAvailability` and existing pagination/continuity/removal semantics.
`NotificationRecord.invitation = 10` and `AttentionItem.invitation = 15`
carry the safe typed projection; `AttentionItem.kind = 16` shares the existing
open string vocabulary. No new inbox service is added.

**`spool_invitation`** is a direct ask to the stored recipient account, with
title/headline "Invited to <spool> as <role> by <inviter.handle>". Optional
display name accompanies the handle; a public agent label may only follow as
"via <label>". If inviter identity is unavailable, omit it and use
"Invited to <spool> as <role>". Reuse InvitationResolution's read-time public
inviter/lifecycle omission rules; never fabricate a username or disclose a
private resolved UUID before acceptance. Member/grant principals are visible
through their ordinary authorized reads after acceptance.

The stored binding authorizes the invitee to read only invitation state, spool
name/address, role, expiry and public attribution before membership. It grants
no other spool access. The notification/outbox authorizer MUST use this binding
instead of requiring the membership Accept has yet to create. Terminal updates
retain this narrow read authority for the intended invitee.

Pending account/handle items advertise fully qualified routes
`/heddle.api.v1alpha2.SpoolService/AcceptInvitation` and
`/heddle.api.v1alpha2.SpoolService/DeclineInvitation`, with invitation target,
host endpoint and existing implemented/authorized/requirements flags.
`authorized` MUST be false for agent/delegated credentials; advice must reflect
the human-session gate without granting authority.
Capabilities are `CAPABILITY_ACCEPT_INVITATION = 10` and
`CAPABILITY_DECLINE_INVITATION = 11`. Advice never grants authority. Terminal
updates remove actionable advice and update all devices. Marking read,
dismissal or snoozing MUST NOT decline; only DeclineInvitation does that.

**`spool_invitation_declined`** is an ambient update to the human inviter,
without Accept/Decline advice or a separate pending attention ask. Both kinds
reuse [preferences, effective delivery, outbox, authorizer and unsubscribe](notifications.md).
Invitations default to immediate in-app/email/push when available; decline
defaults to in-app + daily email digest + push off. Per-channel preferences
apply, including disabled in-app: suppression does not alter invite lifecycle.
No security-email lock is added. Invitees without membership use account-level
preferences; never disclose unauthorized spool cells in the preference matrix.

## Inviter read model and people-only rows

`ObserveSpool(SPOOL_SECTION_INVITATIONS, SpoolPages.invitations)` returns the
existing paginated `SpoolEvent.invitation`. Hosts MUST run
`validate_invitation_record_projection` / `validateInvitationRecordProjection`
(or equivalent) against the original normalized recipient arm before emitting
ANY InvitationRecord, including Create/replay, ObserveSpool invitations,
`NotificationRecord.invitation` and `AttentionItem.invitation`. The respective
spool/notification/attention projection validators invoke this shared gate.
It rejects substitution of a handle with its private account ID, invalid
role/state, missing public inviter handle, UUID-as-inviter and orphan agent
labels. Private bindings never supply projection recipient values.
Administrators can see all retained
states in People/invitations with live versions and the existing read budget.

| InvitationRecord field | Tag | Meaning |
| --- | --- | --- |
| ref / version | 1 / 2 | Stable invitation/spool identity and opaque CAS version |
| role / expires_at | 4 / 5 | Offered role and optional acceptance deadline |
| email / handle / account_id | 8 / 9 / 10 | Only the original normalized recipient arm |
| state | 11 | Authoritative effective lifecycle status |
| created_at / updated_at | 12 / 13 | Server creation / last committed transition time |
| inviter | 14 | Optional current PublicOwner, no UUID |
| inviter_via_agent_label | 15 | Public label only alongside inviter handle |
| spool_name / spool_address | 16 / 17 | Invitation-scoped display, not authority |

On migration omit historically unknown timestamps. Preserve private human
bindings; old account UUID strings become account arms, email strings email
arms. Redeemed maps to ACCEPTED, revoked to REVOKED, otherwise deadline decides
EXPIRED/PENDING. Inconsistent legacy rows require host reconciliation; do not
infer agent recipients.

**Normative:** agents are delegations of a user, not people. Every member,
grant and invitation read (MemberRecord, GrantRecord, InvitationRecord and
composed directories) MUST NOT return an agent/service principal as its own
row, recipient or inviter. Materialize human account rows only. Delegated
actions inherit human attribution, optionally qualified by a public agent
label. Direct grant/account-recipient inputs naming agents MUST be refused,
including UUID-shaped agent credential identifiers.
