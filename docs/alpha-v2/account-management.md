# Account management additions

Spool invitations addressed to handles resolve on the host, never through a
client account-ID lookup. The [administration contract](administration.md)
specifies typed recipients, exact public-directory disclosure, private stable
binding, signed-in Accept/Decline and the state machine. The invitee uses their
verified session or credential without a link secret or prior spool membership.
Handle changes never retarget invitations. Email keeps link/OAuth redemption.

Agents are delegations of their human user, not people. Member, grant and
invitation reads MUST never return an agent principal as its own row. The human
is the member/grantee/recipient/inviter; a public agent label only qualifies
attribution and never replaces that person.

This is the additive contract for [api#315](https://github.com/HeddleCo/api/issues/315)
and weft [#2530](https://github.com/HeddleCo/weft/issues/2530),
[#2531](https://github.com/HeddleCo/weft/issues/2531), and
[#2532](https://github.com/HeddleCo/weft/issues/2532). It declares server behavior
for those implementation issues; it does not assert that weft already implements
the new commands. All existing field numbers, field types, and methods survive.
Package versions stay at 0.31.0-alpha.18.

## Signed commands and receipts

`IdentityService.RemovePasskey`, `SetDisplayName`, `SetPrimaryHandle`, and
`RemoveHandle` use exactly the same rpc_contract policy as `RenamePasskey`:
authenticated-principal signing identity, Tier-1 proof of possession over the
exact method and complete deterministic protobuf request, durable write,
client-operation-ID retries, identity-and-credentials capability, and caller-bound
account authorization with existence hidden. There is no new portable SignedRecord
format or owner-key ceremony. `SetDisplayName`, `SetPrimaryHandle` and
`RemoveHandle` are ordinary account commands whose effective delegated permissions
and full credential caveats must still be enforced. `RemovePasskey` additionally
requires the existing `require_independent_root` predicate: `root_established`
plus an unattenuated credential (one authority block). Delegated and ephemeral
credentials cannot retire a durable passkey authority, even with full account
scope and valid request PoP. Caller ownership, exact-method caveats, version CAS
and the last-method check are still required.

Every request has `client_operation_id` at tag 1. It must parse with weft's existing
`uuid::Uuid` parser, as used by `identity_v2_management::start`: 32 ASCII hex
digits, a 36-byte hyphenated UUID, that UUID inside braces (38 bytes), or the
`urn:uuid:` form (45 bytes). Hex digits may be uppercase or lowercase. The maximum
is 45 ASCII bytes; whitespace is not trimmed and arbitrary nonblank strings are
invalid. This inherits the existing ID scheme and introduces no new validator.
Every response has a
`MutationReceipt` at tag 1. A same-ID/same-request retry returns the original
outcome; reusing an operation ID with different request bytes is rejected.
State changes and receipt persistence commit together.

`RemovePasskey` takes the account-private `PasskeyRecord.ref` and its exact
`expected_version` (tag 3), just like `RenamePasskey`. A version mismatch changes
no state. The reference must be unscoped (`spool` absent), with a nonempty ID of
at most 1366 ASCII bytes: the unpadded base64url representation of the existing
1..1024-byte WebAuthn credential ID, as checked by weft's
`identity_v2_management::passkey_reference`. A successful response carries the
updated revoked record and version.
Weft must atomically check that another usable sign-in method remains, and refuse
removal of the last one with typed `CALL_FAILURE_CODE_FAILED_PRECONDITION` and
`ERROR_REASON_LIFECYCLE_STATE`, without committing removal. Recovery factors alone
do not count as usable sign-in methods. Retiring the passkey authority and
revoking temporary sessions minted by that passkey happen together. Public signed
evidence for already admitted history remains available. Device-root cascades
follow the [canonical identity model's CURRENT/TARGET revocation policy](https://github.com/HeddleCo/weft/blob/integration/docs/IDENTITY_RESOURCE_AUTHORIZATION_MODEL.md#revocation-decisions).

`SetDisplayName` takes `display_name` at tag 2 and returns the updated
`PrincipalRecord` at tag 2. Normalization is exactly
[`RenamePasskeyRequest.label`](../../proto/heddle/api/v1alpha2/identity.proto):
trim Unicode White_Space at both ends, normalize to NFC, reject Unicode general
categories Cc, Cf, Cs, Co, Cn, Zl, and Zp, then reject more than 256 UTF-8 bytes.
The implementations are [`normalize_passkey_label`](../../src/v2/passkey_label.rs)
and [`normalizePasskeyLabel`](../../packages/typescript/runtime/v2-passkey-label.ts).
Empty clears the explicit name; observation falls back to the primary handle, or
the generated pet name while unclaimed. `PrincipalRecord.display_name` already
exists at tag 12. Display names never establish authority or change account UUIDs.

`SetPrimaryHandle` and `RemoveHandle` take the exact canonical
`PublicHandleRecord.handle` at tag 2. Inputs must be nonempty and at most
256 UTF-8 bytes, including the provider qualifier, checked before normalization
(so trimming cannot rescue an oversized input). Whitespace-only inputs are
invalid. The canonical grammar/parser is
[`weft_base::handle::parse_canonical_text`](https://github.com/HeddleCo/weft/blob/integration/crates/weft-base/src/handle.rs):
native `name`, GitHub `gh:name`, and other providers `host:name` (for example
`gitlab.com:name`; bare `gitlab:name` is not a provider-qualified handle).
The parser trims and ASCII-lowercases to derive exact lookup coordinates; it
does not apply confusable folding. Native names retain
[`weft_base::principal::is_valid_human_username`](https://github.com/HeddleCo/weft/blob/integration/crates/weft-base/src/principal.rs)
validation; provider handles must match an existing verified provider binding.
Only active verified claimed handles owned by the caller's account
are eligible; held names are not claimed handles. Selection atomically updates
the account's primary handle and returns the principal and public handle.
Removal returns the updated principal and preserves existing directory/tombstone
policy. Weft must atomically refuse removing the primary or last active claimed
handle with the same typed FailedPrecondition/lifecycle-state failure. The caller
must select another primary before removing the old one. These two commands and
`SetDisplayName` follow `ClaimHandle`'s operation-ID semantics; they do not introduce
a CAS against the credential-dependent principal projection.

## Passkey and current-credential metadata

`PasskeyRecord` gains `created_at` (6), `last_used_at` (7), optional `aaguid` (8),
and optional `authenticator_name` (9). Historical unknown timestamps stay absent;
unused/unknown last use stays absent. Last use means a successful authentication
with that exact passkey, not a rename or observation.

Clients should request WebAuthn attestation conveyance **"indirect"** when creating
a passkey so registration can extract the AAGUID from authenticator data. AAGUIDs
are exactly 16 bytes when present; omitted and all-zero values mean unknown
authenticator. Privacy restrictions may prevent usable metadata. AAGUIDs and
friendly authenticator names are advisory display metadata, never account
authority, proof of manufacturer trust, or sign-in permission. Friendly names
use the same NFC/256-byte label policy and are rendered as untrusted text.

`CurrentCredentialRecord.passkey_credential_id` (optional bytes, tag 18) identifies
the raw WebAuthn credential ID used to authenticate this original session. It is
1..1024 bytes when present, matching the existing PasskeyAuthority credential-ID
bound. It is absent for non-passkey authentication and unknown historical
bindings. Hosts derive it from the verified persisted original authentication;
clients never infer it from a device ID or a paginated session row. This projection
already means "this credential/session" in `GetIdentity` and `ObserveIdentity`.
`IntrospectCredential` inspects a supplied Biscuit and is not the current-session
projection, so it needs no duplicate field. Neither a credential ID nor metadata
is a reusable authentication assertion.

## Account actions and session pages

`PrincipalRecord.actions` is already generic (`ActionAvailability`, tag 9), so
there is no schema change to its shape. Hosts must declare the account-scope
commands `RenamePasskey`, `RemovePasskey`, `RevokeDevice`, `RevokeSession`,
`SetDisplayName`, `SetPrimaryHandle`, and `RemoveHandle`. `authorized` reflects the
exact current credential and its caveats; refused actions remain declared with
`authorized=false`, including `RevokeDevice` for an ephemeral sign-in and
`RemovePasskey` whenever `require_independent_root` fails. The same existing
predicate must govern handler authorization and action availability. Clients
should read these declarations rather than infer permission from authentication
method labels or account rooting tier. Target-specific checks, including
last-method, primary/last-handle safeguards and session ownership, still apply at
mutation time. Self-revocation may be permitted even when managing other sessions
is refused; target-specific affordances and requirements refine account actions.

`ObserveIdentityRequest.session_state` (tag 10) filters the existing `sessions`
page without changing `PageRequest` (tag 2):

| Value | Meaning |
| --- | --- |
| UNSPECIFIED (0) | ALL: preserves old clients' existing behavior |
| ACTIVE (1) | Not revoked and expires after the server's snapshot time |
| ENDED (2) | Revoked, signed out, or expired at the snapshot time |
| ALL (3) | Both active and ended authorized sessions |

Settings clients should explicitly request ACTIVE. Unknown enum values are
InvalidArgument. Filtering happens before pagination, byte budgets, and matching
counts; page/checkpoint cursors are bound to the selected filter. Live views must
remove rows that leave the selected state, including expiry without a subsequent
client request. The filter does not widen account/session authorization, request
an omitted sessions section, or filter `CurrentCredentialRecord.session`.

`SessionRecord.user_agent` already exists at tag 8. Empty means unavailable.
Hosts capture it at creation from client transport metadata when available, retain
it verbatim, and reject more than 8192 UTF-8 bytes or Unicode Cc before storing it.
This bound matches weft's existing identity-view bound. The new optional
`SessionRecord.device_label` (11) captures the client-supplied label at session
creation, including `BeginAuthenticationRequest.device_label` when enrollment is
declined. It uses the passkey label normalization/bounds; empty means no label.
Both are advisory, client-supplied, untrusted display text; neither proves a device
identity. Changes in display metadata do not change the session's authorization
version. Old sessions may carry neither value.

Rust `v2::account_metadata` and TypeScript `v1alpha2/account-metadata` provide the
same normalization and bounds checks. Shared fixtures cover Unicode normalization,
UTF-8 byte boundaries, optional binary presence, AAGUID length, and credential IDs.

## Held-name notification kinds

V2 uses an open string vocabulary for `NotificationRecord.kind` and
`NotificationRule.kind`. Add `HELD_NAME_REQUESTED`, delivered to the held name's
holder when a request starts, and `HELD_NAME_REQUEST_LAPSED`, delivered to the
requester when the 30-day right-of-first-refusal window lapses unclaimed. The
existing existence-hiding handle request must not expose the holder's identity.

Both kinds are **direct asks** under the
[2026-10-03 owner decision on weft#2529](https://github.com/HeddleCo/weft/issues/2529#issuecomment-5964072062):
inbox immediately, email immediately by default, and push immediately once
available, subject to each channel's preferences. Inbox delivery is on/off and
never delayed; digest is email-only. Defaults are owned by weft. The effective
delivery projection and other notification fields belong to api#313; this change
only extends the kind vocabulary. Rust and TypeScript export constants for both
strings, without introducing or renumbering a notification enum.

## Verified implementation evidence

Consumer acceptance requirements for weft#2530/#2531/#2532: add `RemovePasskey`
to `INDEPENDENT_ROOT_METHODS` and classify it as `DenyAttenuated` in
`AUTH_ROOT_BOUNDARY_CATALOG`; classify the other three new commands as
`SafeBearer`. Reuse `require_independent_root` in the removal handler and the
existing action-availability predicate in the principal projection. Handler
tests must use valid request signatures, owned targets, matching versions and
two usable sign-in methods: full-scope delegated and ephemeral requests fail
specifically on authority, while an eligible independent-root request succeeds.
Also assert that removal is declared with `authorized=false` for both denied
credentials. Keep the other three commands delegatable with complete caveats.

When wiring the existing validators into those consumers, cover every accepted
UUID form and malformed/over-45-byte IDs; empty/whitespace-only handles;
256-byte and 257-byte raw handle inputs including provider qualification and
multibyte UTF-8; and overlong inputs whose trimmed form would otherwise fit.
Cover absent/scoped/empty/over-1366-byte passkey references as well. These are
consumer acceptance requirements, not claims of handler execution by this API
contract PR. API tests pin the normative text and public package import.

The issue evidence was checked read-only with `git show origin/integration:<path>`
at weft `70eda4107ec2b81cab0b8d2ff88f08ba010a05c0`:

- `crates/weft-hosted/src/server/hosted/identity_v2_management/recovery.rs:1230-1237`
  retires unselected passkey certificates and their temporary sessions.
- `crates/weft-hosted/src/server/hosted/identity_v2_management.rs:238-242`
  checks the exact 32-byte passkey version and uses `normalize_passkey_label`.
- `crates/weft-hosted/src/server/hosted/identity/observation.rs:698-711`
  omits the specified account-management commands; `:525` and `:975` use the
  handle as display name.
- `crates/weft-registry/src/identity_view.rs:216-236` counts/pages all authorized
  sessions without an active-state predicate; `:270-275` enforces the existing
  8192-byte user-agent bound.
- `crates/weft-hosted/src/server/hosted/identity/registration.rs:121` stores the
  requested display name only in challenge metadata;
  `registration/completion.rs:714,722` creates a session without user agent and
  returns the handle as display name, as does `identity/authentication.rs:651,668`.
- `crates/weft-base/src/escrow.rs:657-709` starts the request window;
  `:835-864` only sets a claimed handle primary when none exists;
  `:1059-1088` reverts lapsed requests without notification.

Descriptor conformance checks every new method's signing, durable effect,
receipt, operation ID, capability and existence policy. Rust/TypeScript tests pin
additive field tags/presence and share metadata validation vectors. The command
descriptor test first failed on unmodified alpha.18 with
`missing identity RPC: RemovePasskey`, then passed with these additions.
