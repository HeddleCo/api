# Creator-only pending invitation code reads

Owner decision, 2026-10-05: the user creating an invite can copy its link as
many times as desired until it is claimed. This contract adds hosted unary
reads `IdentityService/GetSignupInvitationCode` and
`SpoolService/GetInvitationCode`. Each takes an `invitation: RecordRef` and
returns its own response with only `redemption_secret: bytes` at tag 1.

Dedicated RPCs keep capability material out of the shared `SignupInvitation`
and `InvitationRecord` types, which appear in lists and observations. Existing
creation responses retain their separate creator-only `redemption_secret`.
These four response roots are the only outputs that may carry invitation codes.
Lists, observations, inbox events, public previews, mutation receipts and audit
records MUST NOT carry plaintext codes or ciphertext. Redemption/preview inputs
may still submit a held code; they never echo it in their outputs.

## Authorization and lifecycle (normative host requirements)

Both reads require an authenticated principal and request proof of possession.
The host MUST resolve the immutable creator account subject recorded when the
invitation was created and compare it to the authenticated caller account
subject after normal credential verification, attenuation and revocation checks.
The request reference is a selector, never authorization. Handles, current
membership, spool administration, owner/support/operator status and knowledge
of a recipient or code do not bypass creator equality. Spool creator means the
original inviter only, not any administrator who could have created an invite.
The accountable account remains the creator when a delegated agent creates it;
delegation must independently permit this read. Another account's agent cannot
read it. For GetInvitationCode, the original inviter MUST additionally still
have current ADMINISTRATOR authority for every offered role, checked under the
same read/transition lock BEFORE decrypting or returning a code. Creator identity
survives demotion, but demotion denies this read even before auto-revoke commits.
After creator matching, map lost authority to FAILED_PRECONDITION /
INVITATION_INVITER_AUTHORITY_LOST (205), with no identity/resource/context detail.
Signup code reads have no spool-admin requirement.

An unknown reference and a non-creator MUST receive indistinguishable
`NOT_FOUND`, using the same lookup/authorization shape and disclosing no code
or lifecycle detail. A malformed reference receives `INVALID_ARGUMENT` before
lookup. Do not accept a creator identity or pending state from request input.

For a known creator, return the original code only while the invitation is
unredeemed, unrevoked and `now < expires_at`. Equality at nanosecond precision
is expired. Newly created code invitations MUST have a finite, valid expiry;
the host MUST apply its configured `INVITATION_CODE_MAX_LIFETIME_SECS` maximum
lifetime. Email-recipient CreateInvitation requires explicit `expires_at`;
omission returns `INVALID_ARGUMENT / ERROR_REASON_FIELD_REQUIRED`, field
`invitation.expires_at`. Handle/account_id invitations have no code and retain
optional expiry, as specified in [administration.md](administration.md). Missing
or malformed legacy expiry fails closed to an empty code. A redeemed, revoked or expired
invite returns an empty response, including immediately after the transition.
Hash-only legacy invites and handle-addressed spool invitations without a code
also return empty; hosts MUST NOT mint a replacement code as a side effect.
There is no read-once flag, quota consumption, version change or invitation
extension: repeated reads return the exact original bytes while pending.

Check creator, current inviter admin authority (spool invitations) and lifecycle before decryption. Reads MUST serialize with redeem,
revoke and expiry cleanup on the same authoritative invitation state: a read
linearized after a terminal transition cannot decrypt or return the code. A
read that completed before the transition can already have reached a client;
the client-held copy cannot be erased, but redemption must refuse terminal
invites. Signup admission reservations are provisional and do not by themselves
mark an invitation redeemed; the consuming registration transaction is the
claim. Reads MUST NOT release or prolong an in-use reservation. A spool decline
or any later terminal state added by a host must likewise suppress and erase
any code. These rules also cover account deletion and host administrative revoke.

## Encrypted storage and destruction (normative host requirements)

The host MUST store retrievable code material encrypted at rest under its host
KEK with an authenticated encryption algorithm (AEAD), such as AES-256-GCM or
XChaCha20-Poly1305. Use a fresh cryptographically random nonce as required by
the selected algorithm and persist the algorithm/version and KEK identifier
with the ciphertext. Plaintext storage, deterministic nonces, unencrypted
operation retry bodies and logging response bodies are forbidden.

AEAD associated data MUST bind a versioned invitation-code purpose (distinct
`signup-invitation-code-v1` and `spool-invitation-code-v1` domains), deployment
identity, the complete stable invitation reference (including spool ID when
present) and immutable creator account subject. Use an unambiguous canonical
encoding, for example length-prefixed UTF-8 components; never concatenate
ambiguous strings, use mutable handles or omit the purpose. Verify all bindings
against the authoritative row before releasing plaintext. A key rotation
rewrap/re-encrypt MUST preserve code bytes, bindings and expiry and must never
recreate erased code material. Failure to authenticate ciphertext is a
secret-free internal failure, never a fallback that mints or exposes a code.

Redemption MUST independently verify a stored cryptographic hash of the
high-entropy original secret, using constant-time comparison, and enforce
current lifecycle and reservation rules. Retrievability does not replace this
verification path. Persist the encrypted code and its verification hash with
the invitation's creator and expiry in the creation transaction.

The ciphertext MUST be destroyed in the redeem/revoke transaction and upon
expiry. Expiry requires scheduled cleanup at the expiry boundary; a read also
checks current time and removes expired material without disclosing it, so a
delayed worker cannot permit a late read. Destruction includes recoverable code
copies in caches, idempotency response storage and delivery/outbox payloads;
keep only secret-free metadata and any hash needed for non-disclosing status
resolution. Creation retries after a terminal transition MUST NOT replay a
saved plaintext or encrypted code. Backup/restore policy MUST account for
erasure and MUST scrub terminal/expired ciphertext before serving restored
data. Shared host KEK encryption alone is not per-invitation cryptographic
erasure. Historical backup copies must never reopen a terminal invitation.

Security position: a **DB + KEK compromise exposes pending codes**, which the
owner accepts. Their usefulness is bounded by expiry and terminal-state
redemption checks. Encryption protects a database-only disclosure while the
KEK stays separate. No claim of secrecy from a compromised host or creator is
made. Ciphertext destruction does not erase previously copied client links.

## Rate limits, audit and transport (normative host requirements)

The host MUST enforce both a caller-account limit shared across the two RPCs
(default 30 attempts per rolling minute) and a caller-plus-invitation limit
(default 10 attempts per rolling minute), plus a deployment-wide abuse budget.
Hosts may configure tighter limits. Count successful, empty, denied and unknown
reads before decryption; never let invite-ID rotation bypass the account limit.
Return `RESOURCE_EXHAUSTED` with a retry delay and no code, without revealing
whether the invitation exists. These are pacing limits, not a lifetime copy
allowance. Authentication and ordinary credential revocation still apply.

Every authenticated attempt MUST produce a protected audit entry containing
method, authenticated caller subject, requested stable reference, server time,
request correlation and outcome (returned, empty, denied, throttled or internal
failure). Audit delivery MUST be secured before plaintext is released; audit
failure must fail closed. Audit never contains code bytes, a hash of them,
ciphertext, KEK material, full links or response bodies. Anonymous authentication
failures use the host's normal authentication audit without inventing a subject.

Reads are domain read-only and safely retryable; security audit and expired
ciphertext cleanup are operational obligations. Transport adapters MUST prevent
caching of these responses (`Cache-Control: no-store` for HTTP), redact them
from tracing/error reports, and avoid placing code material in paths or queries.
Neither a retry nor an observation cache may retain returned secrets. Client
copy surfaces request this RPC on demand and keep returned bytes out of shared
account/spool view state and durable local caches.

## API conformance boundary

Rust `v2::invitation_code` and TypeScript `v2/invitation-code` validate the two
response types against trusted caller/creator subjects, lifecycle and current
time; the spool validator also requires the host-loaded current inviter role.
They reject demoted spool creators, non-creators even for empty responses and nonempty
terminal responses; malformed/missing expiry also fails validation. Hosts map
unknown/non-creator reads to `NOT_FOUND`, and map missing/invalid legacy expiry
to empty without calling the known-valid-state response validator. Client
validation is an additional disclosure check, not a source of authority.

`tests/fixtures/invitation-code-reads.json` supplies identical Rust/TS vectors
and protobuf response bytes. Descriptor walks cover all service outputs,
including nested lists, observations, inbox and receipts; only top-level create
and creator-read responses may expose codes. This repository contains API types
and validators, not a host database or service implementation. Hosts must add
transactional encryption/deletion, AEAD substitution, rate-limit/audit and
concurrent lifecycle integration tests when implementing these contracts.

## Alpha.38 lifecycle integration

Spool invitations use `InvitationRecord.state: InvitationState`; the retired
`redeemed`/`revoked` boolean fields remain reserved. Only PENDING EMAIL
invitations with original retrievable material can return a nonempty code.
ACCEPTED, DECLINED, REVOKED and EXPIRED states are terminal; unspecified or
unknown states suppress disclosure too. Handle/account invitations and missing
recipient arms never have retrievable codes and MUST return empty for their
creator. Terminal transitions, including acceptance/decline, MUST destroy any
retrievable material in the same transaction. Signup invitations retain their
separate redeemed/revoked flags. The shared state vectors and mutation probes
cover these rules in both languages, independently of the wall-clock expiry
check. No alpha.38 reserved field is restored by this release.
