# Custodial recovery signing

Status: proposed design and additive contract for [api#301](https://github.com/HeddleCo/api/issues/301).
Implementations follow in Weft, then Tapestry. Compiled RPCs do not advertise
support: custody stays unavailable with typed `FailedPrecondition` until the
signer, notification outbox, transaction gates and reviewed warning are live.
No schema version bump, compatibility shim or verifier bypass is involved.

## Authority and sources

Follow Weft's [canonical identity/resource/authorization model](https://github.com/HeddleCo/weft/blob/main/docs/IDENTITY_RESOURCE_AUTHORIZATION_MODEL.md),
including its CURRENT/TARGET distinction. Email verifies a recovery factor; it
does not establish an owner, grant spool access, issue a session or promote an
agent. Account UUIDs, handles, account tiers, attribution and claims are selectors
or display data, never authority. Recovery extends the admitted owner history;
it preserves sequence zero, owner ID, account UUID and spool genesis. In
particular, this is not the agent claim ceremony in [weft#1861](https://github.com/HeddleCo/weft/issues/1861).

[weft#1521](https://github.com/HeddleCo/weft/issues/1521) establishes explicit
opt-in, email recovery and a cancellable delay.
[weft#1527](https://github.com/HeddleCo/weft/issues/1527) requires atomic retirement
of used recovery authority. [heddle#1952](https://github.com/HeddleCo/heddle/pull/1952)
and `crates/capability-verifier/src/owner.rs` on fetched main require Recover to
carry a next policy and all next-guardian possession proofs, with the retained
old guardian count below the next threshold. For old policy `{W0}, threshold=1`,
the next policy must therefore be `{W1}, threshold=1`, with `W1 != W0`.
The Recover has zero old-authority overlap and preserves the effective signed
`window_secs`. The default is 604800 seconds.

## OWNER DECISIONS

Recommendations below are used throughout this proposed contract; owner review
is pending. None weakens the retained-old-guardian rule.

1. **Delay:** preserve the current signed policy's nonzero window, default seven
   days. Begin the clock at successful email-proof admission and durable first
   notification, not at an unauthenticated begin. Do not allow an attempt to
   shorten it. Changing the policy window uses the existing owner-authorized
   policy transition and its old window.
2. **Co-signing initiative:** require a fresh proposed-root request proof for
   `PrepareCustodialRecover` after the window. Weft must not autonomously
   co-sign, complete, or choose the replacement root because a timer fired.
3. **Veto and signature release:** allow current-root veto until hosted completion,
   including after preparation, but guarantee prevention of portable signature
   release only until preparation wins its transaction. An already released
   signature cannot be cryptographically recalled. Offline consumers must verify
   current admitted history; an offline fork remains a residual custody risk.
   A longer cancellable period after release needs a new verifier protocol,
   not an assertion that email or hosted status can revoke portable signatures.
4. **Paper plus custody:** retain one paper-kit product ceremony and explicit
   opt-in. The present verifier supports one active custodial 1-of-1 policy or
   a noncustodial threshold policy; it rejects a 1-of-1 PAPER policy and a
   threshold-one PAPER/WEFT union. Recommend offering custody as an explicitly
   selected active policy, with fresh paper recovery policy required on opt-out.
   One kit can encode multiple paper guardians, as the existing ceremony does.
   Simultaneous independent 1-of-1 paper and custody paths require a separately
   approved verifier change. Never silently pretend a retired kit still works.
5. **Lifetimes and limits:** email challenge lasts 15 minutes; a verified attempt
   expires 24 hours after eligibility; at most one email-verified pending attempt
   per account. Begun attempts must not occupy that slot. These bounds and the
   rate limits below are recommended service defaults, subject to owner review.

## Flow and state machine

The client generates a fresh Ed25519 root R1 locally. It proves possession on
every requester RPC with the exact Tier-1 CallContext request proof, even before
R1 has an account credential. This public exception proves only the selected
key and this ceremony, using `principal:device-key:<lowercase-hex-R1>`; no
account session is inferred from it. Invalid supplied credentials fail closed.

1. `BeginCustodialRecovery` selects an account by immutable UUID and R1. The host
   creates a random attempt UUID and 32-byte challenge. Its binding contains the
   account UUID, attempt UUID, R1 and challenge expiry. A random 32-byte email
   secret is delivered only to the account's **already verified** address. The
   response contains no email address, secret or owner history. Unknown,
   opted-out and ineligible accounts receive indistinguishable synthetic
   challenge/attempt records and response timing. Only delivery differs.
2. `SubmitRecoveryProof.custodial_email` carries that exact binding and secret,
   with R1's request proof. Compare the canonical binding with the stored one,
   constant-time check the stored domain-separated secret hash, verify expiry,
   and recheck the verified-email row/version and current custody consent.
   A signup email reservation, OAuth claim, session or proof from another
   attempt is insufficient. Consume the secret atomically. Capture the current
   owner tip, old custodial guardian ID and effective window. Commit the pending
   attempt plus first-notification outbox intent in one transaction, or reject.
   Set `started_at` to that commit's server time and `eligible_at = started_at +
   window`; overflow and zero windows reject. Set expiry to eligibility + 24h.
3. The root observes the warning/attempt through authenticated identity views or
   notification and can veto. The recovering client polls `GetCustodialRecoveryAttempt`.
   `EMAIL_PENDING -> TIME_LOCKED -> READY` is server-time driven; READY confers
   no authority. `VETOED`, `EXPIRED`, `SUPERSEDED`, and `COMPLETED` are terminal.
   Any intervening owner-tip/policy/email/consent change supersedes the attempt;
   its window never carries forward to another attempt or root.
4. After eligibility, `PrepareCustodialRecover` checks the exact attempt version
   and current tip under the account lock. Mint a fresh, account-scoped W1 in
   custody, never a previously used, pending or retired guardian key. Construct
   one canonical Recover with previous hash/sequence from the captured tip,
   next root R1, next policy `{W1}, threshold=1`, unchanged effective window,
   `valid_from = eligible_at`, overlap zero and a random 32-byte nonce. W0 signs
   the normal transition body; W1 signs the same body as possession proof.
   Persist one immutable proposal and custody reservation atomically. Retries
   return exactly that proposal and do not mint more keys or refresh deadlines.
5. The response has the typed `SignedOwnerKeyTransition`, canonical transition
   body and SHA-256 signing digest, plus the exact admitted owner history needed
   to check it. The next-authority proof is absent. The client independently
   verifies the history, all fields, fresh policy, W0 signature, W1 proof and
   canonical digest. It adds only R1's `next_authority_key_proof`; it does not
   sign protobuf bytes or change the body or other signatures.
6. `SubmitCustodialRecover` includes the exact attempt reference/version and the
   now fully signed Recover, with a fresh R1 request proof. Under the same
   account lock recheck veto, time, expiry, tip, email/consent and proposal
   equality. Use the shared verifier's `apply_transition_with_timelock`, with
   `pending_since = started_at`; do not invent a separate acceptance rule.
   Atomic completion appends the transition, activates W1, retires W0, closes
   the attempt and invalidates competing attempts/old authority credentials.
   Return the accepted OwnerState and receipt, **no credential or access grant**.
   Further credential enrollment proves its own key through existing contracts.

All state-changing RPCs have a nonempty client operation ID (1..128 UTF-8 bytes).
Idempotency is scoped to method, proved key and attempt (begin: selector and key),
and retains a hash of the exact request. Same ID/different bytes conflicts.
Exact completed retries return the original receipt without a second mutation;
fresh proofs are still required. Preparation changes the version and returns it
in `proposal.recovery`; submission must use that returned version. A failed
veto does not fall back to email-secret veto or a session-authorized operation.

## Messages, RPC authorization, bounds and audit

`CustodialEmailBinding` is a version-1 canonical intent. Integers are big endian;
UUIDs, keys and challenge have fixed widths, not counted fields. In field order:
u32 version, raw16 account, raw16 attempt, raw32 R1, raw32 challenge, i64 expiry.
An email token is an opaque 32-byte random secret, **not a signed authority**.
Store only `SHA256("heddle-custodial-email-secret-v1" || canonical_binding || token)`.
Never log request bodies containing it. `SubmitRecoveryProof` gains a distinct
typed `custodial_email` proof arm; it is never reinterpreted as paper unlock or a
portable transition. Reject raw proof messages with multiple oneof arms before
protobuf last-wins decoding, as with the existing authority proof contracts.

`RecoveryAttempt.custodial` adds this binding, state, started/expiry timestamps
and captured owner tip. Before email proof the captured tip is empty. Existing
eligible/vetoed/completed fields agree with the custodial state. Unknown or zero
states reject mutations; absent custody details cannot enter this workflow.
An attempt version is 32 bytes; references are UUIDs with no spool. Timestamps
are whole positive Unix seconds. All messages are bounded before decoding:
begin/get/veto 8 KiB, proof 8 KiB, prepare/submit and response 512 KiB (including
bounded owner history, subject to any stricter shared-verifier limits).

| RPC/message | Authorization | Recommended rate/bounds | Durable audit |
| --- | --- | --- | --- |
| BeginCustodialRecovery | Public; exact request PoP by proposed R1. Only existing verified email may receive delivery. | 3/account/hour, 10/source/hour, 3/key/hour; UUID selector and 32-byte R1; synthetic accounts consume equal quotas. | Attempt/selector hash, proved key, delivery intent, outcome; no token/email. |
| SubmitRecoveryProof.custodial_email | R1 request PoP AND exact unexpired binding/token. | 5 tries/attempt lifetime; 10/source/hour; lock challenge on exhaustion; secret exactly32, binding exactly132 canonical bytes. | Consumption or rejection reason, captured tip, window, notification outbox ID. |
| GetCustodialRecoveryAttempt | Public; request PoP by this attempt's R1 or separately verified current root. Wrong key/missing ref are existence-hidden. | 6/attempt/minute, 60/source/minute; single record, no listing or secrets. | Bounded access log keyed to attempt and proof key; no durable mutation. |
| PrepareCustodialRecover | R1 request PoP; exact version, email admitted, window elapsed, still opted in/current tip. | 3/attempt/hour, 10/account/day; one immutable proposal per attempt, one reserved fresh key. | Proposal digest, W0/W1 key IDs, HSM operation/reservation IDs, release timestamp. |
| SubmitCustodialRecover | R1 request PoP plus R1 portable proof; exact prepared proposal; all transaction gates. | 5/attempt/hour; 1 transition, 1 old authorization, 1 next guardian proof; accepted retry is a no-op. | Original Recover, old/new tips, key retirement/activation IDs, receipt and commit time. |
| VetoCustodialRecovery | Public; current-root request PoP AND `heddle.custodial-recovery-veto.v1` SignedRecord. No agent, delegated key, attribution or email substitute. | 10/account/minute; per-source global abuse ceiling; owner veto has a reserved quota separate from recovering-client quotas. | Root key ID, attempt/version, signed reason-free veto, retirement of reservation, commit time. |

The veto SignedRecord uses existing `identity_management::recovery_action` with
account UUID string, operation ID, exact attempt reference/version and proposed
R1, in its new distinct domain. It must be signed by the independently resolved
current root. CAS mismatch changes nothing: refetch and sign again. A successful
veto is terminal, invalidates email proof/proposal admission and destroys any
unused W1 reservation. Veto and submit use the same account/attempt lock: the
first committing operation wins; a veto already committed always denies submit.
Source limits include a global service ceiling against distributed flooding;
rate-limit responses use the standard typed failure/retry hint.

After factor admission, wrong version is Conflict; early prepare/submit or a
vetoed/expired/superseded attempt is FailedPrecondition; malformed/oversized input
is InvalidArgument. Before factor admission, missing account/opt-in and bad
binding/token are indistinguishable Unauthenticated outcomes. Request PoP failures
are Unauthenticated. No failure returns a partial proposal or fresh-key secret.
Audit retention follows the existing security-audit policy; log structured IDs,
digests and verdicts, never tokens, email addresses, key material or credentials.

## Custody lifecycle and threats

W0/W1 are per-account recovery-only Ed25519 keys held by an isolated KMS/HSM.
They cannot sign capabilities, spool operations, owner roots as authority keys,
or arbitrary caller-supplied bytes. The signer validates the captured account
tip, pending attempt and exact canonical Recover independently of the HTTP
handler. Separate email-delivery, state-admission and signing permissions.
The reviewed versioned custody warning and digest gate remain mandatory.

Lifecycle: `reserved -> active -> retired -> destroyed`; a key is active only
if named in the committed current policy. Persist HSM reservation and proposal
before release; retries reuse them. Crashes reconcile reservations against the
durable owner tip; uncertain state fails closed. On CAS failure/veto/expiry,
destroy an unused W1; on completion retire W0 atomically with owner CAS and
schedule secure destruction. Keep public keys/signatures for history. Restoring
backups never reactivates a retired key. Operational rewrapping of an active HSM
key does not change its public identity or substitute for fresh recovery keys.

Email compromise can satisfy the factor: the nonzero delay, current-root
notifications and veto are the defenses. Independently notify enrolled devices
and existing account channels so an attacker controlling email cannot suppress
every warning. Delivery outages never shorten the window or trigger fallback.
Weft compromise remains a custody risk: an attacker controlling the one guardian
can produce a portable Recover. Key isolation, narrow signer admission and
honest warning text bound this risk; email is not an offline verifier rule.

Replay across attempts fails through UUID/challenge/R1/expiry binding and secret
consumption. Fixation fails because the client owns R1, creates its local intent
and checks the entire binding before opening email; links display the account
and R1 fingerprint and never auto-submit or change the selected key. The email
link carries no authority beyond its one challenge. Changing the verified email
requires the existing account authorization and supersedes pending attempts.
Clock uncertainty, notification-transaction failure, lost custody keys, unknown
states, stale history and unavailable verifiers all deny; none selects a shim.

## Paper path and opt-in/out

Paper Recover remains client-produced normal guardian evidence, with the same
nonzero window, mandatory next policy/proofs and atomic spent-key retirement.
Custodial email is never accepted as a paper factor, nor is an unavailable
custodial signer replaced by paper without explicit selection and valid proofs.
New kit secrets stay client-side. This contract adds no paper-code writer or
revives the dead v2 paper-code storage path called out in weft#1527.

Opt-in is an explicit owner-authorized recovery-policy change (or reviewed
registration selection), including warning consent, W0 possession and the
existing current-authority/guardian approvals. Weft#1521 must provide the actual
enrollment signer and consent gate before this path is offered. Account metadata
cannot opt in. Opt-out installs a verified noncustodial policy with fresh paper
guardians and all normal approvals; commit supersedes attempts and retires
custodial keys. It does not simply delete a method and leave no recovery policy.
Policy changes honor the old veto window. A custodial Recover preserves opt-in
and window while replacing W0 with W1; it does not renew consent or enlarge scope.

## Conformance boundary

Shared Rust/TypeScript vectors exercise canonical email bindings, typed wire
carriers, immutable proposals and admission gates. Required negatives: another
attempt's email proof, missing fresh guardian/proof, early submit and vetoed
submit. These are contract checks, not evidence of shipped Weft transactions,
notification delivery or HSM deletion. Those implementation tests must accompany
weft#1521/#1527. Portable signatures continue to use the shared verifier's
canonical transition digest, never a custody-specific transition signature.
