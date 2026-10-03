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

The [owner decisions on PR #302](https://github.com/HeddleCo/api/pull/302#issuecomment-5957524845)
are accepted and govern this contract. None weakens the retained-old-guardian rule.

1. **Delay:** preserve the current signed policy's nonzero window, default seven
   days. Begin the clock at successful email-proof admission and durable first
   notification, not at an unauthenticated begin. Do not allow an attempt to
   shorten it. Changing the policy window uses the existing owner-authorized
   policy transition and its old window.
2. **Co-signing initiative:** require a fresh proposed-root request proof for
   `PrepareCustodialRecover` after the window. Weft must not autonomously
   co-sign, complete, or choose the replacement root because a timer fired.
3. **Veto and signature release:** allow current-root veto until completion
   commits, including after preparation. Preparation releases no W0 authorization.
   W0 signs privately only under the final account/attempt lock after all gates
   pass. Release the completed signed history only after commit; veto, expiry
   and rollback after signing never expose W0's signature. A veto that commits
   first therefore prevents a portable Recover assembled from the prepared result.
4. **Paper plus custody:** retain one paper-kit product ceremony and explicit
   opt-in. The present verifier supports one active custodial 1-of-1 policy or
   a noncustodial threshold policy; it rejects a 1-of-1 PAPER policy and a
   threshold-one PAPER/WEFT union. Offer custody as an explicitly
   selected active policy, with fresh paper recovery policy required on opt-out.
   One kit can encode multiple paper guardians, as the existing ceremony does.
   Simultaneous independent 1-of-1 paper and custody paths require a separately
   approved verifier change. Never silently pretend a retired kit still works.
5. **Lifetimes and limits:** email challenge lasts 15 minutes; a verified attempt
   expires 24 hours after eligibility; at most one email-verified pending attempt
   per account. Begun attempts must not occupy that slot. These bounds and the
   rate limits below are service defaults under the accepted owner decisions.

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
   `valid_from = eligible_at`, overlap zero and a random 32-byte nonce. Only W1
   signs the body as possession proof; W0 authorization remains absent.
   Persist one immutable proposal and custody reservation atomically. Retries
   return exactly that proposal and do not mint more keys or refresh deadlines.
5. The response has the immutable body, W1 possession proof, canonical bytes
   and SHA-256 signing digest, plus the exact admitted owner history needed to
   check it. Both W0 authorization and the next-authority proof are absent.
   The client independently verifies the history, all fields, fresh policy,
   W1 proof and canonical digest. It adds only R1's `next_authority_key_proof`;
   it does not sign protobuf bytes or change the body or W1 proof. Even after
   locally adding R1's proof, this result cannot satisfy the old-policy threshold.
6. `SubmitCustodialRecover` includes the exact attempt reference/version, prepared
   body and W1 proof plus R1's proof, with a fresh R1 request proof. Authorizations
   must remain empty. Under the final account/attempt lock recheck veto, time,
   expiry, tip, email/consent and proposal equality. Obtain/add W0's authorization
   privately, then invoke the published `apply_transition_with_timelock` with
   `pending_since = started_at`. Commit the owner transition, W1 activation,
   logical W0 retirement and attempt completion atomically; invalidate competing
   attempts/old authority credentials. Buffer all private signing results behind
   this commit boundary. A failed verification, CAS or commit discards them and
   returns no signed candidate, including through errors, logs or retry caches.
   Release the completed signed OwnerState and receipt only after commit, with
   **no credential or access grant**. Further credential enrollment proves its
   own key through existing contracts.

All state-changing RPCs have a nonempty client operation ID (1..128 UTF-8 bytes).
Idempotency is scoped to method, proved key and attempt (begin: selector and key),
and retains a hash of the exact request. Same ID/different bytes conflicts.
Exact completed retries return only the already committed history and original
receipt under fresh authorization by the original R1, without another signature
or mutation. Failed/rolled-back retries never return a private signing result.
Preparation changes the version and returns it in `proposal.recovery`; submission must use that returned version. A failed
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
| SubmitRecoveryProof.custodial_email | R1 request PoP AND exact unexpired binding/token. | 5 tries/attempt lifetime; 10/source/hour; lock challenge on exhaustion; secret exactly32, binding exactly108 canonical bytes. | Consumption or rejection reason, captured tip, window, notification outbox ID. |
| GetCustodialRecoveryAttempt | Public; request PoP by this attempt's R1 or separately verified current root. Wrong key/missing ref are existence-hidden. | 6/attempt/minute, 60/source/minute; single record, no listing or secrets. | Bounded access log keyed to attempt and proof key; no durable mutation. |
| PrepareCustodialRecover | R1 request PoP; exact version, email admitted, window elapsed, still opted in/current tip. | 3/attempt/hour, 10/account/day; one immutable proposal per attempt, one reserved fresh key. | Proposal digest, W0/W1 key IDs, W1 possession operation/reservation IDs; no W0 signing or release. |
| SubmitCustodialRecover | R1 request PoP plus R1 portable proof; exact prepared proposal; all transaction gates. | 5/attempt/hour; 1 transition, 0 client old authorizations, 1 next guardian proof; accepted retry is a no-op. | Committed Recover, old/new tips, W0 signing and key retirement/activation IDs, receipt and commit time. |
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
is InvalidArgument. Independently authenticated current owners retain their
owner-authorized view/veto channel. Before factor admission the shared
`SubmitRecoveryProof` method and all custody RPCs use existence `HIDE`:

- Begin issues the same bounded EMAIL_PENDING record for real, synthetic,
  opted-out and missing accounts; only email delivery differs. Get with that
  attempt's proved R1 returns the same pre-factor shape, without owner history,
  email, opt-in status or a pending-slot distinction. Missing attempt references
  and unproved/wrong keys return the same Unauthenticated envelope.
- Request-key resolution and PoP checking use the same lookup and verification
  work for real and synthetic records. Missing/opted-out records take the same
  bounded lookup path; neither the key lookup nor its failure can disclose the
  selected account. Never substitute a session key or treat a proposed key as
  a current owner for veto.
- Invalid factor probes normalize bad binding/token, missing attempts,
  consumed/expired challenges and exhausted challenge guesses to the same
  Unauthenticated code, message, details and timing class. Include no
  state-specific retry hint. Pre-factor prepare/submit/veto probes with no
  admitted factor or independently verified current root use that same failure;
  they return no partial proposal, history or W0 authorization.
- Apply equal source/key/selector/attempt quotas, including synthetic records
  and missing references. General rate limits may return the standard uniform
  retry hint only at identical public quota boundaries, independent of existence
  or private challenge state. Charge reserved owner-veto quota only after current
  owner authentication; unauthenticated traffic cannot exhaust it.
- A deployment-wide unsupported-feature FailedPrecondition is uniform across
  every selected account and attempt, including the shared proof arm. It must
  never depend on account existence, opt-in or whether the attempt is real.

Weft must compare the full sequence begin -> get -> invalid proof -> get ->
prepare -> submit -> veto across real/synthetic/opted-out/missing records, with
fresh, consumed, expired and exhausted challenges and valid/wrong request keys.
Compare status, message/details, record shape, quota charges, retry hints and
response timing, not begin alone. Only proof of the actual bound factor (or
independent current-owner authorization) permits detailed state errors.
Audit retention follows the existing security-audit policy; log structured IDs,
digests and verdicts, never tokens, email addresses, private signing candidates,
key material or credentials.

## Custody lifecycle and threats

W0/W1 are per-account recovery-only Ed25519 keys held by an isolated KMS/HSM.
They cannot sign capabilities, spool operations, owner roots as authority keys,
or arbitrary caller-supplied bytes. The signer validates the captured account
tip, pending attempt and exact canonical Recover independently of the HTTP
handler. The enrollment signer separately permits guardian possession proofs
and authorized policy changes needed for opt-in/out; it never signs those
records as the owner authority. Separate email-delivery, state-admission and signing permissions.
The reviewed versioned custody warning and digest gate remain mandatory.

Lifecycle: `reserved -> active -> retired -> destroyed`; a key is active only
if named in the committed current policy. Persist the HSM reservation and W1-only proposal
before preparation returns; retries reuse them. Private W0 signing candidates
are never response or retry-cache artifacts before completion commits. Crashes reconcile reservations against the
durable owner tip; uncertain state fails closed. On CAS failure/veto/expiry,
destroy an unused W1; on completion retire W0 atomically with owner CAS and
schedule secure destruction. Keep public keys/signatures for history. Restoring
backups never reactivates a retired key. Operational rewrapping of an active HSM
key does not change its public identity or substitute for fresh recovery keys.

Email compromise can satisfy the factor and both explicit R1 requests: those
requests prove intent/possession, not an additional factor. The nonzero delay,
current-root notifications and veto are the defenses. Independently notify enrolled devices
and existing account channels so an attacker controlling email cannot suppress
every warning. An owner with an accessible current root can veto until completion
commits, preventing W0 release. An offline owner, lost root or unusable alert
leaves a patient mailbox holder able to recover at eligibility; outbox intent
is not proof of delivery or observation. A stolen delegated/session key cannot
veto, while a stolen usable current-owner private key already has owner authority
and can veto legitimate recovery. The protocol cannot distinguish two holders
of that same private key. Delivery outages never shorten the window or trigger
fallback. These accepted policy limits remain in the custody warning.
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
carriers, immutable W1-only proposals and structural admission gates. The helper
matrix covers missing/empty/wrong-kind next policies, missing/wrong-signer W1
proofs, W1 equal to W0 or R1, absent/malformed R1 proof, attempts after veto or
expiry, unknown state, fixed widths, zero/overflowing windows and timestamp
addition. Raw proof vectors cover every pair of tags 3/4/5 in both orders and
repeated same-arm tags. The bounded checked decoders reject those original bytes
before ordinary protobuf decoding discards an arm. Already-decoded helpers do
not enforce other RPC byte ceilings; Weft must enforce them before decoding.

The additive Rust `v2::custodial_recovery` and TypeScript
`@heddleco/api/v2/custodial-recovery` helpers encode the email intent, derive the
stored secret hash, recompute the restricted canonical Recover body/digest,
and check structural prerequisites. They do not verify email delivery/secret
equality, request proofs, owner history or Ed25519 signatures. A well-shaped
invalid signature can pass a helper; it must fail the published verifier.
The caller supplies the persisted current attempt/proposal and independently
resolved old guardian; client-carried observations never become trusted state.

Run `node tests/generate-custodial-recovery-fixture.mjs` after `npm run build`
to reproduce `tests/fixtures/custodial-recovery-v1.json`. Seeds are public test
data. `completed_recover_wire_hex` is the post-commit artifact, never a prepare
response. The retained-W0 vector has a recomputed canonical digest, valid W0
authorization, R1 proof and W0 next-guardian proof, and a corresponding W0-only
persisted proposal for helper isolation.

`cargo test --locked --manifest-path tests/custodial-verifier/Cargo.toml`
runs the committed harness pinned to published capability-verifier 0.28.7
and its exact published API dependency, 0.31.0-alpha.19. The published API
types remain isolated from the checkout contract crate. It asserts the exact retained-policy
error, missing/empty/wrong-kind policy errors, missing/wrong/invalid W1 proof,
W1 equal to R1, insufficient/invalid old authorization, missing/invalid R1 proof,
and zero old-authority overlap. A fully signed backdated `valid_from` succeeds
as portable history at `now >= valid_from` but fails trusted-start timelock
admission. There is no second verifier implementation. `tools/verify.sh` runs
this harness alongside API and TypeScript conformance.

The release scenarios represent prepare followed by winning veto, expiry,
rollback after private signing and both submit/veto commit orderings. Using only
the returned proposal and R1 seed, the published portable verifier rejects the
client-assembled Recover for missing old-policy authorization, regardless of
hosted state errors. The completion-first fixture is portable and terminal.
These are API boundary fixtures, not a Weft transaction or timing-equivalence
implementation. Weft's host suite must inject failure after W0 signing/before
commit, capture all response/error/retry-cache paths, and race actual submit/veto
transactions under their shared lock. Veto-first, expiry and rollback must expose
no W0 authorization; submit-first may return only the committed history under
original-R1 retry authorization. It must also test durable secret consumption,
email-version supersession, exact retry binding, notification intent, quotas,
the full pre-factor probe sequence above, stricter raw/history bounds, key
retirement/cleanup and backup restoration. These gates accompany weft#1521/#1527
before custody is available. The reflection suite checks the shared proof RPC's
HIDE metadata as well as the five custody RPCs.
