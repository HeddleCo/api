# ADR: Store the review cursor in `WorkflowService`

- Status: Proposed
- Date: 2026-07-31
- Scope: contract and storage design only
- Consumer: [HeddleCo/tapestry#303](https://github.com/HeddleCo/tapestry/issues/303)

## Context and provenance

The 2026-07-31 Tapestry audit found no server-persisted “reviewed through this
revision” value. Its fresh-checkout basis was `api@8640e12`, `weft@abc2e28`,
and `heddle@fb9906d`; the detailed finding distinguishes state-scoped check
acknowledgements from thread approvals and leaves service ownership unresolved
([audit basis and finding](https://github.com/HeddleCo/tapestry/blob/eb1a8e43bb9897b035b043823d8b759b1433a891/docs/specs/00-heddle-backend-asks.md#L1-L41)).
Tapestry currently plans device-local memory keyed by repository, thread, and
reviewer, with a later RPC swap
([interdiff spec](https://github.com/HeddleCo/tapestry/blob/eb1a8e43bb9897b035b043823d8b759b1433a891/docs/specs/01-interdiff-review.md#L61-L65)).

The adjacent primitives do not already provide this value:

- `ReviewCheckAck` is signed, state-scoped evidence keyed by actor, check kind,
  and file or signal reference. `GetReviewProgress` starts from a state, not a
  thread
  ([contract](https://github.com/HeddleCo/api/blob/8640e121bf951e1d37ce9145772da20c67cfc8ea/proto/heddle/api/v1alpha1/state_review.proto#L260-L307)).
- `ThreadApproval` is an endorsement of one source-to-target merge at a source
  head. Its `source_state` is used by the merge gate and its `expires_at` is
  policy data
  ([contract](https://github.com/HeddleCo/api/blob/8640e121bf951e1d37ce9145772da20c67cfc8ea/proto/heddle/api/v1alpha1/registry.proto#L832-L879)).

The cursor must identify a specific revision, not a count: it is the `from`
endpoint for Tapestry's interdiff. A display ordinal may change after a rewrite,
while the exact reviewed content must not.

## Decision

Add a distinct `ThreadReviewCursor` resource and its RPCs to
`WorkflowService`.

The cursor is one mutable, non-expiring row per `(repository, source thread,
reviewer)`. Its value is the exact immutable state the reviewer most recently
finished reading. It is not a check acknowledgement, signature, verdict,
approval, or merge-gate input.

This chooses structural ownership over the superficially closer review-check
semantics:

1. The resource being tracked is a thread. The state is its cursor value.
   `ThreadSummary` already supplies the thread's base and current states
   ([contract](https://github.com/HeddleCo/api/blob/8640e121bf951e1d37ce9145772da20c67cfc8ea/proto/heddle/api/v1alpha1/workflow.proto#L70-L117)).
2. A direct primary-key lookup answers “how far has reviewer R got on thread
   T?” It does not scan a row for every state or invent a secondary projection
   over check acknowledgements.
3. Approval and cursor advancement can share one service transaction. The UI
   can read the caller's cursor and the thread's approvals in one RPC.
4. Reusing `ReviewCheckAck` would overload an auditable, signed per-state check
   with aggregate mutable state. Adding an index/projection to make that cheap
   would create the cursor under another name.

Placement next to approval does **not** make the cursor an approval. It has its
own message, RPCs, table, authorization rule, and retention semantics. It has no
target thread, note, revocation, TTL, or effect on merge eligibility.

## Semantics

### Position and thread membership

`reviewed_state` is an exact state, never a revision number. For v1, a state is
eligible for advancement only when it lies on the current thread's first-parent
segment after `base_state` and through `current_state`. This matches the
audited server's thread-ref history order, which follows `first_parent()`
([Weft implementation](https://github.com/HeddleCo/weft/blob/abc2e28c852201f72492131d5ea4ff87bd0f3c05/crates/weft-hosted/src/server/hosted/canonical_repository.rs#L1287-L1321)),
while using the Workflow thread boundary rather than treating all pre-thread
ancestry as revisions.

The server returns the raw stored position plus a computed attachment:

- `ATTACHED`: the exact state is still on the current thread segment.
- `DETACHED`: the state exists but is no longer on that segment.
- `STATE_UNAVAILABLE`: the state cannot be resolved or is no longer visible.

An absent cursor means the reviewer has never advanced it.

### Monotonic multi-device writes

Advancement is server-monotonic, not last-write-wins:

- same state: idempotent no-op;
- later state on the same current segment: update;
- earlier state on that segment: no-op and return the authoritative later
  cursor;
- state outside the current segment: `FAILED_PRECONDITION`;
- attached state after a previously stored cursor became detached or
  unavailable: update, because this is the first reviewed point in the new
  lineage.

Thus a stale device cannot move another device's cursor backwards. V1 has no
reset-to-rereview operation. Resetting a UI's comparison base is a local view
choice and must not erase the durable fact that later content was read. A
future explicit review-cycle model would need a cycle identity and history;
overloading this cursor would lose information.

### Interaction with thread approval

`ApproveThread` implicitly advances the caller's cursor through
`source_state`, in the same transaction as the approval write. Endorsing a
state asserts that the approver read it. Failure to validate or advance the
cursor fails the approval transaction; an approval must not exist without that
minimum review position.

The converse is false: advancing a cursor never approves anything.

Advancing beyond an approval does not itself stale, revoke, refresh, or replace
the approval. Approval staleness remains exclusively the merge gate's
comparison of `ThreadApproval.source_state` with the source head (plus its
independent TTL). If the source head moved, that movement—not the cursor
write—is why a stale-on-update policy rejects the approval. Expiry or revocation
of an approval never rolls back or deletes the cursor.

The cursor is keyed only by the source thread. Reading a source thread for one
merge target is still reading the same content for another target; target
thread remains approval-only data.

### Writer and Biscuit scope

Only the reviewer themselves may advance v1. `reviewer_user_id` is derived from
the authenticated Biscuit and is deliberately absent from the write request.
A delegated agent may not advance its delegating human's cursor. A service or
agent principal may own a separate cursor only when it maps to its own immutable
user UUID; principal kinds without that identity are unsupported in v1.

The write requires proof of possession, a `client_operation_id`, and thread
read access: `right("thread", "<repo>/threads/<thread>", "read")`, including
that right inherited from repository read. It does **not** require repository
write, because this is caller-bound personal metadata and reviewers may be
read-only. The audited authorization vocabulary already defines canonical
thread paths and thread rights
([resource hierarchy](https://github.com/HeddleCo/weft/blob/abc2e28c852201f72492131d5ea4ff87bd0f3c05/crates/weft-authz/src/access/resource.rs#L16-L24),
[right vocabulary](https://github.com/HeddleCo/weft/blob/abc2e28c852201f72492131d5ea4ff87bd0f3c05/crates/weft-authz/src/biscuit/facts.rs#L19-L85)).
An operation-ceiling caveat must also permit `AdvanceThreadReviewCursor`.

Any thread reader may read a named reviewer's cursor, consistent with the
existing state-review progress read being repository-reader scoped
([contract](https://github.com/HeddleCo/api/blob/8640e121bf951e1d37ce9145772da20c67cfc8ea/proto/heddle/api/v1alpha1/state_review.proto#L371-L387)).

## Proposed proto

The messages belong in `workflow.proto`. `attachment` is computed at read time
and is not stored.

```protobuf
enum ReviewCursorAttachment {
  REVIEW_CURSOR_ATTACHMENT_UNSPECIFIED = 0;
  REVIEW_CURSOR_ATTACHMENT_ATTACHED = 1;
  REVIEW_CURSOR_ATTACHMENT_DETACHED = 2;
  REVIEW_CURSOR_ATTACHMENT_STATE_UNAVAILABLE = 3;
}

message ThreadReviewCursor {
  RepositoryRef repo_path = 1;
  string thread = 2;
  string reviewer_user_id = 3;
  // Exact immutable physical revision, not an ordinal or logical change id.
  StateId reviewed_state = 4;
  google.protobuf.Timestamp advanced_at = 5;
  // Biscuit session that last advanced the row, for attribution only.
  string reviewer_sid = 6;
  ReviewCursorAttachment attachment = 7;
}

message GetThreadReviewContextRequest {
  RepositoryRef repo_path = 1;
  string source_thread = 2;
  string target_thread = 3;
  // Empty means the authenticated caller.
  string reviewer_user_id = 4;
}

message ThreadReviewContext {
  // Absent when this reviewer has no cursor.
  ThreadReviewCursor cursor = 1;
  repeated ThreadApproval approvals = 2;
  StateId current_state = 3;
}

message AdvanceThreadReviewCursorRequest {
  RepositoryRef repo_path = 1;
  string thread = 2;
  StateId reviewed_state = 3;
  string client_operation_id = 4;
}

message AdvanceThreadReviewCursorResponse {
  ThreadReviewCursor cursor = 1;
  // False for an equal-state or backwards stale-device no-op.
  bool advanced = 2;
}

service WorkflowService {
  rpc GetThreadReviewContext(GetThreadReviewContextRequest)
      returns (ThreadReviewContext);
  rpc AdvanceThreadReviewCursor(AdvanceThreadReviewCursorRequest)
      returns (AdvanceThreadReviewCursorResponse);
}
```

Both RPCs use `CAPABILITY_AREA_REVIEW_DECISIONS`. The get is read-only, safe to
retry, and requires an authenticated resource reader. The advance is a durable
write with proof of possession, `RETRY_BEHAVIOR_CLIENT_OPERATION_ID`, and an
authenticated resource reader; the handler additionally binds the written
reviewer to the caller and rejects on-behalf delegation. `ApproveThread`
keeps its existing response type and gains the normative transactional side
effect described above, avoiding a breaking RPC signature change.

## Storage sketch

Resolve `RepositoryRef` to the immutable hosted repository UUID before storage.
Use the immutable user UUID already used by approval rows, not a username. The
audited approval store records `approver_user_id` and session attribution
([schema](https://github.com/HeddleCo/weft/blob/abc2e28c852201f72492131d5ea4ff87bd0f3c05/migrations/002_tenancy.sql#L131-L145)).

```sql
thread_review_cursors (
  repo_id             uuid        NOT NULL REFERENCES spools(spool_id)
                                  ON DELETE CASCADE,
  thread_name         text        NOT NULL,
  reviewer_user_id    uuid        NOT NULL REFERENCES users(id)
                                  ON DELETE CASCADE,
  reviewed_state_id   bytea       NOT NULL, -- exact 32-byte StateId
  reviewer_sid        text,
  advanced_at         timestamptz NOT NULL DEFAULT now(),
  CHECK (octet_length(reviewed_state_id) = 32),
  PRIMARY KEY (repo_id, thread_name, reviewer_user_id)
);

CREATE INDEX thread_review_cursors_by_reviewer
  ON thread_review_cursors (reviewer_user_id, repo_id, thread_name);
```

The primary key serves the single-thread context lookup and prefix scans for all
reviewers on a thread. The secondary index supports “my unread threads” without
a table scan; a bulk unread RPC is still out of scope for v1. The approval side
already has a source/target-thread lookup index
([schema](https://github.com/HeddleCo/weft/blob/abc2e28c852201f72492131d5ea4ff87bd0f3c05/migrations/002_tenancy.sql#L159-L177)),
so `GetThreadReviewContext` is two indexed reads in one server operation, not a
state-history scan.

The advance transaction takes a transaction-scoped advisory lock derived from
the complete primary key (covering the missing-row case), resolves the thread
base/head, validates the candidate against the current first-parent segment,
locks the existing cursor row, and applies the monotonic rules. The same helper runs
inside `ApproveThread`'s database transaction. `client_operation_id` provides
request retry deduplication; the keyed advisory lock provides cross-device
serialization. No `expires_at` column exists.

Rebases do not eagerly rewrite cursor rows and therefore need no state-id index.
Attachment is evaluated against the current thread when read or advanced.

## Rebase and fork behavior

A rebase replay creates a new authored physical state with a new parent while
copying the logical `change_id`
([Heddle implementation](https://github.com/HeddleCo/heddle/blob/fb9906d0658b89ead7ac14a090ddc17b9d20378c/crates/cli/src/cli/commands/rebase/rebase_ops.rs#L460-L495)).
The object model explicitly distinguishes a rewrite-stable 128-bit `ChangeId`
from a content-addressed 256-bit `StateId`
([identities](https://github.com/HeddleCo/heddle/blob/fb9906d0658b89ead7ac14a090ddc17b9d20378c/crates/object-model/src/object/hash.rs#L97-L174)).

Therefore v1 does **not** map a cursor through a rebase, even when an old and new
state share a logical change ID:

1. The stored exact old state remains the durable statement of what was read.
2. If that state still resolves but is off the rewritten thread segment, the
   cursor is returned as `DETACHED`. Tapestry may offer a clearly labelled
   old-to-new comparison because `GetCompare` accepts independently resolved
   visible states without an ancestry requirement
   ([Weft implementation](https://github.com/HeddleCo/weft/blob/abc2e28c852201f72492131d5ea4ff87bd0f3c05/crates/weft-hosted/src/server/hosted/canonical_repository.rs#L763-L788)),
   but it must not present the rewritten revision as already reviewed.
3. If the old state no longer resolves or is no longer visible, return
   `STATE_UNAVAILABLE`; the UI requires a full review of the new lineage.
4. After the reviewer reads an eligible state on the new lineage, advancement
   replaces the detached position. An old device cannot restore the old value
   because its candidate is not on the current segment.

A fork has a different thread key and starts with no cursor. V1 never copies a
cursor from the parent thread: shared ancestry is not proof that the reviewer
reviewed the fork as a unit. The original thread's cursor is unchanged.

## Consequences and rejected alternatives

- Review progress survives devices and sessions without acquiring endorsement
  or expiry semantics.
- Cursor reads are direct and approval reads remain policy-oriented.
- Approval becomes a one-way implication: approval advances review progress;
  review progress never implies approval.
- Monotonicity makes accidental “rereview reset” impossible; an explicit future
  review-cycle feature can preserve history instead of destroying it.
- `StateReviewService` check acknowledgements remain per-state evidence. A new
  `CHECK_KIND_REVIEWED` is rejected because it needs a second projection to
  answer the actual thread query and conflates append-like evidence with a
  mutable bookmark.
- Adding cursor fields to `ThreadApproval` is rejected because it would couple
  progress to target thread, TTL, revocation, and gate semantics.

## UNKNOWN — must be settled before implementation

1. **Exact wire identity is inconsistent in the audited producer.** The API has
   distinct `StateId` and `ChangeId` messages
   ([contract](https://github.com/HeddleCo/api/blob/8640e121bf951e1d37ce9145772da20c67cfc8ea/proto/heddle/api/v1alpha1/types.proto#L76-L90)),
   but the pinned Weft adapter populates `StateSummary.state_id` from
   `state.change_id` and then repeats the same bytes in `change_id`
   ([producer](https://github.com/HeddleCo/weft/blob/abc2e28c852201f72492131d5ea4ff87bd0f3c05/crates/weft-hosted/src/server/hosted/canonical_repository.rs#L436-L480)).
   The proto above is safe only if `reviewed_state` is the immutable physical
   state. The API and Weft owners must settle whether the producer is wrong or
   `StateId` is intentionally an alias. A conformance test proving that wire
   `StateId` changes while wire `ChangeId` remains stable across rebase would
   settle it; the same decision must cover `ThreadApproval.source_state` before
   approval can advance a cursor safely. If `StateId` must remain logical, the
   cursor needs an explicit immutable `revision_address` instead; the contract
   already uses such an address for native and Git-overlay refs
   ([contract](https://github.com/HeddleCo/api/blob/8640e121bf951e1d37ce9145772da20c67cfc8ea/proto/heddle/api/v1alpha1/types.proto#L5-L11)).
2. **Thread rename identity is not specified.** The public workflow model keys
   a thread by `name` and exposes no immutable thread ID
   ([contract](https://github.com/HeddleCo/api/blob/8640e121bf951e1d37ce9145772da20c67cfc8ea/proto/heddle/api/v1alpha1/workflow.proto#L70-L83)).
   The Workflow owner must state either that names are immutable in v1 or that a
   rename transaction moves cursor rows. If rename must preserve identity
   across systems, an immutable thread ID is required before freezing the
   storage key.

## Out of scope for v1

- implementation, migrations, generated clients, or the Tapestry RPC swap;
- backward cursor movement, manual reset, review cycles, or cursor history;
- an agent advancing a human's cursor, delegated writes, or cursor principals
  without their own immutable user UUID;
- cursor inheritance or automatic remapping across fork, rebase, squash, or
  logical-change succession;
- per-file/per-signal acknowledgement changes, signatures, verdicts, approval
  policy, approval TTL, or merge-gate changes beyond implicit advancement;
- batch cursor reads, unread feed aggregation, notifications, or revision
  numbering;
- a new thread-revision enumeration endpoint or cross-repository cursors.

## Document location

This repository has no numbered ADR directory at the audited API commit. Its
existing design note is a flat document under `docs/`
([example](https://github.com/HeddleCo/api/blob/8640e121bf951e1d37ce9145772da20c67cfc8ea/docs/operation-cutover.md#L1-L14)),
so this ADR follows that convention as `docs/review-cursor.md` rather than
creating a new hierarchy or numbering scheme.
