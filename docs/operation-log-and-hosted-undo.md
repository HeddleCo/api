# ADR: A hosted lifecycle operation log with non-destructive thread undo

- Status: Proposed
- Date: 2026-08-01
- Scope: contract and storage design only
- Consumer: [HeddleCo/tapestry#308](https://github.com/HeddleCo/tapestry/issues/308)

## Context and provenance

The source ask is the 2026-08-01 addendum to Tapestry's backend audit: add a
queryable repository/thread lifecycle log with stable IDs and add hosted undo
for thread lifecycle
([fresh Tapestry checkout](https://github.com/HeddleCo/tapestry/blob/de3ae83c12fba56b8450313bb826f9c1acc8be9a/docs/specs/00-heddle-backend-asks.md#L213-L236)).
This ADR designs them together. Undo addresses an operation assigned by the
log; there is no undo-only addressing scheme.

Fresh-checkout basis, read 2026-08-01:

- `HeddleCo/api@334170c9c9bca8b7f41b0b6329c20bb5c081eee9`;
- `HeddleCo/tapestry@de3ae83c12fba56b8450313bb826f9c1acc8be9a`
  on `claude/heddle-vcs-research-a8ff40`;
- `HeddleCo/weft@3c4f9c6d952104430fb168826627795d5b3d7944`;
- `HeddleCo/heddle@84e4a3a52d3aa859cd3a4c4304921cee85402df0`.

The recent review-cursor ADR is the relevant design precedent. It chose a
first-class cursor owned by the structural resource rather than overloading a
nearby record type, and it identified immutable physical state and immutable
thread identity as prerequisites
([API ADR](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/docs/review-cursor.md#L30-L61),
[unresolved identities at the time](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/docs/review-cursor.md#L303-L326)).
API #70 has since defined `StateId` as the immutable 32-byte physical revision
and added immutable `thread_id` fields while keeping thread names renameable
([identity contract](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/proto/heddle/api/v1alpha1/types.proto#L80-L90),
[thread contract](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/proto/heddle/api/v1alpha1/workflow.proto#L70-L130)).
Those identities are the basis of this design.

## What exists today

### `ListActions` is not the lifecycle log

`ListActions` accepts the same state-addressed request as `GetState`. Its
`ActionSummary` has a string ID, before/after states, description, timestamp,
and untyped `operation_json`
([contract](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/proto/heddle/api/v1alpha1/repository.proto#L320-L332)).
The hosted handler resolves a visible state and reads the action index for that
state; the index is keyed by `(repo_id, to_state_id)`
([handler](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-hosted/src/server/hosted/canonical_repository.rs#L1360-L1420),
[index query](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-storage/src/action_index.rs#L235-L265)).
It is the existing per-state, ancestor-scoped inspection view, not a
repository-wide, thread-keyed, pageable history.

This ADR **supersedes the separate “type `ListActions.operation`” ask for the
operations timeline and undo use case**: those consumers should move to the
typed lifecycle log below. It does not silently change or remove
`ActionSummary.operation_json`. If `ListActions` remains a supported surface
for other consumers, typing or deprecating that legacy field is still separate
contract maintenance; it is not required to implement this ADR.

### `SubscribeRepoEvents` is delivery, not history

The public contract is a server stream with string event types and a numeric
`after_event_id`, not a bidirectionally pageable historical query
([contract](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/proto/heddle/api/v1alpha1/repository.proto#L641-L667)).
The native dispatcher routes only identity wait and operation watch; every
other server stream, including `SubscribeRepoEvents`, returns UNIMPLEMENTED
([dispatcher](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-hosted/src/native_dispatch.rs#L2247-L2269)).
As a public surface it is therefore live-only in shape and currently
unreachable through the native transport; it is not a supported history API.

Weft nevertheless has a durable `repo_events` table and a capability-gated
`list_since` storage method
([schema and indexes](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/migrations/003_storage.sql#L57-L72),
[history read](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-storage/src/events/pg.rs#L475-L565)).
That makes `repo_events` a useful transactional outbox and catch-up source. Its
free-form public vocabulary and one-event-at-a-time delivery shape still do not
make it the typed lifecycle authority.

### `OperationService` is LRO/job tracking

`OperationService` models queued/running/terminal work and currently has only
import and remote-sync kinds
([contract](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/proto/heddle/api/v1alpha1/operation.proto#L11-L43)).
The implementation states that operations are persisted in `import_jobs` and
maps that table directly to API snapshots
([implementation](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-hosted/src/server/hosted/operation.rs#L1-L6),
[query](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-hosted/src/server/hosted/operation.rs#L396-L417)).
`import_jobs` contains claim leases and job phases
([schema](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/migrations/004_import.sql#L51-L70)),
and re-sync deliberately reuses those job rows, leases, phases, and progress
stream
([schema note](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/migrations/004_import.sql#L545-L558)).

`ListOperations` and `CancelOperation` are routed but both handlers explicitly
return UNIMPLEMENTED
([handlers](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-hosted/src/server/hosted/operation.rs#L1314-L1341)).
The code implies cancellation can be implemented as job control: clearing or
expiring the worker lease makes its next heartbeat fail and drops the in-flight
future
([heartbeat semantics](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-workers/src/import_worker.rs#L121-L178),
[lease-fenced renewal](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-workers/src/import_worker.rs#L2309-L2336)).

Therefore **`OperationService` is not the operation-log home**. It remains
asynchronous job tracking. The lifecycle log gets a new
`OperationLogService`. API PR
[#73](https://github.com/HeddleCo/api/pull/73) is open, not landed, and adds
`ListOperationsRequest.repository`; this ADR neither edits `operation.proto`
nor competes with that filter.

### The local vocabulary and the non-destructive invariant

Weft already has a Postgres `oplog` table with JSON `op_data`, batches,
attribution, an optional UUID operation ID, and a mutable `undone` flag
([schema](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/migrations/003_storage.sql#L33-L55)).
Its backend serializes Heddle's typed `OpRecord` values into those rows and
round-trips attribution and operation IDs
([backend](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-storage/src/storage/postgres/pg_oplog.rs#L33-L96),
[append](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-storage/src/storage/postgres/pg_oplog.rs#L202-L242)).
The local enum already names snapshots, thread create/delete/update, fork,
collapse, transaction outcomes, conflict resolution, redaction, purge, remote
thread updates, visibility changes, and head updates
([base vocabulary](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/schema/src/op_record/types.rs#L85-L260),
[tail vocabulary](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/schema/src/op_record/types.rs#L261-L378)).
`ConflictResolved` now carries resolver attribution and a typed resolution mode,
so the hosted type must preserve those fields rather than regress to a string
([mode](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/schema/src/op_record/types.rs#L14-L33),
[record](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/schema/src/op_record/types.rs#L200-L211),
[Heddle #1174](https://github.com/HeddleCo/heddle/pull/1174)).

The stronger local timeline invariant is the design requirement here:

- `Undo` and `Redo` are `TimelineCursorMoveReason` values, not deletion
  operations;
- editing from a rewound position has the explicit branch reason
  `EditFromRewoundCursor`;
- undo and redo resolve adjacent targets from a retained branch, and applying a
  cursor-move record changes only the derived cursor;
- navigation rebuilds all branches and steps, then marks the active path rather
  than deleting the inactive ones.

These properties are explicit in the fresh checkout
([vocabulary](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/object-model/src/object/timeline.rs#L275-L294),
[target resolution](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/repo/src/timeline_view.rs#L386-L428),
[append and replay](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/repo/src/timeline_view.rs#L517-L528),
[cursor recording](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/repo/src/timeline_view.rs#L590-L629),
[navigation projection](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/repo/src/timeline_navigation.rs#L106-L201)).
The hosted design must preserve: **undo navigates; it does not truncate,
discard, or make the forward branch unreachable**.

The existing Postgres `undone` flag and `mark_batch_undone` methods are not
sufficient hosted semantics because they mutate stack membership without
encoding a shared cursor or branch topology
([current methods](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-storage/src/storage/postgres/pg_oplog.rs#L402-L520)).
They may remain an internal compatibility field, but the new RPCs do not expose
or toggle it.

### Agent timeline remains separate

`AgentService.ListAgentTimelineEvents` is a planned, run-keyed query over
`CanonicalTimelineOperation`
([contract](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/proto/heddle/api/v1alpha1/agent.proto#L10-L54),
[messages](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/proto/heddle/api/v1alpha1/agent.proto#L198-L214)).
Heddle defines agent timelines as adjacent metadata for tool calls, cursor
movement, branches, and captures “without becoming source history states”
([architecture](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/CONTEXT.md#L163-L176)).

That separation is intentional. An agent timeline answers “what did this run
do?” The lifecycle log answers “what durable mutation happened to this
repository/thread?” A capture can correlate the two with `agent_run_id` and
`timeline_operation_id`, but the lifecycle operation is the sole source-history
record and the agent event remains execution provenance.

## Decision

Add a new `OperationLogService` in a future `operation_log.proto`. It owns
typed, stable, repository lifecycle operations and the hosted thread-undo RPCs.

**Hosted undo is a query over the operation log followed by a mutation. It is
not its own subsystem that happens to read the log.** `PreviewThreadUndo`
queries the log and current thread cursor to produce an exact plan.
`UndoThreadOperation` atomically validates that plan, moves the same cursor,
and appends another operation to the same log.

There is one authoritative mutable lifecycle cursor per `(repository,
thread_id)`. It is **shared per thread**:

- not per user, because a personal viewing position would not undo a shared
  thread lifecycle mutation;
- not per repository, because undoing one thread must not move unrelated
  threads;
- shared among all thread viewers, because it selects the authoritative hosted
  thread position. After one writer moves it, every other viewer observes the
  new position on refresh or a future event stream.

Moving the shared cursor is a real collaborative hazard even though no history
is destroyed. The authorization and confirmation rules below treat it as a
thread write, not as harmless personal metadata.

## Lifecycle operation model

### Stable operation IDs

An operation ID is the existing API `OperationId`, whose wire contract is an
opaque 16-byte durable identity
([current type](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/proto/heddle/api/v1alpha1/types.proto#L101-L119)).
For lifecycle operations the server assigns a UUIDv7 when one logical mutation
enters its commit transaction. One atomic mutation gets one operation ID even
when it emits multiple local `OpRecord` details or affects multiple threads.
The same ID groups those details and is the address accepted by preview and
undo.

The ID is not derived from a state hash, thread name, actor, timestamp, batch
number, or `client_operation_id`. It therefore remains the identity of the
historical operation after:

- **rebase/rewrite:** the old operation and ID remain; the rewrite is a new
  operation with a new ID and explicit before/after physical states;
- **repository or thread rename:** stored effects use internal repository ID
  and immutable `thread_id` and retain the names at the time, so a rename does
  not rewrite the operation;
- **thread fork:** the source operation keeps its ID. The fork is a new
  operation and new thread ID that references the source cursor; IDs are never
  copied or reassigned.

The operation remains addressable even when it is no longer on the active
branch. That does not imply it remains eligible for undo; eligibility is a
dynamic query over the current cursor, topology, authorization, and retained
objects.

`OperationId` is also the representation used by asynchronous jobs, but the
resource domains remain distinct: `OperationService.GetOperation` looks up a
job; `OperationLogService.GetLifecycleOperation` looks up lifecycle history.
UUIDv7 generation is globally collision-resistant, and the fully qualified RPC
names prevent lookup ambiguity. A job that eventually mutates a repository can
be correlated through `initiating_job_id`; its job ID does not become the
lifecycle operation ID.

### Typed vocabulary and self-description

The public kind/detail vocabulary starts from local `OpRecord`; it does not
invent a parallel set of opaque JSON labels. The aggregate mapping is:

| Local record(s) | Lifecycle kind |
| --- | --- |
| `Snapshot`, `Checkpoint`, `GitCheckpoint` | `CAPTURE` |
| `ThreadCreate` | `THREAD_CREATED` |
| `Goto`, `ThreadUpdate`, `RemoteThreadUpdate`, applicable `HeadUpdate` | `THREAD_POINTER_MOVED` |
| `ThreadDelete`, `RemoteThreadDelete` | `THREAD_DELETED` |
| new typed immutable-ID rename record | `THREAD_RENAMED` |
| `Fork` | `THREAD_FORKED` |
| `Collapse`, `EphemeralThreadCollapse` | `THREAD_COLLAPSED` |
| `FastForward` or another atomic land | `THREAD_MERGED` |
| new typed terminal-transition record | `THREAD_ABANDONED`, `THREAD_ABORTED`, or `THREAD_SUPERSEDED` |
| `ConflictResolved` | `CONFLICT_RESOLVED` |
| `TransactionAbort` | `TRANSACTION_ABORTED` |
| `Redact`, `Purge` | `REDACTION_APPLIED`, `CONTENT_PURGED` |
| `StateVisibilitySet`, `StateVisibilityPromote` | `STATE_VISIBILITY_CHANGED` |
| new typed shared-cursor-move record | `CURSOR_UNDO` or `CURSOR_REDO` |

`TransactionCommit` is an atomic sentinel, not a user-facing operation.
Markers and the local `UndoRecoveryUpdate` ref are local implementation records
and do not independently produce lifecycle envelopes. A detached `Goto` or
`HeadUpdate` also has no hosted thread effect and is not exposed as a thread
operation.

The current `OpRecord` enum does not have terminal thread metadata, hosted
shared-cursor, or immutable-ID rename variants. Local rename is a
`ThreadCreate`/`ThreadDelete`/optional `HeadUpdate` batch and even notes that it
persists a new local thread ID
([rename path](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/cli/src/cli/commands/thread.rs#L2515-L2564));
that cannot define a hosted rename whose API `thread_id` must remain unchanged.
Those three semantic rows therefore require additive typed local records before
their public envelopes can be emitted. The service must not infer them later
from batch shape, feed prose, or current snapshots. This is a deliberate
extension of the local vocabulary, not a parallel operation vocabulary.
The proposed state-visibility detail likewise preserves Heddle's
public/internal/team-scoped/restricted/private vocabulary, including its
qualifier
([visibility type](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/object-model/src/object/visibility_tier.rs#L14-L53)).

The aggregate envelope adds information that a row-level `OpRecord` does not
currently provide: stable aggregate identity, affected immutable thread IDs,
per-thread parent/branch edges, authenticated actor subject, a sanitized
summary, before/after thread snapshots, correlation IDs, and current
undoability. Cursor-move detail reuses the local `Undo`/`Redo` reason vocabulary
because hosted multi-user cursor state has no local storage equivalent.

Every entry returned to a model or UI has:

- a typed kind and typed detail arm;
- authenticated actor subject plus explicit human/agent display attribution;
- immutable affected thread IDs and names-at-the-time;
- exact physical before/after `StateId` values when content changed;
- previous and resulting lifecycle state when metadata changed;
- a concise server-produced summary intended for selection, not parsing;
- a current `UndoAssessment` explaining eligibility or the stable refusal
  reason.

No lifecycle detail uses `google.protobuf.Struct`, JSON, or a stringly typed
kind escape hatch. A new local `OpRecord` that should be public requires an
additive enum value and typed detail arm.

### Scope, filtering, and pagination

`ListLifecycleOperations` requires one repository and optionally filters by:

- immutable thread ID (with current name as the human-facing companion);
- exact authenticated actor subject;
- inclusive lower and exclusive upper server commit time;
- one or more typed lifecycle kinds.

`occurred_at` is assigned by the server in the commit transaction, never taken
from a client clock. All supplied filters are ANDed; repeated kinds are ORed.
Results are newest first by immutable, unique repository-local sequence.
`page_size` defaults to 50 and is capped at 200. `page_token` is an opaque
authenticated keyset token containing repository ID, filter hash, and the next
sequence boundary. Changing any filter while reusing a token returns
`INVALID_ARGUMENT`. Appends cannot move or duplicate an existing page boundary.
There is no fixed 50-row terminal window and no cursorless continuation like
`GetFeedSnapshot`, whose current contract is capped at 50 with no pagination
([feed contract](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/proto/heddle/api/v1alpha1/attention.proto#L27-L34)).

### Relationship to `repo_events` and `feed_items`

The lifecycle log is the **source** for durable user-visible repository/thread
lifecycle facts. `repo_events` is its delivery/outbox projection, and
`feed_items` is a user-facing materialized projection. They are not three
sibling authorities.

For every lifecycle fact, the operation envelope, local `OpRecord` detail, and
one or more `repo_events` outbox rows commit in the same transaction; a
cursor-affecting fact also checks and updates the thread cursor there. Lifecycle
`repo_events` gain `source_operation_id` and
`thread_id`; an event kind that represents lifecycle state must point to exactly
one lifecycle operation. Operational invalidations that are not lifecycle facts
may remain event-only and never appear as lifecycle history.

The existing feed architecture listens to repo events and inserts
`feed_items`
([pipeline](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-hosted/src/feed/mod.rs#L1-L18),
[materializer](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-hosted/src/feed/materializer.rs#L1-L12)).
It already stores a unique source event ID
([write path](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-hosted/src/feed/store.rs#L187-L230)).
The projection follows `repo_events.source_operation_id`; a rolled-up feed item
uses a link table for all contributing operation IDs. Feed debounce, scoring,
resolution, expiration, or deletion never changes the lifecycle log. The log is
never reconstructed from feed rows.

`SubscribeRepoEvents` can later expose typed kind and source operation ID and
be routed by the dispatcher, but serving that stream is not required for the
historical RPC. Consumers use the log for history and events only for low
latency invalidation/catch-up.

## Hosted undo semantics

### Undo is navigation plus an appended operation

Each cursor-affecting thread mutation forms a retained branch node linked by
`parent_operation_id`; audit-only thread facts remain in the chronology without
advancing the cursor. `thread_lifecycle_cursors.cursor_operation_id` selects the
effective node for the shared thread. Cursor-move operations are appended
to the chronological log but carry explicit `from_cursor_operation_id` and
`to_cursor_operation_id`; they do not delete nodes or pretend the skipped nodes
ceased to occur.

For a normal eligible lifecycle operation, `target` must be the current cursor
node for that thread. V1 intentionally provides one-step undo, not arbitrary
seek disguised as undo:

1. preview resolves the target's parent for that thread;
2. preview identifies that one target as leaving the active path;
3. commit compares the current cursor/version with the preview;
4. commit appends a `CURSOR_UNDO` operation and moves the cursor to the target's
   parent in one transaction.

The skipped branch remains fully queryable and redoable. A later edit from the
rewound cursor creates a new child branch with reason
`EDIT_FROM_REWOUND_CURSOR`; it does not overwrite the old child. Undo is thus a
new forward log operation whose effect is pointer movement.

The undo operation is itself undoable. When the cursor is at its recorded `to`
endpoint, targeting a `CURSOR_UNDO` moves back to its `from` endpoint and
appends a `CURSOR_REDO`; preview names the operations re-entering the active
path. Targeting that redo when the cursor is at the redo's `to` endpoint moves
back again. Intervening edits must first be undone one step at a time until the
recorded endpoint is current, but they never erase the older move or either
branch. This makes every retained branch navigable through recorded cursor
moves without adding an arbitrary seek/reset RPC in v1.

### What is undoable in v1

V1 deliberately supports only operations with one affected thread, an exact
retained before snapshot, and no external or second-thread effect:

- a single-thread pointer move, including a capture/ref advance or a
  single-thread rewrite whose exact prior state is retained;
- a single-thread transition to abandoned, aborted, or superseded when the
  exact prior thread metadata is retained;
- a prior `CURSOR_UNDO` or `CURSOR_REDO` whose inverse endpoints remain
  reachable and whose recorded `to` endpoint is the current cursor.

Kind alone is not enough. An otherwise supported entry is refused when it is
not the current cursor node (or, for a cursor-move target, the cursor is not at
its recorded `to` endpoint), its before state/metadata is unavailable, a later
multi-thread boundary makes the move ambiguous, or the current cursor no longer
matches the preview.

`UndoAssessment.undoable` reports those structural/topological conditions.
`caller_can_execute` separately reports current authorization; lack of write
authority does not rewrite the historical fact that a move has a valid inverse.

### What is explicitly not undoable in v1

- repository, namespace, or spool deletion;
- thread create/delete, rename, fork, collapse, merge/land, or any operation
  affecting more than one thread;
- conflict resolution, whether standalone or atomically bundled with a capture
  (a later standalone captured pointer move may be independently undoable);
- approvals, signatures, policy/grant changes, discussions, feed state, or
  agent-run control;
- import, remote synchronization, cancellation, or any other
  `OperationService` job/external side effect;
- redaction, purge, visibility changes, or object/storage GC;
- an uncommitted/in-flight mutation or any entry missing exact retained
  before/after data.

This list is intentionally narrower than the local `OpRecord` vocabulary.
Logging an event and knowing its inverse are separate claims. New undoable kinds
require a later ADR or additive decision that specifies their atomic inverse,
authorization, topology, and external-side-effect behavior.

### Preview and confirmation

`PreviewThreadUndo` is read-only and never reserves or moves the cursor. It
returns:

- the selected target and current shared cursor;
- the exact destination cursor and before/result thread snapshots;
- every operation that would leave or re-enter the active path;
- whether the next edit would fork;
- stable refusal/warning codes and a human/model-readable explanation;
- a short-lived opaque `confirmation_token` binding repository, thread ID,
  target ID, current cursor/version, destination, plan hash, and expiry.

`UndoThreadOperation` requires that token plus the same explicit IDs. The token
is confirmation of an exact preview, not authorization; the server rechecks the
Biscuit and every precondition. Any plan change returns `ABORTED` with a stable
“preview stale” detail and no mutation. This makes “preview, present, confirm”
the only commit path for both UI and future MCP tools.

### Concurrency and idempotency

The transaction takes the same per-thread serialization lock used by ordinary
thread mutation, then compare-and-swaps `(cursor_operation_id, version)`.

- Two clients using the same `client_operation_id` receive the first committed
  result.
- Two clients using different IDs and the same preview race: one commits; the
  other gets `ABORTED` because the cursor version changed and must preview
  again.
- A target is addressable only after its original mutation commits. There is no
  partial lifecycle operation to undo.
- A normal mutation that started from a stale pre-undo cursor may persist
  immutable uploaded objects, but it may not move the thread pointer. It fails
  its cursor CAS and must be retried/reconciled from the new cursor.
- An edit begun after observing a rewound cursor appends a new branch and moves
  the shared cursor to it; the old forward branch stays reachable.

`client_operation_id` follows the repository's existing retry pattern for
proof-of-possession durable writes
([example contract](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/proto/heddle/api/v1alpha1/state_review.proto#L407-L425)).
The dedup key is `(repo_id, authenticated_subject, rpc_verb,
client_operation_id)` and stores a request hash and resulting cursor-move
operation ID. Reusing the key with a different request returns
`ALREADY_EXISTS`; an ambiguous-response retry returns the original result.

### Authorization

An unfiltered repository listing requires repository read. A thread-filtered
listing and preview require that thread's read right (repository read may
satisfy it by inheritance). A thread-scoped result includes only that thread's
effect and sets `effects_truncated` when other effects were projected out;
seeing all effects of a multi-thread operation requires repository read.
`GetLifecycleOperation` similarly requires repository read or read on every
affected thread, and repo-only operations always require repository read. This
prevents an operation envelope from becoming a cross-thread name or state-ID
leak. Preview is intentionally available to a reader so a reviewer can
understand recoverability without being able to move the pointer.

Thread/repository rights are necessary but not sufficient when an operation
references a state with a narrower content-visibility tier. List omits an
operation whose safe typed projection would reveal inaccessible state metadata;
get hides its existence. Preview requires visibility of both the current and
result snapshots, and commit rechecks that visibility. A writer cannot use undo
to move the shared pointer blindly to a state they are not allowed to inspect.

Commit requires:

- proof of possession;
- `right("thread", "<repo>/threads/<current-thread-name>", "write")`, including
  inherited repository write;
- an operation-ceiling caveat that explicitly permits
  `UndoThreadOperation`;
- visibility access to both current and destination snapshots;
- the preview token, expected cursor/version, and `client_operation_id`.

The current Biscuit vocabulary defines name-based thread paths and distinct
thread read/write rights
([resource hierarchy](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-authz/src/access/resource.rs#L16-L24),
[rights](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-authz/src/biscuit/facts.rs#L19-L85)).
Delegated tokens can also carry an explicit operation allowlist
([operation ceiling](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-authz/src/biscuit.rs#L1334-L1352)).
The handler resolves immutable `thread_id` to its current name before checking
that right; the stored operation never keys identity by the name.

Any human, service, or delegated agent principal with that attenuated write
authority may commit; it need not be the original operation's actor. The
contract uses proof of possession rather than human verification so a future
MCP tool is possible. Delegation cannot exceed the parent token's resource or
operation ceilings.

The shared-pointer consequence is explicit: **a successful undo changes the
authoritative thread position seen by every user, not only the caller's view**.
Thread read is insufficient precisely because this is shared state.

## MCP-facing properties

The RPC is not exposed as an MCP tool by this ADR, but the contract is shaped so
that a later tool need not guess or scrape UI text.

### Naming and discoverability

`ListLifecycleOperations` exposes typed kind, stable ID, authenticated actor,
affected thread, exact before/after snapshots, sanitized summary, and current
undo assessment. A model can filter narrowly and call
`GetLifecycleOperation` before selecting an ID. Free-form JSON classification
is not part of the selection path.

### Blast radius and recovery

The shared scope and every operation leaving or entering the active path are
explicit in preview. The commit is bounded to one thread in v1, uses cursor
CAS, and cannot delete the forward branch. The undo is logged and undoable, so
an agent mistake
has an ordinary previewed inverse (`CURSOR_REDO`) while retained objects exist.

### Confirmation semantics

There is no direct unpreviewed mutation. The short-lived confirmation token
binds the exact plan, and commit fails closed if anything changed. An MCP host
can require a human confirmation before passing the token, but the backend does
not falsely claim that possession of a token proves a human clicked; it proves
only that this exact plan was previewed and remains current.

## Proposed proto

The sketch reuses `OperationId`, `RepositoryRef`, `StateId`, `StatePrincipal`,
`StateAgent`, `StateStatus`, `ThreadState.Kind`, `AgentRunId`, and
`TimelineOperationId`. Names and tag numbers are proposed, not implemented.

```protobuf
enum LifecycleOperationKind {
  LIFECYCLE_OPERATION_KIND_UNSPECIFIED = 0;
  LIFECYCLE_OPERATION_KIND_CAPTURE = 1;
  LIFECYCLE_OPERATION_KIND_THREAD_CREATED = 2;
  LIFECYCLE_OPERATION_KIND_THREAD_POINTER_MOVED = 3;
  LIFECYCLE_OPERATION_KIND_THREAD_DELETED = 4;
  LIFECYCLE_OPERATION_KIND_THREAD_RENAMED = 5;
  LIFECYCLE_OPERATION_KIND_THREAD_FORKED = 6;
  LIFECYCLE_OPERATION_KIND_THREAD_COLLAPSED = 7;
  LIFECYCLE_OPERATION_KIND_THREAD_MERGED = 8;
  LIFECYCLE_OPERATION_KIND_THREAD_ABANDONED = 9;
  LIFECYCLE_OPERATION_KIND_THREAD_ABORTED = 10;
  LIFECYCLE_OPERATION_KIND_THREAD_SUPERSEDED = 11;
  LIFECYCLE_OPERATION_KIND_CONFLICT_RESOLVED = 12;
  LIFECYCLE_OPERATION_KIND_TRANSACTION_ABORTED = 13;
  LIFECYCLE_OPERATION_KIND_REDACTION_APPLIED = 14;
  LIFECYCLE_OPERATION_KIND_CONTENT_PURGED = 15;
  LIFECYCLE_OPERATION_KIND_STATE_VISIBILITY_CHANGED = 16;
  LIFECYCLE_OPERATION_KIND_CURSOR_UNDO = 17;
  LIFECYCLE_OPERATION_KIND_CURSOR_REDO = 18;
}

enum LifecycleActorKind {
  LIFECYCLE_ACTOR_KIND_UNSPECIFIED = 0;
  LIFECYCLE_ACTOR_KIND_HUMAN = 1;
  LIFECYCLE_ACTOR_KIND_AGENT = 2;
  LIFECYCLE_ACTOR_KIND_SERVICE = 3;
  LIFECYCLE_ACTOR_KIND_SYSTEM = 4;
}

enum UndoRefusalReason {
  UNDO_REFUSAL_REASON_UNSPECIFIED = 0;
  UNDO_REFUSAL_REASON_NONE = 1;
  UNDO_REFUSAL_REASON_KIND_NOT_SUPPORTED = 2;
  UNDO_REFUSAL_REASON_MULTIPLE_THREADS = 3;
  UNDO_REFUSAL_REASON_NOT_ON_ACTIVE_PATH = 4;
  UNDO_REFUSAL_REASON_RETENTION_GAP = 5;
  UNDO_REFUSAL_REASON_CONCURRENCY_BOUNDARY = 6;
  UNDO_REFUSAL_REASON_PREVIEW_STALE = 7;
  UNDO_REFUSAL_REASON_TARGET_NOT_CURRENT = 8;
  UNDO_REFUSAL_REASON_INTERVENING_OPERATION = 9;
}

enum CursorMoveReason {
  CURSOR_MOVE_REASON_UNSPECIFIED = 0;
  CURSOR_MOVE_REASON_UNDO = 1;
  CURSOR_MOVE_REASON_REDO = 2;
}

enum LifecycleBranchReason {
  LIFECYCLE_BRANCH_REASON_UNSPECIFIED = 0;
  LIFECYCLE_BRANCH_REASON_ROOT = 1;
  LIFECYCLE_BRANCH_REASON_EDIT_FROM_REWOUND_CURSOR = 2;
  LIFECYCLE_BRANCH_REASON_THREAD_FORK = 3;
}

enum ConflictResolutionMode {
  CONFLICT_RESOLUTION_MODE_UNSPECIFIED = 0;
  CONFLICT_RESOLUTION_MODE_OURS = 1;
  CONFLICT_RESOLUTION_MODE_THEIRS = 2;
  CONFLICT_RESOLUTION_MODE_EDIT = 3;
  CONFLICT_RESOLUTION_MODE_AUTO = 4;
}

enum StateVisibilityKind {
  STATE_VISIBILITY_KIND_UNSPECIFIED = 0;
  STATE_VISIBILITY_KIND_PUBLIC = 1;
  STATE_VISIBILITY_KIND_INTERNAL = 2;
  STATE_VISIBILITY_KIND_TEAM_SCOPED = 3;
  STATE_VISIBILITY_KIND_RESTRICTED = 4;
  STATE_VISIBILITY_KIND_PRIVATE = 5;
}

message LifecycleActor {
  // Authenticated Biscuit subject; authoritative for filtering/audit.
  string subject = 1;
  LifecycleActorKind kind = 2;
  StatePrincipal principal = 3;
  optional StateAgent agent = 4;
}

message ThreadIdentity {
  string thread_id = 1;       // immutable and authoritative
  string thread_name = 2;     // name at this snapshot
}

message ThreadLifecycleSnapshot {
  ThreadIdentity thread = 1;
  optional StateId current_state = 2;
  ThreadState.Kind thread_state = 3;
  optional StateStatus current_state_status = 4;
  optional string terminal_reason = 5;
  optional string superseded_by_thread_id = 6;
  repeated string supersedes_thread_ids = 7;
  // False represents the absent side of create/delete.
  bool exists = 8;
}

message ThreadEffect {
  ThreadIdentity thread = 1;
  optional ThreadLifecycleSnapshot before = 2;
  optional ThreadLifecycleSnapshot after = 3;
  // Previous cursor node for this thread; absent at its root or for audit-only facts.
  optional OperationId parent_operation_id = 4;
  // Stable server-assigned branch identity, not a display name.
  string branch_id = 5;
  // Set when this effect creates a branch; otherwise unspecified.
  LifecycleBranchReason branch_reason = 6;
  // True only when this operation is a selectable thread cursor node.
  bool cursor_node = 7;
}

message CaptureOperationDetail {
  StateId before_state = 1;
  StateId after_state = 2;
  string intent = 3;
}

message ThreadLifecycleOperationDetail {
  string reason = 1; // display text; kind/thread_effects are authoritative
}

message ConflictResolvedOperationDetail {
  string conflict_id = 1;
  LifecycleActor resolver = 2;
  ConflictResolutionMode mode = 3;
  string resolution_summary = 4;
}

message TransactionAbortedOperationDetail {
  string transaction_id = 1;
  string reason = 2;
}

message RedactionOperationDetail {
  bytes redaction_id = 1;
  bytes blob_id = 2;
  optional StateId state = 3;
  string path = 4;
}

message ContentPurgedOperationDetail {
  bytes redaction_id = 1;
  bytes blob_id = 2;
}

message StateVisibilityValue {
  StateVisibilityKind kind = 1;
  // Team id or restriction label for the qualified kinds only.
  optional string qualifier = 2;
}

message StateVisibilityOperationDetail {
  StateId state = 1;
  optional StateVisibilityValue before = 2; // absent means public-by-default
  StateVisibilityValue after = 3;
}

message CursorMoveOperationDetail {
  ThreadIdentity thread = 1;
  OperationId target_operation_id = 2;
  optional OperationId from_cursor_operation_id = 3; // absent means root
  optional OperationId to_cursor_operation_id = 4; // absent means thread root
  CursorMoveReason reason = 5;
  repeated OperationId operations_leaving_active_path = 6;
  repeated OperationId operations_entering_active_path = 7;
}

message LifecycleOperationDetail {
  oneof detail {
    CaptureOperationDetail capture = 1;
    ThreadLifecycleOperationDetail thread_lifecycle = 2;
    ConflictResolvedOperationDetail conflict_resolved = 3;
    TransactionAbortedOperationDetail transaction_aborted = 4;
    RedactionOperationDetail redaction = 5;
    CursorMoveOperationDetail cursor_move = 6;
    ContentPurgedOperationDetail content_purged = 7;
    StateVisibilityOperationDetail state_visibility = 8;
  }
}

message UndoAssessment {
  bool undoable = 1;
  UndoRefusalReason refusal_reason = 2;
  string explanation = 3;
  bool caller_can_execute = 4;
}

message LifecycleOperation {
  OperationId operation_id = 1;
  RepositoryRef repository = 2;
  uint64 repository_sequence = 3;
  LifecycleOperationKind kind = 4;
  LifecycleActor actor = 5;
  string summary = 6;
  repeated ThreadEffect thread_effects = 7;
  LifecycleOperationDetail details = 8;
  google.protobuf.Timestamp occurred_at = 9;
  UndoAssessment undo = 10; // computed against the current cursor/caller
  optional OperationId initiating_job_id = 11; // OperationService domain
  optional AgentRunId agent_run_id = 12;
  optional TimelineOperationId timeline_operation_id = 13;
  // True when authorization projected out effects on other threads.
  bool effects_truncated = 14;
}

message ListLifecycleOperationsRequest {
  RepositoryRef repository = 1;
  optional string thread_id = 2;
  optional string actor_subject = 3;
  repeated LifecycleOperationKind kinds = 4;
  optional google.protobuf.Timestamp occurred_at_gte = 5;
  optional google.protobuf.Timestamp occurred_at_lt = 6;
  uint32 page_size = 7;
  string page_token = 8;
}

message ListLifecycleOperationsResponse {
  repeated LifecycleOperation operations = 1;
  string next_page_token = 2;
  LifecycleHistoryBoundary history_boundary = 3;
}

message LifecycleHistoryBoundary {
  bool complete_from_repository_creation = 1;
  optional uint64 oldest_available_sequence = 2;
  optional google.protobuf.Timestamp oldest_available_at = 3;
  string explanation = 4;
}

message GetLifecycleOperationRequest {
  RepositoryRef repository = 1;
  OperationId operation_id = 2;
}

message ThreadLifecycleCursor {
  RepositoryRef repository = 1;
  ThreadIdentity thread = 2;
  optional OperationId cursor_operation_id = 3;
  string branch_id = 4;
  uint64 version = 5;
  ThreadLifecycleSnapshot snapshot = 6;
  optional OperationId last_cursor_move_operation_id = 7;
  google.protobuf.Timestamp updated_at = 8;
}

message PreviewThreadUndoRequest {
  RepositoryRef repository = 1;
  string thread_id = 2;
  OperationId target_operation_id = 3;
}

message ThreadUndoPlan {
  LifecycleOperation target = 1;
  ThreadLifecycleCursor current_cursor = 2;
  optional OperationId destination_cursor_operation_id = 3;
  ThreadLifecycleSnapshot result_snapshot = 4;
  repeated LifecycleOperation operations_leaving_active_path = 5;
  repeated LifecycleOperation operations_entering_active_path = 6;
  UndoAssessment assessment = 7;
  bool next_edit_will_fork = 8;
  string confirmation_token = 9; // empty when not undoable
  google.protobuf.Timestamp confirmation_expires_at = 10;
}

message UndoThreadOperationRequest {
  RepositoryRef repository = 1;
  string thread_id = 2;
  OperationId target_operation_id = 3;
  optional OperationId expected_cursor_operation_id = 4;
  uint64 expected_cursor_version = 5;
  string confirmation_token = 6;
  string client_operation_id = 7;
}

message UndoThreadOperationResponse {
  LifecycleOperation cursor_move_operation = 1;
  ThreadLifecycleCursor cursor = 2;
}

service OperationLogService {
  rpc ListLifecycleOperations(ListLifecycleOperationsRequest)
      returns (ListLifecycleOperationsResponse);
  rpc GetLifecycleOperation(GetLifecycleOperationRequest)
      returns (LifecycleOperation);
  rpc PreviewThreadUndo(PreviewThreadUndoRequest)
      returns (ThreadUndoPlan);
  rpc UndoThreadOperation(UndoThreadOperationRequest)
      returns (UndoThreadOperationResponse);
}
```

`ListLifecycleOperations`, `GetLifecycleOperation`, and
`PreviewThreadUndo` are read-only, safe-retry RPCs with resource-reader access.
`UndoThreadOperation` is a proof-of-possession durable write with
`RETRY_BEHAVIOR_CLIENT_OPERATION_ID`, `client_operation_id_required: true`,
resource-writer access sourced from the request repository/thread, and
existence hiding. A new capability area such as
`CAPABILITY_AREA_OPERATION_LOG` is preferable to reusing
`CAPABILITY_AREA_ASYNCHRONOUS_OPERATIONS`, because the latter belongs to LRO
jobs.

## Storage sketch

`lifecycle_operations` and its linked existing `oplog` rows are one canonical
parent/child log: the new parent is the public semantic operation, while the
`OpRecord` rows remain its canonical typed local details. The thread effects,
topology, and shared cursor make that unit queryable and navigable. This is a
normalization around the current log, not a second event stream.
The tables are shown in logical order; foreign keys that point to a table shown
later are added after table creation (and same-transaction topology constraints
may be deferrable).

```sql
lifecycle_operations (
  operation_id          uuid        PRIMARY KEY, -- UUIDv7
  repo_id               uuid        NOT NULL REFERENCES spools(spool_id)
                                   ON DELETE CASCADE,
  repo_sequence         bigint      NOT NULL,
  kind                  text        NOT NULL,
  actor_subject         text        NOT NULL,
  actor_kind            smallint    NOT NULL,
  actor_json            jsonb       NOT NULL, -- typed attribution encoding
  summary               text        NOT NULL,
  detail_bytes          bytea       NOT NULL, -- canonical typed proto/envelope
  initiating_job_id     uuid,        -- OperationService domain; no FK here
  agent_run_id          text,
  timeline_operation_id bytea,
  occurred_at           timestamptz NOT NULL DEFAULT now(),
  CHECK (repo_sequence > 0),
  UNIQUE (repo_id, repo_sequence),
  UNIQUE (repo_id, operation_id),
  UNIQUE (repo_id, operation_id, repo_sequence)
);

lifecycle_operation_counters (
  repo_id               uuid   PRIMARY KEY REFERENCES spools(spool_id)
                                  ON DELETE CASCADE,
  next_repo_sequence    bigint NOT NULL CHECK (next_repo_sequence > 0)
);

lifecycle_operation_threads (
  operation_id          uuid        NOT NULL,
  repo_id               uuid        NOT NULL,
  thread_id             text        NOT NULL, -- opaque API identity, not UUID
  thread_name_at_time   text        NOT NULL,
  parent_operation_id   uuid,
  branch_id             uuid        NOT NULL,
  before_state_id       bytea,
  after_state_id        bytea,
  before_thread_state   smallint,
  after_thread_state    smallint,
  before_snapshot_bytes bytea, -- typed restoration snapshot, versioned
  after_snapshot_bytes  bytea, -- typed restoration snapshot, versioned
  before_exists         boolean     NOT NULL,
  after_exists          boolean     NOT NULL,
  is_cursor_node        boolean     NOT NULL,
  repo_sequence         bigint      NOT NULL,
  PRIMARY KEY (operation_id, thread_id),
  UNIQUE (repo_id, thread_id, operation_id),
  FOREIGN KEY (repo_id, operation_id, repo_sequence)
    REFERENCES lifecycle_operations(repo_id, operation_id, repo_sequence),
  FOREIGN KEY (repo_id, thread_id, parent_operation_id)
    REFERENCES lifecycle_operation_threads(repo_id, thread_id, operation_id),
  FOREIGN KEY (repo_id, thread_id, branch_id)
    REFERENCES lifecycle_thread_branches(repo_id, thread_id, branch_id),
  CHECK (before_state_id IS NULL OR octet_length(before_state_id) = 32),
  CHECK (after_state_id IS NULL OR octet_length(after_state_id) = 32)
);

lifecycle_thread_branches (
  repo_id                  uuid NOT NULL REFERENCES spools(spool_id)
                                 ON DELETE CASCADE,
  thread_id                text NOT NULL,
  branch_id                uuid NOT NULL,
  parent_branch_id         uuid,
  forked_from_operation_id uuid,
  created_by_operation_id  uuid, -- absent only for a cutover root
  reason                   text NOT NULL CHECK
                             (reason IN ('root',
                                         'edit_from_rewound_cursor',
                                         'thread_fork')),
  PRIMARY KEY (repo_id, thread_id, branch_id),
  FOREIGN KEY (repo_id, thread_id, parent_branch_id)
    REFERENCES lifecycle_thread_branches(repo_id, thread_id, branch_id),
  FOREIGN KEY (repo_id, forked_from_operation_id)
    REFERENCES lifecycle_operations(repo_id, operation_id),
  FOREIGN KEY (repo_id, created_by_operation_id)
    REFERENCES lifecycle_operations(repo_id, operation_id)
);

thread_lifecycle_cursors (
  repo_id                       uuid        NOT NULL REFERENCES spools(spool_id)
                                            ON DELETE CASCADE,
  thread_id                     text        NOT NULL,
  current_thread_name           text        NOT NULL,
  cursor_operation_id           uuid,
  branch_id                     uuid        NOT NULL,
  version                       bigint      NOT NULL,
  last_cursor_move_operation_id uuid,
  snapshot_bytes                 bytea       NOT NULL, -- current typed snapshot
  updated_at                    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (repo_id, thread_id),
  CHECK (version >= 0),
  FOREIGN KEY (repo_id, thread_id, branch_id)
    REFERENCES lifecycle_thread_branches(repo_id, thread_id, branch_id),
  FOREIGN KEY (repo_id, thread_id, cursor_operation_id)
    REFERENCES lifecycle_operation_threads(repo_id, thread_id, operation_id),
  FOREIGN KEY (repo_id, thread_id, last_cursor_move_operation_id)
    REFERENCES lifecycle_cursor_moves(repo_id, thread_id, move_operation_id)
);

lifecycle_cursor_moves (
  move_operation_id        uuid PRIMARY KEY,
  repo_id                  uuid NOT NULL,
  thread_id                text NOT NULL,
  target_operation_id      uuid NOT NULL,
  from_cursor_operation_id uuid,
  to_cursor_operation_id   uuid,
  from_cursor_version      bigint NOT NULL,
  to_cursor_version        bigint NOT NULL,
  reason                   text NOT NULL CHECK (reason IN ('undo', 'redo')),
  UNIQUE (repo_id, thread_id, move_operation_id),
  CHECK (to_cursor_version = from_cursor_version + 1),
  FOREIGN KEY (repo_id, move_operation_id)
    REFERENCES lifecycle_operations(repo_id, operation_id),
  FOREIGN KEY (repo_id, thread_id, target_operation_id)
    REFERENCES lifecycle_operation_threads(repo_id, thread_id, operation_id),
  FOREIGN KEY (repo_id, thread_id, from_cursor_operation_id)
    REFERENCES lifecycle_operation_threads(repo_id, thread_id, operation_id),
  FOREIGN KEY (repo_id, thread_id, to_cursor_operation_id)
    REFERENCES lifecycle_operation_threads(repo_id, thread_id, operation_id)
);

lifecycle_operation_state_roots (
  operation_id uuid  NOT NULL,
  repo_id      uuid  NOT NULL,
  state_id     bytea NOT NULL CHECK (octet_length(state_id) = 32),
  PRIMARY KEY (operation_id, state_id),
  FOREIGN KEY (repo_id, operation_id)
    REFERENCES lifecycle_operations(repo_id, operation_id)
);

lifecycle_operation_dedup (
  repo_id             uuid        NOT NULL,
  actor_subject       text        NOT NULL,
  rpc_verb            text        NOT NULL,
  client_operation_id text        NOT NULL,
  request_hash        bytea       NOT NULL,
  result_operation_id uuid        NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (repo_id, actor_subject, rpc_verb, client_operation_id),
  FOREIGN KEY (repo_id, result_operation_id)
    REFERENCES lifecycle_operations(repo_id, operation_id)
);
```

Future lifecycle writes first allocate `operation_id` and `repo_sequence`, then
insert the envelope; the per-repository counter is locked and incremented, so
allocation never uses `MAX(repo_sequence) + 1`. Every underlying `oplog` row
for that logical mutation uses the same non-null `oplog.operation_id`. Existing
rows can be grouped by
their immutable `(repo_id, scope, batch_id)` during migration and assigned a
persisted operation ID once only when the backfill can prove physical state and
thread identity. Unmappable history stays internal and the API reports its
cutover through `history_boundary`; it never fabricates thread identity or
synthesizes operation IDs at read time.

Required indexes:

```sql
CREATE INDEX lifecycle_operations_repo_recent
  ON lifecycle_operations (repo_id, repo_sequence DESC);
CREATE INDEX lifecycle_operations_repo_actor_recent
  ON lifecycle_operations (repo_id, actor_subject, repo_sequence DESC);
CREATE INDEX lifecycle_operations_repo_kind_recent
  ON lifecycle_operations (repo_id, kind, repo_sequence DESC);
CREATE INDEX lifecycle_operations_repo_time_recent
  ON lifecycle_operations (repo_id, occurred_at DESC, repo_sequence DESC);
CREATE INDEX lifecycle_operation_threads_thread_recent
  ON lifecycle_operation_threads (repo_id, thread_id, repo_sequence DESC);
CREATE INDEX lifecycle_operation_threads_parent
  ON lifecycle_operation_threads (repo_id, thread_id, parent_operation_id);
CREATE INDEX lifecycle_operation_state_roots_state
  ON lifecycle_operation_state_roots (repo_id, state_id);
CREATE INDEX oplog_repo_operation
  ON oplog (repo_id, operation_id, batch_index)
  WHERE operation_id IS NOT NULL;
```

The repository and thread indexes directly serve the required scopes. Actor,
kind, and time indexes support their filters; PostgreSQL may bitmap-intersect
them for combined predicates. Sequence is the pagination key and tie-breaker.
No index depends on a renameable thread name.

Cursor rows and cursor-move `from`/`to` endpoints may reference only
`lifecycle_operation_threads.is_cursor_node = true`; cursor-move operations
themselves set it false. This cross-row condition is enforced by the write
transaction (or a deferred constraint trigger), not inferred from operation
kind at read time.

At cutover, new lifecycle-producing `oplog.operation_id` values reference
`lifecycle_operations(operation_id)` and are non-null by write-path invariant.
The column remains nullable only for legacy rows that the identity-safe
backfill cannot map.

`repo_events` gains nullable `source_operation_id uuid` and `thread_id text`,
plus an index on `source_operation_id`; lifecycle-producing paths require both.
A `feed_item_operations(feed_item_id, operation_id)` link supports materialized
rollups. These are projections of `lifecycle_operations`, not alternate
operation records.

The undo transaction locks `thread_lifecycle_cursors`, verifies version and
preview hash, appends the cursor-move envelope/detail/outbox rows, updates the
cursor, and commits deduplication atomically. Ordinary thread mutations use the
same cursor row and parent/branch rules, so undo cannot race a side channel that
does not know about the cursor.

The cursor row is authoritative for the hosted thread position. The existing
name-keyed `refs` row and thread metadata are materialized to that position in
the same transaction; they are not a competing second cursor. Reads must not
serve a ref value that has diverged from the lifecycle cursor/version.

At a cutover boundary, each existing thread receives a root branch and cursor
snapshot without a fabricated historical operation. An absent
`cursor_operation_id` means that retained baseline, not a missing thread; the
first post-cutover operation records the baseline as its `before` snapshot.

## Retention and garbage collection

V1 has **no lifecycle-log retention limit and no pruning**. While a repository
exists:

- lifecycle operations, thread effects, branch edges, and cursor moves do not
  expire;
- every before/after state required to navigate a reachable branch is a GC root
  through `lifecycle_operation_state_roots`;
- feed expiration and event compaction cannot remove lifecycle history or its
  state roots;
- a thread deletion, if later made undoable, cannot cascade its history.

The list response reports whether history is complete from repository creation
or starts at a declared migration/cutover boundary. That boundary acknowledges
legacy data that cannot be safely backfilled; it is not a v1 retention policy.

This is deliberately unbounded. The first pruning policy is the point at which
“undo navigates; it does not destroy” stops being universally true. It requires
a separate design that states whether branches are archived, tombstoned, or
made explicitly unavailable and how preview communicates that boundary. A
quiet age/size cap is rejected.

Repository deletion remains an explicit v1 exception: it is not undoable and
currently deletes the spool row while log/event tables cascade from it
([delete path](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-registry/src/pg_hosted_registry/mod.rs#L1938-L1954),
[current cascades](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/migrations/003_storage.sql#L33-L71)).
The invariant applies to lifecycle history inside a live repository; it does
not promise hosted undelete.

## Consequences and rejected alternatives

- The log and undo share one identity, topology, transaction, authorization
  domain, and retention story.
- A UI or model can select an operation without parsing JSON or reconstructing
  history from a live event stream.
- Shared per-thread cursor movement gives hosted undo real product semantics;
  a per-user cursor was rejected as personal inspection, not lifecycle undo.
- A repository-global cursor was rejected because unrelated threads would
  interfere and require repository-wide serialization.
- Extending `OperationService` was rejected because queued job execution,
  leases, cancellation, and terminal snapshots are a different lifecycle.
- Making `feed_items` or `repo_events` the history source was rejected because
  feed rows roll up/expire and event kinds are delivery-oriented.
- Toggling `oplog.undone` was rejected as the hosted contract because it cannot
  preserve a branching shared cursor.
- Compensating “revert commits” alone were rejected: they can preserve content
  but do not restore abandoned/aborted/superseded thread metadata or model the
  local cursor invariant. Cursor moves may later trigger materialization, but
  pointer topology remains authoritative.

## UNKNOWN — must be settled before implementation

1. **Weft does not yet honor the API's physical-state and stable-thread-ID
   contract.** Fresh Weft still fills wire `StateId` from the 16-byte
   `change_id` and repeats it as `ChangeId`
   ([producer](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-hosted/src/server/hosted/canonical_repository.rs#L438-L486)),
   while fresh API requires a 32-byte physical `StateId`. Weft is also pinned to
   `heddle-api = "0.2.1"`
   ([dependency](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/Cargo.toml#L45-L56)),
   and its thread-summary adapter predates the required `thread_id` fields
   ([adapter](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-hosted/src/server/hosted/canonical_workflow.rs#L230-L303)).
   Upgrading Weft, persisting/backfilling stable thread IDs, and passing
   rebase/rename conformance tests would settle this. The operation schema must
   not ship with logical IDs stored in physical-state columns.

2. **The fresh checkout exposes two local undo mechanisms.** The agent timeline
   has the append-only cursor/branch model required by this ADR, but the
   `heddle undo` CLI still selects oplog batches, materializes inverse changes,
   and marks batches undone, while retaining a recovery ref
   ([CLI path](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/cli/src/cli/commands/undo.rs#L106-L158),
   [recovery behavior](https://github.com/HeddleCo/heddle/blob/84e4a3a52d3aa859cd3a4c4304921cee85402df0/crates/cli/src/cli/commands/undo.rs#L206-L234)).
   The owner-provided invariant decides the hosted design: cursor navigation and
   retained branches. The Heddle owner must still say whether the legacy CLI
   will converge on that model or remain a separate compatibility mechanism;
   an end-to-end test that edits after undo and enumerates both branches would
   settle behavioral equivalence.

3. **Complete hosted producer coverage is not evident.** Weft constructs
   `PgOpLogBackend` with no operation ID
   ([constructor](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-registry/src/hosted_repository.rs#L67-L91)),
   while successful push finalization appends `repo_events` in its publication
   transaction
   ([push transaction](https://github.com/HeddleCo/weft/blob/3c4f9c6d952104430fb168826627795d5b3d7944/crates/weft-hosted/src/service/refs_hosted_impl.rs#L1292-L1404)).
   A mutation-by-mutation producer audit and integration test must identify
   which current hosted paths write complete `OpRecord` batches, which only
   write events/action indexes, and how old rows are grouped before backfill.

4. **Thread authorization paths are still name-based.** This ADR can resolve a
   stable thread ID to the current name and excludes rename undo in v1, but it
   does not settle whether future Biscuit thread resources should become
   ID-keyed. An authorization ADR or a rename conformance test proving grants
   intentionally follow (or intentionally do not follow) a rename would settle
   that broader question.

5. **Legacy thread-history backfill may not be identity-safe.** Pre-API-#70
   `oplog` records carry thread names rather than immutable thread IDs, and the
   current hosted producer does not yet satisfy the 32-byte physical-state
   contract. A replay audit across create/rename/delete/fork batches, compared
   against surviving thread records and physical objects, would settle which
   repositories can be backfilled without guessing. If it cannot prove the
   mapping, the public history begins at a declared cutover and
   `history_boundary.complete_from_repository_creation` remains false.

## Out of scope for v1

- implementation, proto edits, migrations, generated clients, dispatcher
  routes, feed changes, or a Tapestry integration;
- serving `ListOperations`/`CancelOperation` or changing the concurrent
  `OperationService` repository-filter PR;
- changing or removing `ListActions.operation_json`;
- an MCP server/tool declaration, tool naming policy, or MCP-host UI;
- per-user/private lifecycle cursors or a repository-wide working-copy cursor;
- direct redo RPC, arbitrary seek/reset, cross-thread atomic undo, or undo of
  any kind outside the explicit v1 list;
- thread create/delete/rename/fork/collapse/merge undo, repository undelete,
  external-side-effect compensation, conflict-resolution inversion, redaction,
  purge, visibility, approval, policy, or grant undo;
- retention, archival, pruning, quotas, branch squashing, state-root release,
  or any weakening of the non-destructive invariant;
- converging agent-run timelines with lifecycle history; only correlation IDs
  are included;
- a live operation-log subscription; paged query is v1 and `repo_events`
  remains the delivery projection;
- opening follow-up issues before owner confirmation.

## Document location

This repository uses flat design documents under `docs/`; API #69 likewise
landed as one ADR-only file
([example](https://github.com/HeddleCo/api/blob/334170c9c9bca8b7f41b0b6329c20bb5c081eee9/docs/review-cursor.md#L342-L348)).
This ADR follows that convention and intentionally contains no implementation.
