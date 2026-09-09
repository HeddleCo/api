# Shared source targets for annotations and discussions

Status: design agreed during the structured annotation cutover; implementation in progress. Typed scalar/tag signing and original-reference predicates are a foundation, not acceptance of automatic target tracking.

## Decisions

A reference points to a shared target core. Its original source is immutable signed evidence. The current path, symbol name, range, resolution status and body-change state are projections, never rewrites of an author's tags or prose.

There are two independent identities:

- `TargetId` identifies a logical file, symbol or range. Intern references to an already-known current target to reuse its identity; do not hash each new reference's current revision and accidentally create a new core on every capture.
- A resolution binding selects the current Thread being viewed, an explicit other Thread, or an exact pinned historical revision. Inherited annotations resolve in the fork. Explicit cross-Thread references retain their named Thread. Branch bindings are independent even when their target identities and baseline maps are shared.

Targets themselves use indirection: symbol/range cores refer to a stable file identity, rather than duplicating a mutable path. A file rename changes its path binding once. A function move changes that function's binding once. A reference to an exact range keeps stable origin positions and explicit endpoint affinity; insertions at a boundary must have deterministic include/exclude behavior.

## Capture and reads

Capture produces a bounded delta over changed source, using Merkle subtree equality and the semantic/diff work it already does. It publishes a new revision's binding-map root by structurally sharing unchanged entries. It never enumerates referencing annotations or discussions.

Each changed file gets a shared source transition: old/new blob identities, file lineage/rename decisions, a line/offset edit map and changed symbol mappings. These are reusable data, not one transformation copied per reference. Unrelated captures reuse the same file-binding identity, so location caches keyed by `(file binding, target)` stay valid.

Resolve a target lazily through that shared transition structure. Materialize current line numbers only when requested. Cache composed mappings and target resolutions; compact excessive transition depth outside the capture commit path. Readers have explicit work budgets and report pending/ambiguous/unavailable rather than following an unbounded history or guessing a destination.

This targets O(changed-source delta + changed core bindings) capture work, independent of reference count. A file rename has one core mutation even with many targets and references. A line insertion records its edit once, rather than shifting every range. It does not promise O(1) source parsing, arbitrary symbol matching, all query results, network fanout, or compaction. If every target genuinely changes in unrelated ways, computing all their resolutions still takes work; indirection and laziness avoid making capture pay it eagerly.

## Query and observation

Scalar predicates index the signed revision. Current-source predicates join reference membership to shared target/file bindings and the selected revision's position map. They must not query stale original path/line columns as if those were current. Historical/source-evidence queries explicitly select original coordinates.

Return the required target records with the existing composed observation/page. Context/discussion/tag views reference their IDs. A capture pushes one target/file-binding update per changed core; clients already holding its referencing records derive their displayed location. There is no per-tag lookup RPC or forced resend of unchanged prose. Query-window membership changes still require correct additions/removals, and recipients/output size remain unavoidable costs.

Visibility is evaluated for the annotation and any source evidence used to resolve it. A target reference grants no ability to read a private source or infer hidden query counts. Projection keys include the authoritative scope/revision; a cached match is not authorization. Ambiguous moves, deletion, unavailable source and conflicting merge destinations remain explicit states.

## Existing code to reuse or replace

`repo/src/discussion_anchor_travel.rs` contains conservative file/symbol rename rules and a batch file-rename pass. Its single-symbol helper recomputes rename candidates; it should consume a shared transition instead.

`repo/src/context_snapshot_travel.rs` currently enumerates context entries, collects full old/new file maps, and rebuilds changed annotation blobs. It selects file/symbol anchors, not line ranges. `discussion_snapshot_travel.rs` similarly materializes discussions and baseline trees. Extending these loops to tags would preserve the very fanout this design removes.

Keep the existing matching primitives and ambiguity policy; replace the ownership of current locations with shared target/file bindings. Context primary anchors, discussion primary anchors and structured reference tags must use the same resolver and projection representation.

## Acceptance evidence needed

- A capture unrelated to references resolves/writes zero reference targets.
- Renaming one file performs the same core work with one or 10,000 referring annotations.
- Moving a symbol updates one target; inherited and explicit cross-Thread references resolve in their correct branches.
- Inserting lines before many ranges writes one shared edit map, with no eager per-range updates. Boundary insert/delete and overlapping edits follow explicit affinity rules.
- Forks structurally share maps; branch edits cannot change the parent's resolution. Merges preserve ambiguity instead of selecting an arbitrary current binding.
- Current-path/range query results agree with displayed locations after capture, before pagination, including live removal/addition and source visibility.
- Old signed tags/proofs remain byte-identical through all captures. Restart/replay reconstructs the same target cores and bindings.
- Cold resolution and mapping compaction obey budgets; unsupported/partial analysis is visible rather than silently called complete.
