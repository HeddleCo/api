# Source-backed conditional review data

The v2 analysis surface carries `BEHAVIOR_CHANGES` through `ObserveAnalysis`.
`BehaviorChange` is a self-contained structural map, not a generated diagram or
an assertion about runtime effects. Existing `AnalysisEvent.diff` records and
`ContentService` file/tree inventories remain independent and complete on their
own terms; a behavior map never substitutes for either.

## Implemented slice

Heddle's shared semantic engine and optional `heddle-thread-api/semantic-analysis`
projection implement Rust field initializers and assignments introducing an
`if/else` value or changing an existing conditional. Weft's native `semantic`
feature serves this projection for published native State revisions in one spool.
The local projection also accepts exact Git commit IDs. Wiring a device daemon
analysis RPC is still foundation work; merely exporting the projection does not
advertise a device handler.

The PR #1718 fixture is pinned to the complete `crates/verbs/src/save.rs` blobs at
`92a9b0705370d2c04f8bcaf9b7141937085d0ad9` and
`2a67bcaf7446def0bd01e4b9b79b2cbb9e203401`. It yields:

| Fact | Source-backed structure |
| --- | --- |
| Containing operation | `capture`, with symbol semantic hash and exact name span |
| Target | `SavePlan.git_scope` (syntactic address, not inferred type resolution) |
| Written predicate | `git_overlay` |
| Binding value | `repo.capability() == RepositoryCapability::GitOverlay` |
| Original value | One `GitScope::None` expression, with no branches |
| True result | `GitScope::WorktreeAll`, replacing that original expression |
| False result | `GitScope::None`, retaining the same original expression |

An assignment's `operation_id` and `value_id` describe containment. A conditional
names its predicate and ordered labeled branches; each branch names its result.
Binding records preserve the written occurrence, declaration, lexical scope and
resolved expression. Correspondences refer to those existing expression IDs, so
one old fact can support several comparisons. Provenance belongs to each fact
and correspondence. The renderer controls layout and may repeat presentation.

There are no invented call-order edges, inferred consequences or blanket test
approval. Existing resolved calls/references are a separate graph; proving an
effect requires consumer implementation evidence. Test evidence, if added later,
must bind a particular assertion/run and revision to a particular claim.

## Matching and limitations

Matching requires the same exact qualified symbol address and syntactic target.
Multiple candidates remain ambiguous. Unique targets compare normalized
non-comment tokens and, for predicates, resolved local bindings. Declarations
are found in lexical scope and source order; outer or later shadowed declarations
cannot replace the actual binding. Mutable/reassigned bindings and unsupported
patterns remain explicit. The first slice does not infer symbol renames, type
flow, effects, macro expansion, `match`, guards, statementful branches or nested
conditional results. Missing else and parse errors are explicit limitations.

`Retained` means retained structure under the documented match method, not
equivalent runtime behavior. A change in a resolved predicate can coexist with
retained branch-result expressions. Identical supported conditionals and
comment/whitespace-only edits do not produce changes.

## Identity and navigation

Every navigable fact binds an exact revision, repository-relative path, blob
hash and zero-based half-open UTF-8 byte span. Expressions include exact text.
An optional lexical-scope span uses the declaration's same revision/path/blob;
the enclosing block text is not duplicated. No line-number or Tree-sitter node
identity is used for cross-revision matching.

Record identity binds both exact revisions, source blobs, path and analyzer
versions. Source-local fact IDs include the exact blob, side, symbol, structural
occurrence order and extraction/binding versions. Whitespace can preserve a
semantic hash while invalidating all affected source locations and record IDs.
Extraction and binding dependencies cover the entire source blob, including
declarations/writes outside the changed expression. Comparison dependencies bind
both artifacts, versions and exact revision pair; selection/pagination caches
must additionally bind paths and symbol selectors. The existing process-local
parse cache is reused; no persisted expression graph or new cache store is added.

## Bounded observation

The native Weft slice accepts 1–16 exact paths, at most 64 exact symbol selectors,
and only `BEHAVIOR_CHANGES`. Paths normally come from the existing full diff or
file inventory. Empty symbol selection scans all functions in those files.
Each source file is bounded at 1 MiB and 512 assignment candidates; request input
work is bounded at 4 MiB per page. These are explicit limits, not silent success.
Larger scopes use further path selections; omitted/unsupported scopes retain
typed reasons. A truncated candidate inventory cannot support confident matches.

Pages count typed result records (including coverage fragments); each page also
includes one `AnalysisRecord`. `finding_count` is absent until an exact total is
known. Coverage fragments accumulate within the committed page. Analyzed scope
describes this pattern only; omitted scope, partial bindings, unavailable source,
and an empty supported result remain distinguishable. `selection_exhausted`
describes analysis, while checkpoint `page.exhausted` describes delivery.

The shared Open/Data/Checkpoint/Complete state machine stages changes atomically.
A new observation replaces its query window. Typed upserts, section replacement
and behavior removals remain available to evolving analyzers; the current pure
analyzer has immutable inputs/results, so FOLLOW stays open for cancellation and
authority rechecks without inventing updates. Resume of an already committed
unchanged page sends no duplicate data. Changed query/authority cursors reset;
page tokens are separately bound to query and authority. FIN without Complete
is interruption, never complete analysis.

Both revisions must pass current publication and audience checks. Authority and
audience are rechecked before every frame and while idle. Analysis never opts a
device's private data into hosted persistence. Browser/operator client builds
remain parser-free; extraction is an explicit host feature.
