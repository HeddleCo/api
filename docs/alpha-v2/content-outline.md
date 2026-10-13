# Exact-revision file outlines

`ReadContentRequest.selections` accepts `outline { path, page }`. It uses the
request's exact revision and owning Thread, with all `ReadContent` audience,
source, public-tip and entry gates applied before index lookup or output. It
never substitutes a current tip, another Thread's index, an ancestor index, or
an empty complete result for a missing index. A missing or inaccessible file
has the same call-level existence-hiding response; no readiness metadata leaks.

Each `ContentEvent.outline_symbol` gives name, `SymbolKind`, container (empty
at top level), opaque stable symbol ID and one-based inclusive start/end lines.
Rust and TypeScript validate kinds against the generated `SymbolKind` enum,
rejecting `UNSPECIFIED` and unknown values rather than hard-coding a numeric range.
Use the index's symbol address also used for source anchors; never replace it
with a semantic meaning hash. Stability is within the exact indexed revision,
including retries/pages and unchanged projections. Renames/moves across
revisions require explicit source-target resolution and do not promise a global
symbol identity. An outline requires syntactic symbol coverage, not a cross-file
resolver. An indexed empty file can have complete coverage and zero symbols.

The normalized path and each name/container/symbol ID are at most 4096 UTF-8
bytes. An encoded symbol is at most 16384 bytes. Enforce these indivisible bounds
at index admission; incompatible older indexes are unavailable independently of
query matches. Lines must be positive, ordered, and within the exact source
file. Never truncate names or skip an oversized row while claiming completeness.

Default page size is 100; maximum 256. Opaque page tokens are at most 4096 bytes
and bind caller authority, endpoint, owning Thread, exact revision, index
identity, normalized path, page size and accepted budget. Recheck live authority
on every page. Order by `(start_line, end_line, symbol_id, name, container, kind)`;
identical rows are emitted once. Visible rows alone affect counts and boundaries.
Changed authority/index identity invalidates the cursor; an outline never follows
symlinks or spool links.

The existing finite `ReadBudget` limits rows and encoded bytes as well as work.
Selections with an outline require effective minimums of 4 items, 65536 frame
bytes and 65536 snapshot bytes after clamping, before file/index selection. Reserve
8192 bytes for completion/PageInfo plus 1024 for framing and controls. Thus a
maximum row and completion fit; every nonempty page can emit its first visible
row. Shorten later rows to fit and provide a continuation; never return a cursor
before an unreturned first row. Index traversal is capped at 100000 visited
symbols per query; a lower endpoint limit may yield a deterministic prefix with
partial coverage, or `RESOURCE_EXHAUSTED` when no safe prefix is possible.

Every selection terminates with `selection_complete`, `section="outline"`, exact
`computed_for`, and `PageInfo`. Missing completion before FIN is interruption.
Coverage is `COMPLETE`, `PARTIAL` or `UNAVAILABLE`. COMPLETE describes the page's
symbol coverage; `page.exhausted` alone says pagination is finished. A page can
be complete with a continuation. PARTIAL exposes a bounded safe prefix or
incomplete analysis; UNAVAILABLE means no usable symbol analysis/index. Both
carry a safe `SectionStatusReason`, using `COVERAGE_INCOMPLETE` when no more
specific safe reason applies. Reasons never identify hidden files or languages.
No index must not look like an exhausted complete empty file. Unavailable
coverage has no symbol rows and no continuation. Partial coverage may be
exhausted when all available indexed symbols were emitted; this still does not
claim full source coverage.

Rust `v2::content` and TypeScript `./v2/content` provide matching outline input,
row and completion validators and bound constants. These helpers check structure;
hosts independently enforce exact file/index bindings, source line counts, paging,
work limits and disclosure.


## Endpoint negotiation (alpha.48)

Hosts implementing outlines advertise
`MANDATORY_PROTOCOL_FEATURE_CONTENT_OUTLINE_V1` (4) in
`DescribeEndpointResponse.protocol.mandatory_features`, merged into the
existing sorted, unique feature set. Advertise it only after implementing the
complete outline semantics above. Do not add it to `ReadContent`'s per-method
`mandatory_features`: tree, blob, diff, provenance and state reads remain usable
when outline support is absent.

Clients check Rust `v2::protocol::host_supports(peer, ContentOutlineV1)` or
TypeScript `hostSupports(peer, MandatoryProtocolFeature.CONTENT_OUTLINE_V1)`
before offering outline selections. The corresponding require helpers return
`Reject::MissingFeature(ContentOutlineV1)` / throw
`MissingProtocolFeatureError` with `feature = CONTENT_OUTLINE_V1`.
Rust `validate_outline_read(read, peer)` requires a final
`Option<&ProtocolCompatibility>`; TypeScript `validateOutlineRead(read, peer)`
accepts an optional final negotiated peer. Missing negotiation refuses outlines.
Typed clients automatically consult their stored peer when a `ReadContent`
request contains any outline selection, before transport. Re-negotiate after
endpoint/connection replacement. Output-row and status validators remain
structural and do not require a peer. Existing protobuf bytes are unchanged.
