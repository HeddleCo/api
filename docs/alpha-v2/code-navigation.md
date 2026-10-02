# Revision-pinned code navigation and client index ingestion

This additive v2 contract implements the API slice of [api#289](https://github.com/HeddleCo/api/issues/289),
[weft#2487](https://github.com/HeddleCo/weft/issues/2487) and
[weft#2021](https://github.com/HeddleCo/weft/issues/2021). Handler implementation
in weft and heddle follows separately. Compiled methods do not advertise support;
endpoints advertise only implemented handlers. No synchronous parsing is allowed.

## STEP 0 evidence and owner decision

The earlier issue descriptions assume an ingestion path that v2 does not have.
The owner chose to restore client ingestion on 2026-10-02 in
[this decision](https://github.com/HeddleCo/api/issues/289#issuecomment-5943491284).
The source observations below were checked at weft `49e82a27502f501c3a24418eac6a1e0544f3e7b7`
and heddle `52bb0aaf063fdb76f9e392d1432d25df7705a8a7`:

- [weft#2414](https://github.com/HeddleCo/weft/pull/2414) deleted the legacy push
  path. Native `PublishContent` receives original genesis, causal operations,
  packs and Finish; its wildcard rejects sidecars, including attachments:
  [publication.rs:576](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/crates/weft-hosted/src/server/hosted/publication.rs#L576),
  [publication.rs:676](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/crates/weft-hosted/src/server/hosted/publication.rs#L676).
- Native analysis builds a semantic index and puts its nodes into
  `AnalysisArtifact.semantic_index`:
  [analysis_compute.rs:51](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/crates/weft-hosted/src/server/hosted/analysis_compute.rs#L51),
  [analysis_compute.rs:68](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/crates/weft-hosted/src/server/hosted/analysis_compute.rs#L68).
  The worker encodes that artifact, stores derived blob bytes and registers
  its descriptor:
  [analysis_worker.rs:345](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/crates/weft-hosted/src/server/hosted/analysis_worker.rs#L345),
  [analysis_worker.rs:383](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/crates/weft-hosted/src/server/hosted/analysis_worker.rs#L383),
  [thread_artifacts.rs:211](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/crates/weft-storage/src/thread_artifacts.rs#L211).
  This does not install a client `StateAttachment`.
- Content search extracts definitions and inserts `hosted_search_symbols`:
  [content_search.rs:1286](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/crates/weft-workers/src/content_search.rs#L1286),
  [content_search.rs:1750](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/crates/weft-workers/src/content_search.rs#L1750).
  That projection is not a client semantic graph attachment either.
- The API already has generic `TransferSidecar.KIND_ATTACHMENT`, with exact
  revision, address, record format and canonical bytes. `ReplicationOperations`
  carries signed causal operations and admissions, not arbitrary attachments.
  The added opening manifest supplies the missing explicit semantic closure
  commitment; no parallel StateAttachment envelope is introduced.

## Service placement and addressing

Four finite unary methods belong to `ContentService`, alongside `ReadContent`:

| Method | Selector | Result |
| --- | --- | --- |
| `GetFileSymbols` | Path | Paged defined symbols: address, name, kind, span, semantic hash |
| `GetDefinition` | Path and `CodePosition` | Covering occurrence and definition, or typed reason |
| `GetSemanticRefs` | Symbol address or position, kind, hop cap | Paged original oriented edges; refs, callers or callees |
| `GetSemanticImporters` | Path, hop cap | Paged reverse-dependency file paths and distances |

These methods share revision/source ownership, entry filtering, deployment targets
(weft and daemon), resource reader authority and repository-inspection capability
with content reads. They inspect an already stored graph; `AnalysisService` owns
execution and retained server-produced artifacts, and `SearchService` owns queries
over search projections. Neither substitutes for the admitted attachment.
The owed `GetSemanticRefs` and `GetSemanticImporters` names are retained; the
single-state envelope becomes one exact v2 `RevisionRef`, never a multi-state
`QuerySemanticGraph`.

Every request includes a required owning `ThreadRef`, exact `RevisionRef`, and
`ReadBudget`. Spools must match, and the revision must be accepted source history
of that exact Thread (including an admitted genesis seed). Native State revisions
are the initial ingestion profile. An exact Git revision can be read only when
the endpoint has an independently validated exact native capture mapping; no
mapping means `NO_INDEX` after source authorization, never a mutable-ref or latest
revision fallback. Unsupported source formats use the existing typed
`UNIMPLEMENTED` call failure. Paths are normalized repository-relative files:
reject empty paths, absolute paths, dot/dot-dot components and NUL; never follow
symlinks, gitlinks or spoollinks. An address/hash confers no authorization.

`CodePosition.byte_offset` is required and zero-based in the exact source blob's
UTF-8 encoding. Optional `line` and `column` are supplied together, one-based;
columns count UTF-8 bytes, not Unicode scalars, graphemes or UTF-16 units. LF
starts a new line; CR in CRLF counts as a byte of the preceding line. A position
at EOF, beyond EOF, inside a UTF-8 code point, or outside a line is
`OUT_OF_BOUNDS`. Missing required coordinates, malformed UTF-8 source, or
inconsistent redundant coordinates use `INVALID_ARGUMENT/FIELD_INVALID`.
Valid source-byte validation does not parse code.

Occurrence byte spans are half-open. Definition `SymbolEntry.span` and
`SourceLocation` use one-based inclusive line bounds; `CodeSpan` preserves those
bounds and includes byte endpoints only when stored evidence supplies them.
Deriving line numbers from validated source bytes is allowed; inventing a
definition byte span from whole-line bounds is not. Symbols preserve the native
kind tags and `hd-sem-sym-v1` semantic hash; the hash is not a CAS address.
`CodeSymbolAddress` preserves `SymbolAnchor`'s path and `container::path::name`
spelling. Optional `definition_index` identifies the canonical `symbols` array
entry of the pinned attachment; it does not survive attachment replacement.

## Outcomes, readiness and attestation

Every response has `CodeNavigationMetadata`: exact Thread/revision, usable
`index_present`, query-language `resolver_present`, language, attestation and
selected attachment ID. `resolvers` is a sorted unique list for the query language
and visible result languages. A resolver flag describes cross-file resolution
used by that attachment, rather than just code installed on the serving endpoint.
Only Rust and TS/JS currently have cross-file resolvers. Parsed Python and other
languages can still return outlines, same-file definitions and same-file refs
with `resolver_present=false`. Resolver versions must be recognized; grammar
presence alone does not assert cross-file resolution.

`index_present=true` means a complete, usable, admitted client attachment in the
authorized Thread/revision view, and `attestation=CLIENT_ATTESTED`. Otherwise
attestation is `UNSPECIFIED` and `attachment_hash` is empty. Missing index is not
an exhausted successful collection. No server AnalysisArtifact or search table
changes these fields. The attestation is provenance, not server verification.
[weft#2022](https://github.com/HeddleCo/weft/issues/2022) may later cross-check in
background workers, flag mismatches, downgrade trust or quarantine. Quarantined
indexes are unusable and yield `NO_INDEX` with no usable-index identity. A future
trust projection can expose a downgrade to authorized readers; this contract
does not claim `SERVER_VERIFIED` or perform inline tree-sitter cross-checks.

Source/Thread/path authorization happens before graph metadata or outcomes.
For an authorized file, reason precedence is:

1. `OUT_OF_BOUNDS` for an invalid position range.
2. `NO_INDEX` when no usable exact attachment exists.
3. `AMBIGUOUS` for multiple visible covering occurrences or definitions.
4. A unique recorded visible definition/edge is returned, including same-file
   results when `resolver_present=false`.
5. `NO_RESOLVER_FOR_LANGUAGE` if resolution is needed but unsupported for that
   language; otherwise `NOT_FOUND` when no visible occurrence/target is known.

Definition responses always select exactly one outcome arm; reason must never
be `UNSPECIFIED`. They retain a unique visible occurrence on unresolved answers.
Collections use reason `UNSPECIFIED` for success (including truly empty results),
and other reasons for unavailable/ambiguous roots. Unavailable collections are
empty, have no next token and `exhausted=false`; successful empty collections
have `exhausted=true`. File outlines do not require a cross-file resolver.
An accessible occurrence whose target is absent or hidden uses `NOT_FOUND` in
both cases; it must never expose a hidden spelling, path, span, hash or candidate
count. Hidden occurrences do not participate in ambiguity decisions.

## Paging, graph traversal and bounded work

Default page size is 100; maximum is 256. `ReadBudget.max_items` caps returned
rows, and `max_frame_bytes` and `max_snapshot_bytes` each cap the whole encoded
unary response including metadata/page information. Zero uses endpoint defaults;
defaults never exceed 256 rows or 1 MiB. Hard response ceiling is 1 MiB.
Reject requests exceeding hard or advertised endpoint limits with
`CallFailureCode.RESOURCE_EXHAUSTED` and `ErrorReason.QUOTA_EXCEEDED`.
Do not silently widen a budget. If even one row plus metadata cannot fit, return
the same typed failure; otherwise return a resumable page. Definition results
follow the same byte budget. Count only visible emitted rows against max_items.

`hop_cap=0` means one hop; maximum four. `REFS_OF` traverses incoming RefersTo,
Calls and TypeRef edges; `CALLERS_OF` traverses incoming Calls only;
`CALLEES_OF` traverses outgoing Calls only. A position first resolves to one
visible definition. Incoming traversal continues from a source occurrence's
unique enclosing definition; outgoing traversal continues from each target
definition. No enclosing definition means a leaf, not fabricated membership.
Edges preserve source-to-target orientation and native kind. Emit each edge
once at its minimum hop; visit each definition once at minimum distance. Importer
queries walk `ReverseDependencyIndex` backwards, returning each importing path
once at minimum distance. The selected path is excluded on cycles. All traversal
stays in the requested Thread/revision; authorization precedes visiting edges.

Outline order is `(path, start_line, symbol_id, definition_index)`. Graph order is
`(hop, source.path, source.local_id, target.path, target.definition_index, kind)`;
importer order is `(hop, path)`. Each page uses the same immutable attachment and
revision. Tokens are opaque, integrity protected and bound to endpoint, method,
Thread, revision, attachment, normalized selector/kind/hop cap, budget/page size
and caller authority. Recheck current authority and entry visibility on every
page; changed attachment or authorization invalidates the token using
`CURSOR_INVALID`. Neither tokens nor errors reveal hidden sequence numbers.

Work is capped at 100000 visited visible graph records per query, with endpoints
free to advertise smaller caps. A bounded deterministic prefix may be returned
with `truncated=true` when graph depth or work caps omit visible reachable rows.
That bit is independent of paging: `next_page` alone does not set it, and
`exhausted=true` means all rows within the capped traversal have been paged,
not that the entire graph was traversed. Only visible successors can set the bit.
If an endpoint cannot produce a safe deterministic prefix within its work bound,
it must fail `RESOURCE_EXHAUSTED`; no fabricated complete empty answer. Hidden
objects may consume internal defensive work, but cannot affect successful
readiness, counts, truncation or page boundaries.

## Ingestion using the existing attachment lane

`PublishContentOpen.semantic_indexes` is optional, with at most one manifest.
Omission retains source-only publication. Each manifest commits the original
StateAttachment ID, semantic root Blob hash, exact native `State.tree` hash and
the sorted unique `(Blob hash, decoded canonical size)` semantic object inventory.
The request opening proof, operation dedup and transfer plan bind all these
fields along with Thread, revision, policy, pack/index identities and endpoints.
Reusing an operation ID with another manifest is an operation-ID conflict.

The original attachment travels as `TransferSidecar` with `KIND_ATTACHMENT`,
the exact opening revision, `record_format="heddle-state-attachment-msgpack-v1"`,
original named MessagePack `StateAttachment` bytes, and address algorithm
`"state-attachment"`. Its 32-byte digest is the native typed ID:
`BLAKE3(UTF8("state-attachment") || u64_le(byte_length) || 0x00 || bytes)`.
It must decode as `StateAttachmentBody::SemanticIndex(root_hash)`, bind the exact
native State ID, match the manifest ID/root and retain attribution, creation time
and same-kind predecessor. No `AnalysisArtifact` conversion is permitted.
The existing attachment classification requires current spool-write, plus
per-author authorship, schema, provenance, integrity, ownership and predecessor
validation; a courier, hash or original attribution is not current authority.
Owner authorization on a sidecar never bypasses this ordinary-write rule.
For direct publication, attribution must match the authenticated author/agent.
Publishing another author's attachment requires independently verifiable
authorship evidence admitted by the existing provenance rules; when unavailable,
reject rather than treating the courier's opening proof as that author's proof.

All semantic canonical object payloads travel as Blob records in the existing
declared native pack/index pair. Only the manifest's semantic extras are exempt
from the source-only closure exclusion. For each payload, Blob identity is
`BLAKE3(UTF8("blob") || u64_le(byte_length) || 0x00 || payload)`.
Validate exact lengths, object identities and recognized versioned native codecs.
The closure includes root, semantic directory/file nodes, binding delta and its
entire parent chain, referenced target file nodes, importer index and every
other transitively referenced semantic object. Reused objects still appear in
the manifest and must be independently proven available under this transfer's
scope; a bare hosted CAS hit cannot satisfy the manifest. Opaque entries refer
to exact source blobs, which belong to the separately authorized source closure.
No unlisted semantic object, missing reference, cycle or unrelated history is
accepted. Live `ReplicateThread.operations` continues to carry original causal
dependencies/admissions; it does not independently ingest an index.

The source-tree commitment equals the exact admitted revision's `State.tree`.
`SemanticIndexRoot.tree` names a semantic tree and is not compared to that source
hash directly. Walk both trees: normalized semantic paths must exist in the
source, directories must agree, parsed file `source_blob` must equal that path's
exact source Blob hash, and opaque commitments must match their source targets.
Validate occurrence spans against source byte lengths/code point boundaries,
definition line ranges, edge occurrence IDs, definition indexes and referenced
file nodes. Binding deltas may reference historical nodes in their closure, but
the materialized effective graph may contain only current-tree file bindings.
Reverse-dependency rows and effective edges must name paths in that same tree.
Historical semantic dependencies require independently validated provenance and
disclosure ceilings; importing them never publishes historical source bytes or
widened audience access. They remain internal to the effective-graph projection.
Reject mismatched source tree, malformed/incomplete closure, inconsistent
addresses or impossible spans using `INVALID_ARGUMENT/FIELD_INVALID` with a
field path, never an index-ready success. This validates structure and binding;
it does not prove the client's semantic interpretation is correct.

Supporting endpoints advertise `TransferReady.semantic_index_limits`, each
positive and at most these fixed ceilings:

| Bound | Hard maximum | Accounting |
| --- | --- | --- |
| Nodes | 100000 | Unique semantic objects plus each inline directory entry, symbol, scope, import, occurrence, edge and reverse-dependency row; across the entire publication |
| Bytes | 67108864 (64 MiB) | Sum of all decoded canonical semantic payload bytes, original attachment bytes and encoded manifest bytes; duplicate transmitted bytes also charge general transfer limits |
| Depth | 64 | Both decoded MessagePack nesting and longest reference walk, including binding-delta parent chains; root starts at depth one |

Check advertised lengths/counts before allocation, stream under the general
frame/transfer bounds, and recheck actual decoded counts while walking.
Enforce nested collection/string lengths, checked arithmetic and iterative walks;
never trust the manifest's sizes in place of actual bytes. Bounds are independent
of source limits and include already-retained semantic objects. Reject excess
nodes, bytes or depth with typed `RESOURCE_EXHAUSTED/QUOTA_EXCEEDED`, identifying
the offending request field without exposing unrelated objects. Absent limits
means this profile is unsupported: reject a nonempty manifest with
`UNIMPLEMENTED`, never ignore it and return a source-only successful receipt.

Finish validates current authority, policy and all closures before one atomic
storage/projection publication. Install attachment and closure durably with a
Thread/revision lookup and `CLIENT_ATTESTED` provenance, then issue the existing
`PublicationReceipt`. Accepted inventory commits the existing pack extents
followed by each length-delimited `SemanticIndexPublication` in manifest order
(empty manifests preserve the existing inventory hash). Publication never changes
causal heads. Interruption, mismatch or limit failure leaves no usable index,
source-availability change or successful receipt. Retrying a committed exact plan
replays the receipt. Index-only restoration is a publication of an already
available exact source plus the new manifest; it cannot alter that source.

Retain original bytes, the entire semantic closure, attribution/predecessor
records and lookup as one reachable unit under the source Thread's retention
policy. GC must not delete any member while the attachment is retained, and must
remove stale lookup/projections when it expires, is purged or quarantined.
Readiness follows usable retained closure, never dangling rows. Selection follows
native same-kind predecessor currency; incomparable concurrent live index heads
are `AMBIGUOUS` with no selected attachment identity, never last-writer-wins.
For that case `index_present=true`, `attestation=CLIENT_ATTESTED`, and no query
payload; definition/collection reason is `AMBIGUOUS`. No hidden head participates.

Fetch explicitly opts in with `TransferSelection.include_semantic_index`.
`TransferReady.semantic_indexes` gives the same complete manifest; original
attachment bytes use the existing sidecar frame and objects use the pack/index
pair. The receiver applies the same integrity/binding/closure limits. A
quarantined, absent or unauthorized index contributes no manifest. Raw Fetch
requires authority for every closure member, including historical semantic
dependencies and hidden entries; otherwise omit the entire index manifest and
sidecars, without hidden-member counts or a partial semantic closure. Metadata
replication alone and Fetch receipts never grant permission to re-publish it.

## Authorization and public-tip embargo

The RPC contract matches content reads: public resource read,
`PROOF_IF_AUTHENTICATED`, `RESOURCE_READER` on `revision.spool`, existence hiding,
safe retry and read-only effect. Anonymous reads still pass every live public
source gate; supplied account credentials require proof. Require the owning
Thread's audience and source policy independently of Spool access. Inaccessible
Thread/revision/file requests return the same call-level `NOT_FOUND` as absent
ones, before returning index/language metadata. Do not put typed navigation
reasons or client attachment IDs on a denied call.

The canonical [identity/resource authorization model](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/docs/IDENTITY_RESOURCE_AUTHORIZATION_MODEL.md)
was read, including ordinary-write visibility and attachment classifications.
That revision does not contain a public-tip embargo section. The concrete
public-tip rules were therefore also checked in
[visibility.rs:196](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/crates/weft-sync/src/visibility.rs#L196),
[thread_source.rs:786](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/crates/weft-hosted/src/service/scope/thread_source.rs#L786)
and [whole_tip_source.rs:23](https://github.com/HeddleCo/weft/blob/49e82a27502f501c3a24418eac6a1e0544f3e7b7/crates/weft-hosted/src/service/scope/whole_tip_source.rs#L23):
an unserved reachable Private/Restricted embargo ancestor withholds a later
public tip; Internal/TeamScoped retain the existing walk-through rule. Absence
of a visibility sidecar inherits Spool visibility; an explicit sidecar is
evaluated as declared. Historical and metadata-only captures use the same
bounded live ancestry verdict; source hashes or public descendants never bypass it.

Apply inherited entry redaction/visibility to the requested file, occurrence,
definition, importer and both edge endpoints before metadata, traversal,
ambiguity, counts or pagination. Never traverse through hidden intermediary
definitions to expose visible downstream results. Filter before page boundaries,
and omit total counts unless they count only caller-visible rows. Raw attachment
bytes and raw graph objects are not exposed through these RPCs. Semantic facts
are authored sidecars: an identical source in another Thread does not grant
access to this Thread's attachment or its provenance.
