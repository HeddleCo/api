# Public catalog rows, filters, paging and summaries

`WorkspaceService.ObserveCatalog` discovers publicly visible Spools as `CatalogEvent.spool` (`SpoolOverview`). Its existing public authorization scope is unchanged: private Spools are excluded even for their members. Every emitted row must also be readable by the caller under the current visibility/ancestry rules. `public_owner` contains only an already-public owner handle and display name. It never exposes `owner_genesis`, account identifiers, membership, or private identity. `last_activity_at` reflects the latest known **public** activity; private activity cannot move it. `catalog_activity` counts public open Threads and public landings in the trailing 30 days. Counts derived from rollups are display hints, not authority or landing eligibility.

Triage against alpha.16 (`2858ab54ae00f827e290cc66579d1f4e42ab9b02`):

| Weft issue | Classification | Contract |
| --- | --- | --- |
| [2504](https://github.com/HeddleCo/weft/issues/2504) | API-NEEDED | `ObserveCatalogRequest.filter = 5` (`CatalogFilter`). |
| [2505](https://github.com/HeddleCo/weft/issues/2505) | WEFT-ONLY | Existing `ObserveCatalogRequest.query = 1`, `SpoolOverview.path_segments = 12`, `public_owner = 16`, and `PublicOwner.handle = 1`. Expand matching semantics below; no wire addition. |
| [2506](https://github.com/HeddleCo/weft/issues/2506) | API-NEEDED | `CatalogEvent.summary = 6` (`CatalogSummary`) with linkable `CatalogLeader` values. |

## Search and filter semantics

Trim surrounding whitespace and use deterministic Unicode case folding for the query and searchable values. A nonempty query is a **literal substring**, including `/`, matched against any public name, slug, description, the canonical address (`path_segments` joined with `/`), any individual address segment, or `public_owner.handle`. An empty query matches all eligible catalog rows. This is case-insensitive, so `HEDDLECO/WEFT` matches `heddleco/weft`, and `heddleco/` browses that address text across the catalog. Do not consult private aliases, owner account IDs, private descriptions or unreadable path segments. The existing selected `CatalogSort` governs order; address matches do not override its pagination order. No new relevance sort is introduced.

An absent filter and an empty `CatalogFilter` are semantically identical and preserve the unfiltered behavior. A false boolean imposes no predicate (it does not select the complement). All enabled predicates, the prefix, and query are ANDed **before** paging and summary aggregation:

| Field | Predicate |
| --- | --- |
| `has_open_threads` | At least one public, readable Thread on the Spool has lifecycle `DRAFT`, `ACTIVE`, or `READY`. Count each Thread once. `LANDED`, `ABANDONED`, unknown and unspecified lifecycle values are excluded. |
| `landed_within_30d` | At least one successful public, readable `LandingRecord` has `executed_at` in `(as_of - 30 * 86400 seconds, as_of]`. Count distinct signed landing operation digests, once each in the containing target Spool; retries, failed attempts and lifecycle changes without a successful landing add nothing. Separate successful landings of the same source count separately. This is a rolling duration, not a calendar month. |
| `require_review_to_land` | The catalog row's `SpoolSettings.require_review_to_land` is true. This selects the setting, not outstanding review tasks, policy evaluation, approval count or current landing readiness. Missing settings do not establish true. |
| `namespace_prefix` | A literal prefix of the canonical `path_segments` array, case folded by the same normalization as query. `["heddleco"]` matches that segment and its descendants, not `heddlecompany`; `["heddleco", "weft"]` matches that complete leading pair. It is one ordered prefix, not an OR list. Empty means unrestricted. Empty segments, embedded `/`, `.` and `..` are invalid input and rejected, never silently ignored. |

The row `catalog_activity`, filter predicates and summary use the same public projection and rollup boundary. Unknown or unavailable activity does not establish an enabled activity predicate. It must not silently become a zero in an allegedly complete summary: if required rollups cannot be obtained within the freshness bound, fail the snapshot with the existing stream failure contract instead of presenting incomplete totals as complete. The server may bound query/prefix input lengths under its normal request limits and reject oversized input; it must not truncate it and change the match.

## Sorting and tokens

`CatalogSort.UNSPECIFIED` keeps the legacy `(slug, Spool UUID)` ascending order:

| Sort | Primary key | Tie break |
| --- | --- | --- |
| `UNSPECIFIED` | Slug, ascending, using the legacy collation | Spool UUID, ascending |
| `NAME` | Case-normalized public name, ascending | Spool UUID, ascending |
| `PATH` | Case-normalized full canonical path, ascending | Spool UUID, ascending |
| `RECENT_ACTIVITY` | `last_activity_at`, descending, unknown last | Spool UUID, ascending, including among unknown timestamps |

Name/path sorting and cursor comparison use deterministic normalization and collation. `PageInfo.matching_count`, when present, is the exact number of caller-visible rows matching **both query and filter** across the entire catalog snapshot, not the loaded page. `exhausted` and `next_page` describe that same set. The optional count may be absent when expensive; an absent count is not zero or a global unfiltered total.

A page token is opaque and binds the normalized query, canonical filter (all three booleans plus ordered normalized prefix; absent equals empty), selected sort, caller scope, catalog generation/snapshot boundary, last primary key and last UUID. The server applies the corresponding exclusive keyset predicate. It rejects a token reused with a different query, filter, sort or caller scope as invalid input; it never ignores the changed input. A stale generation token is rejected and the client restarts from the first page. The generation advances when caller-visible membership, filter inputs, name, canonical path or an activity sort key changes, including expiry out of the rolling window. Advancing a caller's generation solely because hidden data changed would create an existence oracle and is forbidden. The observation binding/resume cursor also binds query and filter under the existing stream contract.

## Summary confidentiality, freshness and cost

A server implementing these additions emits one `CatalogEvent.summary` during each replacement snapshot, before its snapshot-complete boundary, even for an empty result. It aggregates the **entire** caller-visible query/filter set, independent of page size, page token or sort. Absence from an older server means unavailable, not zero. `as_of` is a required timestamp giving the evaluation boundary; activity windows use UTC seconds and exclude their lower endpoint. `spool_count` is the exact matching count; `open_thread_count` and `landed_30d` sum the row metrics. `active_7d` counts matching Spools whose public `last_activity_at` is in `(as_of - 7 * 86400 seconds, as_of]`, once per Spool, not activity events. Future timestamps do not count.

The summary is a **snapshot**, not live-updated and not refreshed on a cadence within that observation. Live row upserts/removals do not imply a revised summary. Open a new replacement snapshot to refresh it. Resume preserves the original snapshot's summary/boundary; if it cannot be retained, the server requires a replacement snapshot under the ordinary stream contract. Use indexed public projections and precomputed public rollups; rollups may lag `as_of` by at most **300 seconds**. All rows and aggregates in a snapshot use the same rollup cut. `approximate=false` means exact aggregation of that projection, not a transactionally current count of underlying operations. Existing authority expiry/revocation rules still terminate or invalidate streams; a cached summary must never be replayed into a caller scope that can no longer read its entries.

Each leader list has at most **5** distinct matching Spools with a positive metric, ordered by that metric descending, then canonical Spool UUID ascending. Zero-count Spools are excluded; fewer than five is valid. `CatalogLeader` includes only the readable Spool ref, public name, independently disclosable canonical path and the corresponding metric (`count`), so a leader outside the loaded page remains linkable without a second read. The two lists may overlap.

For more than **10,000 caller-visible matching Spools**, the server may cap activity aggregation at the first 10,000 matching Spools ordered by UUID, setting `approximate=true`. In that case activity totals are **unscaled lower bounds**, and the lists are leaders among those candidates, not guaranteed global leaders. `spool_count` stays exact (an indexed count); there is no probabilistic extrapolation. The server may instead use precomputed exact aggregates and leave `approximate=false`. At or below 10,000 matches it must aggregate all matches and use false. Page counts and predicates remain exact over the snapshot projection regardless of this aggregation cap. Work is bounded by indexed selection/counting plus at most 10,000 metric rows and two five-entry leader lists, avoiding per-result reads. Implementations unable to supply this contract within their read budget fail explicitly rather than scan without a bound or return a misleading zero.

**Confidentiality applies before every predicate, rollup, count, candidate limit and ranking.** Only public catalog Spools readable by the caller participate. Private/member-only activity on public Spools is also excluded. Hidden Spools must not alter totals, leaders, the approximation threshold/flag, rollup freshness, or token validity. Global rollups or caches must be scoped/projected before aggregation; they must not reveal hidden existence through a changed count, label, placeholder or suppression reason. The shared fixture's `outsider-before-private` and `outsider-after-private` vectors are byte-identical at the same snapshot boundary despite an added high-activity private Spool. This is a contract projection vector, not evidence that weft's live authorization implementation is complete; enforcement remains in weft#2504/#2506.

Primary language and size buckets remain deferred: the public catalog source has neither a cheap language signal nor a shared size measure. This additive contract introduces no version bump, new RPC, relevance score or authorization scope.
