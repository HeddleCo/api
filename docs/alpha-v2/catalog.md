# Public catalog rows and paging

`ObserveCatalog` returns publicly visible Spools as `CatalogEvent.spool` (`SpoolOverview`). `public_owner` contains only an already-public owner handle and display name. It is populated only on publicly visible rows. It does not expose `owner_genesis`, account identifiers, membership, or any private identity. `last_activity_at` reflects the latest known **public** activity; private activity cannot move it. `catalog_activity` counts public open Threads and public changes landed in the trailing 30 days. Counts derived from rollups can lag and are display hints.

`CatalogSort.UNSPECIFIED` keeps the legacy `(slug, Spool UUID)` ascending order. The server orders by one of these pairs:

| Sort | Primary key | Tie break |
| --- | --- | --- |
| `UNSPECIFIED` | Slug, ascending, using the legacy collation | Spool UUID, ascending |
| `NAME` | Case-normalized public name, ascending | Spool UUID, ascending |
| `PATH` | Case-normalized full canonical path, ascending | Spool UUID, ascending |
| `RECENT_ACTIVITY` | `last_activity_at`, descending, unknown last | Spool UUID, ascending, including among unknown timestamps |

Name and path keys must use a deterministic normalization and collation for both ordering and cursor comparison. A page token is opaque to the client and binds the normalized query, selected sort, caller scope, catalog generation, last primary key, and last UUID. The server applies an exclusive keyset predicate matching the chosen order. It rejects tokens from another query or sort and tokens whose catalog generation has changed. The generation must advance when visibility, name, canonical path, or an activity sort key changes, so a page never silently skips or repeats rows after a sort key moves. Clients restart from the first page after a stale token error.

An implementation can read a page with one bounded query over public Spools, public owner labels, and precomputed per-Spool activity rollups. Each sort uses a sortable column or expression and the UUID tie break; the activity order needs an explicit null branch in its keyset predicate. Store or index the normalized name and path keys and the public activity timestamp where needed. The new row fields do not require a lookup per result row.

This contract does not define a primary language or size bucket. The current public catalog source has neither a cheap language signal nor a shared size measure, so those optional fields are deferred.
