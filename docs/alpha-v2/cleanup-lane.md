# Tapestry cleanup lane contract

This additive v2 bundle is intended for the next alpha after alpha.15. It does
not change package versions, signed records, canonical operation encodings, or
owner policy. Weft implements population/enforcement; tapestry consumes the
projections. Generated bindings alone do not implement these behaviors.

## Alpha.15 triage

Baseline: `54f3e3fd16ddf319c06d990f6fa691fdd12c8182` (`origin/main`). Line
references below refer to that commit, not the expanded schema.

| Weft issue | Triage | Missing contract / existing portion |
| --- | --- | --- |
| [2496](https://github.com/HeddleCo/weft/issues/2496) C1 | API-NEEDED | Exact-revision bounded path listing. `TreeRead` has a bounded depth (`content.proto:13–23`); Search has no path domain and indexes source tips only (`content.proto:151–165,182–240`). |
| [2497](https://github.com/HeddleCo/weft/issues/2497) C2 | API-NEEDED | `SpoolOverview.ancestors`; **WEFT-ONLY portion:** populate existing `parent = 2` (`views.proto:111`) and reuse `SpoolAddress` (`common.proto:71–74`). |
| [2498](https://github.com/HeddleCo/weft/issues/2498) C4 | API-NEEDED | `ContextRecord.author_display_name`, `DiscussionTurn.author_display_name`. **WEFT-ONLY history portion:** `CaptureSummary.principal_name = 11`, `principal_email = 12` already exist (`thread.proto:387–388`); source history also has `StatePrincipal.name = 1` (`common/repository.proto:159`). No duplicate history field. |
| [2499](https://github.com/HeddleCo/weft/issues/2499) C6 | API-NEEDED | `ProviderRepository.default_branch`, `refs`, `refs_status`, opt-in `ObserveIntegrationsRequest.include_refs_for`. **WEFT-ONLY portion:** `linked_spools = 7` already specifies caller-visible account-wide links (`integration.proto:29–35`); no new scope input is needed. |
| [2500](https://github.com/HeddleCo/weft/issues/2500) C7 | API-NEEDED | `ActionAvailability.capability` and `Blocked.error`. **WEFT-ONLY call-failure portion:** `CallFailure.error = 4` already carries `ErrorDetail` (`common/errors.proto:73–78`), as does `StreamFailure.error = 5`; populate these instead of adding another channel. |
| [2501](https://github.com/HeddleCo/weft/issues/2501) C8 | API-NEEDED | `SearchHit.thread_name = 10`, `spool_path = 11` (`content.proto:242–263` has neither). |
| [2502](https://github.com/HeddleCo/weft/issues/2502) C9 | API-NEEDED | `ThreadRelationship.name = 3`, `lifecycle = 4` (`thread.proto:38–48` has only thread and kind). |

## C1: exact-revision paths

`ContentService.ListPaths` is a finite server stream at a required `RevisionRef`
and required owning `ThreadRef`; both Spools must match, and the exact accepted
revision must belong to that Thread. This supports readable retained revisions
as well as tips and does not change Search's tip-only semantics. No fallback to
another revision, latest pointer, or Thread containing the same source object.

`prefix` is a case-sensitive literal UTF-8 prefix of the normalized
repository-root-relative path. Empty lists all paths; `src/` selects descendants
of that directory, whereas `src` also matches `src-old/file`. No substring,
fuzzy, glob, Unicode folding, or structured query syntax. NUL, absolute paths,
backslashes, and `.`/`..` segments are invalid. Return leaf paths (regular files,
symlinks, gitlinks, spoollinks), never directory rows; never follow links.
Results are unique and ordered by ascending unsigned UTF-8 bytes of the whole
path, with no depth cap and no ranking.

`page.size`: zero means 1000, maximum 4096; larger values are INVALID_ARGUMENT
with FIELD_INVALID for `page.size`. ReadBudget zero fields choose advertised
finite defaults; nonzero values are upper bounds that may shorten the page.
The generic `normalize_page_size` / `normalizePageSize` helpers do not apply to
these RPC-specific bounds. The first event is the mandatory effective `accepted_budget` echo under the
shared stream.proto clamp/floor rules. Charge every event including this echo and completion. Paths are emitted individually so
`max_frame_bytes` bounds every frame. Fixed request/control overhead that cannot fit is INVALID_ARGUMENT before
matching; data exceeding the window returns PARTIAL with continuation, never
RESOURCE_EXHAUSTED solely because of matching data. Completion uses section `paths`, exact `computed_for`,
coverage, and PageInfo; COMPLETE means this window was evaluated, while
`exhausted` alone means there are no more visible matches. Unavailable source
uses coverage UNAVAILABLE without a fabricated empty COMPLETE result. Missing
completion before FIN means interruption. No server-wide result truncation:
continue until exhausted. Counts are omitted unless an exact visible-only count
can be established within the bounded read.

Cursors are opaque and bound to endpoint, method, exact caller authority,
Thread, revision, prefix, ordering, and accepted page/budget. Invalid/mismatched
cursors use CURSOR_INVALID and require restarting. A continuation rechecks
current authority; no token is an access grant. Apply the same live gates as
ReadContent: resource reader on revision.spool, independent Thread audience and
source policy, accepted membership, inherited entry visibility/redaction, and
bounded public-tip ancestry/embargo verdict. An unserved reachable
Private/Restricted ancestor withholds a later public tip; hashes and public
descendants never bypass that gate. Filter entries before limits, ordering,
counts, coverage and cursor construction; hidden-only changes never affect
those outputs. Absent and forbidden Thread/revision requests have identical
NOT_FOUND failures without hidden IDs, paths, counts, or distinct reasons.
Recheck eligibility immediately before handoff. See the canonical
[authorization model](https://github.com/HeddleCo/weft/blob/main/docs/IDENTITY_RESOURCE_AUTHORIZATION_MODEL.md)
and [existing content-read gates](code-navigation.md#authorization-and-public-tip-embargo).

## C2: spool ancestry

`ancestors` contains current `SpoolAddress` entries ordered root → immediate
parent, excluding self. Every entry has its stable ID and authorized canonical
display path. Omit unreadable ancestors entirely; no blank slots, redacted
segments, tombstones, hidden counts, or explanations. The list is the visible
subsequence, so consumers must not infer that adjacent entries are actual
parent/child or that the first entry is the physical root. Canonical paths may
only contain segments independently disclosable to this caller; omit an address
whose full path cannot safely be disclosed. Apply the same rule to the existing
self `path_segments`, rather than reconstructing hidden paths from ancestry.

Every emitted nested `SpoolOverview` has its actual immediate `parent = 2` set;
roots have no parent. Never infer or substitute a more distant visible parent.
To reconcile this guarantee with existence hiding, an overview whose immediate
parent identity is unreadable is withheld as a whole (no placeholder row or
ancestry-specific reason). This does not grant parent read access, change the
child's ACL, or prohibit independently authorized child content/sections.
Unreadable outer ancestors can still be omitted while the readable immediate
parent remains. Exact reads use the same absent/withheld overview shape.
Addresses are current presentation, never mutation authority. Include this
projection on all overview surfaces, not just a first workspace page.

## C4: author display

`ContextRecord.author_display_name = 15` and
`DiscussionTurn.author_display_name = 10` are server-derived **live** display
names at observation time, resolved from the existing authenticated
`principal_id` attribution. Delegated turns show the human account's name;
`agent_id` remains separate. Renames affect subsequent observations, including
historical context revisions/turns. Leaving membership does not erase an
otherwise disclosable identity. Unresolved, deleted, or caller-withheld authors
produce the same empty string; never require member-list access. An imported
provider label is not proof of a bound account: without an authenticated
binding, leave this field empty and keep any original qualified label intact.
No guessed identity, stripped `gh:` prefix, or verification badge from a name.
The field carries no email, handle-verification claim, credentials, or authority.
It is outside signed operation bodies and never changes their actor IDs.

History already carries the producer's **snapshot** claimed name/email through
`CaptureSummary.principal_name/principal_email` and `StatePrincipal.name/email`.
Populate these from original source attribution, including departed/imported
producers; do not silently replace immutable claims with current account names.
Existing AttributionAssurance and signed binding proofs remain authoritative
about provenance. Names are display claims, not identity verification. Apply
existing record and personal-data disclosure gates; unavailable names stay
empty. No new history field or reverse identity lookup is needed.

## C6: provider defaults and refs

`default_branch = 8` is the provider's current exact branch name (e.g. `main`,
without `refs/heads/`); empty means unknown/unavailable/no default. Never guess
main/master. It is available independently of optional refs and may name a
branch outside the returned page. It is provider metadata, not import authority.

`include_refs_for = 6` selects at most eight unique `(connection,
provider_repository_id)` pairs using `ProviderRefsRequest`, each with its own
PageRequest. Requires `include_repositories = true`; selected connections must
be within request scope and currently authorized. Do not query a provider or
emit details for unauthorized repositories. Unknown and forbidden selectors
have the same existence-hiding failure. Repository inventory paging remains
independent: a selection loads refs only when that repository row is emitted;
no synthetic row, automatic inventory widening, or change to linked_spools.
Use the stored provider credential, including private repository access, and
revalidate the exact connection/installation/repository association.

Each repository ref page defaults to 128 and caps at 512; eight selectors cap a
snapshot or delta batch at 4096 refs, additionally bounded by ObserveOptions.budget.
Use these RPC-specific bounds, not the generic page helper. A repository row
and its embedded refs must fit max_frame_bytes; shorten the visible ref page
and return a continuation when needed. Fixed selection/control overhead that cannot fit is INVALID_ARGUMENT before
matching. Data exceeding the window returns PARTIAL with continuation.
Excess
selector count, duplicates, or oversized pages are INVALID_ARGUMENT with the
corresponding FIELD_INVALID. `refs = 9` contains branch/tag entries sorted by
unsigned UTF-8 bytes of their fully qualified names (`refs/heads/...` or
`refs/tags/...`), unique by name. `head_oid` is the exact lowercase provider Git
object ID: a tag uses its ref target (possibly an annotated tag object), not an
implicitly peeled commit. `kind = 0` or unknown means unknown, never a branch.

`refs_status = 10` is absent when unrequested. When requested it uses section
`provider_refs`, coverage and PageInfo: COMPLETE+exhausted proves a known empty
set; PARTIAL/UNAVAILABLE means no claim of completeness, regardless of how many
refs appear. Provider failure/rate limits do not fabricate known-empty refs.
Continuation tokens bind exact caller authority, connection, repository, page,
budget and provider snapshot. A moving provider snapshot invalidates the cursor
with CURSOR_INVALID; never silently skip/duplicate entries across mutations.
No provider tokens, secrets, or hidden refs appear in status/counts/cursors.
Unknown/unrequested metadata must survive older servers as absence.

## C7: capabilities and typed refusal

`Capability` values are stable: UNSPECIFIED=0, RECORD_REVIEW=1, LAND=2,
PUT_GRANT=3, CREATE_INVITATION=4, REVISE_SPOOL=5. They identify semantic actions
independently of RPC spelling; `method` remains the concrete invocation route.
Other actions can remain UNSPECIFIED until explicitly added. Never rename,
renumber, reuse, or infer new enum semantics from method suffixes.
UNSPECIFIED and unknown numeric values are unknown and grant no affordance.
Known values still require implemented && authorized && no unmet requirements;
advice never authorizes a call. Older readers ignore the new field and keep
their existing route behavior; new readers accept old missing values as zero.

Call-level refusals already use `CallFailure.error = 4` and streaming failures
`StreamFailure.error = 5`. Populate existing ErrorDetail on spool settings,
invitation, seat and plan refusals; no duplicate error channel. For an admitted
mutation returning `MutationReceipt.blocked`, new `Blocked.error = 2` carries
the same typed reason alongside existing requirements. One primary reason is
chosen deterministically by admission order; validation precedes authorized
policy/plan evaluation. Use FIELD_INVALID/FIELD_REQUIRED plus the actual proto
field path for validation; POLICY_DENIED for authorized policy refusal,
PLAN_LIMIT for plan/seat limits, QUOTA_EXCEEDED for exhausted quota, and
ROLE_INSUFFICIENT for insufficient known resource rights. Use existing typed
context when needed. English prose remains display-only. Missing/UNSPECIFIED or
unknown reason means generic refusal, never success or automatic retry.
Existence-hiding failures take precedence: RESOURCE_NOT_FOUND with empty
resource/field/context for absent or forbidden resources; never reveal a hidden
policy, seat count, account, or invite lifecycle in a typed detail. Advice can
change between read and write; actual mutation admission always rechecks.

## C8 and C9: readable labels

`SearchHit.thread_name = 10` and `spool_path = 11` are current observed labels
for the owning Thread and its Spool, individually subject to read and path
disclosure gates. No extra lookup is required for readable names. Empty string
and empty list cover unavailable, unrequested, older-server, and caller-withheld
metadata identically. A hit without an owning Thread leaves thread_name empty;
spool_path is present only for a readable owning Spool. Metadata never expands
hit visibility or reveals a hidden ancestor segment.

`ThreadRelationship.name = 3` and `lifecycle = 4` describe the current readable
related Thread. Omit the whole relationship when its reference would disclose
an unreadable Thread; do not return a hidden ID with blank labels. When a caller
already independently knows the reference but metadata cannot be resolved,
empty name and UNSPECIFIED lifecycle supply no state verdict. Unknown lifecycle
codes remain unknown. Labels and lifecycle are hints: eligibility, audience,
source state, and requirements still gate landing. Never offer a landing target
solely because a relationship has an ACTIVE or READY lifecycle.

## Compatibility and evidence boundary

Descriptor tests pin every added field's number/type/cardinality and the RPC's
content-read authorization. Shared Rust/TypeScript vectors cover exact revision
and paging, ordered visible ancestry, unresolved names, refs pages/readiness,
zero/unknown enums, typed refusal channels and readable/omitted labels. Frozen
alpha.15 readers discard the new fields while preserving every old field; new
readers accept their outputs with absent metadata. These tests prove wire and
schema semantics, not hosted authorization/index/provider implementation; weft
issues own live enforcement and population tests.
