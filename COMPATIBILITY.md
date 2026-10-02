# Compatibility policy

Content and symbol search index only each Thread's current source tips
(HeddleCo/weft#2433). `SearchRequest.source_scope` keeps its tags and
`SEARCH_SOURCE_HISTORY_RETAINED` (2) stays defined, but both retained-history
scope and an exact `source_revision` naming a visible accepted revision that
is not a current tip of a selected Thread fail with
`CALL_FAILURE_CODE_FAILED_PRECONDITION` and a message beginning "only Thread
tips are indexed". No results are returned from any other revision. Omitted or
CURRENT scope, and an exact current tip, are unchanged; unknown, unaccepted or
withheld revisions still yield no visible candidates, and the REVISION domain
still resolves historical identifiers. Full-history search is planned
(HeddleCo/weft#2470). This is a documentation change only: no tags, names or
wire bytes change, and no breaking override is required.

`SectionStatus.reason` (tag 6) and `SectionStatusReason` are additive for
HeddleCo/api#277 and HeddleCo/weft#2423. Existing tags 1–5 are unchanged.
An omitted reason decodes as UNSPECIFIED (0), preserving older servers;
older consumers may ignore the new field. Clients use a generic coverage label
for unspecified or unknown future codes. The reason supplements PARTIAL or
UNAVAILABLE coverage and cannot disclose withheld content or existence; see
the [stream contract](docs/alpha-v2/streams.md#views-paging-and-bounded-work).
No breaking override or legacy migration-manifest change is required.
Package versions remain unchanged; the next release is cut separately.

All `0.x` consumers exact-pin package versions. Breaking changes increment the
minor version and require a checked-in report under `breaking/` plus coordinated
consumer release candidates. Removed field names and tags are reserved and are
never reused, including before 1.0.

Buf compares release candidates with the latest published descriptor. A
pre-1.0 override must be named in the breaking report. At 1.0 the wire package
moves to `heddle.api.v1`; breaking overrides stop and a new package generation
is required.

The migration from `heddle.v1` is intentionally incompatible and is recorded
exhaustively in `migration-manifest.json`. There is no dual registration or
wire compatibility shim.

Version 0.2 is the coordinated hard cutover from generated tonic bindings to
the transport-neutral hosted-call contract. Consumers must move together; the
package does not contain a tonic compatibility feature or a dual-protocol
router.

The four live handle operations are explicitly retained as
`IdentityService/{ClaimHandle,GetHandleStatus,RequestHeldName,ResolveHandle}`.
Their migration requires the [Weft adapter](https://github.com/HeddleCo/weft/issues/591)
and [Tapestry adapter](https://github.com/HeddleCo/tapestry/issues/163) before
HeddleCo/heddle#1021 repins; until then the shared descriptor is a cutover
contract, not authorization to remove the live legacy registration.

`ProviderRepository.linked_spools` (tag 7) is an additive repeated `SpoolRef`
projection for HeddleCo/api#271 and HeddleCo/weft#2392. It covers the account's
caller-visible spools with a matching provider repository id or clone origin,
including spools outside the `ObserveIntegrations` request. Invisible links are
omitted without failing the read; an empty list means no visible link. Older
messages decode with an empty list, and older consumers may ignore the field.
No breaking override or legacy migration-manifest change is required. Package
versions remain unchanged; the next release is cut separately.

`AttentionItem.snoozed_until` (tag 14) and the `SetAttentionStateRequest.snooze`
oneof (`snoozed_until` tag 6, `clear_snooze` tag 7) are additive for
HeddleCo/api#273 and HeddleCo/weft#2400. On the item, an unset or past timestamp
means not snoozed. A future time removes the item from pending on every device.
It returns as pending when that time passes, or earlier when new activity
arrives on its subject; the server then clears the snooze and bumps version.
On the request, an absent `snooze` oneof leaves the current snooze unchanged,
so a resolution or `pinned` update does not clear it. `snoozed_until` sets a
snooze. `clear_snooze` must be true and clears it; false is rejected.
`expected_version`, `client_operation_id` idempotency and `pinned` behave as
today (`pinned` stays the absolute pin value on every call). Older messages
decode with no snooze, and older consumers may ignore the fields. No breaking
override or legacy migration-manifest change is required. Package versions
remain unchanged; the next release is cut separately.

`BeginPairingRequest.web_origin` (tag 6) is an optional string for
HeddleCo/api#278 and HeddleCo/weft#2421. Empty means the server uses its
configured default web origin. The server accepts a value only when it matches
the server's CORS allowlist and the preview-origin policy (canonical HTTPS DNS
host; no port, userinfo, path, or extra label); otherwise the request fails
with InvalidArgument. It changes only the host of the returned
`verification_uri`. It grants nothing, is not a secret, and is not part of the
signed pairing binding (`subject_possession` / `PairingInitiationBinding`): the
server checks the host against its own policy, so signing it would not grant a
wider origin. Older messages decode as empty (server default), and older
consumers may ignore the field. No breaking override or legacy
migration-manifest change is required. Package versions remain unchanged; the
next release is cut separately.

HYBRID import authority and host witness (api#296, weft#2469) add new messages,
RPCs and proof fields without changing existing tags or capability signature
formats. Protocol version 2 with mandatory semantic feature
`IMPORT_AUTHORITY_HOST_WITNESS_V1` is required before HYBRID execution, Fetch,
publication or relay; missing support fails closed before staging/mutation. An
old peer may decode protobuf but must never ignore the new authority requirements.
See the [wire/verification contract](docs/alpha-v2/import-authority-host-witness.md).
The release/cutover cascade is api → heddle → weft → tapestry, coordinated with
new-format import and native reinitialization; no legacy proof conversion or
immutable receipt re-signing is permitted. This additive schema PR bumps no
package version and creates no tag. The eventual release is a separate step.
