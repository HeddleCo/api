# Compatibility policy

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
