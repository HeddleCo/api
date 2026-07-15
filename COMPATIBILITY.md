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

The four live handle operations are explicitly retained as
`IdentityService/{ClaimHandle,GetHandleStatus,RequestHeldName,ResolveHandle}`.
Their migration requires the [Weft adapter](https://github.com/HeddleCo/weft/issues/591)
and [Tapestry adapter](https://github.com/HeddleCo/tapestry/issues/163) before
HeddleCo/heddle#1021 repins; until then the shared descriptor is a cutover
contract, not authorization to remove the live legacy registration.
