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
