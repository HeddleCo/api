# @heddleco/api

Generated ESM types for `heddle.api.v1alpha1`. Install from GitHub Packages and
exact-pin `0.x` releases.

Configure `@heddleco:registry=https://npm.pkg.github.com` and authenticate with
a classic GitHub token carrying `read:packages`, then install
`@heddleco/api@0.1.2` exactly.

The `@heddleco/api/treadle` export provides
`canonicalTreadleDefinitionBytes()` and `treadleDefinitionBlake3()` for the
versioned, signed treadle CI definition contract. Construct definitions with
the generated `Treadle*` schemas; do not hash generic protobuf output directly.
