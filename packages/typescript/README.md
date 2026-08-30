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

The `@heddleco/api/treadle-authoring` export provides the composable authoring
SDK: `definePipeline`, `defineCheck`, `defineService`, `secretRef`, `matrix`,
`job`, `emitPipeline`, plus compact helpers `rust`, `test`, `sh`, and
`hostTargetEnvironment()`. Pipeline `defaults` and language-pack defaults fill
only omitted check fields; the emitted `TreadleDefinition` is still the fully
populated protobuf contract. `jobs` may be an array of `job()` values or a
name → check-list record. Language packs are runtime values that still emit
argv `command` + `args` (never a shell string, never an in-process
`cargo.run()`). The rust pack defaults `cachePaths` to `["target"]`, pin
`target_environment` to the v1 fixture linux/amd64 digest (golden/conformance
stability), append `-- -D warnings` on `clippy`, and pass `--check` on `fmt`.
A pipeline that `heddle ci run --local` must admit has to override with
`defaults.targetEnvironment: hostTargetEnvironment()`, which maps
`process.platform`/`process.arch` onto proto `darwin`/`linux`/`windows` and
`amd64`/`arm64` (dummy image digest; host-exec v0 does not pull). Matrix jobs
are expanded by typed JavaScript callbacks before protobuf emission; there is
no expression or template language. `emitPipeline()` returns the canonical
protobuf bytes and a deterministic `treadle.lock.json` artifact whose
`definition_digest` is the BLAKE3 content address of those bytes.

`node packages/typescript/compile-treadle.mjs <pipeline> [--out-dir dir]`
loads the file's `export default` (`definePipeline` return), emits, and writes
`.heddle/treadle.definition.bin` (canonical bytes) and
`.heddle/treadle.lock.json` (`format_version` + hex digest). `--out-dir`
defaults to `{cwd}/.heddle`. Missing default export fails closed. The compact
local-run example is `packages/typescript/examples/local-host.mjs`.
