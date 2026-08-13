# Treadle definition format v1

`heddle.api.v1alpha1.TreadleDefinition` is the language-neutral contract between
treadle authoring SDKs and native runners. The canonical protobuf bytes—not a
TOML, JSON, or TypeScript representation—are content-addressed with BLAKE3 and
bound by signatures/verdicts.

The definition is already lowered when emitted: pipeline → concrete jobs →
argv-only checks. Matrix values are concrete author-time bindings. The format
has no template, expression, shell command, or unresolved-variable type.

## Required v1 semantics

- `format_version` is exactly `1`; `name`, every job/check/service/secret name,
  every check command, and every service image locator are non-empty.
- A pipeline has at least one job and every job has at least one check. Job
  names are unique. Matrix dimension names are unique within a job. Check names
  are unique within a job. Service and secret names are unique pipeline-wide.
- A check passes `command` and the ordered `args` directly to process spawning.
  No shell parsing, interpolation, or command-string fallback is permitted.
- `class` is a gating request only. Maintainer-signed protected policy is the
  authority that decides whether a check gates acceptance.
- Every concrete check has a `target_environment` containing an immutable OCI
  image digest (`sha256:` plus 64 lowercase hexadecimal digits) and a present
  platform with lowercase OCI/Go-style `os` and `arch` values. This is an
  authoritative execution input, not a hint. An OCI image digest is
  platform-specific: a runner on a different OS or architecture MUST refuse
  the check instead of silently issuing a mismatched verdict. Binding both is
  what makes “run locally == run on the CI box” verifiable.
- `determinism_class` is required. `DETERMINISTIC` permits runner policy to
  consider an untrusted local result for queued-run supersede;
  `NONDETERMINISTIC` requires a trusted/authorized runner. `network_access =
  NONE` is only a partial proxy and MUST NOT be used in place of the explicit
  determinism class.
- `timeout_seconds` is positive. `retry`, `isolation`, `target_environment`,
  and its `platform` are always present, including the zero/default forms of
  the two hint messages, so absent-message aliases are invalid.
- Every environment entry has exactly one source: a literal value or the name
  of a declared secret. Secret values never occur in a definition. Every
  names-only secret declaration has a required tier: `STANDARD` or
  `TRUSTED_RUNNER_ONLY`. A check that references a trusted-runner-only secret
  is ineligible for untrusted local supersede regardless of its determinism
  class.
- Working directories and cache paths use normalized, slash-separated,
  repository-relative paths. Empty working directory means repository root.
- Service dependencies must reference declared pipeline services. Every service
  retains an image registry locator but also pins a required immutable
  `oci_image_digest`; runners use and verify the digest, never a floating tag,
  as image identity. Service readiness commands are also argv-only.
- Every check has at least one valid push, manual, or five-field cron trigger.
- `supersede_older_runs = false` means do not supersede. Zero isolation limits
  mean no requested limit, unspecified network access means no network hint,
  zero retries means no retry, and an empty secret provider lets policy choose.
  `UNSPECIFIED` determinism and secret tiers are invalid. These are the only
  meanings of those protobuf scalar defaults.

The axes deliberately do not duplicate one another. `class` remains a gating
hint, and every field in `isolation` remains a non-authoritative resource or
isolation request. `target_environment` is the authoritative required runtime
identity. `determinism_class` and the tiers of referenced secrets are separate
inputs to local-run-supersede eligibility; neither can be inferred from
`class`, isolation profile, or network access.

## Canonical bytes

All implementations MUST perform these steps before hashing or signing:

1. Reject any definition that violates the v1 rules above or whose
   `format_version` is not exactly `1`.
2. Clone and sort every set-like repeated field by the order below. Reject
   duplicate set members instead of silently coalescing them. String comparison
   is unsigned lexicographic comparison of the original UTF-8 bytes; Unicode is
   not normalized. Preserve sequence fields exactly.
3. Encode the normalized message as protobuf wire bytes with fields in ascending
   field-number order, shortest-form varints, packed encoding for repeated
   numeric scalars, ordinary proto3 omission of default scalar values, and
   explicit encoding of required present messages (`retry`, `isolation`,
   `target_environment`, and `target_environment.platform`). Do not emit
   unknown fields. Enum values use their stable protobuf numeric encoding;
   required enums reject their `_UNSPECIFIED = 0` value before encoding.
4. The content address is the raw 32-byte unkeyed BLAKE3 digest of those bytes,
   conventionally displayed as lowercase hexadecimal.

| Location | Canonical order |
| --- | --- |
| `definition.jobs` | job `name` |
| `definition.services` | service `name` |
| `definition.secret_refs` | secret `name` |
| `job.matrix` | dimension `name` |
| `job.checks` | check `name` |
| check/service `env` | entry `name` |
| `check.service_dependencies` | raw UTF-8 value |
| `check.retry.flake_signatures` | raw UTF-8 value |
| `check.cache_paths` | raw UTF-8 value |
| `check.triggers` | numeric `kind`, then `cron_expression` |
| `service.ports` | numeric value |

`check.args` and `service.readiness.args` are semantic sequences and MUST NOT be
sorted. The order of every message's fields is its protobuf tag order.

The Rust implementation is
`heddle_api::treadle::canonical_treadle_definition_bytes`; the TypeScript
implementation is `canonicalTreadleDefinitionBytes` from `@heddleco/api/treadle`.
The Rust canonical decoder re-encodes and byte-compares input, so alternate wire
encodings, unknown fields, and unsorted definitions fail closed.

## Conformance guardrail

`tools/verify-treadle-conformance.mjs` builds the shared definition with the
generated TypeScript messages and asserts its canonical bytes and BLAKE3 against
`tests/fixtures/treadle-definition-v1.json`. The Rust
`tests/treadle_definition_contract.rs` independently builds the same logical
definition with the generated prost messages and asserts the exact same bytes
and digest. The fixture input is intentionally unordered.

Any code generator or canonicalization change that alters either side therefore
fails byte identity, not merely compilation or logical equality.

## Version changes and migration

Until format v1 ships and definitions can be signed, its schema is still being
completed without a version bump. Once shipped, canonical semantics never
change in place. A field or rule that changes the signed logical definition
requires a new definition-format version and a new version-specific canonical
encoder.

Normal readers accept only their current version and return a “migrate first”
error for every other version. A rollout supplies an explicit forward migrator
that temporarily reads version N, constructs and canonicalizes version N+1,
rewrites the persisted definition/content address and dependent signatures, and
records completion. Once migration is complete, the old-version reader is
removed. There is no permanent dual-read, fallback, shim, or same-version bridge.
