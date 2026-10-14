# Import proof format 2 and deterministic partitioning (alpha.49)

New jobs use `ImportPublicProofBundleV1.format_version = 2`. Signed member
permissions, delegations, genesis authorities, their domains and native originals
remain format 1 and byte-identical. The carrier itself is unsigned; its version
selects verification rules, never a different interpretation of a signed record.

`creator_authority_envelopes` is now a strictly SHA-256-digest-sorted table of
unique, nonempty envelopes, each at most 65,536 bytes. Every entry must be used
and every genesis authority must resolve one entry. A signed branch manifest
references `genesis_authority_digest`, which selects its signed genesis authority;
that authority's existing `creator_authority_envelope_digest` selects the exact
table bytes. Equal envelopes are carried once regardless of branch count.
No signed field, protobuf field number or signing domain changes.

Format 1 retains its frozen positional Commit arrays and 1 MiB proof / 2 MiB
request caps, including verification of the existing alpha.27 corpus as revised
by the documented alpha.32/33 cuts. Format 2 has a 4 MiB proof / 8 MiB request
cap. Native proof carriers, configuration and source-resolution responses retain
their 1 MiB caps. Unknown bundle versions reject `Version`; a rejected submission
is never retried using another format.

`GetImportConfigurationResponse.import_proof_bundle_format_version` is additive:
absent/0 or explicit 1 describes the frozen format-1 contract, and explicit 2
advertises format-2 support. Unknown values reject. A format-2 Commit requires
that explicit advertisement. Hosts advertising 2 must publish
`limits.max_branches <= MAX_BRANCHES = 25`; old format-1 advertisements and
standalone signed scope verification retain their 256 ceiling. New clients use
the advertised version and the partition helper, not the old count ceiling.
Both the child scope and the carried parent permission scope are capped at 25
for format 2. `max_operations` remains at most 256 to preserve bounded retries/history.
The same selected host configuration governs Prepare and Commit.

## Exact delegation arithmetic

The real canonical encoder uses counted strings/bytes, flattened nested messages,
fixed-width integers and counted lists. At the maximum UTF-8 ref length and
SHA-256 OID width:

| Component | Canonical bytes |
| --- | ---: |
| Branch ref | 4 + 1,024 = 1,028 |
| Hash algorithm and ref mode | 4 + 4 = 8 |
| OID, genesis, Thread and frontier digests | 4 × (4 + 32) = 144 |
| Slot ID and disclosure | 8 + 4 = 12 |
| `ImportBranchLimitV1` | **1,192** |
| Manifest entry: limit plus signed genesis digest | 1,192 + 4 + 32 = **1,228** |
| Fixed delegation fields, including maximum source URL (2,048), provider (64), converter (128) and all fixed-width IDs | **2,800** |
| Signed wrapper's signer ID and signature | (4 + 32) + (4 + 64) = **104** |

Thus `signed delegation = 2,904 + 2,420 × N`.
At **25**, this is **63,404 <= 65,536**; at **26**, it is
**65,824 > 65,536**. The body alone is 63,300 / 65,720.
This is an upper bound even though the registered provider names are shorter.
The executable Commit boundary uses `public-git`, whose signed delegation is
**63,350 bytes**, with a **150,928-byte** proof. The test also encodes the
64-byte provider term independently and asserts both arithmetic values.
Every ref is exactly 1,024 UTF-8 bytes, including multibyte characters, and all
OID/digest/UUID/key/signature widths and integer widths are maximal.

## Conservative complete Commit proof arithmetic

Ref lengths alone do not bound opaque authority and original records. Format 2
therefore also bounds the **encoded context** to 64 KiB: clone the proof, remove
member permission, delegation, genesis authorities, original geneses and creator
envelope table, and measure the remaining protobuf bytes. This includes owner
history, transfers, owner chain, policies and any additional carrier fields.
This reserve applies to initial Commit only; cumulative exports retain the
complete 4 MiB carrier cap and their existing sidecar/history count limits.

For valid initial Commit material, the following deliberately conservative
protobuf upper bound includes maximum 64 KiB original records, all 16 original
signatures, a different maximum-sized envelope for every branch, maximum-width
signed binding fields and protobuf tags/length prefixes:

| Component | Encoded upper bound |
| --- | ---: |
| Context, including enclosing version | 65,536 |
| Signed permission and signed delegation, each with outer field framing | 2 × 66,560 |
| Each signed native genesis, including 16 signatures and outer framing | 69,632 |
| Each signed genesis authority, including outer framing | 1,024 |
| Each opaque envelope, including outer framing | 65,536 + 5 = 65,541 |

Total at 25 is
`65,536 + 2 × 66,560 + 25 × (69,632 + 1,024 + 65,541)`
= **3,603,581 < 4,194,304** bytes. Native record formats, field widths and
signature counts are verified independently; this arithmetic grants no native
model or owner authority. Maximum opaque transport material is additionally
constructed with the real protobuf encoder in both languages.

The 64 KiB record ceiling is unchanged. Caller-supplied narrower byte budgets,
large context or invalid individual originals can still refuse; clients measure
the actual complete candidates and never truncate proof material.

## Shared greedy helper

Rust: `partition_import_branches(selection, &ImportPartitionLimits { ... })`.
TypeScript: `partitionImportBranches(selection, limits)`.
Both return complete format-2 proof candidates. Limits contain `max_branches` /
`maxBranches`, `max_record_bytes` / `maxRecordBytes`, `max_bundle_bytes` /
`maxBundleBytes`, and `build_job` / `buildJob`.

The builder receives a contiguous branch slice in exact UTF-8 byte order and
supplies the full candidate job. It must rebuild the scoped permission,
envelope, genesis bindings and delegation for that slice, and allocate distinct
job IDs and keys for sibling jobs. It may use exact-width signature placeholders
before signing; callers must finish signing and verify the final candidates.
A builder cannot return a record detached from the selected branches. Builders
must be deterministic and free of externally visible side effects: a candidate
can be discarded when the next branch crosses a limit.

The helper validates selection order, uniqueness and branch shape. It greedily
appends one branch, measures the canonical signed delegation, permission and
genesis bindings with the real canonical encoders, and measures the whole proof
with the real protobuf encoder. It also enforces original record/envelope limits
and the Commit context reserve. Limits are inclusive and may only narrow the
format-2 ceilings. A `Bounds` failure closes the last accepted prefix and retries
the single next branch; an oversized singleton or any other failure returns the
error. Empty selection returns no jobs. Input order and octets are preserved.
Partitioning never normalizes refs, downgrades formats, reserves jobs or sends
submissions. Receivers decoding a format-2 carrier must supply the explicit 4 MiB
limit to `strict_decode` / `strictDecode`; the generic default remains 1 MiB.

The shared [golden corpus](../../tests/fixtures/import-partition-alpha49.json)
contains exact input wires, count/record/proof/mixed boundaries, one-byte-smaller
budgets, exact output sizes and SHA-256 of every output proof. Rust and TS build
real signed candidates and verify every returned job through full portable
Commit submission verification. Distinct job keys/IDs are deterministic test
inputs, not production key material.

## Proof growth

The same real encoders measure the repeated-envelope format and the deduplicated
format on otherwise identical signed material:

| Branches | Format 1 bytes | Format 2 bytes |
| ---: | ---: | ---: |
| 16 | 84,444 | 29,184 |
| 64 | 909,182 | 108,578 |
| 256 | 12,871,710 | 426,435 |

The incremental format-2 bytes per branch agree within protobuf length-prefix
and decimal genesis-name steps. Rust and TS assert that growth and consume the
same frozen wires. The 64/256 measurements are encoding probes above the new
25-branch admission ceiling; they demonstrate structural growth, not admissible
large jobs. Existing frozen signed vectors are not regenerated.
