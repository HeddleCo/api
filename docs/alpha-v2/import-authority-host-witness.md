# HYBRID import authority and host witness, format 1

This is the api#296 contract, revised in place by api#318 and api#321, for [weft#2479 at
8d427f8c1](https://github.com/HeddleCo/weft/pull/2479/changes/8d427f8c12006c63c5cad43cce260fd91a5e77a5).
The build decision is [weft#2469](https://github.com/HeddleCo/weft/issues/2469).
The undeployed v1 preparation schema is revised in place; its semantics require a coordinated incompatible-peer
gate. Alpha.33 makes the explicit hard cut documented in
[the breaking notice](../../breaking/0.31.0-alpha.33.md). The delivery order is
**api → heddle → weft → tapestry**. This contract neither deploys that cascade
nor establishes that the original runtime defect is fixed.

The core conformance bytes are frozen in
[import-authority-host-witness-v1.json](../../tests/fixtures/import-authority-host-witness-v1.json).
Whole-repository scenarios add the separate
[sibling-job corpus](../../tests/fixtures/import-sibling-jobs-alpha32.json).
Its frozen descriptors identify every new message and field number/type. Rust
and TypeScript read its original bytes, digests and signatures, including the
negative records; they never generate expected signatures during a test. The
maintenance generator requires built bindings and explicit fixture review.

## Message inventory

| Accepted design section | Messages |
| --- | --- |
| Owner-authorized genesis and delegation | `ImportIdentityV1`, `ImportOwnerChainV1`, `ImportBranchLimitV1`, `ImportPermissionScopeV1`, `ImportMemberPermissionV1`, `SignedImportMemberPermissionV1`, `ImportGenesisAuthorityV1`, `SignedImportGenesisAuthorityV1`, `ImportBranchManifestV1`, `ImportJobDelegationV1`, `SignedImportJobDelegationV1` |
| Owner-authorized genesis and delegation: converted content | `DelegatedImportOperationV1`, `SignedDelegatedImportOperationV1` |
| Preparation, custody, state and controls | `ImportJobPreparationV1`, `ImportCommittedSlotV1`, `ImportResultManifestV1`, `PrepareImportJobRequest`, `PrepareImportJobResponse`, `CommitImportJobRequest`, `GetImportJobStateRequest`, `GetImportJobStateResponse`, `ImportJobStatus`, `ImportEligibleRetryTargetV1`, `ImportRetryUnavailableReason`, `CancelImportJobRequest` |
| What the host witness attests | `HostedWitnessBoundaryAcceptanceV1`, `ImportBoundaryAcceptanceV1`, `ImportGenesisWitnessV1`, `ImportAuthorityRecordKind`, `ImportAuthorityWitnessV1`, `HostedLandingRequestProofV1`, `HostedLandingWitnessV1`, `ImportPublicationWitnessV1`, `HostedWitnessStatementV1`, `SignedHostedWitnessStatementV1` |
| Complete authenticated witness set and exact retirement archive | `HostedWitnessEntryV1`, `HostedWitnessSetV1`, `SignedHostedWitnessSetV1`, `HostedWitnessHistoryProofV1` |
| Proof lookup after loss of Thread access | `GetHostedWitnessHistoryProofRequest`, `GetHostedWitnessHistoryProofResponse` |
| Planned cascade: incompatible-peer rejection | `ProtocolCompatibility` |

## Canonical framing and domains

Reuse [owner_records.proto](../../proto/heddle/api/v1alpha2/owner_records.proto#L22):
numbered-field order, mandatory nested messages flattened in place, byte strings
and UTF-8 strings prefixed with their **u32 big-endian byte length**, lists with a
u32 count followed by each element. All uint32/enums are u32be, uint64 is u64be,
int64 is signed two's-complement i64be. UUIDs are 16 raw bytes; hashes, key IDs
and Ed25519 public keys are 32; signatures are 64. Encodings include default
values; there are no omitted signed fields, protobuf tags, hex strings, JSON
numbers, optional-presence ambiguities or protobuf serialization in signatures.
Signed wrappers flatten their body followed by AuthorizationSignature (counted
signer ID, counted signature). These widths and layouts are frozen for v1.
api#318, alpha.32 and alpha.33 revise the undeployed v1 layout in place;
no old layout or compatibility reader is retained. After first
deployment a new signed layout needs a new version/domain and new identities.

Times in import authority are **Unix seconds**, following owner records. Set
freshness, witness intervals and observations are **Unix milliseconds**, following
[descriptor_trust](../../src/descriptor_trust.rs#L120). Its independently pinned
root context selects `(canonical HTTPS authority, descriptor_root_id, root public
key, root-pin epoch)`; the root's transported ID is not a new trust anchor. Both
endpoint descriptor validity windows still must contain verification time; this
contract neither changes those domains nor makes transport keys witnesses.

| Body / hash | Domain and signature input |
| --- | --- |
| `ImportMemberPermissionV1` | Ed25519 over H(`heddle-import-member-permission-v1` || canonical body) |
| `ImportGenesisAuthorityV1` | Ed25519 over H(`heddle-import-genesis-authority-v1` || canonical body) |
| `ImportJobDelegationV1` | Ed25519 over H(`heddle-import-job-delegation-v1` || canonical body) |
| `DelegatedImportOperationV1` | Ed25519 over H(`heddle-delegated-import-operation-v1` || canonical body) |
| `HostedWitnessSetV1` | Ed25519 over **raw** UTF8(`heddle-hosted-witness-set-v1\0`) || canonical body; `body_digest` is H of that input |
| Witness purpose 1 | Ed25519 over H(`heddle-import-genesis-first-admission-witness-v1` || canonical statement) |
| Witness purpose 2 | Ed25519 over H(`heddle-import-authority-first-admission-witness-v1` || canonical statement) |
| Witness purpose 3 | Ed25519 over H(`heddle-import-publication-witness-v1` || canonical statement) |
| Witness purpose 4 | Ed25519 over H(`heddle-hosted-landing-witness-v1` || canonical statement) |
| Owner-chain commitment | H(`heddle-import-owner-chain-v1` || canonical `ImportOwnerChainV1`) |
| Frozen preparation commitment | H(`heddle-import-job-preparation-v1` || canonical `ImportJobPreparationV1`); comparison uses the full canonical bytes |
| Result manifest | H(`heddle-import-result-manifest-v1` || canonical `ImportResultManifestV1`) |

H means SHA-256. The ASCII domains above have **no NUL**, except the explicitly
shown set domain and witness selector. Exact signed-envelope digests use H(domain
|| canonical signed wrapper), with domains `heddle-signed-import-member-permission-v1`,
`heddle-signed-import-genesis-authority-v1`, `heddle-signed-import-job-delegation-v1`,
and `heddle-signed-delegated-import-operation-v1`. Thus a digest commits to the
original signature and signer ID as well as the body. `ImportBranchManifestV1`
contains a full limit and the signed genesis-binding digest, not a bare URL/ref.

Authorization key IDs retain the owner namespace:
H(`heddle-key-v1` || u32be(1) || raw public key).
Witness selectors are H(`heddle-hosted-witness-key-v1\0` || raw public key).
`executor_id` means this selector, never an owner, endpoint or trust anchor.
New witness statement domains deliberately distinguish new accepted-state/order
fields from existing `heddle-thread-genesis-admission-v2`,
`heddle-thread-authority-admission-v3` and `heddle-hosted-integration-v1` formats.
Those original bytes/domains remain unchanged. Consumers must never reinterpret
old receipts, substitute a witness into legacy HostedImport, or use that dispatch
as a fallback around the new delegation/publication requirement.

Canonical HTTPS v1 is conservative: lowercase DNS labels, no userinfo, query,
fragment, port or percent escapes. Authority is an origin with no slash. Source
URLs have nonempty ASCII unreserved path segments, no `.`/`..` or trailing slash.
Provider IDs are lowercase ASCII `[a-z0-9-]{1,64}`; branch refs are full
`refs/heads/...`, ASCII `[A-Za-z0-9/_-.]`, no empty/dot-leading/`.lock` segments,
`..`, `@{`, trailing slash/dot or duplicate refs. Converter version is explicit,
nonempty ASCII, at most 128 bytes. Never silently normalize after signing.
The launch registry has exactly two provider identities. `github` denotes the
connected GitHub adapter: an authenticated caller-owned account connection and
its exact repository/installation grant select credential custody. `public-git`
denotes unconnected public HTTPS Git, including public github.com and gitlab.com
URLs, with no connection or installation and `private = false`. A public
repository ID is the exact URL (or empty on request input). A domain alone never
selects custody. `gitlab` is reserved for a future connected adapter; connected
or private GitLab is deferred and MUST NOT be advertised. `public_git` is
rejected, with no alias. Weft must rename its existing public-source resolver in
the coordinated cutover; this release changes API only.

`IntegrationService.ResolveImportSource` is an authenticated, caller-bound,
request-PoP finite read for both source modes. The host independently resolves
current repository identity, visibility, connection and installation grants,
applies its public URL/SSRF/redirect policy before fetch, and returns the
repository `hash_algorithm`, even without a selected commit or ref page. The
request's metadata is a hint, never evidence. Optional refs use the inventory
coverage/PageInfo semantics, default 128 and max 512 per page; the whole response
is at most 1 MiB. Cursors bind caller, exact custody/URL/repository identity,
accepted bounds and provider snapshot. Unknown/unauthorized connected sources
use uniform NOT_FOUND. No credential is returned or acquired by public discovery.

Discovery also carries `ProviderRepository.size_estimate_state` and
`git_size_kib`. `AVAILABLE` reports approximate **Git repository storage** in
KiB (one KiB = 1024 bytes), including zero for an empty repository. Connected
GitHub adapters MAY use the repository API's size observation; UNKNOWN is always permitted. `UNKNOWN` is an
explicit state and MUST carry zero; unknown enum values refuse. Public HTTPS
Git reports UNKNOWN because no cheap estimate is available. No branch estimate
is exposed: shared Git objects and provider repository size do not offer a cheap
independent branch measurement. Hosts need not fetch/count objects for discovery.

The estimate is advisory, can be stale, is not converted result bytes, and grants
nothing. Clients calculate the total as the size estimate × converter-appropriate
headroom (including the KiB-to-byte conversion and rounding up using checked or
widened arithmetic), capped at `GetImportConfiguration.limits.max_result_bytes`.
For UNKNOWN, clients use the current advertised host maximum. Users never set
this total. The client passes it exactly to Prepare; hosts never fill it from
the estimate.
The estimate is outside all signed import scope/authority layouts.

Resolve accepts a selected source **unchanged or refuses it**. The result must
preserve the exact `clone_url`, connection (including absence), repository ID,
installation ID and visibility. The sole completion is an empty public input
repository ID becoming the exact requested URL; a successful public result
always carries that URL as its ID. Connected IDs are never completed or replaced.
Name, default branch, refs and object format are independently observed metadata,
not identity substitutions. Validate both URLs against canonical HTTPS v1 without
normalizing: `repo` and `repo.git`, path case and different origins remain distinct.
Noncanonical input refuses; it is not repaired into an accepted selection.

Host redirect/SSRF policy governs transport before each fetch/hop. An allowed
transport redirect never changes the requested or signed source identity. If
resolution can only return a different URL or custody identity, refuse rather
than adopt the redirect target, append/remove `.git` or infer alias equivalence.
Any different source requires a new explicit selection, review and Prepare; a
redirect never rewrites prepared or signed bytes. The portable
`validate_resolve_import_source_response` / `validateResolveImportSourceResponse`
check request/result identity and discovery bounds/format, using the host's
independently authenticated connection provider. They perform no network or
current-grant authorization.

Both repository and ref `hash_algorithm` come from independently established
repository object format (for example an authenticated provider object-format
read or Git's object-format advertisement), not the selected OID length, URL,
default branch or a SHA-1 assumption. UNSPECIFIED (zero) means unknown/unavailable;
unknown enum values are unsupported. Missing/failed format discovery blocks
Prepare and signing and offers retrying discovery, even when OBSERVE is chosen.
A discovery response can report zero with empty OIDs without authorizing work.
Every ref's algorithm agrees with the repository, and each nonempty `head_oid`
is exactly lowercase 40-hex for SHA-1 or 64-hex for SHA-256. Mismatch is refused.
For fresh selections, the browser uses `validate_discovered_import_scope` /
`validateDiscoveredImportScope` before preparing/signing: every selected branch
must use that discovered format; a known selected OID must be pinned exactly. Algorithm discovery alone never
waives signed observe disclosure or the settled known-OID pinning rule.

Prepare carries required `ImportSourceSelectionV1`: connection/repository,
installation and visibility, while its URL is `proposed_scope.source_url`.
The host resolves it anew and checks provider/URL, object format, selected OIDs,
configuration and current policy. `prepare_import_source_scope` /
`prepareImportSourceScope` take that independently resolved source.
Commit repeats current grants, format and converter/options/budget checks using
the independently resolved repository supplied to `validate_commit_request` /
`validateImportCommitRequest`. Clearing incoming refs cannot bypass known-OID
pinning. A frozen PINNED_COMMIT retains its selected commit when the branch head
moves after Prepare; Commit never substitutes or requires the new head.
Current source grants, selected-commit availability, revocation and atomic
mutation remain host responsibilities. Exact accepted replay retains its semantics.

Unknown fields, versions, algorithms, purposes, duplicate fields, noncanonical
order and trailing bytes fail closed. `strict_decode` / `strictDecode` compare
decoded protobuf to its re-encoding at the untrusted boundary; signing functions
then use the independent canonical encoding. JSON adapters must similarly reject
unknown/duplicate keys and decode integers losslessly; JSON is not a second
signing format. Opaque canonical bytes require exact parse/re-encode equality in
the consuming native object format.

## Owner-authorized genesis and delegation (P2 #1)
## Owner-authorized genesis and delegation (P2 #1)

`ImportIdentityV1` binds Spool UUID and its immutable genesis digest, owner ID,
owner account UUID, exact accepted owner-state hash and transfer sequence. Verify
the independently selected immutable lineage, original SignedSpoolOwnerGenesis,
owner root/accepted transitions and both parties of each ownership handoff using
heddle's existing owner/keyring/transfer verifier. Neither account UUID equality,
self-PoP, a carried owner root nor a host receipt selects that lineage. A foreign
proof bundle is evidence, not enrollment of the receiver's own account root.

`ImportOwnerChainV1` commits to the selected Spool genesis, sorted unique exact
owner-state hashes (including all transfer parties) and accepted transfer audit
hashes in sequence order. The consumer recomputes it from verified original
histories/handoffs and checks the selected current or witnessed accepted owner;
an incoming commitment alone proves nothing. Permission and genesis/delegation
bindings include this digest. Public proofs retain the full signed histories.

The endpoint algorithm matches heddle#1964: form the sorted unique union of
(1) the verified keyring's owner-state hash, (2) the independently selected
accepted owner's state hash, and (3) the endpoint state hash of each carried,
verified transfer-owner history. Take transfer audit hashes from the verified
keyring's transfers in their accepted order. Do not include every intermediate
rotation hash. Transfer sequence is the accepted transfer count; rotations do
not increment it. A rotated but never-transferred Spool, with keyring and selected
history both ending at the same current state and no extra transfer histories,
uses **only that current state hash** and an empty audit list. If the keyring ends
at an older accepted state and the selected history extends it, include both
endpoints. The complete root/rotation/transfer signatures must still be retained
and verified; endpoint commitments do not permit truncating history.

**The missing member permission is a new, direct, typed owner → device grant:**
`ImportMemberPermissionV1`, owner-signed under its own new domain. It grants
both exact genesis binding and IMPORT_CONVERSION_V1 delegation for **one logical
job and original retry lineage only**. It names the subject device public key,
selected owner/Spool state, provider/source, exact branch genesis/target/frontier
limits, destination version, options, converter, validity and cancellation ID.
There is no device-to-device grant chain or general subdelegation mechanism.
An active direct owner authority may sign the delegation without this grant;
its parent-permission field is exactly zero32. A device MUST supply the new
typed signed permission and its exact digest. PURGE v1, timeline acceptance v3,
ordinary Developer/Admin role, mint-root attachment and KeyBinding self-PoP
cannot satisfy this permission. Existing capability versions/domains do not
change. Authority from an online role is still checked separately for RPC access.

Permission bounds are explicitly **one logical import**, at most **256 branches
and 256 converted operations/slots**. Branch limits
are sorted unique full refs, with one stable slot per branch in this first format.
There are **no per-branch byte budgets**. `max_result_bytes` is ONE positive
u64 result-byte total, and `max_operations` is the operation total. This signed
bound authorizes how much a server-held job key may write under the user's
delegation, limiting the blast radius of a compromised or buggy worker. It is
not a storage quota; repository storage may grow beyond it and is billed
separately. The protocol imposes no fixed byte ceiling. Stable branch/ref/slot
identities remain exact. Certificate scope can select a subset and reduce the total and operation count, never add a ref/slot/genesis/target,
change initial frontier/source/options/converter/destination version, or expand
a parent's time window. The parent cannot outlive its verified issuing authority.
The owner grants permission over branch limits BEFORE genesis authorization
proofs are produced; only the child manifest adds their signed proof digests.
This prevents a cyclic permission/genesis/delegation digest dependency.

The host accounts result bytes and operations durably under the one delegation
and its optional parent. `(logical job, full ref, slot_id)` records identity,
uniqueness and exact replay, without a branch byte counter. Retry preserves those
totals. Only the direct active owner issues the typed member permission.
Generate the parent's cancellation ID and nonce as independent CSPRNG-generated
32-byte values in `heddle-import-cancel-v1`. Each new grant uses a fresh nonce;
issuers prevent reuse, and exact replay preserves the original signed bytes.
The delegation's separate host-issued cancellation ID is checked independently.
Revocation of either applicable cancellation ID invalidates new work.

Known user authority, descriptor-root and all CURRENT/RETIRED/REVOKED witness
keys are forbidden as job signers. Known job keys cannot join a witness set.
Persist job-key → logical-job associations in issuer custody and receiver trust
state and reject conflicts. A fresh receiver cannot discover undisclosed reuse;
the issuer must enforce global prepare/commit uniqueness.

`ImportGenesisAuthorityV1` binds the exact native Thread genesis ID, original
creator signature/key and separately transported creator-authority envelope
digest. Its device signature supplies no missing creator signature. Independently
verify the original genesis/envelope, then the binding and manifest; never rewrite
retained original authority to match a later owner state.

Genesis envelope dispatch is explicit. For member/device import authority, use
`UTF8("heddle-signed-import-member-permission-v1\0") || canonicalHybridV1(SignedImportMemberPermissionV1)`:
the complete original signed permission, including its owner signature, and bind
SHA-256 of those exact envelope bytes. A device's unrelated ThreadControlAuthority
cannot replace it. For direct-owner authority (no member permission), retain the
original native account genesis authority envelope and verify it through the
native `thread_control_authority::verify_genesis_with_retained_mint_roots` path;
an empty or arbitrary envelope is refused. Preserve that envelope's original
`/heddle.api.v1alpha2.IntegrationService/ImportSource` signed method context.
Commit carries these retained originals without rewriting their context; closing
the ImportSource RPC does not reopen it or invalidate retained provenance.
Both paths still verify the native creator signature, exact genesis binding and
manifest independently.

`DelegatedImportOperationV1` is a NEW typed converted result. The job key signs
its exact logical job, original retry lineage, physical operation ID, signed
certificate digest, ref/slot, observed Git OID AND hash algorithm, original genesis,
target and expected/result frontiers, content digest/byte count, options/converter.
PINNED_COMMIT authorizes the exact raw 20-byte SHA1 or 32-byte SHA256 commit;
**Whenever the exact selected commit OID is known, the caller MUST pin it.**
The client MUST use OBSERVE_AT_EXECUTION only for genuinely unknown OIDs and
MUST never downgrade a known OID. A branch whose OID was known but became
unavailable MUST be excluded, not observed. Failed pinning, stale observations
and empty OIDs never authorize a silent downgrade. The signed `ref_disclosure`
for OBSERVE_AT_EXECUTION authorizes this fixed promise:

> The exact commit is unavailable. This branch may move before execution. The
> import will convert the commit observed when the job executes, which may differ
> from the commit you saw when selecting the branch.

OBSERVE requires the SIGNED `ref_disclosure` field: the signature is the explicit
authorization, recorded in the authorization as the audit trail. Presentation
to a human is client product policy, not a protocol requirement. A client may
automatically include genuinely unknown-OID branches and set and sign the
disclosure on the user's behalf as part of a one-click repository import,
without branch selection or authorization screens and without showing the
disclosure to the user. The client MUST never sign a scope wider than the user's
action and MUST pin every known OID. Each observe branch
has an empty `pinned_commit_oid`, an explicit hash algorithm and
`ref_disclosure = IMPORT_REF_DISCLOSURE_OBSERVE_AT_EXECUTION (1)`.
Pinned branches require `ref_disclosure = UNSPECIFIED (0)`. Alpha.32 removes/reserves field 9 `max_result_bytes` from
`ImportBranchLimitV1` and its canonical u64be encoding. Field 10 appends **u32be(ref_disclosure)** to its canonical layout;
the parent scope, prepared scope and signed manifest all bind it. A genuine
delegation signature without the marker still rejects with `RefDisclosure`.
The result retains its exact observed OID and algorithm.

`validate_ref_selection` / `validateImportRefSelection` additionally take an
independently known OID available when choosing the scope. They reject observe
mode or a different pin with `RefPinning`; None/undefined supplies no
authorization and never changes the mode. A receiver cannot discover an
undisclosed locally known OID from signed bytes alone. It verifies the explicit
signed marker and mode; authoring clients and hosts with that independent
knowledge MUST enforce exact pinning. No implicit mutable-ref authorization
exists: unsigned or missing disclosure and silent downgrades always refuse.
A URL/ref signature does not prove deterministic Git conversion or original
Git authorship; those require
retained objects and a mapping verifier, or the disclosed trust in the converter.

Owner → typed parent (or direct owner) → delegation → job operation signatures
are independent of host witness resolution. `VerifiedImportDelegation` proves
signature/scope at the supplied independently verified authority time;
`verify_operation` proves only structural signature and delegated scope.
`verify_new_operation` additionally checks current time. None replaces current
owner/policy/cancellation/device/session/credential/mint-root checks or storage
leases/frontier CAS. The caller supplies the owner verifier's actual host/receiver
time for new work, never an author's claimed time. Historical verification uses
the independently verified witness observation/order plus public accepted-state
proofs and original signatures, not a backdated job timestamp.

### Configuration and caller-selected scope (api#327 G2)

Prepare is authenticated and idempotent: persist the distinct encrypted job seed
and exact unsigned proposal before returning. The reservation ends exclusively at
Prepare time + 3600 seconds. No prepared job executes before Commit verifies the
complete user-signed proposal, original branches, current permission and budgets.
A proposal change requires fresh preparation and signature.

Call authenticated `GetImportConfiguration(destination)` before choosing the
scope. It requires destination write permission and request PoP, hides unavailable
destinations, and returns one complete bounded snapshot. A dedicated unary RPC
keeps this small configuration independent of provider inventory paging and
observation replacement/resume. It is an ordinary read; the eight existing
mandatory-feature import gates remain unchanged. Discovery grants no execution
authority, and Prepare and Commit recheck current support and policy.

The response carries 1–32 converters ordered uniquely by exact ASCII version,
each with a versioned converter-owned `options_encoding`, 1–64 sorted unique
`canonical_options` byte sequences (at most 4096 bytes each), and `default_options`
equal to one of those sequences. These are the complete supported choices; a
default is explicit even when empty. The encoding identifies the converter's
public versioned byte specification. For `heddle-import-options-empty-v1`, the
only canonical value is the zero-length sequence. This fixture converter is an
example, never a universal server version/default. Other encodings require their
own specification; select returned octets verbatim instead of reserializing JSON
or protobuf. Compute `options_digest` using `conversion_options_digest` /
`conversionOptionsDigest` and the preimage below. Responses are at most 1 MiB;
do not truncate supported choices.

The response also carries a complete, bounded, sorted unique provider list
(1–2 entries). Each entry has exactly its registered source mode:
`github` -> CONNECTED, `public-git` -> PUBLIC_HTTPS. Zero, unknown, duplicate,
missing or mismatched modes/providers are invalid; unsupported modes are never
advertised. A deployment may advertise either supported path or both. Prepare
and Commit refuse a path absent from the current advertisement.

Optional `default_converter_version` is a host recommendation, not authority or
silent negotiation. When present it is nonempty and references one advertised
converter exactly. Absent means show an explicit chooser. Multiple converters
are valid; lexical order does not express preference, and clients must not pick
the first or latest-looking version. Alternatives remain explicitly selectable.
The selected entry's exact `default_options` octets retain their existing digest
rules; this marker does not change any signed HYBRID layout or domain.

Positive advertised branches/operations cannot exceed 256. The host byte maximum
is a positive operator-configurable u64, with no fixed protocol byte ceiling.
Prepare and Commit refuse a total above the CURRENT maximum, including a decrease
after Prepare. Once activated, the signed job budget and durable consumption stay
fixed. Changing only the byte maximum MUST NOT advance `destination_version`;
other effective configuration, policy and owner changes still do.
The caller chooses every scope field, including exact ordered branches, stable
slots, disclosure, targets/frontiers, options/converter and totals. Prepare echoes
these bytes or refuses, including equivalent normalization and budget reductions.
The sole completion is an empty `proposed_scope.destination_version`: the host
supplies its current opaque 32-byte token. An exact 32-byte input is compared and
echoed; other widths refuse INVALID_SCOPE and mismatch refuses DESTINATION_CONFLICT.
Commit atomically compares the signed token with current state. Changed destination
requires fresh preparation and signatures. This token is never a caller hash,
overview version or zero32 sentinel.

Success carries a proposal and no refusal. Refusal carries no proposal and a
nonzero typed `ImportPreparationRefusalV1` with a bounded field path, no retained
key/bounds, and activates nothing. Authentication and hidden-resource failures
remain uniform CallFailure. `prepare_scope` / `prepareImportScope` check support,
bounds and CAS; `validate_preparation_response` / `validateImportPreparationResponse`
compare the intended and returned scope exactly. Configuration changes require
a fresh Prepare request ID, never a changed response to an idempotent reservation.

The client generates a fresh non-nil UUID v4 as `retry_lineage_id`, reserves it as
the first physical operation ID, and uses separate Prepare/Commit idempotency IDs.
Occupancy by another request/job refuses OPERATION_ID_REUSED without allocating
a replacement. Exact caller-scoped Prepare replay returns its original reservation;
Commit returns that same UUID in canonical lowercase hyphenated form.
`initial_operation_id` / `initialImportOperationId` validate shape and occupancy.

### Complete initial submission (api#327 G1)

**Prepare → sign → CommitImportJob is sufficient.** Commit carries required
`ProviderRepository source` and optional `initial_base_state` along with its
proof. The host revalidates public-source URL rules or the current authenticated
connection, repository and exact user-granted installation before selecting
provider custody. It binds the resolved provider and exact credential-free
clone URL to the signed scope. Projection hints do not authorize provider access.
Public sources have no connection/installation and cannot claim to be private;
their repository ID is empty or the exact clone URL. Connected sources carry an
account-scoped connection and exact repository/installation IDs.

The proof's `original_geneses`, `creator_authority_envelopes` and
`genesis_authorities` are ordered one-to-one with the signed branch manifest,
with exactly one initial delegation and its exact parent permission (or direct
owner). This is the single branch carrier. Preserve each original creator
signature and verify native IDs, envelope commitments and manifest bindings.
Do not regenerate geneses or submit another branches payload. The optional base
is a canonical synthetic empty native State, at most 4096 bytes, whose native ID
equals the base in **every** original genesis. If absent, the exact base closure
must already be hosted. Nonempty closures use SyncService publication.

Under one authorization/destination/reservation transaction, Commit persists
source/base and verified authority, retains the originals pending native
admission, installs epoch 1, and creates the initial physical operation whose ID
equals `retry_lineage_id`. It queues that operation behind its signed not-before
N. Its successful `MutationResponse.receipt` MUST contain `pending_operation` for that created
operation in the destination Spool, never an `applied` acknowledgement. Failure
leaves no activated job, operation or partial branch publication.

### Exact Prepare/Commit delegation boundary (api#321)

`PrepareImportJobResponse.proposal` is **`ImportJobPreparationV1`**, not a
partially populated delegation. It freezes this complete canonical layout, in
field-number order, using the framing above:

| Field | Frozen value / encoding |
| --- | --- |
| 1 | `format_version`: u32be(1) |
| 2 | `identity`: flattened `ImportIdentityV1`, including all six account/Spool/owner state fields |
| 3–5 | `delegation_id`, `logical_job_id`, `retry_lineage_id`: each counted16 |
| 6–8 | `job_public_key`, `job_key_id`, `owner_chain_digest`: each counted32 |
| 9 | `purpose`: u32be(IMPORT_CONVERSION_V1 = 1) |
| 10 | `scope`: flattened `ImportPermissionScopeV1`, including every exact ordered branch limit, provider/URL, OID algorithm/mode, target/frontier, destination/options/converter and budget |

The final field 11 is `cancellation_id`: counted32. There is no predecessor field.

The server persists this exact preparation with its encrypted job key and bounds
before returning. Idempotent Prepare retries return the same reservation, key,
proposal, host time and bounds; they do not restart the one-hour reservation.
The browser checks the proposed identity and scope against its intended import,
then copies every frozen field into `ImportJobDelegationV1` unchanged. Even a
scope reduction or equivalent URL/ref normalization requires fresh preparation.
Each manifest limit is an exact copy of the corresponding ordered prepared
scope branch. The browser supplies **only**:

- `delegating_public_key`: its authorized signer device (or active owner key);
- `parent_permission_digest`: the exact signed typed owner-issued permission,
  or zero32 for direct active owner authority;
- each manifest entry's `genesis_authority_digest`: the exact signed genesis
  binding for that prepared branch, retaining its original creator signature;
- `not_before_unix_seconds` and exclusive `expires_at_unix_seconds`.

The browser signs the **entire completed delegation**, including frozen fields,
under the existing v1 delegation domain. Prepare has no user signature, parent
grant or genesis-binding placeholder and confers no execution authority.

Prepare returns `prepared_at_unix_seconds = A`, exclusive reservation expiry
`R = A + 3600`, positive `max_validity_duration_seconds = D` and nonnegative
`clock_skew_allowance_seconds = S`. At host-owned Commit time `T`, signed
not-before `N` and exclusive expiry `E` MUST satisfy:

```text
0 <= A <= T < R = A + 3600
0 <= N; A - S <= N <= T + S
N < E; T < E; E - N <= D <= 604800
```

Skew permits clock differences at not-before, never grace after expiry or an
extension of parent/owner authority. Commit may accept `N > T` within skew;
execution remains forbidden until `N`. The typed parent must be valid at actual
Commit time and contain the entire child window, and the child's expiry cannot
exceed the independently verified owner authority expiry. Authority expiry MUST
derive from the **effective selected owner state at the verification time**,
never from the immutable sequence-zero root. A still-deferred, unclaimed owner
with a positive deadline is bounded by `claimable_until_unix_seconds`. After an
accepted `ClaimDeferredHuman`, or any accepted transition clearing deferral,
authority is unbounded (`2^63 - 1` seconds), including after the original claim
deadline. Historical verification MUST use the effective state at that historical
time: a future claim cannot make earlier unclaimed authority unbounded.
`effective_owner_authority_expiry` / `effectiveOwnerAuthorityExpiry` take only
independently verified effective-state inputs. A deferred owner with a deadline
<= 0 is inconsistent and MUST reject `Scope`; the Rust helper now returns
`Result<i64, Reject>` and the TS helper throws. Signed parent and child validity
windows still apply. This matches heddle's `authority_expires_at_seconds`.
Use checked/widened
integer arithmetic, including extreme uint64 duration/skew advertisements.

Commit resolves its single initial signed delegation from `proof.delegations`
and uses the delegation ID to select its durable reservation. It never accepts
a caller-supplied preparation/bounds as authority. Verify original native
geneses, creator signatures/envelopes and independently selected owner history;
then recheck current policy, cancellation, device/credential revocation, custody
association and reservation under the activation transaction. The standalone
`verify_delegation` / `verifyImportDelegation` helpers verify signed authority;
they cannot establish equality to a reservation. Typed RPC clients carry the
request and request PoP only and do not silently complete/sign a delegation.

The generated `commit_vectors` freeze passing completed commits, future
not-before at the skew edge, and negatives for every frozen scalar/byte/string
field (including nested identity, scope, both branches and manifest limits),
## Witness set, statements and retirement

The complete sorted root-signed set is served at
`/.well-known/heddle/hosted-witnesses`, independently of descriptor heartbeat/TTL,
with `Cache-Control: no-store`. It is public metadata, not a Thread inventory.
Verify the root signature, selected authority/root, body digest, positive generation,
canonical semantics and receiver-owned time in `[issued_at_ms, valid_until_ms)`.
Freshness is at most **300000 ms**, without grace. Persist generation/body high-water
per selected authority/root; reject lower generation and same generation with a
different body. One CURRENT member's issuance interval contains the entire set
freshness interval. All IDs/public keys are unique; purpose sets are sorted unique
subsets of the four enum values. No transport attestation supplies membership.
`HostedWitnessKeyRole` has only HOST_WITNESS (1); missing/unknown/job roles reject,
as does a member public key in the persistent known-job associations.

The four purposes are genesis first admission; authority/ownership first admission;
committed import publication; hosted landing. The new common statement binds exact
Spool/genesis, owner state/transfer, accepted policy hash/sequence, admission basis,
publisher, authority and original-signature digests, host transaction/order/time,
and purpose-specific canonical payload. Genesis payload binds the exact genesis
and authority envelope. Authority/ownership payload retains exact operation/claim/
resolution and original signatures. Landing retains its existing request/review/
frontier/execution evidence and distinct meaning. A job certificate grants no
ownership, metadata, policy, generic capture, subdelegation or landing authority.
BoundaryAcceptance attests a currently authorized party's acceptance of exact
original work, not historical non-revocation; it needs the complete signed
originals manifest, intent and per-original receipts from the existing acceptance
contract. Import publication under this delegation uses OriginalAuthority.

### Exact boundary acceptance binding (api#318)

`HostedWitnessStatementV1` canonical field order is fields 1–18 in protobuf
number order, followed by field 19 `boundary_acceptance`. Optional messages
have **u32be(0)** for absent or **u32be(1) || flattened canonical message** for
present; no other selector is valid. This also applies to genesis payload field
5. Even OriginalAuthority includes the absent selector in its signing bytes.
All old v1 statement/payload signatures, leaves, seals and paths are regenerated.
There is one revised v1 format and no dual decoding or old-vector fallback.

`HostedWitnessBoundaryAcceptanceV1` has exactly this frozen order:
`format_version:u32be(1)`, `acceptance_id:counted32`,
`signed_acceptance_digest:counted32`, `originals_manifest_digest:counted32`,
`publication_intent_digest:counted32`, `original_receipt_digests:u32be(count)`
followed by each `counted32` digest in strictly increasing raw-byte order.
The receipt set is nonempty, unique and at most 128; omissions, duplicate receipts
and truncation reject. It contains the complete selected per-original receipts
for this acceptance. The binding is mandatory exactly for BoundaryAcceptance
basis 2, only on purposes 1/2. OriginalAuthority basis 1 has no binding; converted
publication and landing use basis 1. A genesis payload carries exactly its
matching evidence. Authority payload field 6 carries a unique acceptance-ID-sorted
list of evidence for its original and boundary dependencies, within the 64-KiB
payload limit. Other originals never inherit a neighboring receipt's acceptance.

`ImportBoundaryAcceptanceV1` flattens, in field order: `binding`,
`signed_acceptance:SignedRecord`, `originals_manifest:counted bytes`,
`publication_intent:counted bytes`, `original_receipts:u32be(count)` followed by
canonical `SignedRecord` entries in the binding's exact receipt-digest order.
Its manifest is the **complete** native `OriginalPublicationManifest` named
MessagePack, and intent is exact named MessagePack `PublicationIntent`.
The signed native acceptance commits to both of their native IDs: that signature
is the complete manifest/intent signature binding; no separate manifest signer
or second intent signing format is invented. Acceptance and receipts each have
exactly one original Ed25519 signature. Their original bytes are unchanged.

| Field | Exact commitment preimage / algorithm |
| --- | --- |
| `acceptance_id` | Native `BLAKE3(UTF8("heddle-original-boundary-acceptance-v1") || u64le(len(A)) || 0x00 || A)`, with `A` the exact native acceptance body |
| `signed_acceptance_digest` | SHA256(`UTF8("heddle-signed-native-record-v1") || canonical SignedRecord`), including the original acceptance signature/key |
| `originals_manifest_digest` | SHA256(`UTF8("heddle-boundary-originals-manifest-v1") || u32be(len(M)) || M`), complete manifest bytes `M` |
| `publication_intent_digest` | SHA256(`UTF8("heddle-boundary-publication-intent-v1") || u32be(len(I)) || I`), complete intent bytes `I` |
| Each `original_receipt_digests` entry | SHA256(`UTF8("heddle-signed-native-record-v1") || canonical SignedRecord`), exact original native admission receipt and signature |
| Fixture binding commitment | SHA256(`UTF8("heddle-hosted-boundary-acceptance-binding-v1") || canonical binding`); the statement signs the full flattened binding, not just this digest |

Domains in this table have no terminal NUL. Native manifest and intent IDs inside
`A` remain BLAKE3 typed IDs with the same native preimage as the acceptance ID,
using `heddle-original-publication-manifest-v1` and
`heddle-original-publication-intent-v1` respectively. They are checked against
`M` and `I`, independently of the SHA256 transport commitments. Every receipt's
native `AdmissionBasis::BoundaryAcceptance.acceptance` MUST equal `acceptance_id`.
Its native kind/subject must name the exact original: genesis receipt `thread`,
or authority receipt `Operation`/`OwnershipClaim`/`OwnershipResolution` subject.
The witness binding must equal the sidecar binding byte for byte. These checks
reject a substitution even if the outer hashes and witness signature are valid.

`native_dependencies` / TS dependency verification admit native
`heddle-original-boundary-acceptance-v1`, `heddle-thread-genesis-admission-v2`,
and `heddle-thread-authority-admission-v3` only when the **exact SignedRecord**
resolves in matching validated evidence; absent evidence rejects
`BoundaryAcceptance`, never a generic Version or Signature error. No allowlist-only
acceptance path exists. Complete manifest selection, original/account/Spool/kind,
receipt scope, native canonical re-encoding, receipt issuer trust and current
accepting authority still require native verification. Signature/commitment
matching does not select an owner or witness trust root. The published-codec gate
calls `selected`, `authorize_with_acceptance` (including `authorize_evidence`),
and the real current accepting-authority verifier against independently selected
roots, using authenticated witness times. All accepted evidence and dependency
signatures are covered by the canonical payload and binding in the retirement
leaf; per-original receipt commitments refer to existing native receipts, so
there is no circular commitment to the enclosing HYBRID statement.

Frozen passing vectors cover both branch genesis acceptances and source acceptance
with native acceptance/receipt dependencies, plus exact retirement proofs.
Negatives isolate acceptance exchanged between originals, a complete manifest
mismatch, a complete intent mismatch, a receipt from another acceptance, missing
statement binding, and missing dependency evidence. They have authentic witness
signatures and otherwise exact commitments; each reports `BoundaryAcceptance`
and then verifies its neighboring exact control in both Rust and TypeScript.

Each committed converted operation has its own receipt with the shared complete
publication-manifest digest. `ImportPublicationWitnessV1` binds exact signed job
operation and certificate, source observation/OID algorithm, logical/physical
job/slot, expected/result frontiers and manifest. The enclosing common statement
binds accepted owner/policy/basis/transaction/order/time. Original user/job proofs
are independently mandatory. Atomically journal canonical statement/signature
and all dependencies with the actual admitted/published result; never export a
successful receipt before commit. Witness signatures supply no missing user
signature or conversion mapping proof.

Retirement tree:

- Leaf: H(0x00 || purpose_u32be || canonical_length_u64be || canonical || signature).
- Internal node: H(0x01 || left32 || right32). Empty root: H(empty).
- Sort leaf digests bytewise, reject duplicates, recursively split at the largest
  power of two STRICTLY smaller than count; no odd-leaf duplication.
- Proof: executor selector, purpose, u64 index/count, bottom-up sibling hashes.
  Direction is derived from index/count/tree shape; reject extra/missing siblings.

The receiver recomputes the leaf from its exact original canonical statement and
signature; a supplied leaf digest alone is insufficient verification. CURRENT
historical testimony needs its issuance interval. RETIRED additionally needs the
exact inclusion proof. New issuance requires CURRENT and actual host time/fence.
A retired seed signing an in-range/backdated new statement cannot substitute an
old path. REVOKED/unknown/purpose-mismatched testimony fails closed.

## Proof lookup and disclosure

`IntegrationService/GetHostedWitnessHistoryProof` and the HTTPS route
`/.well-known/heddle/hosted-witness-history-proof` share the exact request/response
DTOs (POST, protobuf application body on HTTPS). Each request has one **32-byte
executor ID and one 32-byte leaf digest**, no batch/list/prefix/pagination; validate
before archive I/O. Success returns **proof only**, at most **64 siblings / 4096
encoded response bytes**. Root/count come from the fresh authenticated signed set,
not from an untrusted lookup response. No original bytes, Thread/account IDs,
content, delegation or authority bundles are returned. Unknown ID/leaf/unsealed
archive share uniform NOT_FOUND; no metadata-rich errors or request-digest logs.
Use bounded per-source/global rate and concurrency limits, uniform size/latency
classes where practical, and retryable throttling.

Possession of the exact digest is sufficient; no session or current read grant is
required. This preserves retrospective retrieval after download, lost grant and
Thread deletion. Public seals/archive nodes/proofs survive resource deletion,
account purge and descriptor cleanup indefinitely. Ordinary Fetch still checks
current disclosure/audience/published revision; proof lookup restores no read
permission, public original, enrollment or mutation authority. Export/Fetch/relay
carry each original owner/genesis/delegation/operation/publication dependency,
signed set and per-statement proofs; receivers may fetch missing retirement paths.

A hit confirms membership of this exact digest in the public sealed archive, and
index/count/path reveals tree structure. A digest is NOT a formal proof of
possession: anyone knowing it can query, and someone able to reconstruct the
exact signed statement can test admission. Signatures make broad guessing
impractical but do not prevent known-statement confirmation. This limited
existence oracle is deliberate policy; there is no zero-leak claim or enumeration
endpoint. Mirror/backup the public archive independently of Thread storage.

## Bounds, mutation checks and compatibility

| Item | Maximum / required bound |
| --- | --- |
| Canonical signed import body / witness payload | 64 KiB |
| Signed set, complete public proof bundle | 1 MiB each; reject, never truncate |
| Witness entries | 4096 |
| Import branches/operations | 256 each; one result slot per branch in v1 |
| Policy records / original geneses / creator envelopes | 256 each |
| Member permission / publication manifest snapshots | ONE optional / 256, digest-sorted unique |
| Typed genesis/authority/landing payload sidecars | 256 each, inside the bundle byte budget |
| Witness dependencies / retirement proofs | 1024 each, also inside bundle byte budget |
| Inclusion siblings / encoded lookup response | 64 / 4096 bytes |
| Source URL / full ref / root ID | 2048 / 1024 / 256 UTF-8 bytes |
| Keys / signatures / hashes / UUIDs | Exactly 32 / 64 / 32 / 16 raw bytes |

Explicit out-of-band descriptor-root replacement invalidates old contexts and
preserves authenticated history, generation high-water, known seals, intervals,
tombstones, job-key associations and the clock floor. Replacement compares the
expected old pin and advances its epoch by one; generation and high-water MUST
NOT reset. There is no previous-root overlap. The old root MUST NOT authenticate
new responses, and every context created under its epoch rejects as
`StaleContext`. Clients install the new pin explicitly out of band.
Compromised-root recovery requires
independent pre-compromise provenance, not a newly signed archive/higher generation.
Otherwise affected history is unavailable. The owner [accepted replica-held root
custody](https://github.com/HeddleCo/weft/issues/2469#issuecomment-5943900946) for first
release; exact seals defend witness-key-only compromise under honest-root/journal
assumptions, not whole-replica compromise. Fence issuance, replace the root out of
band and fail closed on unprovable history; isolate the issuer after launch.

Per the **OWNER DECISION of 2026-10-03**, `ProtocolCompatibility` requires
**protocol_version = 2** and the sorted unique mandatory feature list containing
exactly **IMPORT_AUTHORITY_HOST_WITNESS_V1 (1)** on these eight
**IntegrationService** RPCs only: **ImportSource**, **RetryImportSource**,
**CancelImportJob** and **GetHostedWitnessHistoryProof**. Missing/unknown
version/features reject with FAILED_PRECONDITION / incompatible peer BEFORE
staging or mutation, not merely after ignored additive proof fields.
`RpcContract` and the generated Rust `MethodDescriptor` declare that exact gate
set; Rust `Client` and TS `createServiceClient` check negotiated support before
transport. `MethodDescriptor.verify_protocol` provides the server dispatch gate
before body parsing. HTTPS equivalents advertise/require
`Heddle-Protocol-Version: 2` and
`Heddle-Mandatory-Features: import-authority-host-witness-v1` on those import routes.
Capability/method listing alone does not establish semantic support.

**SyncService Fetch, PublishContent and ReplicateThread do not declare a
method-wide mandatory feature in this release.** Ordinary openings and ready
replies without HYBRID evidence do not require HYBRID protocol negotiation.
Present HYBRID evidence still requires explicit compatible consumer support.
The optional protocol and public proof fields remain additive in the schema.
The Sync gate is deferred to the **same release that ships real HYBRID support
in both heddle and weft**, tracked by
[api#307](https://github.com/HeddleCo/api/issues/307). There is no bridge. This

| Purpose / typed payload | Exact canonical field order |
| --- | --- |
| 1 / `ImportGenesisWitnessV1` | `format_version:u32`, `binding:SignedImportGenesisAuthorityV1`, `original_genesis:SignedRecord`, `creator_authority_envelope:bytes`, `boundary_acceptance:optional<ImportBoundaryAcceptanceV1>` |
| 2 / `ImportAuthorityWitnessV1` | `format_version:u32`, `kind:u32`, `original:SignedRecord`, `dependencies:list<SignedRecord>`, `authority_envelope:bytes`, `boundary_acceptances:list<ImportBoundaryAcceptanceV1>` |
| 3 / `ImportPublicationWitnessV1` | `format_version:u32`, `signed_operation_digest:bytes`, `delegation_digest:bytes`, `logical_job_id:bytes`, `retry_lineage_id:bytes`, `physical_operation_id:bytes`, `ref_name:UTF8`, `slot_id:u64`, `hash_algorithm:u32`, `observed_commit_oid:bytes`, `expected_frontier_digest:bytes`, `resulting_frontier_digest:bytes`, `terminal_manifest_digest:bytes` |
| 4 / `HostedLandingWitnessV1` | `format_version:u32`, `execution:SignedRecord`, `request:HostedLandingRequestProofV1`, `source_operation:SignedRecord`, `review_evidence:list<SignedRecord>`, `authority_envelope:bytes` |
| `HostedLandingRequestProofV1` | `format_version:u32`, `signing_identity:UTF8`, `method_path:UTF8`, `timestamp_millis:i64`, `nonce:bytes`, `request_body:bytes`, `signature:RecordSignature` |
| `SignedRecord` transport commitment | `format:UTF8`, `canonical_record:bytes`, `signatures:list<RecordSignature>` |
| `RecordSignature` | `public_key:bytes`, `signature:bytes` |

All format versions above are exactly 1. Native record bodies are the already
versioned **named MessagePack** formats: `heddle-thread-genesis-v1`,
`heddle-thread-operation-v1`, `heddle-thread-ownership-claim-v1`, and
`heddle-thread-ownership-resolution-v1`. This does not introduce another native
record encoding. Signatures verify raw `UTF8(format) || 0x00 || canonical_record`.
Each record has 1–16 signatures, sorted uniquely by raw public key; claims and
resolutions require both the original local-owner and accepting-publisher
signatures. Each native body is at most 64 KiB within the payload's 64-KiB budget.
Dependencies/evidence have at most 128 entries, sorted uniquely by
H(`heddle-signed-native-record-v1` || canonical SignedRecord); every entry is
independently verified and must be part of the native causal/authority closure.
Never use a dependency signature to authorize its neighboring original.

Purpose 2's kind discriminator selects exactly **1 = ThreadOperation v1,
2 = ownership claim v1, 3 = ownership resolution v1**; unknown/zero rejects.
Kind 1 retains original source/control records, never a hosted execution as a
source-author grant. Claims resolve their original local-key genesis, complete
source frontier and account acceptance; resolutions additionally resolve every
conflicting original claim, the winning member and complete accepted frontier.
Neither a witness nor an incoming kind selector supplies this authority.

Purpose 4 retains the existing native `HostedIntegration` v1 inside the original
ThreadOperation v1 **Integration** body. The enclosing operation binds target,
parents and executor. Its named MessagePack fields, in native order, are
`version`, `spool`, `spool_genesis`, `executor`, `source_thread`, `source_operation`,
`source_revision`, `target_thread`, `expected_target_frontier`, `result`,
`initiating_request_proof`, `review_policy_version`, `review_evidence`,
`executed_at_ms`. UUIDs use MessagePack bin16; native 32-byte IDs/keys and Vec<u8>
use arrays of integer bytes; sets are bytewise sorted arrays. `result` is native
Capture v1, described below. This selects the existing
`heddle-hosted-integration-v1` meaning; HostedImport is explicitly ineligible.
The native landing verifier still checks exact source State, target ancestry,
policy and all review/evidence originals. Request proof is the original
`signing::unary_bytes` / `unarySigningBytes` input for
`/heddle.api.v1alpha2.ThreadService/LandThread`, positive millisecond timestamp,
16-byte nonce, deterministic `LandThreadRequest` protobuf bytes and signature.
`signing_identity` is `principal:device-key:` followed by lowercase hex of its
32-byte signer. It uses the unchanged `heddle-req-sig-v1` counted textual
request framing, not the witness digest; the payload retains the full preimage.
The existing hosted initiating-proof ID is frozen exactly as follows. Let `U`
be the unchanged unary signing input and `S` the original 64-byte Ed25519
signature. Let `P = U || S`, with no separator or additional length around `S`.
The ID is native `ContentHash::compute_typed("weft-hosted-landing-request-proof-v1", P)`:
`BLAKE3(UTF8(domain) || u64_le(len(P)) || 0x00 || P)`. Both the domain and the
signature's inclusion are mandatory. A witness signature cannot replace `S`.
Never compute State IDs by hashing MessagePack: State's existing versioned
field hash remains unchanged. Ordinary native Captures must contain a child
State; their declared State parents, after excluding the signed genesis base,
must equal the States selected by their complete causal operation parents.
The frozen "old parentless capture" negative still rejects.

**Owner decision (2026-10-05): delegated native IMPORT parent rules.**

An import produces **one native operation per branch result slot**; v1's one
slot and fixed frontier are unchanged. Git ancestors are not native operations:
they are State objects in the tip State's parent closure, transferred and
verified as content.

The import rule is selected **only by the separately authenticated IMPORT
carrier**: the verified import delegation and signed import operation that bind
this exact operation's operation ID, Thread/genesis, causal frontier and
delegation scope. Caller context never selects it. A carrier for another
operation or frontier does not unlock it. Every path that admits or verifies an
imported Capture MUST verify its carrier. The signed `ThreadOperation` has no
import field; imported Captures use `SourceAuthor::LocalKey`. There is no signing
or wire-format change.

With an **empty causal frontier (first import)**, the State carries its converted
Git parents unchanged: none for a root commit, or the tip's ordered Git parents,
including merges and multi-root histories. These State parents are not compared
with the operation's causal parents. The genesis base (synthetic seed) MUST never
appear among them; the signed genesis binds the canonical synthetic empty base.
Git-parent fidelity is attested by the shared converter and the host witness's
signed conversion. This is the same trust basis used by the retired
`HostedImport` receipt, not new trust.

With a **non-empty causal frontier**, State parents MUST strictly equal the
source States of the complete causal operation parents, with the seed excluded.

Standalone operation validation without its verified carrier keeps the strict
ordinary rule. Ordinary native Captures are unchanged: they still require a
child State, and the frozen "old parentless capture" negative still rejects.
Conformance vectors follow after the next heddle release because
`tools/hybrid-native` pins published heddle.
This docs-only decision does not change the frozen vectors, State IDs or
converter correctness.

For account-native originals, `authority_envelope` is exact canonical protobuf
`ThreadControlAuthority` format 1 from `identity.proto`, including its verified
owner history, owner/passkey mint-root association and **sealed** signature-v1
Biscuit. Its existing dual-oneof-tag rejection and ordinary action/scope/PoP
checks remain mandatory. The native vectors include a real sealed device-minted
signature-v1 Biscuit, a genuine owner-signed device mint-root attachment, source
and control operations, a co-signed claim/resolution and an original landing
request, review and execution. The token uses only published fixture seeds and
contains no appendable proof secret. Its maintenance input is the frozen
`hybrid-native-biscuit-v1.binpb`; it is never minted during verification. The
creator envelope in the import-specific genesis vector is exact
`UTF8("heddle-signed-import-member-permission-v1\0") || canonical signed permission`;
this proof grants the scoped genesis/import rights only, never metadata/landing.

`ThreadControl.authority_envelope` is an ordinary native `Vec<u8>` and therefore
uses an integer array, including inside review controls. In contrast,
`SourceAuthor::Account.authority` explicitly uses native `serde_bytes` binary.
Never choose the representation from the semantic meaning of "bytes"; retain
the pinned codec's representation and exact parse/re-encode equality.

The locked `tools/hybrid-native` tool uses published `heddle-api
0.31.0-alpha.19`, `heddle-thread-api 0.28.7`, `heddle-object-model 0.28.7`,
`heddle-crypto 0.28.7`, `heddleco-capability-verifier 0.28.7`, and
`heddle-biscuit-verifier 0.28.7`. Rechecked on 2026-10-04: the complete 0.28.7 crate set
and alpha.19 are published; 0.28.7 requires exactly alpha.19,
so 0.28.7/alpha.19 is the newest compatible published pair. Maintenance
generation uses these codecs. `tools/verify.sh` runs its
fixed-vector gate for native parsing, re-encoding, signatures, child ancestry,
causal/claim closure, original authority and hosted request binding, plus fresh
historical verification from the complete export, independently selected roots
and retirement paths. The boundary gate matches receipt subjects one-to-one
to the complete native selected set, resolves each signed original and creator
envelope, and verifies current accepting authority for every selected subject.
It checks every supplied dependency acceptance and selects the enclosing
original's acceptance by the statement's exact binding. Frozen two- and
three-original controls and multiple dependency acceptances accompany omission,
duplicate, substitution and extra-receipt negatives. Shared Rust/TypeScript
commitment tests remain separate from these native semantic checks. It also rejects the retained old parentless and
non-canonical originals and the old request-proof formula, and independently
removes each selected policy and genesis-admission original. The closed legacy
dispatch control retains its exact pre-`source_ref` negative bytes.

Common field matching is also frozen:

- Purpose 1 `authority_digest` is the signed genesis-binding digest;
  publisher is its creator key ID. Match the binding's exact identity and
  native Thread genesis ID, original creator signature and H(raw creator
  envelope). Independently verify that envelope and the native genesis.
- Purposes 2 and 4 `authority_digest` is
  H(`heddle-hosted-authority-envelope-v1` || counted exact envelope).
  Purpose 2's publisher is the original native actor/acceptor; purpose 4's
  publisher is the original landing requester. Both require independent native
  authority at the statement's accepted state/order/time.
- Purposes 1/2/4 `original_signatures_digest` is
  H(`heddle-hosted-original-signatures-v1` || u32be(signature_count) || each
  canonical RecordSignature). Traversal order is genesis original; or purpose 2
  original then digest-sorted dependencies; or landing execution, source,
  digest-sorted review/evidence, then original request signature. Native
  signature order inside each record is raw-key order. Purpose 3 remains
  H(raw original 64-byte job signature), bound by its exact signed operation.

`verify_witness_payload` / `verifyWitnessPayload` verify these original signatures
and purpose-specific exact matching independently of `resolve_statement` /
`resolveWitnessStatement`. Their payload argument must be built from the native
verifier's independently verified originals and accepted owner/policy/landing
context. Signature/matching success alone does not establish causal or landing
eligibility. Genuine witness statements with a missing owner signature, and a
genuine witness signature substituted for a job/request signature, fail the
original-evidence check. No legacy HostedImport fallback exists.

## One-shot job lifecycle (alpha.33)

Exactly ONE user-signed delegation authorizes one logical job. Retry creates a fresh
host UUID under that same certificate, without another user signature. Cancel
remains available to any current destination writer with authenticated PoP. At the
exclusive certificate expiry, unfinished work is terminal. Fence paused workers,
destroy the job key and release active refs in that transaction; the client imports
remaining work as a NEW logical job with a new one-click authorization. A physical
attempt's FAILED/CANCELED state does not itself cancel the logical job.

Commit freezes exact request bytes and the source/base association, activates epoch
1, and creates the initial physical operation identified by the client-generated,
non-nil retry-lineage UUID. It returns receipt.pending_operation. Exact caller-scoped
Commit/Retry/Cancel replays return their original receipts before current expiry/CAS
checks. Changed bytes under an existing request ID refuse OPERATION_ID_REUSED.
Retry allocates an unused host UUID from the complete durable prior-attempt set,
persists both supersession links and the receipt atomically, and never uses the
idempotency key as that UUID. Current owner/policy/revocation, leases, source grants,
selected commit availability and frontier CAS are still mandatory for new work.

The contract permits job-key retention for only seven days after certificate-terminal
as an absolute maximum, including backups and replicas. Destroying the encrypted seed
and live key at certificate-terminal is the EXPECTED behaviour. Public proofs,
receipts and replay records remain; encrypted key custody never appears in a proof.
Job custody AEAD context binds version/account/Spool/genesis/logical job/
delegation/key/purpose and wrapping-key version. Restore applies deletion
tombstones BEFORE workers, including restoration from a pre-tombstone backup.
Backup retention cannot extend secret-key retention beyond the seven-day maximum.
Public proofs/results/receipts/history remain indefinitely. Recurring remote sync
requires its own explicit scoped authority and cannot reuse an expired certificate.

### Publication-time genesis admission

For each branch, issue its first P1 admission in the SAME host transaction as its
P3 publication, after all eligibility checks and before making either visible.
Require exactly equal `observed_at_unix_millis` and `host_transaction_id` on the
branch's P1/P3 and equal `executor_id`, with `P1.admission_order < P3.admission_order`.
“Same transaction” is the host's signed assertion. Receivers check its consistency;
they cannot prove atomicity. The host MUST make the pair visible atomically. This authenticated
order permits other statements in the transaction. Conversion start is not an
admission event. There is no admitted-but-unpublished state and no genesis-only
Thread. Retaining a signed original for an unpublished branch grants no testimony.
Pair each P1 with the P3 consumed by that operation's progressive manifest prefix,
independent of statement array order. Refuse unconsumed or duplicate P3s and more
than one P1 per genesis. Every carried P1 must have a matching branch publication. Every published branch
must retain its exact original, creator envelope, P1 sidecar and P1/P3 receipts.

The witnessed time must lie in the exact half-open delegation interval [N,E).
Verify owner key, effective-state expiry, owner interval, parent permission, policy
and revocation live at that time, before issuing testimony. No testimony before
eligibility and no skew grace after E. The native consumer still verifies originals,
policy and owner histories; a witness signature cannot replace those checks.

Clients set not-before approximately now. There is no scheduled-Commit admission
semantics: Commit retains originals and queues work; publication supplies P1/P3.
The existing skew allowance permits a small future N at Commit, but no execution
or testimony occurs before N. The Prepare reservation is still exactly 3600 seconds.
Delegation duration has an absolute protocol ceiling of 604800 seconds (7 days).
Refuse host-advertised D above that ceiling, even for a shorter signed window, and
refuse every signed E-N above it, including direct-owner and recovery certificates.
The ceiling bounds unattended server-held signing authority to one week; effective
owner/parent expiry may shorten it. Rust/TS Commit verification and browser signing
preflight enforce the same bound. Hosts MUST support advertising 86400 seconds
(24 h); the verifier accepts E-N=86400 when D and owner/parent authority permit it.

### Sibling jobs and host ref exclusivity

A client MAY Prepare and Commit sibling jobs sequentially, including preparing the
next after an earlier job completes, or concurrently. Each has its own logical job,
key, signature, cancellation ID and cumulative budget, with at most 256 branches.
There is no spool-wide 256-branch limit. Imports do not advance destination_version;
configuration, policy and ownership changes do. Stale Prepare tokens refuse
DESTINATION_CONFLICT, and stale activation tokens refuse StaleContext.

Hosts MAY reserve all selected full refs at Prepare, or enforce exclusivity at
Commit/activation with a unique index over non-terminal jobs. Either path MUST
atomically refuse a duplicate `(spool_uuid, full_ref)` with DESTINATION_CONFLICT,
including different sources or slots, and activate nothing on refusal. Prepared
key/proposal custody and exact Commit comparison remain mandatory in either mode;
a Prepare proposal alone is not an exclusive-ref reservation. If an inventory is
used, it is complete under the same transaction. Branch target/genesis identities
remain unique within the job and exclusive among active jobs. Same-job branch
rebinding also refuses DESTINATION_CONFLICT. Hosts release refs on definitive
completion, Cancel, revocation or certificate expiry after fencing in-flight work.

Commit sibling conflicts have ONE transport encoding: `CallFailure.code =
ALREADY_EXISTS (6)`, `ErrorDetail.reason = IMPORT_DESTINATION_CONFLICT (505)`.
The Rust `import_commit_conflict_failure` / TS `importCommitConflictFailure` helper
maps the reservation gate's internal DESTINATION_CONFLICT refusal to this envelope.
Stale destination CAS instead encodes `ABORTED (10)` / `VERSION_CONFLICT (502)`,
so clients can distinguish waiting for a sibling from re-Preparing stale state.
Neither admission refusal is replay-frozen under `client_operation_id`: no activation
or mutation receipt exists to freeze. Hosts MUST invalidate the failed preparation,
destroy its prepared key custody and release its reservations atomically. A client
may re-Prepare after resolving the conflict, then submit fresh prepared bytes under
the same unaccepted Commit ID. Accepted Commit receipts remain replay-frozen.
No full ref or hidden sibling metadata needs to be disclosed in the error.

### Learning the already-committed set

Before offering “Import remaining branches” as a NEW job, read GetImportJobState
and require a terminal status. Then start a fresh, complete destination sync/Fetch
after that read (not a previously cached or in-flight Fetch). The terminal fence
prevents further publication by that job. Use the existing `TransferReady.import_authority`
and Fetch/export proof carriers, and verify each selected job's
`ImportPublicProofBundleV1` with `verify_import_bundle_witnesses` /
`verifyImportBundleWitnesses`. Select the old job by the bundle's signed logical
job/lineage and destination identity; retain the verified cumulative
`accepted_history` / `acceptedHistory` manifest. Its `slots` identify committed
`(ref_name, slot_id)` values and their signed operation digests. Subtract these
from that job's exact signed original branch scope, then refresh destination refs
and frontiers through sync before preparing the new scope with fresh target
identities. Destination ref presence alone does not prove that this job committed
a branch. GetImportJobState supplies the terminal status/epoch but no manifest.

Wait for a synchronized destination snapshot after the terminal fence: all
accepted P3 publications must be included before selecting remaining branches.
An incomplete/unverified proof or a stale cached prefix must not be treated as
proof that a branch is uncommitted; finish Fetch/sync first. These existing public
carriers provide the manifest; no new job-state field or RPC is required.

### Minimal state and Retry admission

GetImportJobState returns one authenticated destination-writer snapshot, bounded to
4096 encoded bytes: status, active_cancellation_id, authority_epoch,
active_delegation_digest, and exactly one retry_availability arm. Status is ACTIVE,
COMPLETE, CANCELLED, REVOKED or EXPIRED; expired work cannot be revived. Unknown and
unauthorized jobs use uniform NOT_FOUND. The active digest is required by Retry's
existing request fence; ID/epoch are required by Cancel. No full OperationRecord,
source selector, public proof, owner history or manifest is disclosed on this path.
Fetch/export supplies ImportPublicProofBundleV1 through its own existing carrier.

Eligible retry target names the unsuperseded FAILED/CANCELED physical attempt and
its opaque operation CAS. Otherwise return a known retry reason, including
AUTHORITY_EXPIRED (7). Status and reason MUST agree: ACTIVE permits only
NO_TERMINAL_ATTEMPT (1), ATTEMPT_IN_PROGRESS (2), ALREADY_SUPERSEDED (6), or an
eligible target; COMPLETE requires COMPLETE (3), CANCELLED requires JOB_CANCELLED
(4), REVOKED requires JOB_REVOKED (5), and EXPIRED requires AUTHORITY_EXPIRED (7).
This advice grants no authority. Host Retry admission receives
the durable source association and complete cumulative manifest as separate
receiver-owned context inputs. Connected Retry requires the current caller to own
that exact connection and its exact repository/installation grant; public Git
requires current commit access. Cancel needs no source fetch. Admission also checks
status, epoch, active digest, logical job/lineage, operation CAS, remaining slots,
current authority time and current revocation under one transaction.

### Public proof verification and budgets

The public carrier contains exactly ONE delegation and its sole optional typed
member_permission. The former repeated parent history and predecessor fields are
removed. Manifests are digest-sorted, at most 256: one cumulative manifest for each
publication, or one explicit empty manifest for time-free recovery. Operations
follow authenticated publication order. Their sum must fit max_operations and
max_result_bytes under the one delegation and its parent; Retry never resets totals.
`remaining_import_scope` / `remainingImportScope` subtract committed slots solely
for publication budgeting; they supply no replacement-authority workflow.

`verify_import_bundle_witnesses` / `verifyImportBundleWitnesses` authenticate witness
statements and retirement paths before deriving owner times. The owner resolver
receives ONLY the authenticated time (None/undefined for time-free recovery), without
a delegation index. Resolve the effective owner key and expiry and require its
[effective_from,effective_until) interval to contain that time, at each P1 and P3.
The first P3 time also selects the certificate's initial historical verification.
With no P3 there is no claimed historical admission. Recovery is non-executable;
it can advance authenticated witness-set trust but cannot persist unwitnessed job
history or key associations. Witnessed snapshots preserve exact signed records,
publication prefixes and cumulative manifests and reject rollback/omission.

StaleManifest remains for a missing digest-addressed publication manifest. CommittedSlot
and SlotConflict remain for committed-slot exclusion and nonidentical publication
replay; StaleContext remains for Cancel/Retry/destination fences. These refusals have
non-renewal consumers. The renewal fork and original-window-only refusals are deleted.

UNKNOWN is always a permitted size estimate, including connected GitHub. A host MAY
use the GitHub repository API size; an UNKNOWN answer has git_size_kib=0. Estimates
are advisory and do not replace the signed logical-job budget or publication sum.
