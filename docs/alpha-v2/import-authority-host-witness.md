# HYBRID import authority and host witness, format 1

This is the api#296 contract, revised in place by api#318 and api#321, for [weft#2479 at
8d427f8c1](https://github.com/HeddleCo/weft/pull/2479/changes/8d427f8c12006c63c5cad43cce260fd91a5e77a5).
The build decision is [weft#2469](https://github.com/HeddleCo/weft/issues/2469).
The undeployed v1 preparation schema is revised in place; its semantics require a coordinated incompatible-peer
gate. Package versions and tags do not change in this PR. The delivery order is
**api → heddle → weft → tapestry**. This contract neither deploys that cascade
nor establishes that the original runtime defect is fixed.

The single source of conformance bytes is
[import-authority-host-witness-v1.json](../../tests/fixtures/import-authority-host-witness-v1.json).
Its frozen descriptors identify every new message and field number/type. Rust
and TypeScript read its original bytes, digests and signatures, including the
negative records; they never generate expected signatures during a test. The
maintenance generator requires built bindings and explicit fixture review.

## Message inventory

| Accepted design section | Additive messages |
| --- | --- |
| Owner-authorized genesis and delegation | `ImportIdentityV1`, `ImportOwnerChainV1`, `ImportBranchLimitV1`, `ImportPermissionScopeV1`, `ImportMemberPermissionV1`, `SignedImportMemberPermissionV1`, `ImportGenesisAuthorityV1`, `SignedImportGenesisAuthorityV1`, `ImportBranchManifestV1`, `ImportJobDelegationV1`, `SignedImportJobDelegationV1` |
| Job preparation, encrypted custody, expiry, and retries | `ImportJobPreparationV1`, `ImportCommittedSlotV1`, `ImportResultManifestV1`, `ImportJobRenewalV1`, `SignedImportJobRenewalV1`, `PrepareImportJobRequest`, `PrepareImportJobResponse`, `CommitImportJobRequest`, `RenewImportJobRequest`, `CancelImportJobRequest` |
| Owner-authorized genesis and delegation: converted content | `DelegatedImportOperationV1`, `SignedDelegatedImportOperationV1` |
| What the host witness attests | `HostedWitnessBoundaryAcceptanceV1`, `ImportBoundaryAcceptanceV1`, `ImportGenesisWitnessV1`, `ImportAuthorityRecordKind`, `ImportAuthorityWitnessV1`, `HostedLandingRequestProofV1`, `HostedLandingWitnessV1`, `ImportPublicationWitnessV1`, `HostedWitnessStatementV1`, `SignedHostedWitnessStatementV1` |
| Complete authenticated witness set and exact retirement archive | `HostedWitnessEntryV1`, `HostedWitnessSetV1`, `SignedHostedWitnessSetV1`, `HostedWitnessHistoryProofV1` |
| Proof lookup after loss of Thread access | `GetHostedWitnessHistoryProofRequest`, `GetHostedWitnessHistoryProofResponse` |
| Verification at the mutation boundary / cross-repo proof transport | `ImportPublicProofBundleV1`, `ImportFrontierV1`, `ImportContentV1`, `ImportJobCasStateV1` |
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
signer ID, counted signature). These widths and layouts are frozen for v1. api#318 revises the undeployed v1
layout in place; no old layout or compatibility reader is retained. After first
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
| `ImportJobRenewalV1` | Ed25519 over H(`heddle-import-job-renewal-v1` || canonical body) |
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

Both repository and ref `hash_algorithm` come from independently established
repository object format (for example an authenticated provider object-format
read or Git's object-format advertisement), not the selected OID length, URL,
default branch or a SHA-1 assumption. UNSPECIFIED (zero) means unknown/unavailable;
unknown enum values are unsupported. Missing/failed format discovery blocks
Prepare and signing and offers retrying discovery, even when OBSERVE is chosen.
A discovery response can report zero with empty OIDs without authorizing work.
Every ref's algorithm agrees with the repository, and each nonempty `head_oid`
is exactly lowercase 40-hex for SHA-1 or 64-hex for SHA-256. Mismatch is refused.
The browser uses `validate_discovered_import_scope` / `validateDiscoveredImportScope`
before preparing/signing: every selected branch must use that discovered format;
a known selected OID must be pinned exactly. Algorithm discovery alone never
waives signed observe disclosure or the settled known-OID pinning rule.

Prepare carries required `ImportSourceSelectionV1`: connection/repository,
installation and visibility, while its URL is `proposed_scope.source_url`.
The host resolves it anew, compares the current source to the signed provider/URL
and branch formats/OID selections, then uses current configuration and policy.
`prepare_import_source_scope` / `prepareImportSourceScope` perform these portable
checks using the independently resolved source. Commit repeats current grants,
provider/mode support, object format, known OID and converter/options/budget
checks before custody/activation. The independently resolved current repository is an explicit
input to `validate_commit_request` / `validateImportCommitRequest`, separate from
the untrusted source projection; current hash format and known OIDs come from
that resolved snapshot, so clearing incoming refs cannot bypass known-OID pinning.
A frozen PINNED_COMMIT continues to name its selected commit when the mutable
branch head moves after Prepare; Commit never substitutes or requires a new head. Host lookup/fetch, revocation and atomic mutation
remain host responsibilities. Exact accepted replay retains its settled semantics.

Unknown fields, versions, algorithms, purposes, duplicate fields, noncanonical
order and trailing bytes fail closed. `strict_decode` / `strictDecode` compare
decoded protobuf to its re-encoding at the untrusted boundary; signing functions
then use the independent canonical encoding. JSON adapters must similarly reject
unknown/duplicate keys and decode integers losslessly; JSON is not a second
signing format. Opaque canonical bytes require exact parse/re-encode equality in
the consuming native object format.

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

Permission budgets are explicitly **one logical import**, at most **256 branches,
256 converted operations/slots, 1 GiB of committed result bytes**. Branch limits
are sorted unique full refs, with one stable slot per branch in this first format.
Each branch byte budget is positive; their sum is at most the total. Certificate
scope can select a subset and reduce budgets, never add a ref/slot/genesis/target,
change initial frontier/source/options/converter/destination version, or expand
a parent's time window. The parent cannot outlive its verified issuing authority.
The owner grants permission over branch limits BEFORE genesis authorization
proofs are produced; only the child manifest adds their signed proof digests.
This prevents a cyclic permission/genesis/delegation digest dependency.

The host accounts by `(permission digest, logical job)` and by
`(logical job, full ref, slot_id)`; total budgets never reset on another key,
delegation or retry row. Reissuing permission for the same logical job cannot
reset its durable original limits. Only the direct active owner can issue the
member permission; a member cannot turn its own delegation into another parent.

A renewed parent MUST cover only remaining scope: a subset of the predecessor's
scope, excluding every committed `(ref, slot)` and subtracting consumed operation
and result-byte budgets. It may contain a narrower replacement child, but MUST
NOT regrant the original full scope. Durable original job limits continue to
apply across all parents. Retain the original signed parent/envelope for genesis
verification; never rewrite those originals to match a renewal.

At first issuance, generate `cancellation_id` using a CSPRNG as 32 random bytes
in `heddle-import-cancel-v1`; persist it for the same logical-job/retry-lineage/
grantee public-key lineage. Every reissued permission in that lineage MUST reuse
that cancellation ID. A different lineage receives an independently generated
ID. Each **new grant** MUST use a fresh CSPRNG-generated 32-byte `nonce`, including
renewals with otherwise identical fields; never use a counter, timestamp or
permission digest as a nonce. Issuers must prevent nonce reuse across grants.
Retransmission/idempotent replay of an existing grant preserves its entire signed
bytes, including nonce and signature; it is not a new issuance. A renewal may
reuse that exact still-valid parent only when it already covers remaining scope;
a changed signed grant must have a fresh nonce. Portable helpers
check widths and same-lineage cancellation-ID stability/nonce inequality at
renewal; they cannot prove entropy. Revoking the stable permission cancellation
ID invalidates every reissue/descendant in that lineage. The delegation's separate
host-issued cancellation ID is checked independently.
Known user authority, descriptor-root and all CURRENT/RETIRED/REVOKED witness
keys are forbidden as job signers. Known job keys cannot join a witness set.
Persist job-key → logical-job associations in issuer custody and receiver trust
state and reject conflicts. A fresh receiver cannot discover undisclosed reuse;
the issuer must enforce global prepare/commit uniqueness.

`ImportGenesisAuthorityV1` additionally binds exact native Thread genesis ID,
original creator signature/key and exact separately transported creator-authority
envelope digest. Its device signature supplies no missing creator signature.
Verify each original native genesis and envelope independently, then its new
binding and the manifest. During renewal, retained genesis bindings are checked
against their ORIGINAL delegation/accepted owner context, never rewritten to
match the renewed key or owner state.

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
Failed pinning, stale observations and empty OIDs never authorize a silent
downgrade. OBSERVE_AT_EXECUTION is only an explicit fallback when the caller
cannot obtain the OID. Before signing, disclose this fixed promise:

> The exact commit is unavailable. This branch may move before execution. The
> import will convert the commit observed when the job executes, which may differ
> from the commit you saw when selecting the branch.

The caller must explicitly select and sign that fallback. Each observe branch
has an empty `pinned_commit_oid`, an explicit hash algorithm and
`ref_disclosure = IMPORT_REF_DISCLOSURE_OBSERVE_AT_EXECUTION (1)`.
Pinned branches require `ref_disclosure = UNSPECIFIED (0)`. Field 10 of
`ImportBranchLimitV1` appends **u32be(ref_disclosure)** to its canonical layout;
the parent scope, prepared scope and signed manifest all bind it. A genuine
delegation signature without the marker still rejects with `RefDisclosure`.
The result retains its exact observed OID and algorithm.

`validate_ref_selection` / `validateImportRefSelection` additionally take an
independently known OID available when choosing the scope. They reject observe
mode or a different pin with `RefPinning`; None/undefined supplies no consent
and never changes the mode. A receiver cannot prove UI consent or discover an
undisclosed locally known OID from signed bytes alone. It verifies the explicit
marker, signatures and mode; authoring clients and hosts with that independent
knowledge must enforce exact pinning. No implicit mutable-ref authorization
exists. A URL/ref signature does
not prove deterministic Git conversion or original Git authorship; those require
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

## Preparation, renewal and the existing retry route (P2 #2)

Prepare is authenticated and idempotent: reserve logical job/key, encrypt and
persist the distinct seed BEFORE returning the exact unsigned proposal. A
reservation expires exclusively at prepare time + **3600 seconds**. No prepared
job executes until Commit verifies the complete user-signed proposal/chain,
original branches, current permission and budgets. The browser closes only after
this authorization. A proposal change requires fresh preparation and signature.

### Configuration and caller-selected scope (api#327 G2)

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

Positive host limits cover branches, logical-job operations, total result bytes
and per-branch result bytes. They cannot exceed 256 branches/operations or 1 GiB
total, and per-branch bytes cannot exceed the host total. The caller chooses
**every** scope field: provider/URL, exact ordered branches and ref disclosure,
converter/options, stable slot IDs, per-branch and total budgets, targets and
explicit Thread-specific frontier commitments. There are no omitted-field
defaults or host-allocated slots. Prepare accepts these choices byte-for-byte
or refuses; even budget reductions or equivalent normalization are forbidden.

The one exception is `proposed_scope.destination_version`: empty asks the host
to issue the opaque current **32-byte destination CAS token** in its preparation
transaction; exactly 32 bytes asks it to compare with the current token and echo
it unchanged. Other lengths are INVALID_SCOPE. A mismatched token returns
DESTINATION_CONFLICT. This is neither an overview version, a hash, zero32 sentinel
nor a caller-generated token. No other scope field can be filled. Commit binds
the returned token in its signed delegation and compares it with current
destination state atomically; a changed destination requires new preparation
and signatures. Renewal requests can supply the existing exact signed token;
no token may be substituted around remaining-scope/non-amplification checks.

Success carries a proposal and no refusal. Refusal carries only
`ImportPreparationRefusalV1` with a nonzero typed reason and bounded field path:
INVALID_SCOPE, UNSUPPORTED_CONVERTER, UNSUPPORTED_OPTIONS, BUDGET_EXCEEDED,
DESTINATION_CONFLICT or POLICY_DENIED. It reserves no key/job, returns no proposal,
bounds or renewal state, and activates nothing. Authentication and hidden-resource
failures retain ordinary CallFailure handling without leaking policy details.
`prepare_scope` / `prepareImportScope` enforce support, bounds and CAS;
`validate_preparation_response` / `validateImportPreparationResponse` compare
the request and response before signing and reject changed choices with
`PreparedFields`. Configuration changes require a fresh Prepare/client operation
ID, never a changed response to an idempotent prepared reservation.

The caller generates and persists a fresh non-nil UUID with a CSPRNG (for example
`crypto.randomUUID()`), encodes its 16 raw bytes as `retry_lineage_id`, and uses
it as the **reserved first physical operation ID**. Prepare reserves that exact
UUID for the caller/job/destination. An existing reservation or physical operation
owned by another request/job is a collision: refuse `OPERATION_ID_REUSED` without
allocating another UUID or activating work. An exact caller-scoped Prepare replay
returns its original reservation. Commit MUST create that same physical operation
and return its canonical lowercase hyphenated UUID as `pending_operation.id`.
Prepare/Commit `client_operation_id` values remain separate request idempotency
keys. Renewal and physical retries retain the original lineage UUID, even when
later physical attempts have other IDs. `initial_operation_id` /
`initialImportOperationId` check UUID shape and transactional occupancy inputs;
the response helpers enforce receipt equality.

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
source/base and verified authority, installs epoch 1, creates the initial
physical operation whose ID equals `retry_lineage_id` and makes it runnable. Its successful
`MutationResponse.receipt` MUST contain `pending_operation` for that created
operation in the destination Spool, never an `applied` acknowledgement. Failure
leaves no activated job, operation or partial branch publication.

Commit's caller-scoped `client_operation_id` is its own idempotency key, distinct
from Prepare's. Persist the exact request and receipt with activation. Exact
replay returns that same operation/receipt without creating work or advancing an
epoch, including after expiry, cancellation or response loss. Look up the durable
idempotency row **before** current-authority revalidation; this replay is an
acknowledgement of committed submission, not fresh execution authority. Any
changed request under that ID fails OPERATION_ID_REUSED. `check_commit_replay` /
`checkImportCommitReplay` and response helpers check these invariants; the host
owns durable serialization, current authorization and atomicity.

`ImportSource` is closed: after authentication/authorization it always fails
FAILED_PRECONDITION with `ERROR_REASON_IMPORT_SOURCE_REQUIRES_COMMIT`. It cannot
create or attach to a reservation, alias Commit or activate work. Its duplicate
branch message and fields 8/9 are removed/reserved. Use RetryImportSource for a
failed existing physical operation and explicit RenewImportJob when required.
`verify_commit_submission` / `verifyImportCommitSubmission` compose source/
original validation with the stored-preparation/signature checks. Native canonical
State/genesis validation, independently selected owner history, live source
grants and transaction fences remain the hosted consumer's gates.

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
| 11–12 | `cancellation_id`, `predecessor_delegation_digest`: each counted32; predecessor zero32 initially |

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
N < E; T < E; E - N <= D
```

Skew permits clock differences at not-before, never grace after expiry or an
extension of parent/owner authority. Commit may accept `N > T` within skew;
execution remains forbidden until `N`. The typed parent must be valid at actual
Commit time and contain the entire child window, and the child's expiry cannot
exceed the independently verified owner authority expiry. Use checked/widened
integer arithmetic, including extreme uint64 duration/skew advertisements.

Browser signing uses the separate `preflight_prepared_delegation` /
`preflightPreparedImportDelegation`, with browser clock `B`. It checks exact
proposal/manifest, signatures, scope attenuation and prospective signed windows:
`0 <= B`, `A <= B + S`, `B < R`, `A - S <= N <= B + S`, `N < E`, `B < E`,
`E - N <= D`, `R = A + 3600`. Parent not-before may be up to `B + S` (so a
parent beginning at A is usable when `A-S <= B < A`); parent expiry MUST still be
strictly greater than B and contain the entire child window. Owner expiry still
bounds child and parent. This is prospective signing validation, returns **no
executable/admitted authority**, and asserts no historical acceptance. It does
not invent a host admission time. Native originals and retained renewal genesis
contexts remain independently required. The host verifier continues to require
`T >= A`, parent validity at actual host T, strict exclusive expiry and all
activation gates. Neither browser preflight nor host skew permits execution
before the child's exact signed not-before.

`verify_prepared_delegation` (Rust) / `verifyPreparedImportDelegation` (TS) take
the **host-stored** response, signed child, exact parent permission (if any),
signed genesis bindings and independently verified current owner expectation.
They compare the canonical frozen projection and ordered manifest limits
byte-for-byte (`PreparedFields`); check reservation (`Expired`) and signed host
window (`ValidityBounds`); verify the typed parent and non-amplification
(`ImportPermission` / `Scope`), key roles and complete delegation signature
(`Signature`); resolve each exact signed genesis digest and require its genesis
ID to equal its prepared branch (`GenesisBinding`). Initial bindings also verify
their device signature, identity, parent and chain. The same comparison applies
to a prepared renewal replacement; retained genesis bindings must additionally
be verified in their **original accepted context**, followed by renewal CAS and
remaining-scope checks. No retained binding is re-signed under a new parent.

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
list omission/reordering, each window inequality, missing/mismatched/amplifying
parent, genesis digest/branch substitution, invalid signature and reservation
expiry. Rust and TS assert the exact intended rejection and then accept the
unchanged signed control after **each** negative. Expected bytes and signatures
come solely from the maintenance generator, never test-time signing.

In-window deploy/replica/lease retries preserve the same key and certificate.
`RetryImportSourceRequest` still creates a distinct physical operation. In
`weft/crates/weft-hosted/src/server/hosted/integration_v2/import_retry.rs`,
`native_retry_import_source` MUST follow `retry_original_operation` transitively
(with cycle/foreign-job rejection) to the original logical job/lineage. Its new
`import_jobs` / `native_thread_imports` row is another attempt at that job, not
permission to reset branch identities, first receipts, budgets or result slots.
The request's logical-job, active certificate digest and expected authority epoch
must match the receiver-owned association; row IDs alone establish no authority.

After expiry, new uncommitted work requires user-signed
`ImportJobRenewalV1` AND its signed replacement delegation. Renewal binds the
exact predecessor certificate, expected authority epoch and digest of the complete
durable committed-slot manifest. It preserves logical job, retry lineage, Spool
and immutable genesis, source/options/converter/destination and original branch
proofs; uses a **fresh** subordinate key/delegation ID; excludes committed slots;
and reduces remaining operation/byte budgets by already consumed work. A current
owner/permission chain is independently required for the replacement. Permission
renewal does not resurrect a revoked device or reset accounting.
Explicit job cancellation is terminal and cannot be renewed.

Recovery from an expired predecessor requires no publication receipt.
`verify_renewal_predecessor` / `verifyImportRenewalPredecessor` consume the exact
authenticated Prepare `ImportJobCasStateV1` snapshot and independently verified
predecessor owner context. They check original delegation/parent signatures,
identity, key roles, scope attenuation and window structure, without checking
old execution eligibility at a fabricated timestamp. Their distinct opaque
`VerifiedImportRenewalPredecessor` is **non-executable** and proves neither
current authority nor historical admission. It commits to exact predecessor
signed digest, logical job, lineage, positive epoch and complete committed
manifest (including an empty manifest before any publication).
`verify_renewal_from_state` / `verifyImportRenewalFromState` require that same
snapshot, verify the renewal's predecessor/epoch/manifest CAS and all remaining
scope/parent rules, and require currently valid replacement authority. Initial
original genesis bindings/envelopes retain their independently verified original
context. The host MUST still reject terminal/revoked jobs and recheck current
replacement authority, active predecessor, epoch, manifest, original limits and
activation CAS in one transaction. A locally coherent snapshot alone is not
an authenticated host state or an admission receipt.

Activation, cancellation, publication, slot uniqueness, frontier CAS and worker
lease/generation checks run under the SAME database transaction fence. Activation
CASes epoch/predecessor/committed manifest and advances the epoch exactly once.
Two signed renewals for the same epoch: one wins, the other fails stale; a paused
old worker cannot publish after activation even if its old clock/window appears
valid. A publication racing renewal changes the committed-manifest CAS (and the
lease/authorization state as applicable); renewal must reread state and obtain a
new user signature rather than accepting widened or stale remaining scope.

`ImportResultManifestV1` is the complete sorted exact committed-slot snapshot for
that publication/terminal attempt. Each entry selects one signed operation digest,
result frontier and result byte count. A successful complete-job terminal manifest
must account for every authorized slot; a failed/cancelled/expired attempt may
leave slots for an explicit successor renewal. The host persists each exact
manifest, original receipt and slot association immutably. Renewal's predecessor
and committed-manifest CAS connect the successive attempts to the same logical
job; it cannot replace any committed selection or emit a conflicting terminal
manifest for the same attempt. The complete cumulative snapshot includes results
from predecessor certificates; repeated historical slots are not charged twice.

Commit-success/response-loss followed by physical retry returns the EXACT original
committed operation, witness receipt and manifest. It must not sign another result
using the retry UUID/new key or reissue first admission. A fresh Fetch verifies
that unchanged history after rotation/expiry. The fixed crash/race vectors drive
both language contract tests: concurrent renewal, paused worker, successful commit
with lost response, retry and fresh retired-witness verification. They are a
normative event/byte oracle for the weft PG/lease tests, not evidence that weft's
transaction implementation has shipped.

Recurring remote sync needs its own explicit scoped authority; it cannot reuse
an expired certificate. Job custody AEAD context binds version/account/Spool/
genesis/logical job/delegation/key/purpose and wrapping-key version. Retain keys
only seven days after each certificate becomes terminal, then delete live seed
and data-key custody with tombstones. Backups purge within 30 days of live removal;
restore applies tombstones BEFORE workers, even from a pre-tombstone backup.
Public proofs/results/receipts/history remain indefinitely. Renewal must not
extend predecessor-secret retention indefinitely. Custody/storage are weft work.

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

RETIRED closes issuance and seals its exact lifetime journal root/count. It cannot
reactivate, extend/change its interval, enlarge/change its seal or disappear.
REVOKED is a permanent tombstone with positive effective time; all its statements
reject, including previously sealed ones. Compare full snapshots against retained
seals/intervals/tombstones, not just individual signatures. Fresh clients depend on
an honest root/issuer/journal to preserve completeness; this is not a transparency
log. Set issuance renewals advance generation. Retire only at or after every
previous old-CURRENT set expiry and after the transactional issuance fence closes.

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
| Owner histories / ownership transfers / delegation lineage | 64 each; 63 renewals |
| Policy records / original geneses / creator envelopes | 256 each |
| Member permissions / retained manifest snapshots | 64 / 320, digest-sorted unique |
| Typed genesis/authority/landing payload sidecars | 256 each, inside the bundle byte budget |
| Witness dependencies / retirement proofs | 1024 each, also inside bundle byte budget |
| Inclusion siblings / encoded lookup response | 64 / 4096 bytes |
| Source URL / full ref / root ID | 2048 / 1024 / 256 UTF-8 bytes |
| Keys / signatures / hashes / UUIDs | Exactly 32 / 64 / 32 / 16 raw bytes |

Before every durable install, admission, replay acceptance or publication, recheck
receiver-owned root-pin epoch, set generation/digest/freshness and exact resolved
statement under the SAME trust/mutation serialization. A previously resolved
opaque object is not perpetual authority. Newer generation invalidates cached
contexts; re-resolve original staged bytes under the newest set. Retirement needs
new paths; freshness renewal requires no content redownload. Current owner/policy/
revocation/cancellation/expiry/lease/frontier changes likewise invalidate new work.
Persist the last accepted wall-clock floor and compare elapsed monotonic time;
detected rollback or unavailable trustworthy time fails closed. Restart retains
high-water, seals and clock floors. Persist original signed-set bytes;
`restore_history_snapshot` / `restoreWitnessHistorySnapshot` reconstruct ONLY
that receiver-owned previous snapshot, even after its freshness expires. It
cannot authorize a fresh mutation: authenticate the newest set at actual time
against that high-water and the saved clock floor. An uninformed fresh receiver can accept an
unexpired authentic older set; the five-minute bound is NOT owner/policy freshness.

Explicit out-of-band descriptor-root replacement invalidates old contexts and
preserves known seals/intervals/tombstones. Compromised-root recovery requires
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
**SynchronizeRemote**, **PrepareImportJob**, **CommitImportJob**, **RenewImportJob**,
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

**SyncService Fetch, PublishContent and ReplicateThread do not declare or enforce
that mandatory feature in this release.** Their native Fetch/Publish/replication
openings and ready replies likewise do not require HYBRID protocol negotiation.
The optional protocol and public proof fields remain additive in the schema.
The Sync gate is deferred to the **same release that ships real HYBRID support
in both heddle and weft**, tracked by
[api#307](https://github.com/HeddleCo/api/issues/307). There is no bridge. This
narrowing is safe because no HYBRID-imported records exist anywhere yet: only the
still-gated import RPCs can create them, and no peer can serve those RPCs until
HYBRID support ships.

Until that release, **peers MUST NOT create or serve HYBRID records over Sync**.
A non-HYBRID peer **MUST reject any Sync record/frame carrying `import_authority`
before staging, installation, relay or publication, never silently ignore it**;
this includes an empty-but-present bundle. The existing message fields on
TransferReady, PublishContentOpen, PublicationReceipt, ReplicationOpen,
ReplicationReady and ReplicationOperations expose presence as Rust
`Option<ImportPublicProofBundleV1>` / TS `importAuthority !== undefined`, so this
rejection needs no schema change. Generated clients and generic proof helpers do
not automatically enforce that consumer support policy; consumers must implement
the presence check in their Sync dispatch/record handlers. Keeping the fields
optional does not authorize ignoring imported authority.
No old-key enrollment, automatic owner/root replacement or immutable receipt
re-signing is allowed. Operational reset/re-import is a separate task.

Rust errors and the TS `HybridContractError.reason` use the same rejection names
in the fixed fixture: Signature, Semantic, HighWater, JobAsWitness, Scope,
Expired, RenewalFork, ImportPermission, StaleContext, Proof, Revoked, Protocol, StaleManifest, CommittedSlot,
Canonical, Bounds, Transition, KeyRole, Root and SlotConflict. Map wire failures
through the existing CallFailure vocabulary; sensitive lookup misses remain
uniform. No package-wide error enum is reinterpreted.

Consumers: heddle capability-verifier owns owner-history/current authority and
portable permission context; api import_authority/witness_trust own these new
canonical signatures, attenuation checks and authenticated set/proof resolution.
Heed this split in object-model/crypto/repo/thread-api/hosted-client. Weft admission,
initial/subsequent finalize AND `integration_v2/import_retry.rs` consume the same
formats under storage fences; tapestry signs the same TS canonical bytes and
reviews the ref promise/remaining scope with the existing device key.

## Review round 1: historical closure and frozen purpose payloads

The authoritative history in `ImportPublicProofBundleV1` is now
`member_permissions` (at most 64) and `manifests` (at most 320: 256 publication
snapshots plus 63 renewal snapshots and one empty/terminal snapshot). Each
collection is strictly sorted by its **recomputed** 32-byte canonical digest;
duplicate digests, conflicting bytes, missing references and truncation reject.
The existing singular permission field is an optional alias; the terminal field
is the required final-snapshot selector. Both must equal their exact collection
entries. Delegations and accepted renewals are in activation order, at
most 64/63; each replacement equals the next original signed delegation and its
predecessor digest equals the previous original. Genesis proofs always resolve
their original parent, even when later delegations retain those genesis digests.

Resolve every nonzero parent permission digest from this collection, including
those in original genesis bindings. Zero32 denotes direct active owner authority
and never triggers lookup. Resolve every renewal manifest digest, each publication
payload's manifest digest, and the final snapshot from the manifest collection.
Every manifest slot resolves exactly one original signed operation and its
unchanged result frontier/byte count. Every committed original operation resolves
its original signed delegation and an exact publication statement/snapshot. All
snapshots are cumulative subsets of the final snapshot; they cannot select a
second result for one logical job/ref/slot. Keep complete earlier permissions,
accepted owner histories, transfers, policies, native geneses, envelopes and
receipts even after expiry or permission/owner replacement. No earlier receipt
is compared with a later manifest or re-signed. Exact reference matching is
mandatory before independent signature/authority verification; collections are
carriers, never independent trust anchors. `validate_public_bundle` and
`validatePublicBundle` implement this closure check; resolution has no retrieval
fallback. Native creator/owner verification remains mandatory.

Every selected `(spool_uuid, policy_sequence, policy_state_hash)` resolves the
original `SignedSpoolPolicyRecord` and every predecessor back to zero32/sequence
0. Only that pair denotes policy genesis; a positive sequence cannot omit its
signed policy. Each branch's genesis binding resolves its native original,
creator envelope, exact `ImportGenesisWitnessV1` sidecar and original purpose-1
admission statement. Supplying sidecars only for the statements that happen to
be included does not establish completeness. Closure validation checks these
references; native verification separately checks policy preimages, signatures,
owner context and all admission signatures and retirement paths. Historical
authority times come from receipts **after** authenticating them, converted
from milliseconds to seconds; callers cannot substitute a convenient time.

The frozen renewed export contains two original permissions (the first expires
at 1300 seconds), predecessor and successor certificates, accepted renewal,
two operations, both publication snapshots, the real sequence-1 signed policy,
and both original branch genesis admissions and publication receipts. A fresh
receiver at 1350 seconds uses independently selected roots and the export plus
later exact retirement paths. It verifies the predecessor at its witnessed
publication time and the successor at its witnessed publication time. Checking
an expired permission as current authority correctly fails. This is the contract
oracle for a complete post-renewal Fetch, including permission replacement.

Each statement payload is **exactly** the canonical encoding of the following
message, with no domain prefix, protobuf encoding or trailing bytes. Field order
below is frozen, including default values; nested fields flatten in place using
the framing above. Sidecar DTOs in the bundle retain the same exact objects so
native verifiers can construct the expected payload independently.

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
field hash remains unchanged. An original capture must contain a child State;
its declared State parents, after excluding the signed genesis base, must equal
the States selected by its complete causal operation parents. The synthetic
initial State is a genesis base only and cannot be reused as a source capture.

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

## Review round 1: cross-model commitment preimages

These are SHA-256 **transport commitments**, distinct from native typed IDs.
A native model recomputes its existing object IDs and validates original object
bytes, then constructs these preimages. There is no frontier inferred from a
branch name, author timestamp, host tip projection or repeated constant bytes.

| Commitment | Exact preimage and bounds |
| --- | --- |
| Expected/result frontier | `UTF8("heddle-import-frontier-v1") || u32be(1) || counted(thread_id32) || u32be(count) || each counted(native_operation_id32)`; 0–128 sorted unique IDs, complete source frontier |
| Resulting content | `UTF8("heddle-import-content-v1") || u32be(1) || counted(exact canonical Capture v1 bytes)`; full native State/source-target/visibility bindings, never just an unhashed mutable projection |
| Conversion options | H(`heddle-import-conversion-options-v1` || counted exact converter-version UTF8 || counted converter-defined canonical option octets); the v1 `git-converter/1.0` vector uses the explicit empty options sequence, not a JSON object or omitted commitment |
| Destination version | An opaque 32-byte producer-issued destination CAS token, returned by authenticated preparation; it is not a hash or a native object ID and has no hash preimage |
| Creator authority envelope | Exact H(raw complete envelope bytes); no normalization or protobuf reserialization |
| Signed native dependency | `UTF8("heddle-signed-native-record-v1") || canonical SignedRecord` |
| Authority envelope / original signatures | Exact layouts in the preceding section |
| Policy/owner/Spool/native object IDs | Existing named versioned formats in `owner_records.proto`, `ThreadControlAuthority` and native Thread model; their algorithms and identities are unchanged |

Capture v1 is named MessagePack with exactly `state`, `source_targets`,
`visibility`, in that order. `state` is an integer-byte array containing exact
canonical native State bytes; `source_targets` is null or a native 32-byte ID
array; `visibility` is null or a named map with exactly `state`, `embargo_until`,
`entries`. `state` is null or native VisibilityTier; `embargo_until` is null or
canonical chrono UTC RFC3339 text. Entries are sorted unique `(tree_id32,
leaf_hash32)` maps with exactly `tree_id`, `leaf_hash`, `tier`, at most 4096.
VisibilityTier is native MessagePack string `Public`/`Internal`, or singleton
map `TeamScoped:{team_id:UTF8}`, `Restricted:{scope_label:UTF8}` or
`Private:{scope_label:UTF8}`. Labels are nonempty after trim, no control
characters, at most 256 UTF-8 bytes. Do not silently rename native variant keys.
Use the native capture parser's strict parse/re-encode check; v1's complete
visibility encoding above is selected, never invented by a receiver. Its
State and source-target closure remain required even though their contents are
not copied into a signed witness payload. The new commitment does not redefine
native BLAKE3 typed IDs, native State field hashes or converter correctness.
`result_bytes` accounts for the retained canonical converted result closure,
with native sharing/deduplication fixed by the converter version; it is bounded
by the original logical-job budgets. Fixed vectors include empty expected
frontiers, nonempty actual result-operation frontiers, complete native Capture
bytes, every purpose payload and original signed-wrapper digest preimages.

## Review round 1: wire CAS state, peer negotiation and isolated controls

`PrepareImportJobRequest.renew_logical_job_id` uses the existing authorized
prepare path. Its response MUST include `renewal_state:ImportJobCasStateV1`
with format 1, logical job and original retry lineage, exact active signed
predecessor, current positive `authority_epoch`, and complete committed manifest.
Read this state and the remaining delegation proposal in **one transaction**.
The response grants no authority. Verify proposal/state identities, predecessor
and snapshot; sign the exact snapshot epoch and manifest digest; activation
still performs transactional CAS. A stale state or publication race requires
another job-state read, recomputation/review and exact Prepare before signing.
The dedicated `GetImportJobState` read below supplies discovery and recovery.

Initial Commit installs epoch **1**. Successful renewal increments it exactly
once; successful Cancel increments it exactly once and makes the job terminal.
Failed CAS, Prepare, physical retries and exact replays never increment it.
Publication changes the cumulative manifest atomically while preserving the
current authority epoch; its slot/manifest CAS is separate from that epoch.
Expiry closes issuance without silently incrementing epoch. Overflow rejects.
Cancel's `cancellation_id` MUST equal the ACTIVE delegation's host-issued ID;
parent permission IDs and retained predecessor IDs are not selectors for this RPC.
Under the cancellation transaction, compare the logical job/destination and
expected epoch before the selector: a stale epoch refuses `StaleContext`, with
no mutation; a correct epoch with mismatched selector refuses `Scope`, with no
mutation. A new request for an already terminal cancelled job refuses `Revoked`
after its context/selector checks (FAILED_PRECONDITION/LIFECYCLE_STATE).
Success cancels the whole logical job, advances
the epoch once, fences every worker and preserves committed originals/receipts.
Persist the exact caller-scoped request and receipt atomically. Exact replay is
resolved **before** epoch/terminal/selector revalidation and returns that receipt
without advancing the epoch, including when the original expected epoch is now
stale. Changed inputs under the same client operation ID refuse
`OPERATION_ID_REUSED`. `check_cancel_request` / `checkImportCancelRequest` and
replay helpers supply the portable checks; the host owns the transaction.
Independent revocation of either the parent permission's cancellation ID or the
active delegation's ID still invalidates execution/renewal authority; Cancel's
selector rule does not weaken those checks. `check_import_revocations` /
`checkImportRevocations` check both against the independently selected revocation
set. No renewal after explicit cancellation may reactivate the job. The signed
predecessor digest, epoch, committed manifest and current policy/authority fences
are all required. A response lost after activation is reread through `GetImportJobState`;
it never causes another activation of the original CAS candidate.

`DescribeEndpointResponse.protocol` supplies native negotiated semantic support
on the already authenticated endpoint connection. Retain it with that endpoint,
never infer it from methods/packages or reuse it on reconnection to another
peer. Rust's additive `Client::with_protocol` takes this response; the default
constructor fails closed on every gated route. TypeScript's optional negotiated
protocol has the same rule. Both clients check the exact version/features before
transport, plus native Fetch/PublishContent/ReplicateThread openings and the
first required ready response before exposing/staging records. Missing ready,
data before ready, missing/unknown/duplicate features and wrong version reject.
The transport binds its advertised protocol to the actual peer and supplies the
same protocol in CallContext; HTTPS uses the equivalent authenticated headers.

The fixed controls name the **first failing check**, with a passing neighboring
control and otherwise valid original signatures/context:

| Control | First failing check / rejection |
| --- | --- |
| Actual signed PURGE v1 / timeline v3 / ordinary role offered to parent selector | Typed permission-format selection / `ImportPermission` |
| Replacement includes committed dev slot, signed against the supplied dev snapshot | Committed-slot exclusion / `CommittedSlot`; remaining budgets independently fit |
| Paused predecessor at 1250, inside its [1000,1300) interval | Active certificate/authority epoch fence / `StaleContext` |
| Publication wins at epoch 1 before activating a signature over the earlier snapshot | Manifest digest CAS / `StaleManifest` |
| Actual legacy HostedImport operation signed by the witness | Hybrid import-format dispatch / `Protocol` |
| Authentic 128/129 `é` root IDs, with independently matching selected IDs | 256-byte UTF-8 bound / pass, `Bounds` |

Every existing negative vector also names `first_failing_check` in the shared
fixture. The root-signed invalid-current control isolates the forbidden archive
seal on CURRENT, rather than combining different current-member errors.
`StaleManifest` and `CommittedSlot` have distinct errors so earlier digest failure
cannot masquerade as slot exclusion. The contract harness remains an event/byte
oracle; actual PG transaction, lease, crash and storage execution is still weft's
required downstream gate.

The native named encodings reused here are pinned to
[heddle's Thread formats at 5b76f7f](https://github.com/HeddleCo/heddle/tree/5b76f7f61f1a2f8033a2328dfc178e49d8a7af0e/crates/object-model/src/object/thread_replication),
including `source_author.rs`, `ownership_claim.rs`, `ownership_resolution.rs`,
`metadata.rs`, `integration.rs` and `capture_visibility.rs`. Native State IDs
use `state_core.rs`'s versioned field hash. Changes to those immutable encodings
require new native format names and new vectors, never reinterpretation of these
signed payloads. Root-ID is the only unrestricted Unicode string in the new
witness set. Import refs/providers/converter versions, HTTPS origins and native
format/method/signing selectors are ASCII; manifest refs now enforce that same
ASCII restriction. All permitted Unicode bounds measure encoded UTF-8 bytes.

## Renewal discovery and submission (alpha.24, G1/D1 and G2/D2)

`IntegrationService.GetImportJobState` is a finite unary read, chosen instead of
an Observe section because a renewal needs one complete transactional snapshot
and retained proof, with no stream cursor or inventory dependency. It leaves
Prepare's accept-exactly-or-refuse contract intact. Tier-1 request PoP and an
**authenticated destination writer** are mandatory; a read grant, digest holder,
job key or expired delegation alone cannot authorize this read. Resolve the
specified destination and job under that permission in the same read transaction.
Use uniform NOT_FOUND for unknown and unauthorized jobs. No listing, pagination,
private seed, encrypted custody, bearer credential or source-access secret is
returned. This is distinct from the public witness-history proof lookup.

The request has one canonical destination UUID and one non-nil 16-byte logical
job ID, at most 4096 encoded bytes. A successful response has `state` containing
the existing `ImportJobCasStateV1` and `retained_proof` containing exact accepted
public evidence. The whole response is at most 2 MiB, the proof at most 1 MiB,
and all existing bundle counts apply (64 permissions/owner histories/transfers/
delegations, 63 accepted renewals, 320 manifests, 256 operations/branches/native
originals/policies, 1024 statements/history proofs). Exceeding bounds refuses;
never truncate an accepted chain. The snapshot always includes a format-1
manifest with job and lineage IDs, **including an explicit empty slots array**
before the first publication. The retained proof's terminal selector equals
that snapshot and its digest resolves in the sorted manifest history. Its final
accepted delegation equals the snapshot's exact active signed predecessor.

Retain original signed permission parents, genesis bindings, native originals,
creator envelopes, owner genesis, accepted owner histories/handoffs, and the
active predecessor's exact original owner-chain commitment with the job. Return
these even after ordinary expiry or client loss. Histories preserve exact earlier
states as separate entries when a later state is also returned. Independently
verify them from the selected immutable Spool lineage; a carried hash or host
response cannot enroll an owner. Recover the predecessor's exact historical
context from this evidence without lowering today's owner pin. The read supplies
provenance for the time-free predecessor verifier, never execution or evidence
of an admission that did not occur. Already published history requires the
complete public export closure, original admission/publication receipts and their
policy/retirement dependencies. Before any publication, preserve every actual
admission already stored; absent admissions are allowed and confer no historical
admission claim. Operations and publication statements must be absent with an
empty committed snapshot. No fabricated timestamps or synthetic receipts.

The browser flow is:

1. Read and independently verify retained evidence and the authenticated snapshot.
2. Compute and review the remaining scope from the committed slots and consumed
   budgets. Request an ordinary exact renewal Prepare with this caller-selected
   scope. Only an empty destination token may be filled.
3. Validate the exact scope response and require its **complete** `renewal_state`
   to equal the read snapshot: predecessor bytes, epoch, job/lineage and manifest.
   If publication or another renewal raced, read again, recompute/review and
   re-prepare. Do not sign the stale snapshot or silently reduce the proposal.
4. Obtain the current owner's remaining-scope permission, sign the replacement
   delegation, then sign the renewal. Activation still CASes predecessor, epoch
   and manifest and rechecks current owner, policy, cancellation, reservation,
   expiry, job-key uniqueness, lease and destination frontier atomically.

`validate_job_state_request` / `validateImportJobStateRequest` enforce read
request bounds; response validators enforce snapshot and retained-proof closure.
`validate_renewal_preparation_from_read` / `validateRenewalPreparationFromRead`
enforce the publication race before signing. Authentication, writer permission,
transaction serialization and native owner/witness verification belong to the
consumer implementation; composition helpers do not claim to implement a host.

Lost Prepare responses are recovered by replaying the exact Prepare under its
original caller-scoped operation ID. The state read covers **accepted** jobs;
a prepared-only reservation has no accepted predecessor and returns NOT_FOUND.
After a lost Commit or Renew response, replay the original frozen request to get
its stored receipt and use the state read to discover accepted authority and
committed slots. Compare the candidate digest with accepted history, including
when another accepted renewal has since advanced it. Never interpret response
loss as a new activation opportunity. A lost browser can recover public authority
through this read when it knows the destination/job selector; normal authorized
job inventory supplies selectors, and this RPC adds no enumeration surface.

The exact `RenewImportJobRequest.proof` profile is based on that retained proof:

- `delegations` and `renewals` contain **only the exact prior accepted activation
  history**. The pending candidate occurs only in top-level `renewal`, whose body
  embeds its signed replacement. Append it to accepted history only in the
  successful activation transaction. Duplication, omission, changed historical
  bytes, pending operations or candidate publication evidence refuse.
- `member_permissions` retains every original parent and adds only the exact
  replacement parent if it is new, sorted uniquely by signed-permission digest.
  The optional `member_permission` alias selects that replacement parent exactly;
  for direct owner authority both the alias and a new parent are absent. A still
  valid byte-identical parent may be reused under the settled alpha.23 rules.
- Original genesis bindings, parent references, native geneses and creator
  envelopes stay exact. Each replacement branch references an original initial
  branch binding by digest and preserves ref, slot and genesis. The renewed parent
  covers remaining scope; it never replaces the original genesis parent.
- `owner_genesis` stays exact. `owner_histories` retains every exact earlier
  endpoint and may add the complete independently verified current endpoint;
  `ownership_transfers` preserves the old prefix and may extend it. `policies`
  retains old records and may add current evidence. `owner_chain` selects the
  current replacement chain, while the authenticated read retains the predecessor
  chain. Resolve old and new permission signatures with their **separate** verified
  historical/current owner contexts. Missing either endpoint refuses even if all
  other signatures are valid. No historical clock is invented before publication.
- `terminal_manifest`, digest-sorted `manifests`, operations, witness set,
  statements, history proofs and witness payloads retain the exact read evidence.
  The top-level renewal references that authenticated committed manifest digest,
  active predecessor digest and epoch exactly. Zero-publication requests still
  select and carry the explicit empty manifest; operations and publication
  receipts are absent. Preserve real genesis admissions if present.

`validate_renew_request` / `validateImportRenewRequest` check this request-level
composition against the authenticated read. `verify_renew_submission` /
`verifyImportRenewSubmission` additionally run the existing time-free predecessor
verification with its resolved old parent/context, then current replacement and
renewal verification with the exact new parent/context. Accepted owner histories,
native genesis authority, policy signatures and witness trust must be independently
verified by the consumer before supplying expectations; these API helpers verify
references and import signatures, not native owner-chain enrollment.

Freeze the complete protobuf request body bytes, nested proof records, order and
signatures with the caller-scoped `client_operation_id` before first transmission.
The request is at most 2 MiB, proof at most 1 MiB, ID 1..128 UTF-8 bytes. It is a
transport container, **not** a new HYBRID canonical signing domain. Retrying uses
identical frozen body bytes; fresh transport PoP nonce/timestamp is outside that
body. `check_renew_replay` / `checkImportRenewReplay` compare retained raw octets:
changed bytes under the same ID refuse OPERATION_ID_REUSED. Resolve exact replay
before current expiry/CAS/terminal checks and return the stored receipt without
another epoch increment. A race requiring a different snapshot, proof or signature
requires a new operation ID and preparation. Never mutate a pending frozen request
in place. No v2 encoding or compatibility path is introduced.
