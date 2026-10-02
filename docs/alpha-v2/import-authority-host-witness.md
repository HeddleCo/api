# HYBRID import authority and host witness, format 1

This is the api#296 contract for [weft#2479 at
8d427f8c1](https://github.com/HeddleCo/weft/pull/2479/changes/8d427f8c12006c63c5cad43cce260fd91a5e77a5).
The build decision is [weft#2469](https://github.com/HeddleCo/weft/issues/2469).
The schema is additive; its semantics require a coordinated incompatible-peer
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
| Job preparation, encrypted custody, expiry, and retries | `ImportCommittedSlotV1`, `ImportResultManifestV1`, `ImportJobRenewalV1`, `SignedImportJobRenewalV1`, `PrepareImportJobRequest`, `PrepareImportJobResponse`, `CommitImportJobRequest`, `RenewImportJobRequest`, `CancelImportJobRequest` |
| Owner-authorized genesis and delegation: converted content | `DelegatedImportOperationV1`, `SignedDelegatedImportOperationV1` |
| What the host witness attests | `ImportGenesisWitnessV1`, `ImportAuthorityRecordKind`, `ImportAuthorityWitnessV1`, `HostedLandingRequestProofV1`, `HostedLandingWitnessV1`, `ImportPublicationWitnessV1`, `HostedWitnessStatementV1`, `SignedHostedWitnessStatementV1` |
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
signer ID, counted signature). These widths and layouts are frozen for v1;
a new signed layout needs a new version/domain and new identities.

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

`DelegatedImportOperationV1` is a NEW typed converted result. The job key signs
its exact logical job, original retry lineage, physical operation ID, signed
certificate digest, ref/slot, observed Git OID AND hash algorithm, original genesis,
target and expected/result frontiers, content digest/byte count, options/converter.
PINNED_COMMIT authorizes the exact raw 20-byte SHA1 or 32-byte SHA256 commit;
OBSERVE_AT_EXECUTION has an empty pinned OID and is explicitly disclosed before
signing. No implicit mutable-ref authorization exists. A URL/ref signature does
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
this authorization. A proposal change needs a new signature, not request PoP.

In-window deploy/replica/lease retries preserve the same key and certificate.
`RetryImportSourceRequest` still creates a distinct physical operation. In
`weft/crates/weft-hosted/src/server/hosted/integration_v2/import_retry.rs`,
`native_retry_import_source` MUST follow `retry_original_operation` transitively
(with cycle/foreign-job rejection) to the original logical job/lineage. Its new
`import_jobs` / `native_thread_imports` row is another attempt at that job, not
permission to reset branch identities, first receipts, budgets or result slots.
The request's logical-job, active certificate digest and expected authority epoch
must match the receiver-owned association; row IDs alone establish no authority.

After expiry/cancellation, new uncommitted work requires user-signed
`ImportJobRenewalV1` AND its signed replacement delegation. Renewal binds the
exact predecessor certificate, expected authority epoch and digest of the complete
durable committed-slot manifest. It preserves logical job, retry lineage, Spool
and immutable genesis, source/options/converter/destination and original branch
proofs; uses a **fresh** subordinate key/delegation ID; excludes committed slots;
and reduces remaining operation/byte budgets by already consumed work. A current
owner/permission chain is independently required for the replacement. Permission
renewal does not resurrect a revoked device or reset accounting.

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

`ProtocolCompatibility` explicitly requires **protocol_version = 2** and the
sorted unique mandatory feature list containing exactly
**IMPORT_AUTHORITY_HOST_WITNESS_V1 (1)** for these v1 semantics. Missing/unknown
version/features reject with FAILED_PRECONDITION / incompatible peer BEFORE
staging or mutation, not merely after ignored additive proof fields. New import
RPCs and existing ImportSource/RetryImportSource/SynchronizeRemote plus
SyncService Fetch/PublishContent/ReplicateThread declare that
feature in `RpcContract`. `createServiceClient` checks the negotiated feature
before transport. Rust generated MethodDescriptor retains the same mandatory
features and exposes `verify_protocol` for server dispatch before body parsing.
Servers enforce CallContext/opening protocol gates; clients
check authenticated ready/stream responses. HTTPS equivalents advertise/require
`Heddle-Protocol-Version: 2` and
`Heddle-Mandatory-Features: import-authority-host-witness-v1` on HYBRID routes.
Capability/method listing alone does not establish semantic support. Native
Fetch/Publish/replication openings and ready replies carry the same gate and public
proofs. An old peer cannot install/serve HYBRID records by silently ignoring fields.
No bridge, old-key enrollment, automatic owner/root replacement or immutable
receipt re-signing is allowed. Operational reset/re-import is a separate task.

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

The frozen renewed export contains two original permissions (the first expires
at 1300 seconds), predecessor and successor certificates, accepted renewal,
two operations, both publication snapshots, and both unchanged receipts. A fresh
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
| 1 / `ImportGenesisWitnessV1` | `format_version:u32`, `binding:SignedImportGenesisAuthorityV1`, `original_genesis:SignedRecord`, `creator_authority_envelope:bytes` |
| 2 / `ImportAuthorityWitnessV1` | `format_version:u32`, `kind:u32`, `original:SignedRecord`, `dependencies:list<SignedRecord>`, `authority_envelope:bytes` |
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
Retain the existing native initiating-proof typed ID and never compute State IDs
by hashing MessagePack: State's existing versioned field hash remains unchanged.

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
another Prepare and another user signature. There is no separate state service.

Initial Commit installs epoch **1**. Successful renewal increments it exactly
once; successful Cancel increments it exactly once and makes the job terminal.
Failed CAS, Prepare, physical retries and exact replays never increment it.
Publication changes the cumulative manifest atomically while preserving the
current authority epoch; its slot/manifest CAS is separate from that epoch.
Expiry closes issuance without silently incrementing epoch. Overflow rejects.
No renewal after explicit cancellation may reactivate the job. The signed
predecessor digest, epoch, committed manifest and current policy/authority fences
are all required. A response lost after activation is reread through Prepare;
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
