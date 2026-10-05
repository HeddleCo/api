# Native host witnessing v1 (alpha.34)

Normative companion to `import-authority-host-witness.md`; closes api#339 and api#343.
The original native formats, import formats, witness statement/set formats,
purpose domains and retirement leaf algorithm are unchanged. Native evidence is
an explicit separate carrier, never the result of failing import verification.
The original genesis signature does not cover `creator_authority`; a second
creator signature is mandatory. Neither a Biscuit, request PoP nor witness
signature supplies it.

## Exact signed layouts

Use the existing HYBRID fixed-order framing: bytes/UTF-8 = u32 BE byte length
followed by exact bytes; enums and format versions = u32 BE; sequences = u64 BE;
int64 host times = two's-complement BE milliseconds. Mandatory nested messages
flatten; repeated messages take u32 BE count and flatten each; optional boundary
acceptance takes u32 BE presence (0/1) followed by the unchanged complete payload.
Never sign protobuf or JSON serialization. Strict protobuf decoding rejects
unknown/discarded fields, duplicate tags, noncanonical order and trailing bytes.

`NativeGenesisAuthorityV1` flattens, in this exact order:

1. `format_version` u32 = 1.
2. `identity`: counted Spool UUID (16), immutable Spool-genesis digest (32),
   owner ID (32), Spool owner's account UUID (16), accepted owner-state hash (32),
   ownership-transfer sequence u64. This is `ImportIdentityV1`'s unchanged public
   layout reused as a job-independent lineage tuple; it grants no import scope.
3. `owner_kind` u32 = 1 ACCOUNT or 2 LOCAL_KEY, matching the immutable genesis.
4. `genesis_digest` counted original native typed BLAKE3 ID (32).
5. `original_signatures_digest` counted SHA-256 commitment (32), defined below.
6. `creator_public_key` counted Ed25519 key (32), exactly the original creator.
7. `creator_authority_envelope_digest` counted SHA256(exact envelope bytes) (32).
8. `owner_chain_digest` counted unchanged `ImportOwnerChainV1` digest (32),
   recomputed from independently verified public owner histories/handoffs.
9. `publisher_key_id` counted `heddle-key-v1` ID (32) of the original creator.

The creator signs **SHA256(UTF8("heddle-native-genesis-authority-v1") ||
canonical(NativeGenesisAuthorityV1))**, with no NUL in this domain.
`SignedNativeGenesisAuthorityV1` is that flattened body followed by a flattened
`AuthorizationSignature`: counted signer-key ID (32), counted signature (64).
The purpose-1 `authority_digest` is **SHA256(UTF8(
"heddle-signed-native-genesis-authority-v1") || canonical(signed binding))**.
This digest includes the second signature, avoiding any self-referential field.

`original_signatures_digest` is unchanged:
SHA256(UTF8("heddle-hosted-original-signatures-v1") || u32 BE signature count ||
each counted public key and counted original signature). For genesis there is
exactly one original signature, from the original creator. This commits to the
original signature bytes without replacing or re-signing the genesis.

`NativeGenesisWitnessV1`, the purpose-1 canonical payload, flattens:
`format_version` u32=1, `kind` u32=2 (NATIVE_V1), signed native binding,
original `SignedRecord`, counted exact creator-authority envelope, optional
unchanged `ImportBoundaryAcceptanceV1`. `SignedRecord` remains counted format,
counted original native MessagePack bytes, u32 signature count and flattened
counted key/signature pairs in raw-key order. Native genesis ID remains
BLAKE3(format || original length u64 **LE** || NUL || original canonical bytes).

The first two u32s of native purpose 1 are **1,2**. The unchanged import payload
starts **1,1** (payload version, import binding-body version). Dispatch by the
explicit carrier and purpose; never attempt native parsing after an import
failure. Unknown tags/versions/kinds reject. No signed import bytes change.

The outer `HostedWitnessStatementV1` remains its existing fields 1–19 in order:
version, executor ID, purpose, Spool UUID/genesis, owner ID/state/transfer,
policy state/sequence, basis, original publisher-key ID, authority digest,
original-signature digest, transaction UUID, serialized admission order,
observation milliseconds, counted canonical payload and optional boundary
binding. Purpose 1 retains its existing signing domain
`heddle-import-genesis-first-admission-witness-v1`; sign its SHA-256 canonical
statement digest. The historical name does not grant import authority.
Its authority digest is the signed native binding digest above; its signature
commitment and original publisher must equal the creator-signed binding.

Purpose 2 uses **unchanged** `ImportAuthorityWitnessV1` bytes: version u32,
kind u32 (operation=1, claim=2, resolution=3), original SignedRecord, counted
list of dependencies in signed-native-digest order, counted authority envelope,
counted list of boundary evidence in acceptance-ID order. Its authority digest
remains SHA256("heddle-hosted-authority-envelope-v1" || counted envelope),
original signatures cover original then ordered dependencies, and the publisher
is a verified signing role of the native original. Actor/agent, exact native
method and complete native authority remain independent semantic checks.
Metadata, account source, ownership claim and ownership resolution share this
carrier; no delegation can authorize any of them. Purpose 4 can carry unchanged
`HostedLandingWitnessV1`; purpose 3 is forbidden in the native carrier.

## Producer obligations and basis

CLI **and browser** StartThread producers must:

1. Select/verify the immutable Spool lineage and current owner authority; obtain
   the exact portable native `ThreadControlAuthority` for StartThread. Bind the
   original account/creator and exact `/heddle.api.v1alpha2.ThreadService/StartThread`
   method, using the existing owner → mint-root/capability verification.
2. Construct and sign the original `heddle-thread-genesis-v1` as before. Freeze
   both that original and the canonical authority envelope before constructing
   the binding. Authority may be prepared before genesis; it must be final before
   the second signature. An import member-permission envelope is not native
   authority and cannot pass native envelope decoding.
3. Fill the exact binding above, sign its digest with the **same creator key**,
   then send `StartThreadRequest.thread_genesis`, `creator_authority` and
   `native_genesis_authority` together. Request PoP signs the complete final
   request afterward. The browser can use `signNativeGenesisAuthority`; Rust
   producers use `GENESIS_DOMAIN` and the shared `signing_digest`/canonical code.
4. Preserve all three originals byte-identically in `ThreadGenesisRecord` and
   export them with the complete native witness carrier. A different envelope
   requires a new creator binding, never a rewritten first admission or a host-
   fabricated signature. Retained identities cannot be silently converted.

Local `adopt` continues to sign native genesis/content with the local key and
preserve Git attribution. **LocalKey equals creator**, including in the original
native model. The creator-authority envelope is exactly empty, and its binding
commits to SHA256(empty), not zero32. Before first hosted push the CLI selects the
hosting Spool's independent lineage and signs the native binding with that
original local key. Hosting additionally requires the explicit native ownership
claim, co-signed by the original local owner and the currently authorized
accepting publisher, including the complete observed source frontier. Its
purpose-2 original, envelope, admission and dependencies must be exported.
Uploading, account equality or a witness does not turn LocalKey into Account.
Conflicting claims retain all claims and require the co-signed native resolution,
winning claim, complete conflict set and accepted source frontier. A purely
local capture or LocalKey `LocalIntegration` remains verified by its local
creator plus the explicitly claimed hosting ownership; an account source/control
dependency, including an account-authored `LocalIntegration`, requires purpose 2.

`OriginalAuthority` verifies the original native authority at first admission;
the witness's owner state/transfer must equal the binding's selected state.
`BoundaryAcceptance` verifies a currently authorized accepting party's distinct
signature over the complete exact originals manifest and publication intent,
including exact membership and per-original acceptance-based native receipts.
The original binding/envelope and original creator signature remain mandatory.
The witness still identifies the **original** creator/publisher; the accepting
publisher/authority are separately bound inside the signed acceptance. Accepted
owner/policy state can have advanced since the original binding, while the
immutable Spool lineage must match both. Never assert historical non-revocation
or use an old author timestamp for current authorization. Native subject-kind
permissions remain exact: source acceptance grants no metadata authority; a
local claim or resolution still needs its original co-signatures. No receipt is
reinterpreted from one basis to the other.

## Public native carrier completeness

`NativePublicProofBundleV1` contains public owner genesis, owner histories,
accepted ownership transfers, digest-sorted exact owner-chain history, policies,
native genesis payloads, native purpose-2 payloads, optional hosted landing
payloads, the complete signed witness set, signed statements, per-statement
retirement proofs and foreign dependency references. Originals and envelopes
are embedded in their payloads.
It has no job, import permission, delegation, result slot or terminal
manifest. Foreign evidence is verified against independently selected roots;
carried owner roots and witness sets never enroll themselves.

Every binding resolves its own exact `owner_chain_digest` in `owner_chains`,
including when source/target geneses were admitted under different owner states.
Each chain keeps its original sorted state hashes and accepted transfer order
and resolves every reference in the carrier. All chains share the selected
immutable Spool genesis; no older signed binding is rewritten.

Bounds: 1 MiB encoded carrier, <=64 owner histories/transfers/chains, <=256 policies and
each payload list, <=1024 statements/proofs, existing 64 KiB payload/original
bounds, <=128 native dependencies/receipts, <=16 original signatures and <=64
retirement siblings. No truncation. Payload lists are strictly sorted unique by
signed binding digest (genesis), existing purpose-payload digest (authority or
landing); statements by their purpose signing digest. Every sidecar has exactly
one matching statement and every statement has exactly one complete sidecar.
Multiple purposes may attest the same immutable native original; ambiguous or
conflicting first admissions for one subject must reject at the native gate.

Require an in-carrier witnessed genesis for every same-origin original/dependency;
other-origin dependencies use the exact foreign reference and installed stage
below. Require
byte-identical genesis dependencies, purpose-2 sidecars for every account
source/control/claim/resolution dependency and an explicit witnessed claim for
every hosted LocalKey genesis. A hosted integration dependency resolves through
its byte-identical purpose-4 execution and matching statement; it must never be
given a purpose-2 source-author receipt. Local captures and LocalKey
`LocalIntegration` dependencies resolve as **local work**: preserve the valid
original LocalKey signature and the same Thread's exact witnessed ownership
claim (purpose 2). For `SourceAuthor::LocalKey`, implementers MUST verify the
original signature and require the verified operation publisher to equal the
target genesis's immutable `genesis.owner.local_key` (and the integration's
embedded device). A valid signature by any other key MUST reject, even with a
valid ownership claim and complete causal closure.

Implementers MUST also enforce the native ownership cutoff: select the sole
authorized witnessed claim, or the authorized co-signed resolution with its
winning claim and exact complete conflict set; unresolved conflicts MUST reject.
The integration and its same-Thread causal closure MUST be covered by ancestry
of that claim's signed `source_frontier`, or the selected resolution's signed
`frontier`. Walk from those heads through verified native causal parents; a head
covers itself and its ancestors, so literal frontier membership is not required.
Descendants beyond the signed cutoff MUST reject even if supplied as extra
dependencies under an unchanged, validly signed claim. Cross-Thread source
closure retains each source's own native authorization and ownership cutoff.
A local integration has no account-authority envelope: never manufacture an
empty-envelope purpose-2
receipt or present it as a purpose-4 hosted execution. Select its role from the
embedded native `LocalIntegration.author`, not merely the outer body kind:
an account-authored integration still requires its exact purpose-2 authority
sidecar and cannot use the local-work exception.

Retain the exact cross-Thread source operation and resolve both witnessed geneses
through their own origin carriers, using foreign references where required.
Retain the
target's causal parents, and every dependency needed to verify source revision
and result State ancestry. Resolve each source dependency by its own role
(account source: purpose 2; LocalKey work: native proof plus its Thread's witnessed
claim; hosted integration: purpose 4). The native codecs must independently
verify the canonical original, LocalKey signing role, exact source operation and
revision, target frontier and causal parents, and complete merge State ancestry;
the witness carrier does not replace those checks. Apply these same role-specific rules to
landing source/review closure. Retain every causal parent, ownership claim,
conflict resolution and acceptance dependency required by the native model.
Hosted landing resolves its own exact source/review/target and witness history;
landing is never authorized by genesis admission alone. All selected owner-state
and transfer references resolve in the retained public histories, and every
selected policy head has its complete sequence/hash chain back to zero.

`validate_public_bundle` / `validatePublicNativeBundle` check reference closure,
original signatures and payload commitments. They deliberately do not replace
heddle's full canonical native model, owner/capability, transfer, policy,
revocation, boundary-subject or causal verification, including the mandatory
LocalKey publisher-to-genesis-owner and selected signed-cutoff checks above.
Authenticate the witness set from independently chosen descriptor-root context
and resolve **every** statement
separately. CURRENT needs interval/signature; RETIRED also needs its **exact**
original leaf inclusion; REVOKED rejects. The proof-only lookup remains usable
after access loss/deletion and returns no originals. Recheck the fresh set,
root epoch/high-water/time and each resolved context under the mutation lock.
Current host authority, clock, policy and issuance fences govern new work;
historical accepted-state checks never authorize new work. Receipt issuance,
journal, original and dependencies commit atomically with durable admission.

## Transport and coordinated cutover

`native_authority` is added alongside `import_authority` to TransferReady,
PublicationReceipt, PublishContentOpen, ReplicationOpen, ReplicationReady and
ReplicationOperations, covering Fetch, PublishContent and ReplicateThread.
`ThreadGenesisRecord.native_genesis_authority` retains the exact producer binding.
Reject simultaneous native/import carriers **before staging**. Import carrier
presence always dispatches to the import validator; missing delegation remains
an import refusal. A job-signed original requires its own installed import stage
and an exact foreign reference; an import purpose-1 payload cannot become a
native genesis. Empty/present malformed carriers must reject.
Never drop present evidence on export, relay or retry.

Present native HYBRID evidence requires explicit protocol version 2 and
`IMPORT_AUTHORITY_HOST_WITNESS_V1` feature support, just as import evidence does.
Unsupported producers/consumers reject before staging, installation, mutation or
relay. This release does **not** flip SyncService's method-wide mandatory gate
(api#307). Until the coordinated release, do not create/serve HYBRID native or
import history over Sync. Gate-off is rollout sequencing, never permission to
ignore evidence or invent an endpoint/legacy trust path. At cutover, both arms
become required according to the record's actual authority type; absence of a
carrier cannot choose a permissive local verifier for hosted history.

The owner chose a coordinated reset of disposable staging Threads/jobs and new
witness history, with compatible API → heddle → weft/browser releases. Native
clients re-clone or deliberately reinitialize. There is no proof conversion,
re-witnessing, endpoint trust or backward-compatible bridge. Alpha.28 only owns
the API seam; native install/storage/CLI/browser implementations and their real
StartThread → publish → fresh Fetch tests remain downstream work.

## Imported Git roots

The [delegated native IMPORT parent rules](import-authority-host-witness.md#review-round-1-historical-closure-and-frozen-purpose-payloads)
follow the owner decision of 2026-10-05.

An import produces **one native operation per branch result slot**; v1's one
slot and fixed frontier are unchanged. Git ancestors are not native operations:
they are State objects in the tip State's parent closure, transferred and
verified as content.

The import rule is selected **only by the separately authenticated IMPORT
carrier**, including a durably installed foreign stage: the verified import
delegation and signed import operation that bind
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
Alpha.34 adds generated mixed-origin conformance vectors and staged receiver
models using the published native codecs. Production receiver installation and
Fetch staging remain downstream work in heddle/weft.

## Foreign dependencies (alpha.34 hard cut)

A Thread keeps one immutable IMPORT or NATIVE origin for life. Both public
bundles carry `foreign_dependencies` as references, with one carrier per message.
Every witness SUBJECT MUST have an in-carrier genesis: the P1 original genesis,
P2 `original`, and P4 `execution`. Only authority dependencies, the landing source
and review originals may be foreign. An in-carrier genesis dependency MUST be
byte-identical to its witnessed SignedRecord, including original signatures.
A foreign reference never enrolls an owner or authorizes a subject.

`ForeignDependencyV1` fields are:

| Tag | Field | Rule |
| --- | --- | --- |
| 1 | `format_version` | Exactly 1. |
| 2 | `origin` | Generated `ForeignDependencyOrigin.IMPORT` / `NATIVE`; opposite to the carrier. |
| 3 | `thread_genesis_digest` | Exact 32-byte original Thread genesis ID. |
| 4 | `signed_native_digest` | Exact 32-byte signed-native commitment, including signatures. |
| 5 | `prefix_admission_order` | Positive own-origin authenticated admission cutoff defined below. |

Entries are strictly increasing by raw signed-native digest, unique and fully
used. Each foreign dependency must match both digests. Unknown version/origin,
wrong widths, zero cutoff, missing/mismatched or unused references reject.
The former 128-entry carrier cap is removed. References share the 1 MiB encoded
carrier limit with every original and proof; P2 dependencies/reviews remain
bounded at 128 per payload, and P2/P4 arrays at 256 per carrier. Thus the reference
list cannot exhaust a separate smaller lifetime quota before the carrier does.
Carriers and import snapshots remain cumulative within these existing bounds;
A cumulative export cannot grow beyond 256 sidecars / 1 MiB. Unbounded history
needs a future pagination/cumulative-proof design, explicitly deferred here.
This change removes the earlier reference-only threshold; receivers MUST retain
evidence and enforce snapshot high-water checks when extending an export.

### Deterministic prefix staging

Staging is at ORIGINAL/PREFIX granularity, never whole-Thread granularity.
The tuple `(origin, thread_genesis_digest, signed_native_digest,
prefix_admission_order)` identifies the exact original and its own-origin prefix.
For a delegated import original, the cutoff is the `admission_order` of its exact
P3 publication, selected by replaying `operations` in progressive-manifest order.
The P3 resulting frontier MUST include the original's native operation ID and
its content digest MUST bind that exact capture. The selected manifest contains
all publications through that position, including prior branches of that job.
For an Account/control/claim/resolution original, the cutoff is its exact P2
statement's `admission_order`; for a hosted integration, its exact P4; for a
genesis, its P1. Native LocalKey work has no synthetic P2: use the maximum
admission order in its required P1/ownership-claim/resolution proof closure and
include only the exact signed original's native causal ancestor closure. Its
signed digest disambiguates originals sharing that authority cutoff.

Fetch sends a bounded prefix carrier with the original and all earlier necessary
own-origin admissions, exact signed sidecars/statements, causal ancestors,
owner/policy lineage and retirement proofs. It excludes later P2/P4 admissions
and their foreign obligations. Native prefixes filter statement/sidecar arrays
by the cutoff and retain the required native causal closure. Import prefixes
also truncate `operations` through the selected P3 position, retain their exact
progressive manifests, and select that authenticated cumulative manifest as
`terminal_manifest`; the signed delegation/genesis bindings stay unchanged.
Import native continuations are included only through their P2/P4 cutoff.
Genesis bindings for still-unpublished branches may remain as delegation closure,
without installing those branches. Prefix projection changes carrier arrays and
unsigned selectors, never a signed original, payload, statement or manifest.
Each projected carrier MUST pass its ordinary format/witness/owner/model checks.

The receiver recursively installs foreign ORIGINAL prefixes first, then atomically
installs the requested prefix. Track outstanding obligations by the full original
tuple, so revisiting a Thread at an earlier cutoff is allowed. Reject an unresolved
reference or a repeated outstanding original obligation with `Scope`. A genuine
cycle cannot occur in causally admitted history. A Thread cycle alone is valid:
C's child prefix uses M's import tip; M's later landing uses C's child; C's still
later sync uses M's landing. A fresh receiver installs these prefixes in that
order and can clone both Threads. Never forbid the reverse direction.

Persist originals and their origin proofs in the receiver's admission journal.
Later prefixes extend the same immutable origin: compare retained originals,
signatures and admission bindings byte-for-byte, replay the added causal closure,
keep old evidence, and apply ordinary import high-water/transition checks using
the previously accepted prefix snapshot. Previously installed prefixes can be
reused after the rechecks below. A smaller request may use retained history but
must not roll back the installed prefix. Per-message bounds do not bound traversal
by 128; bound each supplied carrier and traverse distinct original obligations.

### Receiver trust and landing roles

A foreign original's Thread MUST belong to the target's Spool under the same
independently selected deployment authority. Installed origin MUST equal
`ref.origin`, installed Thread MUST equal `thread_genesis_digest`, and the
selected admission cutoff MUST equal `prefix_admission_order`. Any mismatch,
missing stage or substituted original is `Scope`.

Under the receiver's mutation lock, recheck exact original bytes and signatures,
immutable genesis, Spool/deployment membership, and its retained origin proof.
For imported job originals, recheck delegation/job publisher binding and the
exact P3 frontier AND content binding. For native originals and import native
continuations, recheck their exact P1/P2/P4 admission statement and full native
causal/owner/capability/State rules; LocalKey work retains its ownership proof.
Recheck every selected witness against the independently authenticated CURRENT
set, root epoch, generation and clock floors: CURRENT requires interval and
signature; RETIRED requires the exact original leaf proof; REVOKED rejects.
Carried sets and caller-supplied origin/envelope assertions cannot select trust.
Commit dependent admission and retention atomically only after every check passes.
On rejection there MUST be no dependent state change. This rule is tested in
heddle's transaction; these API conformance models do not exercise rollback, and
this API-only verification does not run the downstream transaction suite.
Simultaneous carriers still reject `Protocol` before staging; no fallback.

Landing selects the SOURCE role independently of the target carrier:

- Account: exact installed P2 admission plus `native_authority`, including the
  source's original owner/capability authority.
- LocalKey import: exact installed P3/delegation binding and publisher equal to
  the bound job key, otherwise `ImportPermission`.
- Hosted integration: exact installed P4 and full native landing/source checks.
- Landing request signer: `KeyRole` for any delegation job key in the bundle,
  independently known job association, or explicitly forbidden landing key.

The request-role refusal is portable and shipped in both Rust and TS:
`verify_landing_key_roles` / `verifyLandingKeyRoles` accepts independently selected
known-job and forbidden-landing lists. Import structural validation checks bundle
delegation keys; import witness verification also checks selected owner facts at
the authenticated landing time. Native witness verification checks the known job
keys retained from witness-set verification; receivers also invoke the helper
with their complete role lists. `forbidden_landing_keys` /
`forbiddenLandingKeys` is distinct from keys forbidden to assume a JOB role:
ordinary device keys can be forbidden job keys and valid landing signers.

Binding LocalKey sources to installed carriers, checking the installed P2/P4 of
Account/integration sources, and full request method/body/revision/policy/review
validation remain receiver-normative. Portable role refusal does not supply
those installed-state checks. Multiple import jobs on one Thread are explicitly
DEFERRED: `delegations.len() == 1` remains enforced; no implicit multi-job reader.
The generated fresh-receiver models demonstrate prefix scheduling and exact
bindings, not a production Fetch/storage implementation.
