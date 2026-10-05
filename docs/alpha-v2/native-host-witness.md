# Native host witnessing v1 (alpha.30)

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
payloads, the complete signed witness set, signed statements and per-statement
retirement proofs. Originals and envelopes are embedded in their payloads.
It has no job, import permission, delegation, renewal, result slot or terminal
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

Require a witnessed genesis for every selected native original/dependency,
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

Retain the exact cross-Thread source operation and both witnessed geneses, the
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
an import refusal. A job-signed operation or import purpose-1 payload cannot be
smuggled into native history. Empty/present malformed carriers must reject.
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

The [IMPORT-only parentless exception](import-authority-host-witness.md#review-round-1-historical-closure-and-frozen-purpose-payloads)
(owner decision, 2026-10-05) is selected by the operation's authenticated signed
content, never caller context. Delegated native IMPORT originals preserve
converter/Git parent order without duplicates: State parents exactly equal the
source States of the complete causal operation parents and never include the
genesis base. Empty State parents are valid if and only if causal parents are
empty, including later disjoint Git roots. The signed genesis still binds the
canonical synthetic empty base. Ordinary native Captures still require a child
State, and the frozen old parentless capture negative still rejects.
Conformance vectors follow after the next heddle release because
`tools/hybrid-native` pins published heddle.
