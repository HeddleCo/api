# Committed harness/model attribution

Harness/model identity is ordinary immutable source metadata. New native
agent-assisted captures commit a typed evidence Blob reference in the State;
normal source sharing and audience rules carry it by default. No timeline
preference or public-model allowlist is required. Raw prompts, responses, tool
payloads, credentials, environment bags, external source paths and arbitrary metadata
remain outside this schema. The existing scrubbed timeline v1 contract is
unchanged.

## Authority and representation

The native object-model owns `AttributionEvidenceV1`: `HAE1` followed by strict,
canonical named MessagePack, at most 256 KiB. Identity/correlation values are at
most 256 UTF-8 bytes and pass native field-specific admission. Native Blob
hashing names these exact bytes. `State.attribution_evidence` is a required
32-byte Blob reference when present; format-6 State hashing commits it. Neither
the final StateId nor the capture-operation ID is embedded in the evidence,
avoiding hash cycles. Later observations never rewrite a frozen State.

The API's `StateAttribution` projection is shared by existing `StateSummary`
(tag 12) and `CaptureSummary` (tag 16). Its `evidence_hash` is the exact native
Blob identity. Protobuf projection bytes are not a canonical hash preimage and
are not a provider attestation. Independent verifiers need the original State,
its original signature/source operation, and the referenced Blob. A signature
authenticates its recorder and exact binding, never that a provider executed a
model or that every changed line came from that model.

Native evidence is authoritative. Legacy `Agent` and provider/model summary
fields are deterministic compatibility projections: use a complete response
provider/model pair, otherwise a complete selection pair, otherwise no legacy
Agent. Never pair a selected provider with a response model. Native admission
rejects disagreement. Policy attribution remains a separate existing field.

Selected routing keys, model aliases and separately supplied model revisions
retain their exact accepted values. Response provider/model fields are populated
only from response-reported claims. Missing model/version/backend stays unknown;
no publisher/family inference or alias splitting. Harness version includes its
scope: current invocation, session creation, or installed binary. Resume must
not promote a session-creation version to current runtime identity. Each claim
retains its basis, collection surface and optional scoped observation ID.

The root v1 evidence identity describes the capture caller. The additive
`operations` list retains up to 64 independently scoped contributor observations;
it never silently merges sibling actors, retry attempts or multiple contributors
into that root identity. Each `AttributionOperationIdentity` retains its own
harness/version/scope, selected and response claims, and correlation IDs. Missing
operation fields do not inherit from the caller or another contributor. The
`collection_methods` list separately records up to six unique collector origins:
hook, event stream, OpenTelemetry, transcript, proxy or explicit input. Coalescing
the same fact retains every observed origin. Conflicting identity/model
observations remain separate unresolved operations. Origins do not replace
per-claim provenance, and an enum value does not imply that an adapter is
implemented or supported at runtime. An empty list leaves the origin unknown.

Each operation carries at most 32 distinct file changes. Their repository-relative
paths are normalized and bounded to 1024 UTF-8 bytes; absolute paths, empty/dot/
parent components and escapes are rejected. The typed `AttributionBlobHash` wrapper
holds an exact 32-byte native Blob digest, not an untyped raw-content checksum.
For content-bound transitions, an absent `before` means creation and an absent
`after` means deletion; at least one endpoint must be present and the endpoints
must differ. Unresolved observations may lack a proven transition. These records
are immutable evidence and travel with the same State-bound source metadata.

`CONTENT_BOUND` means native capture linked the reported before/after file
transition to the captured content. It requires the operation's scoped
`tool_call_id`. This records observed transition linkage, never proof that a
provider executed a particular model, that a contributor was the sole author,
or that any individual line belongs to that contributor. `UNRESOLVED` retains
an observation whose content linkage could not be established and must not be
rendered as an actual producer. `UNSPECIFIED` is not a valid native resolution.

`operations_incomplete` is true if additional operation evidence could not be
retained. A false value does not establish complete authorship coverage. Older
records omit the operation list and flag and retain their original native bytes;
empty operations do not mean human-only work. If available evidence cannot
establish a scoped producer, leave that fact unknown rather than assert a global
last-model value. Claim/scope validation, exact hash lengths, collection bounds
and cross-field invariants remain native admission responsibilities; protobuf
projection bytes alone do not attest their validity.

An absent projection means no new evidence reference, as with legacy history
or explicit suppression; it is not proof of human-only work. A present digest
with absent `evidence` means the required payload is unavailable. A present
known harness and missing model means agent-assisted, model unknown.

## Explicit native-format negotiation

`NativeSourceFormat.STATE_V6_ATTRIBUTION_V1` (1) is one inseparable implemented
bundle: format-6 State hash and named MessagePack, HCS3 compact frames, canonical
HAE1 evidence validation and required source-closure preservation. It is
independent of signed operation `record_formats`. Compiled descriptors alone
must not cause a consumer to advertise this capability.

- `DescribeEndpointResponse.understood_native_source_formats` advertises actual
  endpoint support. Absent/empty never supports this addition
- `FetchOpen.understood_native_source_formats` binds receiver support to the
  opening proof. A sender refuses unsupported required formats before source,
  provider or inline bytes; it never strips identity or rewrites old/new States
- `PublishContentOpen.required_native_source_formats` declares additions needed
  by the exact signed publication. The publisher first checks explicit endpoint
  support. `TransferReady.native_source_formats` identifies the exact plan's
  required additions; the receiver checks all are understood before bytes
- Transfer plan/checkpoint digests bind this format set. Resume cannot weaken it
- `ReplicationOpen` and `ReplicationReady` each advertise native support, so a
  signed capture embedding a new State is sent only to an explicitly compatible
  peer in either direction

The receiver derives requirements from actual decoded States/packs, not only
the declaration. A format-6 State or HCS3 frame in a legacy-declared transfer is
rejected. Unknown required formats and unspecified (0) fail closed. Unknown
advertisements confer no support. Rust and TypeScript negotiation helpers share
these rules; consumers still must implement object decoding, proof binding and
closure enforcement. Unsupported peers return an actionable failed-precondition
error. No fallback rewrites or removes attribution.

## Missing objects and publication

Causal metadata admission remains distinct from source publication. An
authenticated capture operation can be retained while `ReplicationReceipt`
reports its missing source/evidence objects. This does not permit treating that
revision as source-available or replacing its attribution with human-only.

Every evidence reference is part of `SharedFacet.SOURCE` closure, independent of
semantic-index or timeline selection. Publication validates State hash, native
evidence hash/schema and compatibility projection, and installs the complete
authorized closure atomically before emitting `PublicationReceipt`. Missing or
invalid evidence prevents publication success. Fetch with partial coverage may
retain pending metadata and report missing objects, but cannot claim complete
closure or materialize an evidence-bearing State as complete without its Blob.

GC, repack, shallow/native fetch and native Git round trips retain the evidence
for each retained State, even when parent history is intentionally omitted.
Evidence is not a mutable/latest attachment and cannot be separately suppressed
while claiming to serve the same complete State. Existing source audience and
authorization checks still apply.

## Compatibility and rollout gate

No evidence reference preserves exact existing State bytes/hashes and format-4/5
stored-ID acceptance. Legacy-only compact batches stay HCS2 and historical HCS1
remains readable. Evidence-bearing States use the new hash domain and never
accept pre-cursor fallback IDs; batches requiring evidence use HCS3.

These protobuf changes and helpers are additive. They do not implement or
activate format-6 writing, native storage, CLI collection, weft admission or
tapestry rendering. Ship consumer read/validation support and negotiated proofs
first, then enable new writes only after end-to-end closure/unknown-identity
tests pass. Keep package versions unchanged until a coordinated release.
