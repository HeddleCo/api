# Collaboration mentions and discussion tags

`EntityRef.principal` names a stable human or agent account UUID. The new
`EntityRef.source` uses `SourceMention`, aligned with the original coordinates
of `SourceAnchor`: exact `RevisionRef`, nonempty repository-relative path,
optional symbol ID, optional one-based inclusive line pair, and optional owning
Thread. The Thread and revision must have the same Spool. This reference is
pinned; it has no implicit tracking policy. Delegated agent attribution remains
separate from the mentioned account. `EntityRef.agent` is not converted to an
account mention implicitly.

Opening `OpenDiscussionRequest.mentions` and `AppendDiscussionRequest.mentions`
use the same `EntityRef` list. Both project onto `DiscussionTurn.mentions`,
including the opening turn. `ContextDraft.mentions` and `ContextRecord.mentions`
carry the same references. At most 128 mentions are allowed per signed command,
including an extracted context's metadata. The complete canonical named
MessagePack mention array is at most **256 KiB (262144 bytes) per command**,
including its array header, map keys, reference values and encoding overhead.
This is independent of protobuf delivery-list size and of enclosing signed-record
bounds. Apply the same cap in Rust canonical encoding and delivery validation,
and in TypeScript signing, verification and typed delivery validation. An
extracted context has the same per-command cap. Paths and symbol IDs are bounded
to 4096 UTF-8 bytes each. Reject non-relative/non-normalized paths, missing exact
revisions, mismatched Thread scopes, zero/reversed lines, or a lone endpoint.
A file mention may omit both lines and the symbol ID.

Hosts compare delivery fields with original signed metadata before admission;
a request proof never substitutes for the portable author's signature. Mention
references grant no access. Principal mentions are retained as opaque principal
ids in **every projection**, unchanged from what the author signed. Hosts never
refuse a command or strip a principal mention because of the mentioned
principal's access. This includes the author's own projection: admission and
projection must not act as a membership oracle. Source mentions may be refused
when the **author** cannot read the source; source, Thread, entry and
record-audience disclosure gates still apply to source references in reader
projections. Errors must not distinguish absent from hidden sources. Original
signed operations remain immutable and have independent operation/source
disclosure gates.

**Only notification delivery is gated by the mentioned principal's access.**
The existing notification kind `mention` goes only to mentioned principals who
can read the collaboration anchor **and** its discussion/context audience at
delivery time. No author-visible field or status reveals whether delivery
happened. Source coordinates in a notification must also pass the recipient's
exact-revision source gates. Recheck access at delivery and observation: queued
notifications cannot outlive revoked read authority. The opaque principal
reference does not enroll a principal, widen an audience, or disclose delivery.

`DiscussionRecord.tags` and `OpenDiscussionRequest.tags` use the existing
`AnnotationTag` union and its 128-tag bound, scalar typing and duplicate-property
rules. `EditDiscussionTagsRequest` / `CollaborationService.EditDiscussionTags`
replace the complete tag list, including an explicit empty list to clear it.
Like a `PutContext` revision, an edit supplies the observed aggregate
`expected_version`, `client_operation_id` and original author-signed operation
with observed causal parents. Reject stale versions and request/signed-body
mismatches. Preserve concurrent tag revisions in the causal register rather
than editing an immutable opening operation or silently choosing a winner.
An edit never creates a discussion turn or increments `turn_count`.

`ObserveCollaborationRequest.discussion_tags` reuses `AnnotationQuery`'s exact,
symbol, path/prefix, overlap and property predicates (at most 64 in total).
Presence selects discussions only; an empty query matches all visible
discussions. It is mutually exclusive with the context-only `annotations`
filter. Apply predicates to each current causal tag revision, never a union of
concurrent tags; other request selectors intersect normally. Visibility applies
before predicates, counts and page boundaries. Source predicates describe
original signed evidence and do not imply automatic source-target tracking.

## Endpoint negotiation (alpha.48)

Hosts advertise implemented semantic support in
`DescribeEndpointResponse.protocol.mandatory_features`, sorted and unique:
`MANDATORY_PROTOCOL_FEATURE_COLLABORATION_MENTIONS_V1` (2) for principal and
source mentions on opening turns, replies and contexts, and
`MANDATORY_PROTOCOL_FEATURE_DISCUSSION_TAGS_V1` (3) for opening tags and
`EditDiscussionTags`, including empty replacement lists. Merge these into the
host's existing feature set; a host implementing HYBRID, mentions, tags and
outlines advertises `[1, 2, 3, 4]`. Advertise a feature only after implementing
its complete semantics. Signed-record format advertisement does not imply it.
These values are **not** per-method `mandatory_features`: ordinary discussion
and context commands remain usable on hosts that do not advertise them.

Clients use Rust `v2::protocol::{host_supports, require_feature}` or TypeScript
`./v2/protocol`'s `hostSupports` / `requireFeature` with the authenticated
endpoint's negotiated `ProtocolCompatibility`. Missing negotiation is missing
support. Discard it when the endpoint/connection changes. Gate UI controls
before constructing variants, then let the encode helpers enforce the same
check. Rust refusal is `Reject::MissingFeature(feature)`; TypeScript throws
`MissingProtocolFeatureError` with its typed `feature` property.

Rust mention encoders/validators and `canonical_discussion_tag_edit` now take
`peer: Option<&ProtocolCompatibility>` as their final argument. Use
`canonical_discussion_open_tags(tags, peer)` for opening tags; the older
`canonical_annotation_tags` remains for existing context tags. TypeScript
`signDiscussion`, `signContext`, `canonicalMention` and `validateEntityMentions`
take an optional final `peer` argument. Omitting it refuses new variants, so
old callers remain compatible but cannot accidentally assume new support.
The signers check before invoking the signing callback. Empty opening tags,
legacy mention variants and existing context tags need no new feature.
`EditDiscussionTags` always requires tag support, even when clearing all tags.
The typed clients consult their stored negotiated peer automatically for
opening, append, context, extracted-context and tag-edit delivery requests
before transport (TypeScript also checks before protobuf encoding). Rust
surfaces these failures as `ClientError::RequestFeature(Reject::MissingFeature(...))`.
Hosts still compare delivery fields with the original signed command and refuse
unsupported signed forms; negotiation never grants authority or changes bytes.

## Canonical compatibility and conformance

Extend the existing signed mention union and the existing protobuf `EntityRef`;
do not replace either list with a new wrapper. Existing mention maps retain
their keys, order, UUID binary representation and tags. New signed maps are:

- Principal: `{kind: "principal", principal_id: <binary UUID>}`.
- Source: `{kind: "source", target: {scope: {spool, thread}, source:
  {revision, path, symbol_id, start_line, end_line}}}`. This is the existing
  annotation source-reference representation, without tracking/projection keys.
- Opening tags: append `tags` after the opening `turn` (after a legacy
  `thread_ref` when one exists); omit it when empty, including explicit `[]`.
- Tag replacement: `{kind: "edit_tags", tags: [...]}` as a new action in the
  existing schema-version-2 discussion content and version-1 Thread operation.

No existing canonical encoding, signature, operation ID or protobuf field tag
changes. Mention arrays and tag arrays retain author ordering. New forms require
consumer implementations that recognize the variants; older verifiers must
refuse unknown forms, never discard signed fields. A valid signature proves
original bytes, not causal admission or live permission.

Rust exposes `v2::collaboration::canonical_mention`, `canonical_mentions`,
`validate_mentions`, `validate_source_mention`, `canonical_annotation_tags` and
`canonical_discussion_tag_edit`. TypeScript extends `CollaborationMention`,
`DiscussionAction` and the existing sign/verify helpers, with `canonicalMention`
and `validateEntityMentions` for typed delivery lists. The generated request and
record surfaces are available in both languages.

`tests/fixtures/collaboration-alpha47.json` contains seven Rust-generated full
signed records with canonical bytes, Ed25519 signatures, operation IDs, protobuf
wire bytes and mention-component vectors. Rust and TypeScript reproduce them;
native conformance also checks signatures/components and compares all seven
existing mention variants with the published native encoder. The pinned
thread-api 0.28.7 native decoder is tested to refuse `edit_tags`, `open_tags` and
`principal_open` signed records with an error rather than dropping signed fields.
The existing
`collaboration-v2-rust.txt` corpus remains unchanged. The pinned capability
verifier has no collaboration-command slice (it verifies owner and control
capabilities); no capability signature format changes. Collaboration schema
admission belongs to the collaboration consumers, independently of that verifier.

The companion [file-outline contract](content-outline.md) uses the generated
`SymbolKind` enum for Rust and TypeScript validation: reject `UNSPECIFIED` and
unknown values, without a separately hard-coded numeric range.
