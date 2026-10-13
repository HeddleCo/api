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
including an extracted context's metadata. Paths and symbol IDs are bounded to
4096 UTF-8 bytes each. Reject non-relative/non-normalized paths, missing exact
revisions, mismatched Thread scopes, zero/reversed lines, or a lone endpoint.
A file mention may omit both lines and the symbol ID.

Hosts compare delivery fields with original signed metadata before admission;
a request proof never substitutes for the portable author's signature. Mention
references grant no access. Before recording or projecting references, hosts
check the author's access to the referenced source and apply its live source,
Thread, entry and record-audience gates. Inaccessible references are refused or
dropped from reader projections; errors must not distinguish absent from hidden
resources. Original signed operations remain immutable and are disclosed only
under their independent operation/source disclosure gates.

The existing notification kind `mention` goes only to mentioned principals who
can read the collaboration anchor **and** its discussion/context audience.
Any source coordinates included in a notification must also pass the
recipient's exact-revision source gates. Inaccessible principal mentions are
refused or dropped and never disclosed to recipients. Recheck access at delivery
and observation: queued notifications cannot outlive revoked read authority.
A safe refusal discloses no target existence, paths, counts or audience. The
reference does not enroll a principal or widen any audience.

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
existing mention variants with the published native encoder. The existing
`collaboration-v2-rust.txt` corpus remains unchanged. The pinned capability
verifier has no collaboration-command slice (it verifies owner and control
capabilities); no capability signature format changes. Collaboration schema
admission belongs to the collaboration consumers, independently of that verifier.
