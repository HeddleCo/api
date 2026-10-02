# Saved times and source path kinds

These additive v2 contracts address [weft#2507](https://github.com/HeddleCo/weft/issues/2507)
and [weft#2508](https://github.com/HeddleCo/weft/issues/2508). This repository
supplies schema, client canonical encoding and conformance vectors. Native CLI
recording and live server lookup/population are the corresponding heddle/weft
implementation work; publishing the fields alone does not implement them.

## Bookmark times and ordering

`BookmarkRecord.bookmarked_at = 5` and `updated_at = 6` use the existing v2
`google.protobuf.Timestamp` convention, with seconds and nanoseconds. These are
private caller-preference metadata, not signed source facts or resource CAS
versions. A server supporting these fields records its transaction commit time:

- The first successful save of a saved interval sets both times to the same
  instant. `bookmarked_at` survives label edits and repeated saves while true.
- An effective label edit changes only `updated_at`. An effective removal sets
  `bookmarked = false`, retains the last known `bookmarked_at`, and changes
  `updated_at` to the removal time. This is the existing retained CAS tombstone.
- Re-saving a tombstone starts a new saved interval and sets both times anew;
  `bookmarked_at` means first saved in that interval, not lifetime-first-ever.
- No-op writes and idempotent retries preserve both times.
  An unsaved/never-saved record has no `bookmarked_at`; a never-mutated default
  has neither time. An effective label edit on it can set only `updated_at`.
- Historical unknown times remain absent, not zero/epoch or an inferred time.
  Editing a legacy saved row sets `updated_at` but does not invent
  `bookmarked_at`. An unmodified legacy row can have neither field. Once both
  are known, `updated_at >= bookmarked_at`; timestamps do not replace CAS.

Workspace bookmark stream/paging order has **no chronological guarantee**.
Clients sort their loaded, caller-visible `bookmarked = true` rows newest-first
by `bookmarked_at` (seconds then nanos), unknown times last. Ties, including
unknowns, use the canonical `BookmarkRef` target identity in ascending UTF-8 byte
order: target kind (`spool` before `thread`), Spool UUID, then Thread's immutable
ID bytes. Label and resource names are never tie breakers. Sorting a partial
page orders only that loaded subset; a complete Saved ordering requires all
pages of the bookmark snapshot. Live events update that local order. Tombstones
remove rows from Saved and are never ranked using `updated_at`.

## Signed-bytes finding

**Source anchors are inside canonical signed bytes.** At inspected heddle
commit `7ae1e3c2d5d3f9f0b4ada5aa4b65fabeb5a3a0f3`,
[`CollaborationSourceAnchor`](https://github.com/HeddleCo/heddle/blob/7ae1e3c2d5d3f9f0b4ada5aa4b65fabeb5a3a0f3/crates/object-model/src/object/collaboration/source.rs#L14)
is serialized inside
[`WireAnchorV1::Source` and the named MessagePack codec](https://github.com/HeddleCo/heddle/blob/7ae1e3c2d5d3f9f0b4ada5aa4b65fabeb5a3a0f3/crates/object-model/src/object/collaboration/codec/v2.rs#L30).
The [decode path preserves exact canonical bytes and hashes them for the operation ID](https://github.com/HeddleCo/heddle/blob/7ae1e3c2d5d3f9f0b4ada5aa4b65fabeb5a3a0f3/crates/object-model/src/object/collaboration/codec/mod.rs#L50).
The [portable Thread operation signature](https://github.com/HeddleCo/heddle/blob/7ae1e3c2d5d3f9f0b4ada5aa4b65fabeb5a3a0f3/crates/crypto/src/thread_operation.rs#L32)
covers the outer canonical operation, including its canonical collaboration body.
The API [browser encoder](../../packages/typescript/runtime/v2-collaboration.ts)
likewise embeds `anchorValue` in signed contexts/discussion opens and source
annotation tags. Protobuf `SourceAnchor` is a read projection of those facts;
adding a protobuf field alone would not record it in an author's signature.

## Optional canonical extension

Keep `heddle-thread-operation-v1`, discussion `schema_version = 2` and context
`version = 2`. Extend the existing named MessagePack source map **only** with
an optional final `path_kind` string. Its ordered keys are:

```text
revision, path, symbol_id, start_line, end_line, [target], [path_kind]
```

The only signed values are `"file"` and `"directory"`. Unknown/UNSPECIFIED omits
the key entirely; neither `null`, `"unspecified"` nor a numeric enum is canonical.
The extension follows `target` when both are present. `path_kind_source` is
never a canonical key. Native implementations must use an optional field with
omit-when-absent serialization (as for `target`), not a default enum serialized
into every old map. All enclosing keys, versions, hashes and signature domains
are unchanged. An empty source path cannot record a kind; directory anchors
cannot include a symbol or line span.

The CLI resolves the path at the **anchored revision**, records the known kind
before signing, and never substitutes its current filesystem/head. The browser
`PortableCollaborationAnchor.pathKind` does the same. Typed source annotation
tag inputs require `RECORDED` with a known kind; `DERIVED` values are rejected
before signing. Target interning ignores kind/provenance: source-file/target
identity retains its existing revision/path/selector preimage.

Old records without the key retain byte-identical canonical bodies, operation
IDs and signatures. Readers/verifiers must verify and retain the original bytes,
not decode with an older model and re-encode after discarding the extension.
Old protobuf readers skip the new fields and retain all old fields. Strict old
canonical verifiers may refuse new extended records until upgraded; this is
not permission to strip the signed key, backfill old signed objects, or claim
support for the new form. Existing independent Rust signature vectors remain
unchanged. New shared vectors verify both kinds and omitted-kind bytes, plus
signature failure when the recorded kind changes.

## Read projection, derivation and confidentiality

`SourceAnchor.path_kind = 8` uses `SourcePathKind`: UNSPECIFIED (0), FILE (1),
DIRECTORY (2). `path_kind_source = 9` uses `SourcePathKindSource`: UNSPECIFIED
(0), RECORDED (1), DERIVED (2).

- RECORDED means the verified original signed source map contains that known
  kind. A server must not mark a caller's unsigned protobuf field RECORDED.
  Do not overwrite a recorded fact with a current-tree guess.
- For an older note with no signed key, weft may inspect the exact
  `SourceAnchor.revision` (State tree or exact Git commit tree) and that exact
  literal path, after authorizing the owning Spool/Thread, revision and path
  using the existing content-read visibility/embargo rules. A blob/file entry is
  FILE; a tree/directory entry is DIRECTORY. Symbol/line selectors do not affect
  kind. Symlinks are file entries, never followed; unsupported entry types
  (including Git submodules) are UNSPECIFIED. An empty path is UNSPECIFIED.
- An authorized lookup with a missing path or unsupported type emits
  UNSPECIFIED + DERIVED. An unavailable revision, denied lookup or no attempted
  derivation emits UNSPECIFIED + UNSPECIFIED. Never infer from dots, extensions,
  line numbers, a local checkout, or a newer revision. A path deleted at the
  current head may still be FILE at its anchored revision.
- Derived kinds, including unknown results, are ephemeral projection metadata.
  Never write them into signed canonical bodies, imported objects, original
  annotation tags or replay records; never re-sign on the author's behalf.
- Content-read authorization/redaction applies to **both** recorded and derived
  kinds before emission. Being allowed to read a note does not itself permit
  reading its source. A hidden path must not reveal FILE versus DIRECTORY,
  existence, or whether an internal lookup succeeded. Withhold/redact the
  source referent under the existing rules; when a redacted projection is
  permitted, both enums are UNSPECIFIED. Never return RECORDED/DERIVED as a
  hidden existence oracle. Do not emit the original portable signed record
  when its embedded referents fail disclosure checks. Evaluate visibility before
  pagination, counts, caching and target resolution; bind derived caches to
  caller authority and exact revision and invalidate on authority loss.

`SourceLocation.path_kind = 7` mirrors the same enum for current resolved
locations/search projections. This message is wholly derived metadata, so it
needs no provenance field. Classify at **its** `revision`, which can differ from
the original anchor revision, under that revision's content-read gates.
Unavailable/hidden source-target resolutions continue to omit the location and
computed revision; do not add kind to such events. See the existing
[source-target visibility contract](source-targets.md).

The conformance fixtures illustrate authorized missing paths, extensionless
files, directories with dots, historical revisions and equal redaction for
hidden file/directory/missing paths. These exercise the contract projection
model, not live weft authorization or tree lookup, which this repo does not own.
