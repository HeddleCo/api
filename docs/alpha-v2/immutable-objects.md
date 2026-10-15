# Immutable SOURCE objects, format 1

`SyncService/OpenObjectSnapshot` and `SyncService/ReadObjects` are additive,
opt-in unary reads. DescribeEndpoint advertises them only when implemented.
An unsupported mode returns the existing unimplemented-method failure; clients
must select a supported mode explicitly. Existing Fetch and its proofs remain
available. There is no have/want negotiation, delta selection, pack construction,
new storage service or edge revocation mechanism in this contract.

Opening requires a Thread, an exact native State RevisionRef in the same Spool,
and explicit positive limits. The host verifies the State's relationship to
that Thread and current SOURCE read authority. The returned snapshot contains
a complete bounded inventory of the permitted projection, including its root
tree. A selected State confers no rights to another Thread, another historical
State, or a raw Git object. Restricted projections must never disclose hidden
IDs through inventory entries, tree bodies or lengths. Refuse a projection
that cannot be represented safely and completely within the limits.

Format 1 deliberately chooses a bounded inventory, rather than introducing a
Merkle proof format. It supports at most 4,096 unique typed objects; larger
inventories require explicit refusal. Inventory paging and other codecs require
a future negotiated format. Inventory entries are strictly ordered by numeric
kind then unsigned lexicographic digest. Only TREE (1), BLOB (2), algorithm
`blake3`, and codec `identity` are supported. Digests are exactly 32 bytes.
Native identity verification uses canonical native bytes, including tree salt;
consumers must retain their native object verifier. Transport vectors contain
synthetic payloads and do not replace native format conformance fixtures.

The host stores/authenticates the snapshot behind a 1..256-byte opaque session
handle. The handle is restricted to the exact user AND authenticated signing
principal. `principal_sha256` is SHA-256 of the exact UTF-8 authenticated Tier-1
signing identity, not a display name, bearer string or mutable account handle.
`user_id` and `spool_id` are 16-byte nonzero UUIDs. `host_public_key` is the
32-byte public authority identity of the endpoint. All 32-byte context fields
are required. Every call uses the existing method-bound Tier-1 proof, covering
the exact request including handle, authority binding, Thread, IDs and ranges.
Hosts match the authenticated user/principal and resolve the handle before
using the public validators. A recomputed hash or caller-supplied inventory is
never authorization. Open response validation binds the selected native State,
Thread, Spool and accepted limits to the original request.

## Limits and resumption

Limits may narrow these inclusive ceilings; zero is invalid:

| Quantity | Ceiling |
| --- | ---: |
| Objects/ranges per read | 512 |
| Encoded protobuf ReadObjectsResponse | 4 MiB |
| Data bytes per chunk/range | 512 KiB |
| In-flight batches per clone | 4 |
| Complete inventory entries | 4,096 |
| Sum of decoded admitted object lengths | 256 MiB |
| Encoded snapshot/open response | 512 KiB |
| Encoded open/read request | 64 KiB |
| Session handle | 256 bytes |

Hosts validate limits before traversing or reading objects. Adapters enforce
wire byte caps before protobuf decoding, using bounded readers; public bounded
decoders are provided for snapshots and object read requests/responses. They
also cap repeated-message counts with existing protobuf wire readers before
decoding, then run semantic validation before allocating from declared lengths. No
allocation may use an unchecked object size, range end, or count. Clients and
hosts bound concurrent batches and share a byte budget across them. Transport
adapters fragment envelopes under their existing frame limits; a chunk's data
limit does not include its protobuf metadata. Four full responses retain at
most 16 MiB of encoded envelopes, plus bounded decoding and object staging.

Each request asks for specific missing typed IDs with offsets and lengths.
IDs must be unique within a batch and members of the authenticated inventory.
Each range is wholly within its declared object and at most the chunk limit.
An empty blob is requested as offset 0, length 0; other zero-length ranges
are invalid. Large objects use successive offset ranges in successive batches.
Range end arithmetic is checked; no arbitrary global CAS probing is allowed.

A response is a nonempty ordered prefix of requested ranges, with one complete
chunk per range. It echoes the binding, codec, exact full decoded object length,
requested offset and data length, and SHA-256(data). `next_object_index` equals
the prefix count; `complete` is true exactly when every requested range was
returned. A host unable to fit one chunk in the accepted encoded response
budget refuses the request with a limit failure. It never emits an empty
progress response. Request the suffix after a partial response. After loss of a
unary response, retry only missing ranges with a fresh request proof. Prefix
indices are relative to each request, not global cursors.

Chunk hashes permit verified staging/resumption, not object installation.
Verify the entire canonical native object against its typed ID before install.
A completed batch does not prove complete snapshot or history coverage. Retain
existing native signed State/history/ownership/witness checks and atomic
admission; this inventory is not a replacement history proof. After authority
expiry, open a fresh snapshot, revalidate membership, and reuse only previously
verified immutable bytes. Never carry the old session or binding forward.

## Revocation and cache lifetime

The host advertises `max_cache_ttl_seconds` explicitly in every snapshot. Its
default is **60 seconds**; it is a positive host-configurable maximum. The host
sets `authorized_at_unix_seconds` from its last LIVE authority check, and sets
an exclusive expiry no later than that check plus the advertised TTL. Times
are unsigned Unix seconds, and expiry must be later than authorization. A
cache accepts only `authorized_at <= now < expires_at`. Use a trustworthy clock
and expire conservatively when clock accuracy is uncertain.

Hosts may serve previously authorized cached bytes after revocation for at
most that TTL window. There is **no synchronous edge revocation gate**. Cache
hits, object misses, retries and regional forwarding MUST NOT restart the
window or mint a later authorization time from cached authority. Only a new
live authorization check may issue a fresh window, and it must refuse revoked
access. Policy/credential/view restrictions all obey this rule. Expiry applies
to each delivery, including a delayed response, not just request receipt. An
already-local verified object is not erased by this network disclosure policy.

Initial caches are private to both user and signing principal, even for public
content. Never share entries by object digest alone, across accounts, or across
principals belonging to one account. Session handles and bearer credentials
must not appear in cache keys or URLs. Restriction changes require fresh live
authority once the existing window ends; synchronous invalidation is optional
only as a way to shorten that window, never a correctness dependency.

## Canonical bindings and transport equivalence

All integers below are unsigned big-endian. `u32` is four bytes; `u64` is eight.
Every field width is validated first; there is no protobuf serialization,
normalization, implicit default or unknown extension in these transcripts.
Format 1's fixed algorithm and codec are implicit in its versioned domain.
Reject unsupported format/kind/algorithm/codec rather than substituting one.

`authority_binding` is SHA-256 of this concatenation, in order:

1. UTF-8 `heddle-object-authority-v1` then one zero byte.
2. Host public key (32), user UUID (16), principal SHA-256 (32), Spool UUID (16),
   Thread ID (32), State ID (32), view digest (32).
3. Authorization epoch (u64), visibility epoch (u64), root tree digest (32).
4. Inventory count (u32), then each entry: kind (one byte), digest (32), full
   decoded object length (u64).
5. Limits: batch objects, response bytes, chunk bytes, in-flight batches,
   inventory objects (each u32), snapshot decoded bytes (u64).
6. Authorized-at (u64), exclusive expiry (u64), maximum cache TTL (u32).

A per-range cache key is SHA-256 of UTF-8 `heddle-object-cache-v1`, zero byte,
authority binding (32), kind (one byte), object digest (32), UTF-8 `identity`,
zero byte, offset (u64), length (u32). This commits to the exact representation
and byte range. Cache chunks individually; never cache a batch envelope under
one object's key. Cache lifetimes remain bounded by the snapshot expiry even
though that expiry is committed in the key.

RPC transports use the same protobuf bodies, request-proof semantics, canonical
bindings, response checks, errors and cache keys. HTTP adapters must preserve
those exact semantics and private cache scope; this slice adds no unauthenticated
object URL or separate HTTP endpoint. Golden JSON, protobuf, authority and cache
key vectors live in `tests/fixtures/immutable-objects-v1.json` and round-trip in
Rust and TypeScript. Regenerate with `npm run build` then
`node tools/generate-immutable-object-vectors.mjs`.

## Failure mapping and cost

Map malformed IDs/snapshots and invalid limits to INVALID_ARGUMENT; binding or
principal mismatch to PERMISSION_DENIED with hidden existence. Missing and
withheld IDs have the same NOT_FOUND failure, without distinguishing inventory
absence from storage absence. Expiry requires reopening (FAILED_PRECONDITION).
Corruption, wrong codec and discontinuous responses fail verification; never
install or silently fall back. Existing transport typed-failure vocabulary is
used without adding a parallel error mechanism.

Cost verdict: this slice adds bounded schema/validation and hashing only. No
new revocation service, storage index, cache runtime, proof tree, compression,
background task, lock or asynchronous future is introduced. Inventory validation
and binding hashing are linear in at most 4,096 entries. A wire preflight adds
one pass over the capped envelope without constructing decoded messages to prevent repeated-empty-
message allocation amplification; it reuses the existing protobuf readers. Membership uses bounded
in-memory lookup; native conformance remains the existing verifier. Performance
claims for imports or clone latency require implementation measurements in
consumers; these contract fixtures provide wire sizes, not clone benchmarks.
