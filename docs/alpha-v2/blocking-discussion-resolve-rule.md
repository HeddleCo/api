# Blocking discussion resolution

API contract for [api#284](https://github.com/HeddleCo/api/issues/284) and
[weft#2443](https://github.com/HeddleCo/weft/issues/2443). The owner chose
`ANY_WRITER` as the default. This change supplies transport and display contracts;
weft enforcement and tapestry presentation follow separately.

`SpoolSettings.blocking_discussion_resolve_rule` is a delegated setting beside
`hold_lifecycle` and the other landing settings. `ReviseSpool` requires resource
administrator authority and replaces complete settings under the spool version
CAS. `UNSPECIFIED` removes the local override: walk to the nearest specified
ancestor, with `ANY_WRITER` as the root fallback. A child can set any explicit
rule. Existing spools with no setting keep today's behavior.

`SignedSpoolPolicy` is deliberately narrower: owner-signed key revocations and
the standing `max_audience` ceiling, computed as a minimum over ancestry. This
discussion rule follows the existing delegated HOLD lifecycle rather than that
owner-gated ceiling. Adding it to signed policy would alter the canonical format
and verifier-owned merge table for a setting that needs neither.

All permitted actors still need ordinary write access:

| Effective rule | Blocking resolve, reopen, and blocking → non-blocking |
| --- | --- |
| `ANY_WRITER` | Any authorized writer |
| `OPENER_OR_ADMIN` | Opener's person or an authorized spool administrator |
| `OPENER_ONLY` | Opener's person; administrators have no exception |

Non-blocking discussions retain ordinary writer behavior. An agent acts as its
person for opener comparison and administrator authority, subject to every
existing agent ceiling. Implementations must reject unknown rule values rather
than silently widening permission.

`DiscussionRecord.actions` uses the existing availability conventions:
`implemented`, `authorized`, `Requirement.explanation` for display reasons,
and `observed_versions` for concurrency prerequisites. Its typed discussion
action avoids inventing a new mutation route. Missing entries mean unknown;
an action is actionable only when implemented, authorized, and free of unmet
requirements. A denied resolution can explain "Only the opener or an
administrator can resolve this blocking discussion". Reopen and blocking
changes have independent entries. There is currently no blocking-change RPC
or signed operation variant; that entry remains unimplemented until supported.
Advice is caller-specific at the observed version and never replaces admission
checks. It must be refreshed after relevant policy, authority, or state changes.

## Resolution provenance

Resolution is signed twice for different purposes: the RPC uses request proof
of possession, and `ResolveDiscussionRequest.signed_operation` carries the
original portable author-signed canonical resolution. Weft checks the request
fields against that original in `collaboration_v2.rs`; the TypeScript runtime's
canonical `resolve` body contains only `kind` and `resolution`.

`DiscussionResolutionRecord.administrator_override` is **server-derived at
admission**, outside both inputs. It is true exactly when the discussion was
blocking, the effective rule was `OPENER_OR_ADMIN`, the verified original actor's
person differed from the opener's person, and that actor was admitted as an
authorized spool administrator within its agent ceilings. An administrator
resolving their own discussion is not an override. `ANY_WRITER` and non-blocking
resolutions do not count as overrides.

Persist the effective rule and marker with the exact original causal operation
ID and verified actor IDs. Do not recompute past markers when settings or grants
change, and do not treat the courier as the resolver. Discussion projections
include current resolution metadata; `include_history` also returns prior
resolutions retained after reopening. Concurrent resolutions remain distinct.

`LandingRecord.blocking_discussion_resolutions` snapshots the same admission
metadata for resolutions considered at landing, subject to the originals'
visibility gates. It is auxiliary display metadata outside the executor-signed
landing body. The author-signed collaboration format, executor-signed landing
format, owner-signed policy, and verifier contracts remain unchanged. No
capability-verifier Rust/WASM slice is needed for this API projection change.
These derived records are not offline-verifiable authorization proofs. Absent
metadata from an older server means unknown, not "no override".

The shared Rust/TypeScript wire fixture covers all rule codes, an unknown code,
denied and unsupported action reasons, original actor/operation attribution,
the same override in discussion and landing views, and older-reader behavior.
The existing canonical collaboration vectors continue to check signed bytes.
Enforcement tests for the actor/rule matrix belong to the weft implementation.
