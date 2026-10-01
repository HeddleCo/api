# Operation, landing assessment, and default Thread observations

Additive v2 contract for [api#287](https://github.com/HeddleCo/api/issues/287),
[weft#2476](https://github.com/HeddleCo/weft/issues/2476),
[weft#2477](https://github.com/HeddleCo/weft/issues/2477), and
[weft#2478](https://github.com/HeddleCo/weft/issues/2478), requested by
[tapestry#587](https://github.com/HeddleCo/tapestry/issues/587). This bundle defines
transport and presentation semantics; persistence, population, and enforcement
belong to the corresponding weft work. The package version and signed formats
are unchanged.

## Operation attempts

`OperationRecord.subject = 15` contains an extensible `OperationSubject` oneof.
Its first case, `import`, is an `ImportOperationSubject`: `source_url` is the
credential-free source URL, with optional provider identity represented by the
pair `provider` and `provider_repository_id` (both populated or both empty).
The provider identifier follows `ProviderConnection.provider`; the repository
identifier follows `ProviderRepository.provider_repository_id`. It identifies
the source actually admitted for this attempt, not the destination spool's
current name or a subsequently edited remote. An import supplies a nonempty
source URL, the provider pair, or both. Never expose URL userinfo, credential
query parameters, OAuth tokens, connection secrets, or source identities hidden
from this caller. Omit unavailable details, or the whole subject if neither URL
nor provider identity is visible; absence or an unknown oneof
case means unknown. Future operation kinds can add cases without changing the
import case.

`created_at = 16`, `started_at = 17`, and `finished_at = 18` are
`google.protobuf.Timestamp`, as elsewhere in v2. Creation is admission of the
attempt; start is its first execution, retained across pause/resume; finish is
its terminal completion, failure, or cancellation. Newly queued attempts have
creation only. A canceled queued attempt can have a finish without a start.
When present, creation <= start <= finish (or creation <= finish without start).
Legacy unknown times are omitted, never fabricated from UUIDs or encoded as an
epoch sentinel. Display and ordering may use these times; they never establish
causality, authorization, or a CAS version.

`retry_of = 19` and `superseded_by = 20` use the new `OperationRef { spool, id }`.
They identify the same operation resource as `OperationRecord.ref` and existing
`RecordRef` mutation inputs, without changing those inputs. Retrying a failed
attempt A admits a new attempt B with the same subject and original destination;
B.retry_of points directly to A and A.superseded_by points directly to B. Links
are recorded atomically at retry admission under A's CAS, not only after B
succeeds. Replaying the same client operation ID does not create another retry.
Further retries form a chain A -> B -> C, never a cycle or self-link. A failed
attempt can have at most one admitted direct replacement. Persisting the
supersession projection changes its observed version, but preserves A's execution
state, failure, timestamps, and historical result; it does not rewrite A to
COMPLETED or clear the failure.

A superseded failure is **historical, not a live failure**: clients may fold it
under the replacement immediately, even while that replacement is queued or
later fails. The unsuperseded end of the chain is the current attempt. Each
attempt retains its own actions; a historical failure must not advertise another
retry. Links obey the operation's visibility gates. A hidden link is omitted,
so absence from an older or filtered observation means unknown, not proof that
the failure is live. Do not infer supersession by name, time, UUID ordering, or a
later success on the same spool.

## Missing landing assessments

The API's Thread record projection is `ThreadOverview`; it has no separate
`ThreadRecord` message. `ThreadOverview.landing_assessment_status = 29` sits
beside `landing_assessment`, and `ThreadAlternative.assessment_status = 7` sits
beside each `assessment`. `LandingAssessmentStatus { state, reason }` uses a
single `Requirement` for the reason, following `ActionAvailability`'s typed
requirement and display explanation convention. The state is machine-readable;
never parse `reason.explanation` to infer it. An emitted status has a nonzero
known state and a reason with a known `Requirement.kind` and nonempty explanation.
Its optional subject, policy, policy version, and recovery method have the same
visibility and advisory semantics as existing requirements. Advice never grants
landing authority.

When `ObserveThread.landing_target` was requested and an assessment is absent,
a new producer supplies the corresponding status on the overview and on every
visible alternative without an assessment. No target means no status. An
assessment and its corresponding status are mutually exclusive. A blocked or
ineligible **returned assessment** keeps its own readiness and requirements;
it does not also acquire a missing-result status. For several published heads,
the legacy singular assessment is intentionally absent: the overview reports
MULTIPLE_HEADS, while the per-head assessments in `landing_assessments` and
`alternatives` remain available. Assessed alternatives have no gap status. If
there are no visible published heads, the overview carries the gap and there
are no invented alternatives. When a shared obstruction prevents assessment,
all affected visible alternatives carry its status. On a new checkpoint, replace
or clear stale status together with the associated assessment.

| State | Meaning / typical reason kind |
| --- | --- |
| PENDING | Evaluation is scheduled or running; REFRESH. Only use when work is actually pending. |
| FAILED | Evaluation failed; ANALYSIS or REFRESH. Sanitize internal errors. |
| NOT_ELIGIBLE | Evaluation is not applicable to this source/lifecycle; POLICY. |
| NO_PUBLISHED_HEAD | No caller-visible published source head to assess; PUBLICATION. Never count hidden heads. |
| BASE_UNREADABLE | A comparison base already known to exist by this caller cannot be read; CAPABILITY. |
| UNAVAILABLE | Required source/target material is unavailable to this caller; CAPABILITY or REFRESH. Does not distinguish absent from forbidden. |
| MULTIPLE_HEADS | The singular aggregate is omitted for competing visible published heads; CONFLICT_RESOLUTION. Per-head results still apply. |

UNSPECIFIED (zero), an unknown numeric state, a missing status from an older
server, or a missing reason all mean unknown. Producers must not emit
UNSPECIFIED as an explanation; readers treat it as unknown, never PENDING or
eligible. Missing data is never permission to land.

Existence hiding applies to state **and** reason. A supplied target ID does not
prove the caller knows the target exists. Do not expose a hidden base/target's
identity, name, policy, path, head count, raw error, or existence via explanation,
subject, or recovery advice. BASE_UNREADABLE is permitted only where an earlier
caller-visible projection or other independent read has established the base's
existence. Otherwise use generic UNAVAILABLE, without a hidden reference or a
base-specific explanation. Missing and forbidden targets retain the existing
identical existence-hiding RPC behavior; this status does not turn a concealed
RPC failure into a successful observation that confirms a target exists.

Read-only inspection of weft `origin/integration` at
`bc4ea473f6afd23d55d9cbd40ea835859200b288` informed this vocabulary:
`crates/weft-hosted/src/server/hosted/observation.rs` currently omits evaluations
with no published heads, incomplete readable published sources, or unreadable
target heads/original base (`assessment_target_visible`). It omits the singular
projection for multiple heads while retaining per-head results. Target Thread
authorization happens independently and can fail the RPC. In
`thread_landing_policy.rs`, policy/evidence/conflict/lifecycle failures with typed
requirements already produce blocked assessments; evaluator/storage errors can
fail the RPC. This contract preserves that distinction. PENDING and FAILED
support implementations that return an observation while evaluation is deferred
or has failed; they do not claim today's evaluator runs asynchronously.

## Spool default Thread

`SpoolSettings.default_thread = 10` is a stable `ThreadRef`, returned through
`SpoolOverview.settings = 6` on spool observation. No duplicate top-level field
or extra list request is needed. It is a local setting with no ancestor
inheritance and no name-based fallback. It identifies a Thread in the containing
spool, not a revision; it may have zero or multiple heads. Clients still observe
that Thread to select readable content and must not invent a winning head.

A resource administrator can set or clear it through the existing
`ReviseSpoolRequest.settings` complete-record replacement under
`expected_version`, the containing spool's CAS. Validate a supplied reference
as an existing readable Thread in that spool; wrong-spool references are invalid
and forbidden/absent Threads must have indistinguishable failures. Omission in
a deliberately submitted complete settings record clears the setting. An
observation's omission does not mutate persisted settings; a filtered projection
must not be blindly treated as a complete admin replacement.

On import, weft resolves the source's advertised default branch to the exact
imported Thread and sets this setting as part of the versioned spool update.
Use branch identity, not `main`/`master` name heuristics. If that branch was not
imported or cannot be resolved, leave the default unset; do not choose another
branch. Retry/reimport preserves an existing administrator selection; it must
not silently replace it. A later administrator change follows the usual CAS.

When the selected Thread is deleted or unreadable, omit `default_thread` for
that caller, retaining the stored selection until an explicit administrator
revision. Do not silently replace it with another Thread or expose a tombstone,
hidden ID, or reason that reveals existence. If readability returns, the same
reference can reappear. An unset, deleted, or hidden selection all look absent.

Shared Rust/TypeScript vectors cover import subjects, timestamps, retry chains,
every gap state (including zero and unknown), overview/per-alternative placement,
multi-head singular gaps, settings/CAS/observation propagation, old readers
ignoring additions, and new readers accepting old records. Descriptor tests pin
field types, tags, enum values, and the unchanged signed policy. Server-side
population and caller-visibility enforcement require the weft implementation.
