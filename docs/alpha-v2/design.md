**Proposed alpha v2 contract**

This proposal follows the user's confirmed model: one user-rooted authority chain; Heddle devices own private data and execute local work; Tapestry combines a Thread across sources and directs local actions to a checkout; Weft provides explicitly selected persistence and hosted coordination. It is a design recommendation, not an implemented contract.

The user additionally confirmed that published work is independent of Heddle device availability: Tapestry talks directly to Weft to review, approve and land a published Thread when Weft has the required source and evidence. Heddle is not a proxy for those calls. Tapestry separately contacts owned devices for local-only Thread data and physical checkout operations. A shared schema means each endpoint implements the operations it owns using its stores and reusable domain libraries; it does not imply forwarding through a Heddle process.

The [preliminary review](review.md) contains source evidence and pinned revisions. The [surface map](v1-disposition.csv) covers all 184 existing RPCs. That mapping alone is insufficient: v2 must also describe capabilities that the current proto lacks.

**Resource and identity model**

Use one stable spool identity, one stable Thread identity, exact immutable source identities, and separate device/checkout identities. Names and paths are selectors or presentation. A Thread created offline must retain its identity when first published, renamed, cloned, or observed through a second device. Evaluate client-generated IDs and admission rules explicitly rather than continuing to equate a local thread name with a hosted server-assigned identity.

Keep StateId, logical ChangeId, and Git object ID distinct; the current API already makes that distinction usefully. Replace strings that accept several incompatible meanings with typed revision selectors. Resolve mutable selectors once per read/action and return the exact selected revisions.

**Thread identity option: hash the immutable creation record**

In response to the user's question about deterministic Thread IDs, a suitable candidate is a typed BLAKE3 hash of a canonically encoded `ThreadGenesis`: spool identity, creator root identity, initial parent Thread identity, initial base revision, initial name, initial intent hash, and a creation-operation identity. This follows Heddle's existing pattern of hashing canonical, typed durable objects. The exact schema and encoding remain proposed.

The creation-operation identity is generated and persisted once when the create command is formed. Retries and replicas reuse the same genesis and therefore compute the same Thread ID. Separate starts with identical parent/name/intent have distinct creation identities and remain separate attempts. Omitting that distinction would intentionally make identical creation inputs converge to one Thread; this should only be selected if such automatic coalescing is desired.

Keep the genesis immutable. Renames, intent revisions, parent changes and source-tip advancement are later records referring to the original Thread ID. Hashing the current mutable fields would change the identity and break the combined replica view. Hash the canonical genesis payload; carry signatures/endorsements separately so later authorization evidence does not rename the Thread. A content hash establishes record integrity, while signature and capability verification establish authority.

A Thread owns its durable intent, source lineage, parent/child relationships, captures and decisions. A checkout owns a device-local working materialization and writer state. A run owns agent activity and attribution. Model these separately, then compose them in reads. Replace paired relationship-name/ID arrays with relationship objects.

The combined Tapestry view can deduplicate identical immutable objects and show publication/availability by source. It must retain different working changes and divergent tips. An observation from the most recently contacted device is not automatically the authoritative winner. Each action names its execution target; selecting a combined Thread does not authorize execution on every copy.

**Authority and connectivity**

Define a portable attachment from the user's root to a browser/device key or capability. Verification needs a trusted root anchor, the attachment/delegation and relevant root transitions, the permitted operation/resource scope, and proof of the caller's possession. It must not need a Weft account lookup for local-device access. Heddle's current independently minted device Biscuit can only satisfy that model once its root attachment is verifiable; local minting alone does not provide it.

Keep human passkey attestation and Ed25519 Biscuit signing as explicit roles. A valid passkey ceremony can authorize a binding; it does not make arbitrary browser and Heddle keys cryptographically related by itself. Choose one canonical attachment representation and a shared verifier rather than accumulating another compatibility envelope.

Bind device endpoint advertisements to the same authority model. Pairing/discovery should allow a browser to retain the endpoint identity and sufficient proof to reconnect. Weft may assist discovery, but its availability must not be required to authorize an already-paired connection. Validate this through the complete connection path: relay admission expiry/renewal and a Tapestry server loader that insists on WhoAmI could otherwise reintroduce a Weft dependency outside the application RPC.

Root/device revocations and root transitions should be signed, distributable facts that peers can exchange. The contract must distinguish the latest known authority state from a claim of globally current state. Define the freshness requirement per operation and the behavior after proof expiry. An unseen revocation cannot take effect instantaneously on a disconnected verifier.

For hosted operations, Weft checks the account/resource binding and relevant authority under hosted policy. Preserve owner-governed purge and delayed recovery/rotation as distinct operations. Existing owner/purge proof types are not automatically device-enrollment certificates. Keyless and deferred-human onboarding must remain explicit cases; they do not silently acquire offline owner authority.

**Shared reads**

For a published Thread, the hosted Thread view comes directly from Weft. Device views are independently available additions showing unpublished captures, working state, runs and selected private detail. A wholly local Thread can be opened directly on its owning device without first obtaining a hosted view. Combining views preserves which exact revisions and observations each source supplied.

Expose a small set of domain views with bounded requested sections. Final method names can follow once the message shapes are agreed.

| View | Initial useful response | Deferred or paged detail |
| --- | --- | --- |
| Account/spool workspace | Spool/thread summaries, attention, relevant identities, source availability, device checkouts, operation health | More spools/threads, full policy/membership detail, historical activity |
| Thread | Intent/version, exact tip/base, capture previews, checkout/run summaries, blockers/conflicts, review/readiness summary, permitted actions | Capture history, full discussions, timeline windows, detailed proof chains |
| Revision/review | Exact compared revisions, change summary, first diff window, relevant context/provenance, decisions and evidence | Further files/hunks, blame, all signatures and diagnostic signals |
| Source content | Requested tree expansions and blob/diff windows at pinned revisions | Further paths, lines, byte ranges and depth |
| Timeline/private detail | Requested typed timeline window or selected private artifact, source and completeness | Older steps, raw retained material and artifact byte ranges |

These views share component types and underlying domain implementations. Heddle, agents and Tapestry can all request them. They are not copies of individual Tapestry page layouts.

**Core service boundaries under discussion**

| Proposed service | Responsibility | Weft endpoint | Heddle endpoint |
| --- | --- | --- | --- |
| ThreadService | Bounded complete Thread decision view, snapshot/update continuity, intent/lifecycle and Thread decisions | Operates on hosted revisions and records; can approve and land independently | Operates on local revisions and records; preserves local-first behavior |
| CheckoutService | Working materialization, capture, filesystem-affecting actions and checkout/run state | No user's physical checkout | Operates on the explicitly selected device checkout |
| ContentService | Revision-pinned trees, blobs, diff/provenance windows and bounded content streams | Serves content held by Weft | Serves content held on the device, including authorized unpublished content |
| SyncService | Transfers selected immutable content and durable records; reports target acceptance | Admits publication and serves hosted replication | Publishes or pulls selected records/content |

These are four central workflow services, not a proposal to fit every capability into four services. Identity/account binding, spool governance, cross-thread collaboration/context, discovery/attention and background operations retain their own lifecycles. ThreadService composes the relevant read projections without making clients invoke each supporting service to draw a Thread. The endpoint should build that projection from its stores and internal domain APIs, not reproduce the client's network fan-out internally.

**Whole-API coverage and ownership**

The user explicitly reaffirmed that this review encompasses spool settings, administration, sharing and invitations, filtered Thread collections, all context/discussions, semantic analysis, identity and the remaining product surface. The four core services above are not a complete service inventory. The following domains must each have explicit read, mutation, authorization and endpoint coverage in the final v2 contract. Candidate grouping is not a frozen count of protobuf services.

| Domain / candidate service | Required scope | Execution and authority boundary |
| --- | --- | --- |
| IdentityService | Account/profile/handle lifecycle, signup invitations, passkeys, root attachments, device enrollment, sessions, agent/service identities, revocation and recovery | User-root proofs remain verifiable by owned devices; hosted account registration and account binding are Weft operations |
| SpoolService | Spool lifecycle and hierarchy, settings, visibility, members, resource invitations/grants, approval groups and policy configuration, provider links and administration views | Weft enforces hosted resource governance; local configuration and applicable signed policies are explicit device capabilities |
| OwnerAuthorizationService | Ownership transfers, owner key transitions, recovery and owner-gated destructive operations | Retain explicit owner proof/ceremony semantics; ordinary membership or write access is insufficient |
| ThreadService | Filtered/paged Thread collections, detail/update views, intent and relationships, lifecycle, review/approval/revocation, landing, effective sharing policy | Each endpoint operates on its held records and exact revisions; hosted decisions are independent of user checkouts |
| CollaborationService | Discussions and turns, resolution/reopening, references and anchors, durable context creation/revision/supersession, history and context extraction | Context and discussions can outlive or span Threads and attach to source entities; Thread and spool reads compose relevant records without owning a second copy |
| AnalysisService | Semantic indexes/symbol queries, semantic diffs and hot spots, provenance interpretation, context suggestions and review analysis | Read results against exact inputs; run analysis at an authorized endpoint with required content, reporting coverage, analyzer version, freshness and failure |
| ContentService | Trees, source blobs, diffs, provenance/artifact windows and bounded byte streams | Each source serves its available authorized content; artifact delivery does not implicitly run analysis |
| CheckoutService and device execution capabilities | Materialization, capture, working/conflict/recovery actions, agent runs, control/permission decisions, runtime profile and broker operations | Explicit device/checkout/run targets and local writer coordination; final split between checkout and execution services remains to be decided |
| SyncService | Ongoing policy-governed publication, pull, resumable transfer, confidential persistence where selected, publication receipts | Source disclosure authority and destination acceptance are both required |
| Workspace/Search projections | Account/spool navigation, cross-spool worklists, bookmarks, discovery, text and semantic search | Bound scopes and source coverage; combine private device results in the browser without copying their contents to hosted search |
| Attention and Notification domains | Actionable work, personal feed interactions, delivery/subscription preferences and read state | Derived workflow attention remains distinct from per-user delivery state, even if observation machinery is shared |
| OperationService and integrations | Typed long-running import, analysis and provider synchronization jobs; progress, results, retries, cancellation and remote-link health | One common job lifecycle, with domain-specific inputs/results and endpoint capabilities; starting a job does not bypass source disclosure policy |

Signup invitations belong to identity onboarding; spool invitations grant resource access. Thread publication policy selects what a source shares and where. Spool access policy decides who can access hosted material, and review policy governs admission/landing. Their effective behavior must be composed explicitly: a Thread setting cannot bypass resource restrictions or create consent to publish another principal's private data. Putting their summaries in one settings response does not collapse their authorization rules.

Collections need the same aggregation discipline as Thread detail. A Thread query should support independent dimensions for lifecycle, review/readiness, ownership/participation, attention for the caller, and publication/source availability. In-flight work and work needing approval overlap; do not force them into a single mutually exclusive status enum. Return bounded, useful rows with exact tips, intent summaries, readiness/blocker summaries and relevant activity so clients do not fetch each Thread's history to draw a list. Counts/facets need a defined authorized query scope and freshness; page and update cursors remain explicit.

Candidate initial reads are a workspace view, a spool view and a Thread view, with requested bounded sections and update continuity. A spool administration view can include settings, effective policy, and the first pages of members/invitations in one response; larger directories retain real pagination. This is read composition across domains, not a requirement that all mutations live in a generic view service.

Analysis results must distinguish absent, pending, stale, partial, failed and complete for the pinned inputs. Expensive computation uses the common operation lifecycle and can update an already-open view. Displaying private device content must not silently upload it for hosted semantic indexing or provider analysis; computation location and permitted disclosure need to be explicit capabilities/policy.

The Thread is the workflow identity and decision context. The spool remains the sharing/authorization resource, immutable revisions identify exactly what was reviewed, and the checkout identifies where working state can be changed. These concepts do not collapse into one giant mutable Thread record or one unrestricted Execute operation.

Example: Weft holds published revision S0, while a connected device has a not-yet-published successor S1. The combined Thread can display both. A hosted approval/land of S0 covers S0. The Thread's configured policy may independently publish S1, which requires its own applicable review/eligibility evaluation. Capturing on a device returns a local revision; publication is a distinct hosted acceptance step even when automatic. A later local sync of a hosted landing must respect local checkout safety and does not automatically overwrite working edits.

Initial view reads should optionally continue as update streams. Define a snapshot boundary and cursor so reconnecting neither loses events between snapshot and subscription nor silently duplicates effects. Specify cursor/filter/source binding, authority changes, tombstones, ordering, cancellation and resync-required responses. Different sources have separate cursors; the combined UI does not get a global transaction across devices and Weft.

Use consistent paging throughout, including per-thread history inside a collection. A limit without continuation is insufficient. Return explicit completeness and computation status where disclosure is authorized. Keep missing and unauthorized resources indistinguishable when required; do not turn detailed partial-result status into an existence leak. Unknown, unavailable and not requested must not be rendered as empty or passing.

A useful performance target is one initial application view request per participating endpoint, excluding authentication/discovery, followed by deliberate expansion or paging. A page drawing from three devices and Weft may therefore need four source requests. Moving the private-data join to Weft to make that number one would violate the ownership model.

**Local and hosted actions**

V2 needs typed device operations covering the actual everyday workflow, including their reverse and recovery paths:

| Capability family | Required operations/observations |
| --- | --- |
| Workspace/source | Status, selected capture, working diff, checkout selection and materialization status |
| Threads | Start/fan-out, update or propose intent, refresh, readiness, land, abandon/supersede where supported |
| Conflicts/recovery | Inspect conflict versions/candidates, propose or apply a resolution, continue, undo and recover |
| Timeline | Read, seek, fork and recover materialization; retain navigation/materialization availability |
| Collaboration | Open/append/resolve/reopen, explicit context extraction, context revise/supersede, anchor/conflict handling |
| Review/policy | Record opinion, attest evidence, approve/revoke, inspect requirements and signed delegation |
| Agent execution | Supported control/steering, permission decisions, acknowledgement and outcome, writer/run status |
| Runtime/private state | Profile metadata/lifecycle, authorized broker execution, selected forensic reads and explicit publication policy |

These are capability requirements, not a proposal for an unrestricted Execute RPC. Keep typed semantic operations and declarative authorization at the granularity needed to enforce each operation. Reuse a common action context/result where it removes repeated framing, but do not hide different effects or permissions inside an untyped command string.

Local commands invoke the reusable Heddle implementation. Capture remains the save boundary, including one-shot selection; the browser must not recreate CLI precedence or an independent staging model. A remote browser issues an operation against a named checkout with required expected versions. Heddle remains responsible for writer coordination and filesystem safety.

Hosted decisions such as approval and landing instead target the hosted Thread and exact relevant source/target revisions directly on Weft. They do not require a checkout ID or an online Heddle device when their required material is already hosted. Offline local landing remains a supported domain operation on Heddle under the applicable signed policy; later publication has its own acceptance result.

Mutations should carry a stable operation identity and the relevant expected source, target, conflict and policy versions. Return the applied result and resulting view revision/patch. A lost reply produces an unknown outcome that the client can reconcile by operation identity; a retry must not duplicate a capture, discussion turn or landing. Maintain exact-payload checks when an idempotency key is reused.

Human-signable actions freeze target, canonical payload, scope, expiry and idempotency identity before approval. The capable client signs those same bytes, and the destination verifies them. A readiness preview can ride in a read view, but a mutation must revalidate its own preconditions. Distinguish a locally completed action from acceptance of its later publication by Weft.

**Replication, confidential persistence and background work**

Preserve Push/Pull's useful foundation rather than replacing it with browser reads: streaming bytes, bounded buffers, resumability, partial fetch, content hashes, exact refs, owner genesis and provider-plan verification. Simplify the opening exchange so selector resolution, current metadata and advertised refs do not require repeated preliminary queries. Keep a separate exact-plan consent exchange where it is semantically necessary.

Use facet-aware transfer planning for source, collaboration, scrubbed timeline and confidential objects. Sharing a byte-transfer mechanism does not give these facets the same projection, reachability, retention, encryption or authorization rules. Normal source publication must not sweep raw transcripts or runtime secrets into a pack because they share storage.

Persistence policy must make destination and included private data classes explicit. Viewing data through the user's browser is independent of publication. Retaining raw forensic material locally is also distinct from disclosure/persistence. A configured opt-in can govern subsequent matching transfers; the API need not force repeated confirmation for every object.

The user confirmed that Thread policy governs ongoing synchronization. Enabling sharing configures a persistent policy for subsequent captures and shared discussion/evidence, rather than requiring explicit publication of each new revision. The policy identifies the selected destination and included data, and each source applies it only within the authority to publish that source's data. It cannot manufacture access or override separate forensic/runtime opt-in requirements.

Setting or revising sharing policy belongs to the Thread domain. SyncService performs the authorized replication and returns receipts naming the accepted revision/records and relevant policy version. Local action completion and hosted acceptance remain separate observations: the client can show saved locally, pending publication, accepted remotely or rejected remotely. Weft's Thread stream advances when publication is accepted; connecting the browser is not required to drive the device's configured synchronization.

Keep one common durable background-operation lifecycle with typed inputs/results, progress, honest cancellation support and resumable observation. Import, provider sync and review analysis can use it. A planned ability to cancel or submit atomically is not advertised as available until the execution path exists.

Keep account and provider administration complete: signup/invites, handles, passkeys, devices, sessions, root recovery, grants and ownership, spool hierarchy, external Git links, search, bookmarks and notification preferences. They need not inflate the critical Thread read. Attention is a domain projection; notification delivery and per-user read state remain separate even if they share update-stream machinery.

**DX/AX assessment: additional requirements before freezing the contract**

The domain/service map is a good foundation, but it does not establish that v2 is the cleanest developer or agent experience. Evaluate a single interaction model across the complete surface. The current contract already declares effects, retries, signing, authorization targets and deployment targets in contract.proto, and supplies typed failures in errors.proto. Preserve those strengths and make them executable across client bindings, endpoint negotiation, tool adapters and conformance checks.

- **Discover, observe, act and reconcile consistently.** Endpoint negotiation reports protocol support, implemented capabilities and limits. Scope-specific views report relevant action requirements and blockers. Keep implemented capability, caller authority, current readiness and local content availability separate. Advertised readiness is an observation, not authorization or a promise a later mutation will pass. Discovery should be available during connection setup without a separate mandatory preflight for every operation.
- **Keep product verbs consistent across human and agent surfaces.** Use the same start, capture, discuss, ready, land and recover semantics in CLI, SDK and agent adapters. Harness integrations handle checkout and writer-lifecycle plumbing ambiently, as specified by #1718. A normal agent task should not require the model to orchestrate lease heartbeats. Declared fan-out creates explicit child Threads. An agent's intent amendment remains a proposal until principal approval where required.
- **Use bounded decision views.** Select typed sections and page/byte windows, with compact summaries, source references and completeness for each section. Source blobs, full history and transcripts are separately expandable. A view can record the precise intent/context/evidence observed at a work boundary for later attribution. Compact agent output must retain blockers, missing coverage, and exact targets; a model-specific token limit is not a reliable wire-size budget.
- **Use one coherent mutation result convention with typed domain payloads.** Include the stable operation identity, exact applied inputs/revisions, resulting revision or applicable view update, and an explicit result or handle to running work. A timeout/lost response leaves an unknown outcome, recoverable by the original operation identity. Deduplication scope, retention and expiry must be specified; do not promise indefinite exactly-once execution. Distinguish operation completion, human authorization still needed, and separate publication receipts.
- **Make recovery executable without prose parsing.** Structured outcomes identify stale versions, writer contention, missing evidence, policy denial, human verification, pending analysis and cursor resynchronization. Give typed requirements and permitted recovery choices where disclosure is authorized. Recovery advice is data, not authority to execute another action. Reuse the existing failure channel rather than inventing parallel boolean/error conventions for each service.
- **Preserve exact human-signable actions.** Freeze payload, scope, revisions, policy assumptions, expiry and operation identity before a human signs. The capable client reviews and signs the same request the endpoint verifies; it must not re-resolve a mutable Thread tip after approval. Preview is useful when human deliberation needs it, but must not become a universal extra RPC for ordinary mutations.
- **Give long-running work and subscriptions shared lifecycle rules.** Snapshot/update continuity, reconnection, source-bound cursors, explicit resync, deadlines, cancellation semantics and progress all use common primitives. A pollable observation form can serve agents that cannot hold streams. Expensive analysis can populate the view asynchronously with honest freshness/coverage rather than blocking the first useful response.
- **Ship transport-neutral types with usable companion clients.** The current Rust package explicitly does not generate transport clients/servers. V2 should supply reusable typed Rust/TypeScript clients or companion packages for supported transports, with shared signing, routing, session management, bounded retries and cursor handling. Keep key possession behind the client's signer/broker boundary. Avoid making each consumer recreate those protocols or silently choose a different device/authority for a mutation.
- **Generate a bounded agent tool surface from the same contracts.** Use curated, task-relevant adapters over canonical typed operations, with progressive tool discovery instead of presenting every RPC for every task. Generate schemas and reuse effect, retry, signature and capability metadata. There is no separately authored agent workflow or untyped universal Execute entry point. Agent-readable identifiers and structured output must round-trip losslessly to the binary contract.
- **Define evolution beyond protobuf field addition.** Negotiate endpoint support and version canonical signed/hashed records explicitly. Define how older readers preserve opaque durable bytes and handle unknown values. Unknown critical actions or policy meanings must be rejected; an unfamiliar optional display field need not prevent a read. Pin action/signing semantics so decode/re-encode through an older client cannot silently change approved work.

The user decided that separate checkouts may contribute concurrently to one Thread; simultaneous writers to the same checkout are unsupported. Writer ownership is checkout-local. The Thread replicates a causal operation graph, preserving independent captures and discussion turns. Source integration is explicit, and hosted landing remains independent of user devices. Child Threads represent work decomposition rather than mandatory concurrency isolation.

Proposed acceptance examples should be executable end-to-end contract scenarios, not only message round trips: open a useful Thread/worklist without per-row reads; start/capture/recover using the same verbs through human and agent clients; reconnect after an ambiguous capture reply without repeating its effect; receive a structured stale-revision or authority result; complete a human-signable action without changing its payload; hand off work with pinned intent/context and explicit writer behavior; continue private work with Weft unavailable; and accept/reject later publication without misreporting local completion. Measure client round trips, bytes, first useful response, endpoint work, and agent-visible tool/output size. Runtime-supported capabilities need handler and behavioral evidence, beyond descriptor maturity labels.

**Cutover and proof**

A new alpha package generation is reasonable because authority attachment, identity, read composition and endpoint coverage change together. Preserve deterministic signing and explicit schema-version rejection. Coordinate Heddle, Tapestry, Weft and generated package releases. Protobuf cutover and #1718's durable storage-format cutover are separate compatibility dimensions; one does not automatically solve the other.

Before implementing, turn the following into the acceptance matrix:

- With Weft unavailable, an already-paired browser opens an owned Heddle device, reads private history, performs a selected local action and verifies its result. Exercise the real relay/discovery/application path, not just the capability verifier.
- A combined Thread retains distinct checkouts/tips across devices and Weft; a command affects only its specified checkout. A stale source/target/conflict version is rejected without changing another replica.
- A populated Thread/review view requires a bounded number of initial calls independent of visible row count. Measure cold and warm connection setup, streams, bytes, server queries/object reads and first useful render. Large histories continue through real cursors.
- Snapshot-to-update transition and reconnect preserve all observable updates; an expired cursor explicitly requires resync. Unavailable data never becomes an empty-success claim.
- A disconnected/lost-reply retry does not duplicate a mutation. A later hosted rejection preserves the completed local action and its history while marking publication accurately.
- Private artifacts remain off Weft, Tapestry server loaders and their logs until an explicit applicable publication policy permits persistence. The browser's own selected data view remains usable.
- Wrong-root, wrong-device, narrowed-capability, stale-proof and relevant revocation cases are rejected by actual endpoints. Review opinion, ordinary write permission and owner purge authority remain distinguishable.
- Every advertised method/capability has a real handler and cross-client conformance evidence. Negative cases prove that limits, authorization and call-count checks fail when the protected property is removed.

No runtime tests or performance benchmarks were run for this review. The current call observations are static source evidence, and the performance budgets above are proposed acceptance criteria. Implementation and migration work remain future work.


**Accepted cutover decision (2026-09-07):** the user explicitly chose a clean
alpha cutover with no migration bridges. The native v2 RPC surface and
streaming lifecycle are specified in [streams.md](streams.md). Earlier inventory
dispositions describe functionality to preserve, not legacy RPC wrappers to ship.

### Account roots and credential results

Account rooting state belongs to the stable principal UUID, independently of
spool membership and ownership. `OwnershipService` bootstraps and transitions
that account root with typed signed records. Rotation, recovery, and recovery
policy changes retain explicit intent; their signed predecessor hash and
sequence provide the concurrency condition. A spool is required only for
resource authorization, lineage, and transfer.

All three onboarding tiers remain supported: self-rooted, server-rooted, and
agent-rooted. The latter is an unclaimed human account with an empty independent
root slot; an agent holds a separate attenuated credential. `AuthenticationResponse`
returns a `CredentialResult`: the accepted client-owned credential registration
or an issued Biscuit, with one session result. Keyed clients mint their own
Biscuits; Weft attaches the proved key and enforces its account/credential
ceiling. Registration returns the credential reference, exact subject, PoP key,
class, and original owner proofs when established. Anonymous/server-rooted
issuance returns raw serialized bearer bytes. Those exact bytes also populate
`CallContext.bearer_capability`; base64 is confined to text storage/configuration. Account views
never return the bearer. Promoting an account does not upgrade an existing agent
credential or erase its attenuation. Tier metadata never authorizes an operation.

The account/credential types describe the complete intended contract; endpoint
discovery must still advertise only implemented ceremonies. In particular, the
canonical identity model distinguishes shipped passkey/agent flows from target
password onboarding and per-user server custody.

Passkey registration uses two RPCs. `BeginRegistration` accepts the one device
public key and either an invitation reservation or verified-email reservation
for signup. An authenticated independent root can instead enroll another
device on its account; a claimable agent credential can begin human claim.
Anonymous signup keeps the anonymous account UUID. The response fixes the
account UUID, relying party, passkey challenge, device-binding challenge and
owner-binding nonce together, so preparing the completion needs no additional
identity lookup or challenge call.

`CompleteRegistration` carries the passkey creation and a follow-up assertion
by that passkey binding the device key. The enrolling Ed25519 key signs the
exact completion in `CallContext`, including both passkey proofs and owner
records; an existing bearer cannot substitute for that proof. New signup
carries typed `OwnerRegistration` evidence. Claim appends the signed
`CLAIM_DEFERRED_HUMAN` transition to the existing deferred root. Device
enrollment does not implicitly replace owner roots or promote rooting tiers.
Owner records retain their original canonical signature domains; ordinary
spool access continues to use the Biscuit capability.

Completion must commit challenge consumption, account/device/owner changes,
session and retry receipt together. Failed proof verification or persistence
must leave the admitted ceremony retryable. Receipt replay still checks current
credential authority, and secret owner-bundle enrichment is never cached as
public retry metadata.


Account provisioning and credential issuance are separate operations.
`ProvisionAccount` creates or recovers the agent's key-bound unclaimed human
account and returns its attenuated agent credential plus the configured claim
origin. It cannot create an independent human root. `PutDelegation` manages a
device/agent/service delegation; `IssueDelegationCredential` explicitly returns
credential material under that delegation's scope and expiry ceiling.
`CreateAnonymousSession` retains anonymous identity continuity and rotates its
separate continuity secret under the existing anti-abuse gate. There is no
generic principal factory or caller-selected rooting tier.

### Signup admission before device establishment

A held invitation code goes directly to `RedeemSignupInvitation`; its typed,
expiring reservation is the `BeginRegistration.invitation_reservation` input.
Reservation does not create an account or permanently consume the invitation.
Retry requires the same operation and secret, and cannot renew an expired or
consumed reservation. This public pre-device ceremony has no request-key proof;
code possession and the shared invitation peer budget are its boundary.

`ResolveSignupInvitation` is an optional invitation-page read. It carries typed
availability, inviter display context and bound email so rendering that page
needs no profile lookups. Coverage and invitation validity are separate concepts.

Email signup keeps delivery and mailbox possession separate. The dedicated,
independently rooted signup-mailer service account calls BeginEmailVerification
with the email, chosen handle and optional held invitation code. Its existing
bearer-only credential remains supported. Weft returns a challenge and delivery
proof to that trusted delivery service; Tapestry sends the proof to the mailbox
and excludes it from the browser's begin response. Without a code, the ceremony
uses an invitation already bound to the requested email. No email binding or
account creation occurs merely because delivery was requested.

CompleteEmailVerification proves the delivered challenge without an account
credential. It atomically consumes the challenge, binds the selected invitation
if necessary, creates a short-lived VerifiedEmailReservation and records its
public receipt. The reservation carries the bound handle and email and feeds
BeginRegistration directly. Retries require the same request, current authority
for privileged delivery, and still-current admission for completion; neither
expired proof nor revoked/consumed invitation is revived by a cached receipt.
Delivery proofs remain outside public deduplication receipts. This replaces the
former email-bootstrap Biscuit and separate invitation-binding RPC.
