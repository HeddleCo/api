# People suggestions and live approval groups (alpha.39)

This document is normative. The API package supplies schemas, Rust/TypeScript
validators, pure projection/evaluation helpers and shared conformance vectors.
It does not implement the hosted database, membership query, rate limiter or
landing transaction. Hosts MUST implement and integration-test those boundaries.
The canonical identity/resource model is
[Weft's identity model](https://github.com/HeddleCo/weft/blob/main/docs/IDENTITY_RESOURCE_AUTHORIZATION_MODEL.md).

## Add people suggestions

`IdentityService.SuggestPrincipals(SuggestPrincipalsRequest)` returns
`SuggestPrincipalsResponse.principals`, containing only
`SuggestedPrincipal.{handle, display_name, kind}`. `kind` is `HandleKind`, the
same handle namespace as `ResolveHandles`. IdentityService owns this read
because identity metadata and the exact public directory lookup belong there,
and an unscoped request composes membership across spools. SpoolService owns
spool invitations and policy administration, not a cross-spool directory.

`prefix` is literal text, not a glob, regex or fuzzy query. Normalize to NFC,
then Unicode lowercase; compare the similarly normalized handle and display
name. The prefix MUST contain 2..64 Unicode scalars after normalization and no
leading/trailing whitespace or control characters; both its input and
normalized encoding MUST fit 256 UTF-8 bytes. Return canonical original handle
and display-name bytes. Rows MUST be sorted by UTF-8 handle bytes, deduplicated
by canonical handle and bounded to 20. There is no pagination, total count,
fuzzy matching or directory traversal affordance. Handles are passed directly
to invitation creation; clients MUST NOT resolve them to account IDs.

The authenticated caller and each returned prefix match MUST currently share
at least one spool where the caller is currently authorized to read the MEMBERS
section. MEMBERS read is member-only and requires the existing section audience
and credential/grant checks; RESOURCE_READER or public content read alone is
insufficient. This applies with or without `spool`: a READER who cannot read
MEMBERS on a large spool cannot enumerate its roster through unscoped suggestions.
Effective membership includes only applicable inherited
ancestor grants (`include_descendants` must cover the spool). Public spool read
access without membership is insufficient. When `spool` is populated, both
caller and each prefix candidate MUST be current effective members of that
specific spool. Unknown, deleted, malformed/empty or non-member scopes MUST
return the same `NOT_FOUND / RESOURCE_NOT_FOUND` envelope with field `spool`,
empty resource and no suggestion payload. Check this BEFORE either the
co-member search or the exact public lookup. A publicly readable spool does
not bypass this check, and a caller's membership elsewhere is insufficient.

In either mode, the host MAY additionally return at most ONE current exact
public-handle match to the normalized prefix, with only the same metadata
already disclosed by ResolveHandles. Public display-name matches and partial
public handles outside the co-member scope are forbidden. This exception
never bypasses the populated spool's caller-membership check. Apply the
20-row bound to the complete result including the exception; hosts may omit
an exact hit when the bounded co-member result already fills the response.
Humans without a handle and humans whose handle is hidden from the caller MUST
be excluded before either search path; do not fall back to account UUIDs or
fail the whole search for a co-member with no handle. UUID-shaped handles are
invalid public metadata and are refused, never displayed as handles.
Agents MUST be excluded even if they have grants, match exactly, or delegate
from a qualifying human. Agent delegations never create separate People rows.

The host MUST enforce an account-wide default of at most 30 attempts per
rolling minute, plus a deployment abuse budget, shared across all prefixes and
spool scopes. Tighter limits are permitted. Debit successful, empty, invalid,
unavailable and denied authenticated attempts BEFORE lookup; prefix or spool
rotation MUST NOT reset the budget. Exhaustion returns `RESOURCE_EXHAUSTED /
RATE_LIMITED` with retry delay and no results. Do not put queried prefixes or
identity metadata in public logs. Query authorized co-member indexes plus
one exact public-handle index; the protocol grants no global prefix scan.
Account deletion and membership revocation MUST be visible to the query's
consistent current authorization snapshot. No principal/account ID, hidden
handle, agent label, matching directory total, or opaque account-bearing
cursor may appear in results or failure detail.

Rust `v2::people` and TS `v2/people` take host-trusted live membership and
candidate context, a distinct list of spools with current MEMBERS-read authority,
per-candidate handle visibility, and an already-debited rate-limit decision. Client-provided
membership lists or booleans are NEVER authority. Response validation checks
the complete deterministic projection. TS also rejects undeclared row
properties and unknown protobuf fields. Rust prost drops unknown fields on
decode; its schema conformance test proves the declared output has no ID
field, while hosts must avoid forwarding unknown raw wire data as people rows.

## Role approval groups

`ApprovalGroupRecord.member_role` (field 6, `ResourceRole`) adds a dynamic
role-membership rule. `UNSPECIFIED` contributes no role members; otherwise
EVERY eligible human whose current effective role on the group's spool is at
least this threshold is a member. PutApprovalGroup now takes
`group.explicit_member_handles` (field 7), replacing `principal_ids`; field 5
and its old name are reserved, with no shim or ID input. After current
ADMINISTRATOR authorization, the host resolves canonical visible human handles
server-side within authorized indexes and stores private stable subject bindings.
Missing, hidden and agent handles uniformly refuse with NOT_FOUND /
RESOURCE_NOT_FOUND, field `group.explicit_member_handles`, without identity
context. UI sends handles directly, never account IDs. Handle renames do not
change private bindings. `resolve_approval_group_members` /
`resolveApprovalGroupMembers` supplies the authorized resolver seam; hosts map
its typed errors and persist atomically with CAS. The resolver takes this group's
current private bindings/visibility and returns the complete replacement binding
set, preserving hidden/no-handle explicit humans when editing visible extras. Host-resolved explicit_member
flags come from THIS group's stored bindings and MUST be rebuilt per group,
never matched against mutable client-supplied handles.
Union the two sets, excluding agents and applying the evaluator's
WRITER (Developer) eligibility floor to EVERY member, including explicit
extras. Explicit membership never grants spool access or approval eligibility.
An ancestor grant counts only where its descendant bit covers the spool; a
revoked grant does not count. Effective role is the maximum applicable current
role. Approval authors remain stable subjects internally; mutable handles
never establish authorization.

`SpoolService.PutApprovalGroup` MUST reject `group.member_role = READER` and
any future role below that floor with `INVALID_ARGUMENT`, typed
`ErrorReason.ERROR_REASON_APPROVAL_ROLE_BELOW_ELIGIBILITY_FLOOR` (403), and
`ErrorDetail.field = "group.member_role"`. `SpoolService.PutReviewPolicy` MUST
likewise reject `policy.minimum_role = READER`, with the same reason and field
`"policy.minimum_role"`. Unknown enum values use `FIELD_INVALID`. UNSPECIFIED
policy minimum defaults to WRITER. If a legacy stored policy still specifies
READER, evaluation MUST apply WRITER, never admit reader approvals. The API
has no Developer enum: `RESOURCE_ROLE_WRITER` is its Developer eligibility role.

Membership MUST be resolved at EACH LANDING EVALUATION using current roles,
including inheritance, not snapshotted at group creation or approval time.
Load policy, memberships, applicable grants and admitted approval state in the
same consistent landing decision/commit transaction; concurrent demotion or
removal MUST cause reevaluation or a transaction conflict before acceptance.
New admins count immediately without rewriting a group or collecting another
approval solely because they acquired its role. An approval given by someone
who subsequently loses the qualifying role MUST stop satisfying that role
group at the next evaluation. It is retained as historical review evidence,
not deleted or silently rewritten. If the person remains an explicit extra
member and meets the policy minimum and WRITER floor, their approval can still
count through that explicit membership. Loss of all spool membership or
demotion below WRITER makes an approval ineligible even for explicit extras.
A later promotion can make a retained approval count again only if the same
approval remains admitted, unrevoked, within TTL, and valid for the exact
reviewed revision and current policy. Existing author exclusions, revision
staleness and other review rules still apply. Each approver counts once per
group; multiple delegations or duplicate review rows do not add votes.

Rust `v2::approval_groups` and TS `v2/approval-groups` validate write thresholds,
combine applicable direct/inherited roles, resolve current groups, validate the
read projection and count distinct currently eligible admitted approvers.
`group_approval_count` / `groupApprovalCount` supplies the live group/role part
of the landing evaluator: hosts MUST filter revoked, expired, stale,
author-forbidden and wrong-revision approvals first. These helpers cannot
supply database isolation or prove an asserted role came from current grants.

## Spool read projection

`SpoolService.ObserveSpool`'s approval-groups snapshot and updates expose
`SpoolEvent.approval_group: ApprovalGroupView`. Its metadata is `ref`, `version`,
`name`, `description`, `member_role`. Counts `resolved_member_count` (10),
`role_member_count` (11) and `explicit_member_count` (12) count distinct bound
human subjects, including hidden/no-handle humans. Resolved and role counts
apply current eligibility; the explicit count includes ineligible configuration.

Approval-group section read authorizes metadata and counts. It does NOT
authorize roster disclosure: `resolved_members` (7) and `role_member_handles`
(8) additionally require current member-only MEMBERS-section read on that spool.
Without it, all handle lists MUST be empty and only metadata/counts are returned.
With it, exclude caller-hidden and absent handles from every disclosed list;
never substitute account IDs. Rows are sorted and deduplicated by canonical
handle. The role subset distinguishes dynamically selected members.

`explicit_member_handles` (9) additionally requires current ADMINISTRATOR and
MEMBERS-section read. It contains the explicit configuration, including
ineligible/demoted extras, so UI edits can round-trip without dropping them.
Load all privately bound explicit humans, including those without current spool
eligibility; resolve their current visible handles independently of resolved
membership. Hidden/no-handle bindings remain private and MUST be preserved when
replacing visible explicit handles. They are not removable through this handle
editor. Ref, CAS version and role rule round-trip normally. Neither handles nor
caller-supplied visibility flags establish authorization; helpers require trusted
`ApprovalGroupViewContext` (`can_read_members`, `is_administrator`).

Apply these checks to every snapshot, upsert, receipt and retry, and emit a
replacement projection when authorization or handle visibility changes.
Use existing group pagination. Do not silently truncate a group's authorized
lists: report section budget failure instead. Observations never authorize
landing; evaluate stable bindings and current roles again. PutApprovalGroup
continues taking ApprovalGroupRecord with the new handle field; regenerate
bindings for this hard cut, with no dual-format compatibility.

Shared fixtures `people-suggestions.json`, `role-approval-groups.json` and
`approval-group-visibility.json`
cover privacy, exact public hits, scope refusals, prefix/count/rate bounds,
role inheritance, new admins, demotion/removal, explicit extras, agent
exclusion, duplicate approvals, policy floors and READER refusals.
`tools/verify-alpha39-people-groups-guards.py` removes each critical guard,
requires real assertion failures, then restores it and requires passing tests.
