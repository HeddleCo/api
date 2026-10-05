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
at least one spool. Effective membership includes only applicable inherited
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
candidate context and an already-debited rate-limit decision. Client-provided
membership lists or booleans are NEVER authority. Response validation checks
the complete deterministic projection. TS also rejects undeclared row
properties and unknown protobuf fields. Rust prost drops unknown fields on
decode; its schema conformance test proves the declared output has no ID
field, while hosts must avoid forwarding unknown raw wire data as people rows.

## Role approval groups

`ApprovalGroupRecord.member_role` (field 6, `ResourceRole`) adds a dynamic
role-membership rule. `UNSPECIFIED` contributes no role members; otherwise
EVERY eligible human whose current effective role on the group's spool is at
least this threshold is a member. `principal_ids` remains the explicit extra
member list. Union the two sets, excluding agents and applying the evaluator's
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
`SpoolEvent.approval_group: ApprovalGroupView`, rather than the storage/write
record. The view fields are `ref`, `version`, `name`, `description`,
`member_role`, `resolved_members` (field 7), and `role_member_handles` (field 8). Each resolved member is an
ID-free `SuggestedPrincipal`; field 5 and name `principal_ids` are reserved in
the view. The ref identifies the group/spool, never an account. The list is the
complete current union of eligible explicit and role members, deduplicated
and sorted as people rows, with no agents. UI can render "Ada, Mara (admins)
and jun" from the administrator threshold, the role-member handle subset and
resolved display names. The role subset distinguishes dynamically selected
members from explicit extras without exposing their account IDs.

Apply the existing approval-group section authorization and group pagination.
Do not silently truncate a group's resolved members: if the complete group
exceeds the accepted observation budget, report the existing section budget
failure rather than claim a complete snapshot. Emit replacement/upsert views
when applicable direct or inherited grants, explicit extras or identity
presentation changes affect the list. A cached observation never authorizes
landing; evaluate live membership again. Mutation responses/receipts MUST NOT
copy principal_ids into a people projection. This alpha cutover changes field
8's message type; consumers regenerate bindings and use ApprovalGroupView,
while PutApprovalGroup still takes ApprovalGroupRecord.

Shared fixtures `people-suggestions.json` and `role-approval-groups.json`
cover privacy, exact public hits, scope refusals, prefix/count/rate bounds,
role inheritance, new admins, demotion/removal, explicit extras, agent
exclusion, duplicate approvals, policy floors and READER refusals.
`tools/verify-alpha39-people-groups-guards.py` removes each critical guard,
requires real assertion failures, then restores it and requires passing tests.
