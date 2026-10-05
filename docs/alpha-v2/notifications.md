# Notification delivery

The inbox is the record. In-app is on/off per kind and appears immediately when
on. Email is off / immediate / digest; push is off / immediate. `DIGEST` is invalid
for in-app and push, including an unspecified channel (a wildcard). Push uses the
same outbox, authorizer and unsubscribe semantics; its sender and subscription
RPCs come later in [weft#2528](https://github.com/HeddleCo/weft/issues/2528).
This contract adds no push subscription RPC.

These are the settled [owner decisions](https://github.com/HeddleCo/weft/issues/2529#issuecomment-5964072062).
Weft owns and computes defaults; clients display the observed effective cells,
for example “Straight away (default)”, rather than reconstructing them.

## Stored settings and effective delivery

`ObserveNotifications(include_preferences = true)` emits one
`NotificationEvent.preferences` with stored `rules`, email cadence, timezone,
per-Spool digest overrides, `effective_delivery`, and `next_digest_at`. Live
preferences updates recompute this projection, including scheduling/policy
changes. No second preferences RPC is necessary. `version` remains the stored
settings version used by `expected_version`; a clock/default-policy change need
not change it.

Each `EffectiveDelivery` identifies concrete kind, channel, origin (human/agent,
or empty for origin-independent kinds), and optional event Spool. Delivery rules
inherit by default: **account → personal/top-level root → children**. For an
event in S, resolve each (kind × actor_origin × channel) separately: S first,
then its parent, continuing through the personal/top-level root. The **nearest
level with a matching rule wins**, even if a farther rule is more specific.
Otherwise use a matching account rule, otherwise a weft default. Within one
level specificity is exact kind before exact channel before exact origin; ties
keep the first rule. Empty or `*` kind is a wildcard; empty/`any` origin matches
human and agent; unspecified channel matches all channels.

Load the actual parent chain using stable Spool IDs, never a string prefix or
a client-supplied chain. Use the host's existing **64 or 128 node** ancestor
bound, including S (and the system root if loaded); the portable helpers accept
only these limits and reject overflow/duplicates. The host must verify parent
links and completeness. A cyclic, incomplete, or over-bound chain fails closed
with `FAILED_PRECONDITION / POLICY_DENIED`; it never silently falls back to
account rules. The shared system root `spool` is transparent and cannot hold
rules. Reject rules resolving to it with `INVALID_ARGUMENT / FIELD_INVALID`.
An unreadable ancestor still participates in resolution: read authorization
controls disclosure, not selection. Locked security/recovery email remains
IMMEDIATE at every level, independently of cadence.

The read-only `source` describes the winning rule's scope:

| Source | Meaning | `source_spool` |
| --- | --- | --- |
| `RULE = 1` | Stored rule at the cell's own scope (account or S) | Absent |
| `DEFAULT = 2` | Weft default, no matching rule at any level | Absent |
| `INHERITED = 3` | Stored rule at a proper ancestor of S | Actual winning ancestor, only when currently readable |
| `ACCOUNT = 4` | Stored account rule applied to a Spool cell | Absent; display “Same as your account settings” |

An account cell can only be RULE or DEFAULT. For INHERITED, the host checks
current read access to the **winning** ancestor. If it is unreadable, retain
INHERITED but omit `source_spool` and display “Inherited from a parent spool”.
Disclose no name, address, ID, depth, placeholder, or alternate readable
ancestor. Also omit stored rules and digest overrides for unreadable scopes
from preferences reads; a source reference redaction alone is insufficient.
Recompute and redact the projection when authorization changes. `source_spool`
is a `SpoolRef`, never an address, account reference, event Spool or system root.
The Rust/TS provenance validators reject references to unreadable ancestors,
non-ancestors, the target or system root. Hosts must compare the projected cell
to the resolver result as well; provenance validation alone does not prove that
a rule actually won. Defaults and effective digest cadence remain host inputs.

`delivery` is the resolved mode, not delivery status or a guarantee that a
destination exists. `locked` is true for security/recovery email, always
IMMEDIATE. The account matrix is complete for supported kinds/origins/channels.
Spool scopes are sparse: include cells for **every readable descendant** where
delivery, source, source_spool or locked differs from its account fallback,
including descendants without local rules. A Spool's account fallback copies
the account cell, changing RULE to ACCOUNT. An omitted Spool cell means this
fallback, not an instruction to reconstruct settings on the client. A child
inheriting an ancestor MUST be emitted even if delivery equals the account mode.
Only readable event Spools are disclosed. Cells are unique by (kind, Spool,
origin, channel). There are at most **4096 cells**, and the **entire encoded
preferences message is at most 1 MiB**, including rules and selector strings.
Weft must reject an oversized projection with `RESOURCE_EXHAUSTED /
QUOTA_EXCEEDED`, never silently truncate it. The Rust/TypeScript bound helper
enforces both limits before emit.

To return a cell in S to inheritance, remove **all S-scoped rules matching that
cell** from the atomic settings replacement. Removing one exact rule can leave
a matching wildcard override; split wildcard rules first if other cells must
retain their overrides. This changes no ancestor/account rules. Explicit
DISABLED is a local override and does not inherit. Stored DELIVERY_UNSPECIFIED
is invalid on write, never an inherit sentinel or an alias for DISABLED.
Migrate legacy unspecified stored routing explicitly: remove a rule intended to
inherit, or replace it with DISABLED if it was intended to mute. Do not evaluate
legacy zero as Disabled under this contract.

`SetNotificationPreferences` atomically validates every stored rule and digest
interval before writing. Projection fields are read-only and ignored on writes (including the
per-Spool next digest timestamp); they are recomputed and never persisted as
rules or accepted as authority. The Rust and TypeScript notification helpers
validate settings replacement and public `UnsubscribeNotifications`. Servers
must invoke these gates or implement equivalent validation; generated protobuf
messages alone do not enforce cross-field constraints. These helpers
complement the host's remaining stored-settings validation, including timezone,
selectors, duplicate overrides and input budgets; they do not replace it.

Unknown channel/delivery enums and unspecified delivery are rejected first with
typed `INVALID_ARGUMENT / FIELD_INVALID`. Next, any selector
that would disable **or digest** locked email returns
`FAILED_PRECONDITION / POLICY_DENIED`, including wildcard kinds/channels,
origin-specific and Spool-specific rules, and signed-out unsubscribe. No partial
write occurs. The email lock takes precedence over the email-only DIGEST check:
other DIGEST rules on in-app/push or wildcard channels return
`INVALID_ARGUMENT / FIELD_INVALID`. In-app and push for those same kinds remain
individually editable.
A broadly disabling rule must be replaced with explicit editable-kind rules.
Locking the email prevents a zero digest interval from suppressing security.

## Email digest

The digest batches only email by the account `digest_interval` and IANA
`timezone`. Supported intervals are one hour, one day and one week; zero is off.
Every supplied duration must have zero nanos and seconds in
`{0, 3600, 86400, 604800}`; every override must contain an interval. Invalid or
missing override intervals return `INVALID_ARGUMENT / FIELD_INVALID`.
Absent account interval uses weft's daily default; empty timezone uses weft's
timezone default. One `NotificationDigestOverride` per Spool replaces its interval;
removing it restores the account cadence. Explicit zero turns that Spool's
scheduled email off without suppressing inbox items or immediate email.

`NotificationPreferences.next_digest_at` is the next account email digest
window; it is absent when the account interval is off. Each override also has a
read-only `next_digest_at`, absent when that override is off. Thus a Spool can
have a next digest while the account cadence is off. These are schedule
projections, not promises of queued mail; turning the interval off sends no
digest email for that scope. A stored DIGEST mode can remain selected while the
cadence is off, but the effective email cell then reports DISABLED while
retaining its RULE/INHERITED/ACCOUNT/DEFAULT source. Destination readiness remains separate from
this routing projection. Cadence changes never delay the inbox or push.
Activity email requires a verified address and current authorization and uses
the existing outbox and unsubscribe path. These contract additions do not
implement the weft email sender or scheduler.

## Default classes and kind vocabulary

Spool invitations add `spool_invitation` (direct ask to the privately bound
invitee) and `spool_invitation_declined` (ambient update to the human inviter).
They reuse this delivery/preferences/outbox contract. The invitation itself
authorizes its narrow inbox projection before membership. Pending items carry
Accept/Decline advice; read/dismiss/snooze never declines an invite. See
[administration](administration.md#inbox-and-delivery) for fields, binding,
projection authorization and terminal updates.

V2 uses string kinds; it removed the v1 `NotificationKind` enum during the
contract freeze. The table names every real historical enum value and its v2
selector, rather than introducing or renumbering an enum. Historical source:
`notification.proto` at API commit `924ce945` (notification service promotion).
`UNSPECIFIED` is a selector wildcard, not a deliverable kind.

| Historical NotificationKind value | V2 kind selector | Default class |
| --- | --- | --- |
| NOTIFICATION_KIND_REVIEW_READY | `review_ready` | Direct ask |
| NOTIFICATION_KIND_AGENT_COMPLETED | `agent_completed` | Ambient (interpretation: completion alone does not ask for action) |
| NOTIFICATION_KIND_SECURITY_SURFACE | `security_surface` | Security, locked (interpretation: treat security alerts conservatively) |
| NOTIFICATION_KIND_DRIFT_ALERT | `drift_alert` | Ambient (interpretation: drift alone is followed activity) |
| NOTIFICATION_KIND_REPO_QUIET_DIGEST | `repo_quiet_digest` | Ambient; weft's `repo_quiet` storage alias denotes the same kind |
| NOTIFICATION_KIND_IMPORTED_DISCUSSION | `imported_discussion` | Ambient |
| NOTIFICATION_KIND_MENTION | `mention` | Direct ask |
| NOTIFICATION_KIND_DISCUSSION_REPLY | `discussion_reply` | Ambient for ordinary participant replies |
| NOTIFICATION_KIND_ACCOUNT_SECURITY | `account_security` | Security/recovery, locked |
| NOTIFICATION_KIND_STEER_HELD | `steer_held` | Direct ask: agent waiting on the recipient |

Direct asks default to inbox + immediate email + immediate push once its sender
exists. Ambient defaults to inbox + daily email digest + push off.
Security/recovery defaults to inbox + immediate, non-suppressible email; push is
off by default. Locks apply to email only, regardless of origin and Spool.

The vocabulary has no separate review-requested, agent-waiting, blocking-reply,
or recovery enum values. Review asks use `review_ready`; waiting on a steer uses
`steer_held`; account recovery uses `account_security`. Ordinary
`discussion_reply` is classified ambient here because its enum comment describes
ordinary replies to a joined discussion. A blocking reply is a direct ask in the
owner model, but this vocabulary has no distinct blocking-reply selector; an
explicit recipient mention uses `mention`. Weft can add a more specific blocking
kind without converting these v2 string fields into enums. Clients display the
observed classification rather than treating every reply as blocking. The
ambiguous interpretations above follow the decision's spirit and are listed
explicitly for weft's default implementation in #2529.

## Inheritance conformance and host integration

The 2026-10-05 owner decision adds hierarchy inheritance to the existing
notification contract. `tests/fixtures/notification-inheritance.json` is shared
by Rust and TypeScript: parent/account fallback, nearest ancestor, per-level
specificity and ties, removal, explicit Disabled, invalid unspecified writes,
source wire round trips, unreadable ancestor redaction, forged provenance,
transparent system root, locks and effective digest-off behavior. Both runners
also exercise the inclusive 64/128 limits and rejection one node over each.
Hosts must integrate the helpers with trusted ancestry loading, current read
checks, scope validation on write (use
`validate_notification_preferences_write_for_system_root` /
`validateNotificationPreferencesWriteForSystemRoot` with the resolved shared
root identity), and projection of readable descendants.
The existing weft `notifications/preferences.rs` exact-path evaluator must be
replaced by this ancestor resolution; this API release does not implement weft
storage/handlers or the UI. Digest cadence still uses its separate existing
account/per-Spool override contract above.
