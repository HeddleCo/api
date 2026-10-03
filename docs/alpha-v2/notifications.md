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
or empty for origin-independent kinds), and optional Spool. `source = RULE` means
a stored selector matched; `DEFAULT` means a weft default. `delivery` is the
resolved mode, not delivery status or a guarantee that a destination exists.
`locked` is true for security/recovery email and its mode is always IMMEDIATE.

The account matrix is complete for supported kinds/origins/channels. Spool
scopes are sparse: include cells when delivery, source or locked differs from
the account cell; omitted Spool cells inherit it. Only currently authorized
Spools are disclosed. Cells are unique by (kind, Spool, origin, channel).
There are at most **4096 cells**, and the **entire encoded preferences message is
at most 1 MiB**, including rules and selector strings. Weft must reject an
oversized projection with `RESOURCE_EXHAUSTED / QUOTA_EXCEEDED`, never silently
truncate it. The Rust/TypeScript bound helper enforces both limits before emit.

Spool rules precede account rules. Within a scope specificity is exact kind
before exact channel before exact origin; ties keep the first rule. Empty or
`*` kind is a wildcard; empty/`any` origin matches human and agent; unspecified
channel matches all channels. Defaults apply only when no rule matches.

`SetNotificationPreferences` atomically validates every stored rule before
writing. Projection fields are read-only and ignored on writes (including the
per-Spool next digest timestamp); they are recomputed and never persisted as
rules or accepted as authority. The Rust and TypeScript notification helpers
validate settings replacement and public `UnsubscribeNotifications`. Servers
must invoke these gates or implement equivalent validation; generated protobuf
messages alone do not enforce cross-field constraints. No generic notification
validator existed in this repository before this addition.

An invalid channel/delivery, unspecified delivery, or DIGEST on in-app/push or a
wildcard channel returns typed `INVALID_ARGUMENT / FIELD_INVALID`. Any selector
that would disable **or digest** locked email returns
`FAILED_PRECONDITION / POLICY_DENIED`, including wildcard kinds/channels,
origin-specific and Spool-specific rules, and signed-out unsubscribe. No partial
write occurs. In-app and push for those same kinds remain individually editable.
A broadly disabling rule must be replaced with explicit editable-kind rules.
Locking the email prevents a zero digest interval from suppressing security.

## Email digest

The digest batches only email by the account `digest_interval` and IANA
`timezone`. Supported intervals are one hour, one day and one week; zero is off.
Absent interval uses weft's daily default; empty timezone uses weft's timezone
default. One `NotificationDigestOverride` per Spool replaces its interval;
removing it restores the account cadence. Explicit zero turns that Spool's
scheduled email off without suppressing inbox items or immediate email.

`NotificationPreferences.next_digest_at` is the next account email digest
window; it is absent when the account interval is off. Each override also has a
read-only `next_digest_at`, absent when that override is off. Thus a Spool can
have a next digest while the account cadence is off. These are schedule
projections, not promises of queued mail; turning the interval off sends no
digest email for that scope. A stored DIGEST mode can remain selected while the
cadence is off, but the effective email cell then reports DISABLED while
retaining the RULE/DEFAULT source. Destination readiness remains separate from
this routing projection. Cadence changes never delay the inbox or push.
Activity email requires a verified address and current authorization and uses
the existing outbox and unsubscribe path. These contract additions do not
implement the weft email sender or scheduler.

## Default classes and kind vocabulary

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
