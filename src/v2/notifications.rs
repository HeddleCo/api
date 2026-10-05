//! Portable notification delivery gates. Hosts must run these before either
//! settings replacement or capability-authorized unsubscribe, then independently
//! check authorization, destination verification and expected_version. These
//! gates complement remaining stored-settings validation: hosts must also check
//! timezone, selectors, duplicate overrides and input budgets.

use crate::heddle::api::common::{CallFailureCode, ErrorReason};
use crate::heddle::api::v1alpha2::{
    EffectiveDelivery, NotificationPreferences, NotificationRule,
    SetNotificationPreferencesRequest, SpoolRef, UnsubscribeNotificationsRequest,
    effective_delivery::Source,
    notification_rule::{Channel, Delivery},
};

pub const MAX_EFFECTIVE_DELIVERIES: usize = 4096;
pub const MAX_NOTIFICATION_PREFERENCES_BYTES: usize = 1024 * 1024;
pub const LOCKED_EMAIL_KINDS: &[&str] = &["account_security", "security_surface"];

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NotificationValidationError {
    #[error("unknown channel or unspecified/unknown delivery")]
    InvalidRule,
    #[error("DIGEST requires the email channel")]
    DigestRequiresEmail,
    #[error("digest interval must be zero, one hour, one day or one week with zero nanos")]
    InvalidDigestInterval,
    #[error("security/recovery email must remain IMMEDIATE")]
    LockedEmail,
    #[error("unsubscribe requires DISABLED delivery")]
    UnsubscribeDelivery,
    #[error("notification preferences exceed the read projection bound")]
    ProjectionTooLarge,
    #[error("ancestor chain must be complete, acyclic and within the host's 64/128-node bound")]
    InvalidAncestry,
    #[error("invalid or unauthorized delivery provenance")]
    InvalidSource,
}

impl NotificationValidationError {
    pub const fn code(self) -> CallFailureCode {
        match self {
            Self::LockedEmail | Self::InvalidAncestry => CallFailureCode::FailedPrecondition,
            Self::ProjectionTooLarge => CallFailureCode::ResourceExhausted,
            _ => CallFailureCode::InvalidArgument,
        }
    }

    pub const fn reason(self) -> ErrorReason {
        match self {
            Self::LockedEmail | Self::InvalidAncestry => ErrorReason::PolicyDenied,
            Self::ProjectionTooLarge => ErrorReason::QuotaExceeded,
            _ => ErrorReason::FieldInvalid,
        }
    }
}

/// Check selector/channel semantics. Wildcard OFF rules that include locked
/// email kinds are rejected rather than silently overriding the user's request.
/// After enum validation, the email lock takes precedence over email-only DIGEST.
pub fn validate_notification_rule(
    rule: &NotificationRule,
) -> Result<(), NotificationValidationError> {
    let channel =
        Channel::try_from(rule.channel).map_err(|_| NotificationValidationError::InvalidRule)?;
    let delivery =
        Delivery::try_from(rule.delivery).map_err(|_| NotificationValidationError::InvalidRule)?;
    if delivery == Delivery::Unspecified {
        return Err(NotificationValidationError::InvalidRule);
    }
    let matches_locked = rule.kind.is_empty()
        || rule.kind == "*"
        || LOCKED_EMAIL_KINDS.contains(&rule.kind.as_str());
    if matches_locked
        && matches!(channel, Channel::Email | Channel::Unspecified)
        && delivery != Delivery::Immediate
    {
        return Err(NotificationValidationError::LockedEmail);
    }
    if delivery == Delivery::Digest && channel != Channel::Email {
        return Err(NotificationValidationError::DigestRequiresEmail);
    }
    Ok(())
}

pub fn validate_notification_preferences_write(
    request: &SetNotificationPreferencesRequest,
) -> Result<(), NotificationValidationError> {
    let preferences = request
        .preferences
        .as_ref()
        .ok_or(NotificationValidationError::InvalidRule)?;
    if let Some(interval) = &preferences.digest_interval {
        validate_digest_interval(interval)?;
    }
    for digest_override in &preferences.digest_overrides {
        let interval = digest_override
            .digest_interval
            .as_ref()
            .ok_or(NotificationValidationError::InvalidDigestInterval)?;
        validate_digest_interval(interval)?;
    }
    for rule in &preferences.rules {
        validate_notification_rule(rule)?;
    }
    Ok(())
}

/// Settings write gate with the resolved system-root identity. Hosts must use
/// this gate (or equivalent scope validation) to forbid system-root rules.
pub fn validate_notification_preferences_write_for_system_root(
    request: &SetNotificationPreferencesRequest,
    system_root: &SpoolRef,
) -> Result<(), NotificationValidationError> {
    validate_notification_preferences_write(request)?;
    if request.preferences.as_ref().is_some_and(|preferences| {
        preferences
            .rules
            .iter()
            .any(|rule| rule.spool.as_ref() == Some(system_root))
    }) {
        return Err(NotificationValidationError::InvalidRule);
    }
    Ok(())
}

fn validate_digest_interval(
    interval: &prost_types::Duration,
) -> Result<(), NotificationValidationError> {
    if interval.nanos != 0 || !matches!(interval.seconds, 0 | 3600 | 86400 | 604800) {
        return Err(NotificationValidationError::InvalidDigestInterval);
    }
    Ok(())
}

pub fn validate_unsubscribe_notifications(
    request: &UnsubscribeNotificationsRequest,
) -> Result<(), NotificationValidationError> {
    for rule in &request.rules {
        validate_notification_rule(rule)?;
        if rule.delivery != Delivery::Disabled as i32 {
            return Err(NotificationValidationError::UnsubscribeDelivery);
        }
    }
    Ok(())
}

/// Validate the documented bound before emitting a preferences read. Stored
/// rules and string lengths count toward the byte cap, not only resolved cells.
pub fn validate_notification_preferences_bound(
    preferences: &NotificationPreferences,
) -> Result<(), NotificationValidationError> {
    use prost::Message;
    if preferences.effective_delivery.len() > MAX_EFFECTIVE_DELIVERIES
        || preferences.encoded_len() > MAX_NOTIFICATION_PREFERENCES_BYTES
    {
        return Err(NotificationValidationError::ProjectionTooLarge);
    }
    Ok(())
}

/// Maximum nodes, including the event spool. Hosts with a 64-node bound pass 64.
pub const MAX_NOTIFICATION_ANCESTORS: usize = 128;

/// Trusted host-loaded ancestry, nearest first. The loader must verify parent
/// links and completeness before calling; never build this from client input or
/// omit unreadable ancestors. The optional shared system root is last.
#[derive(Clone, Debug)]
pub struct NotificationAncestor {
    pub spool: SpoolRef,
    pub readable: bool,
    pub system_root: bool,
}

fn validate_ancestry(
    cell: &EffectiveDelivery,
    ancestors: &[NotificationAncestor],
    ancestor_limit: usize,
) -> Result<(), NotificationValidationError> {
    if !matches!(ancestor_limit, 64 | MAX_NOTIFICATION_ANCESTORS)
        || ancestors.len() > ancestor_limit
        || cell.spool.as_ref() != ancestors.first().map(|level| &level.spool)
        || ancestors.iter().enumerate().any(|(i, level)| {
            level.spool.id.is_empty()
                || ancestors[..i]
                    .iter()
                    .any(|other| other.spool == level.spool)
                || (level.system_root && (i == 0 || i + 1 != ancestors.len()))
        })
    {
        return Err(NotificationValidationError::InvalidAncestry);
    }
    if ancestors.first().is_some_and(|level| !level.readable) {
        return Err(NotificationValidationError::InvalidSource);
    }
    Ok(())
}

/// Resolve one cell from validated settings and trusted complete ancestry.
/// Defaults and effective email cadence are host-owned inputs. Routing and read
/// provenance use the same result; unreadability never changes selection.
/// This plans a projection; hosts still enforce authorization and persist writes.
pub fn resolve_notification_delivery(
    rules: &[NotificationRule],
    cell: &EffectiveDelivery,
    ancestors: &[NotificationAncestor],
    ancestor_limit: usize,
    default_delivery: Delivery,
    digest_enabled: bool,
) -> Result<EffectiveDelivery, NotificationValidationError> {
    validate_ancestry(cell, ancestors, ancestor_limit)?;
    let channel =
        Channel::try_from(cell.channel).map_err(|_| NotificationValidationError::InvalidRule)?;
    if channel == Channel::Unspecified
        || matches!(cell.kind.as_str(), "" | "*")
        || !matches!(cell.actor_origin.as_str(), "" | "human" | "agent")
        || default_delivery == Delivery::Unspecified
        || (default_delivery == Delivery::Digest && channel != Channel::Email)
    {
        return Err(NotificationValidationError::InvalidRule);
    }
    for rule in rules {
        validate_notification_rule(rule)?;
        if ancestors
            .iter()
            .any(|level| level.system_root && rule.spool.as_ref() == Some(&level.spool))
        {
            return Err(NotificationValidationError::InvalidRule);
        }
    }
    let mut selected = None;
    for (i, level) in ancestors
        .iter()
        .enumerate()
        .filter(|(_, level)| !level.system_root)
    {
        if let Some(rule) = best_notification_rule(rules, cell, Some(&level.spool)) {
            let source = if i == 0 {
                Source::Rule
            } else {
                Source::Inherited
            };
            let source_spool = (i > 0 && level.readable).then(|| level.spool.clone());
            selected = Some((rule.delivery, source, source_spool));
            break;
        }
    }
    if selected.is_none() {
        selected = best_notification_rule(rules, cell, None).map(|rule| {
            (
                rule.delivery,
                if cell.spool.is_some() {
                    Source::Account
                } else {
                    Source::Rule
                },
                None,
            )
        });
    }
    let (mut delivery, source, source_spool) =
        selected.unwrap_or((default_delivery as i32, Source::Default, None));
    let locked = channel == Channel::Email && LOCKED_EMAIL_KINDS.contains(&cell.kind.as_str());
    if locked {
        delivery = Delivery::Immediate as i32;
    } else if delivery == Delivery::Digest as i32 && !digest_enabled {
        delivery = Delivery::Disabled as i32;
    }
    Ok(EffectiveDelivery {
        kind: cell.kind.clone(),
        spool: cell.spool.clone(),
        actor_origin: cell.actor_origin.clone(),
        channel: cell.channel,
        delivery,
        source: source as i32,
        locked,
        source_spool,
    })
}

fn best_notification_rule<'a>(
    rules: &'a [NotificationRule],
    cell: &EffectiveDelivery,
    spool: Option<&SpoolRef>,
) -> Option<&'a NotificationRule> {
    let mut best: Option<(u8, &NotificationRule)> = None;
    for rule in rules {
        let exact_kind = !matches!(rule.kind.as_str(), "" | "*");
        let exact_channel = rule.channel != Channel::Unspecified as i32;
        let exact_origin = !matches!(rule.actor_origin.as_str(), "" | "any");
        if rule.spool.as_ref() != spool
            || (exact_kind && rule.kind != cell.kind)
            || (exact_channel && rule.channel != cell.channel)
            || (exact_origin && rule.actor_origin != cell.actor_origin)
        {
            continue;
        }
        let score = u8::from(exact_kind) * 4 + u8::from(exact_channel) * 2 + u8::from(exact_origin);
        if best.is_none_or(|(previous, _)| score > previous) {
            best = Some((score, rule));
        }
    }
    best.map(|(_, rule)| rule)
}

/// Validate provenance before emitting a cell. Hosts must additionally compare
/// against their resolved result: this gate checks disclosure, not rule storage.
pub fn validate_effective_delivery_source(
    cell: &EffectiveDelivery,
    ancestors: &[NotificationAncestor],
    ancestor_limit: usize,
) -> Result<(), NotificationValidationError> {
    validate_ancestry(cell, ancestors, ancestor_limit)?;
    let valid = match Source::try_from(cell.source) {
        Ok(Source::Rule | Source::Default) => cell.source_spool.is_none(),
        Ok(Source::Account) => cell.spool.is_some() && cell.source_spool.is_none(),
        Ok(Source::Inherited) => {
            cell.spool.is_some()
                && ancestors.iter().skip(1).any(|level| {
                    !level.system_root
                        && match &cell.source_spool {
                            Some(spool) => level.readable && spool == &level.spool,
                            None => !level.readable,
                        }
                })
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(NotificationValidationError::InvalidSource)
    }
}

/// Choose scopes BEFORE expanding the kind/origin/channel matrix. The host
/// supplies current readable IDs; rule-free descendants never enter this list.
pub fn notification_projection_scopes(
    request: &crate::heddle::api::v1alpha2::ObserveNotificationsRequest,
    rules: &[NotificationRule],
    readable: &[SpoolRef],
) -> Result<Vec<Option<SpoolRef>>, NotificationValidationError> {
    if let Some(spool) = &request.effective_delivery_spool {
        if !request.include_preferences || spool.id.is_empty() || !readable.contains(spool) {
            return Err(NotificationValidationError::InvalidSource);
        }
        return Ok(vec![Some(spool.clone())]);
    }
    let mut scopes = vec![None];
    for rule in rules {
        if let Some(spool) = &rule.spool {
            if readable.contains(spool) && !scopes.contains(&Some(spool.clone())) {
                scopes.push(Some(spool.clone()));
            }
        }
    }
    Ok(scopes)
}

/// Plan an atomic replacement. Readability and stored settings must be loaded
/// under the same lock/CAS as commit. Clear is caller-account authority only.
/// Host validates storage quotas AFTER preservation, not projection budgets.
pub fn replace_notification_preferences(
    stored: &NotificationPreferences,
    request: &SetNotificationPreferencesRequest,
    readable: &[SpoolRef],
) -> Result<NotificationPreferences, NotificationValidationError> {
    validate_notification_preferences_write(request)?;
    let mut next = request
        .preferences
        .clone()
        .ok_or(NotificationValidationError::InvalidRule)?;
    if next.rules.iter().any(|rule| {
        rule.spool
            .as_ref()
            .is_some_and(|spool| !readable.contains(spool))
    }) || next.digest_overrides.iter().any(|item| {
        item.spool
            .as_ref()
            .is_none_or(|spool| !readable.contains(spool))
    }) {
        return Err(NotificationValidationError::InvalidSource);
    }
    if !request.clear_unreadable_scopes {
        next.rules.extend(
            stored
                .rules
                .iter()
                .filter(|rule| {
                    rule.spool
                        .as_ref()
                        .is_some_and(|spool| !readable.contains(spool))
                })
                .cloned(),
        );
        next.digest_overrides.extend(
            stored
                .digest_overrides
                .iter()
                .filter(|item| {
                    item.spool
                        .as_ref()
                        .is_some_and(|spool| !readable.contains(spool))
                })
                .cloned(),
        );
    }
    next.effective_delivery.clear();
    next.next_digest_at = None;
    for item in &mut next.digest_overrides {
        item.next_digest_at = None;
    }
    Ok(next)
}

/// Invitation-only routing: recipient binding authorizes delivery even without
/// spool read. In particular Decline to a departed inviter MUST use account
/// scope, never InvalidSource and never weaken the ordinary provenance gate.
pub fn resolve_invitation_notification_delivery(
    rules: &[NotificationRule],
    cell: &EffectiveDelivery,
    ancestors: &[NotificationAncestor],
    ancestor_limit: usize,
    default_delivery: Delivery,
    digest_enabled: bool,
) -> Result<EffectiveDelivery, NotificationValidationError> {
    if !matches!(
        cell.kind.as_str(),
        "spool_invitation" | "spool_invitation_declined"
    ) {
        return Err(NotificationValidationError::InvalidRule);
    }
    if cell.spool.is_some() && ancestors.first().is_some_and(|level| !level.readable) {
        let account = EffectiveDelivery {
            spool: None,
            ..cell.clone()
        };
        return resolve_notification_delivery(
            rules,
            &account,
            &[],
            ancestor_limit,
            default_delivery,
            digest_enabled,
        );
    }
    resolve_notification_delivery(
        rules,
        cell,
        ancestors,
        ancestor_limit,
        default_delivery,
        digest_enabled,
    )
}
