//! Portable notification delivery gates. Hosts must run these before either
//! settings replacement or capability-authorized unsubscribe, then independently
//! check authorization, destination verification and expected_version. These
//! gates complement remaining stored-settings validation: hosts must also check
//! timezone, selectors, duplicate overrides and input budgets.

use crate::heddle::api::common::{CallFailureCode, ErrorReason};
use crate::heddle::api::v1alpha2::{
    NotificationPreferences, NotificationRule, SetNotificationPreferencesRequest,
    UnsubscribeNotificationsRequest,
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
}

impl NotificationValidationError {
    pub const fn code(self) -> CallFailureCode {
        match self {
            Self::LockedEmail => CallFailureCode::FailedPrecondition,
            Self::ProjectionTooLarge => CallFailureCode::ResourceExhausted,
            _ => CallFailureCode::InvalidArgument,
        }
    }

    pub const fn reason(self) -> ErrorReason {
        match self {
            Self::LockedEmail => ErrorReason::PolicyDenied,
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
