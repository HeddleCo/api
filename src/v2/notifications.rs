//! Portable notification delivery gates. Hosts must run these before either
//! settings replacement or capability-authorized unsubscribe, then independently
//! check authorization, destination verification and expected_version.

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
    if delivery == Delivery::Digest && channel != Channel::Email {
        return Err(NotificationValidationError::DigestRequiresEmail);
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
    Ok(())
}

pub fn validate_notification_preferences_write(
    request: &SetNotificationPreferencesRequest,
) -> Result<(), NotificationValidationError> {
    let preferences = request
        .preferences
        .as_ref()
        .ok_or(NotificationValidationError::InvalidRule)?;
    for rule in &preferences.rules {
        validate_notification_rule(rule)?;
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
