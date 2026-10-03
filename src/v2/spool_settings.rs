//! Atomic field-mask settings patches. Hosts own CAS and authorization lookup.
use crate::heddle::api::v1alpha2::SpoolSettings;
use prost_types::FieldMask;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SpoolSettingsPatchError {
    #[error("invalid settings mask")]
    Mask,
    #[error("settings clearDenied")]
    ClearDenied,
}

/// Apply only top-level masked fields; an absent selected message is a clear.
/// `can_clear` must check permission to read AND clear the current stored value,
/// including deleted/hidden targets. Replacing either filtered reference also
/// removes its current value and requires this permission. An equal reference
/// does not remove it. This is independent of validating the new target.
/// The host must authorize the administrator, validate set references and the
/// resulting audience/review policy, and bind the stored-value check and update
/// to the same expected_version, with live authorization at atomic commit.
pub fn apply_spool_settings_patch(
    current: &SpoolSettings,
    patch: Option<&SpoolSettings>,
    mask: Option<&FieldMask>,
    mut can_clear: impl FnMut(&str) -> bool,
) -> Result<SpoolSettings, SpoolSettingsPatchError> {
    let mut result = current.clone();
    let empty = SpoolSettings::default();
    let patch = patch.unwrap_or(&empty);
    let Some(mask) = mask else { return Ok(result) };
    for (index, path) in mask.paths.iter().enumerate() {
        if mask.paths[..index].contains(path) {
            return Err(SpoolSettingsPatchError::Mask);
        }
        macro_rules! assign {
            ($field:ident, $replacing:expr) => {{
                if (patch.$field == empty.$field || $replacing) && !can_clear(path) {
                    return Err(SpoolSettingsPatchError::ClearDenied);
                }
                result.$field = patch.$field.to_owned();
            }};
        }
        match path.as_str() {
            "audience" => assign!(audience, false),
            "default_state_audience" => assign!(default_state_audience, false),
            "description" => assign!(description, false),
            "allow_child_creation" => assign!(allow_child_creation, false),
            "require_review_to_land" => assign!(require_review_to_land, false),
            "abandoned_thread_retention" => assign!(abandoned_thread_retention, false),
            "default_review_policy" => assign!(
                default_review_policy,
                current.default_review_policy.is_some()
                    && patch.default_review_policy != current.default_review_policy
            ),
            "hold_lifecycle" => assign!(hold_lifecycle, false),
            "blocking_discussion_resolve_rule" => assign!(blocking_discussion_resolve_rule, false),
            "default_thread" => assign!(
                default_thread,
                current.default_thread.is_some() && patch.default_thread != current.default_thread
            ),
            _ => return Err(SpoolSettingsPatchError::Mask),
        }
    }
    Ok(result)
}
