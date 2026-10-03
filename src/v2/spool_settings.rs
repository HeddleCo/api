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
/// including deleted/hidden targets. It is not a check on the filtered patch.
/// The host must authorize the administrator, validate set references and the
/// resulting audience/review policy, and commit under expected_version atomically.
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
            ($field:ident) => {{
                if patch.$field == empty.$field && !can_clear(path) {
                    return Err(SpoolSettingsPatchError::ClearDenied);
                }
                result.$field = patch.$field.to_owned();
            }};
        }
        match path.as_str() {
            "audience" => assign!(audience),
            "default_state_audience" => assign!(default_state_audience),
            "description" => assign!(description),
            "allow_child_creation" => assign!(allow_child_creation),
            "require_review_to_land" => assign!(require_review_to_land),
            "abandoned_thread_retention" => assign!(abandoned_thread_retention),
            "default_review_policy" => assign!(default_review_policy),
            "hold_lifecycle" => assign!(hold_lifecycle),
            "blocking_discussion_resolve_rule" => assign!(blocking_discussion_resolve_rule),
            "default_thread" => assign!(default_thread),
            _ => return Err(SpoolSettingsPatchError::Mask),
        }
    }
    Ok(result)
}
