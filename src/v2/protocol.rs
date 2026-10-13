//! Variant support advertised by the authenticated endpoint, independent of
//! method availability and signed-record formats. Never reuse across peers.
use crate::heddle::api::common::{MandatoryProtocolFeature, ProtocolCompatibility};
use crate::heddle::api::v1alpha2 as api;
use crate::hybrid_codec::Reject;
use prost::Message;

pub fn host_supports(
    peer: Option<&ProtocolCompatibility>,
    feature: MandatoryProtocolFeature,
) -> bool {
    feature != MandatoryProtocolFeature::Unspecified
        && peer.is_some_and(|p| p.mandatory_features.contains(&(feature as i32)))
}

pub fn require_feature(
    peer: Option<&ProtocolCompatibility>,
    feature: MandatoryProtocolFeature,
) -> Result<(), Reject> {
    if host_supports(peer, feature) {
        Ok(())
    } else {
        Err(Reject::MissingFeature(feature))
    }
}

/// Check delivery variants before transport. Signed-command constructors check
/// before signing; hosts still verify original bytes and delivery correspondence.
pub fn validate_request_features(
    path: &str,
    bytes: &[u8],
    peer: Option<&ProtocolCompatibility>,
) -> Result<(), Reject> {
    use super::collaboration::{canonical_discussion_open_tags, validate_mentions};
    use MandatoryProtocolFeature as F;
    match path {
        "/heddle.api.v1alpha2.CollaborationService/OpenDiscussion" => {
            let r = api::OpenDiscussionRequest::decode(bytes).map_err(|_| Reject::Canonical)?;
            validate_mentions(&r.mentions, peer)?;
            canonical_discussion_open_tags(&r.tags, peer)?;
        }
        "/heddle.api.v1alpha2.CollaborationService/AppendTurn" => {
            let r = api::AppendDiscussionRequest::decode(bytes).map_err(|_| Reject::Canonical)?;
            validate_mentions(&r.mentions, peer)?;
        }
        "/heddle.api.v1alpha2.CollaborationService/PutContext" => {
            let r = api::PutContextRequest::decode(bytes).map_err(|_| Reject::Canonical)?;
            if let Some(context) = r.context {
                validate_mentions(&context.mentions, peer)?;
            }
        }
        "/heddle.api.v1alpha2.CollaborationService/ResolveDiscussion" => {
            let r = api::ResolveDiscussionRequest::decode(bytes).map_err(|_| Reject::Canonical)?;
            if let Some(api::resolve_discussion_request::Resolution::ExtractContext(context)) =
                r.resolution
            {
                validate_mentions(&context.mentions, peer)?;
            }
        }
        "/heddle.api.v1alpha2.CollaborationService/EditDiscussionTags" => {
            require_feature(peer, F::DiscussionTagsV1)?
        }
        "/heddle.api.v1alpha2.ContentService/ReadContent" => {
            let r = api::ReadContentRequest::decode(bytes).map_err(|_| Reject::Canonical)?;
            for selection in r.selections {
                if let Some(api::content_read::Selection::Outline(outline)) = selection.selection {
                    super::content::validate_outline_read(&outline, peer)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}
