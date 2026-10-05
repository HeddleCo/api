//! Scoped people lookup over trusted, current host identity/membership data.
use crate::heddle::api::v1alpha2::{
    HandleKind, SuggestPrincipalsRequest, SuggestPrincipalsResponse, SuggestedPrincipal,
};
use unicode_normalization::UnicodeNormalization;

pub const MAX_SUGGESTED_PRINCIPALS: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PeopleError {
    #[error("uniform unknown/non-member spool refusal")]
    Scope,
    #[error("suggestion account rate limit exceeded")]
    RateLimited,
    #[error("prefix must contain 2..64 scalars and at most 256 UTF-8 bytes")]
    Prefix,
    #[error("invalid public people metadata")]
    Metadata,
    #[error("suggestion violates the scoped people projection")]
    Projection,
}

/// Host-resolved candidate; none of these membership flags comes from clients.
pub struct PeopleCandidate {
    pub person: SuggestedPrincipal,
    pub spool_ids: Vec<String>,
    pub is_agent: bool,
    pub is_public: bool,
}

/// Authenticated caller's live memberships (including inheritance), and a
/// caller-account rate-budget decision already debited for this attempt.
/// Public-spool read access alone MUST NOT populate caller_spool_ids.
pub struct PeopleContext<'a> {
    pub caller_spool_ids: &'a [String],
    pub rate_limit_allowed: bool,
}

pub(crate) fn normalized(value: &str) -> String {
    value.nfc().collect::<String>().to_lowercase()
}

pub fn validate_suggest_principals_request(
    request: &SuggestPrincipalsRequest,
    context: &PeopleContext<'_>,
) -> Result<(), PeopleError> {
    if !context.rate_limit_allowed {
        return Err(PeopleError::RateLimited);
    }
    if request
        .spool
        .as_ref()
        .is_some_and(|spool| spool.id.is_empty() || !context.caller_spool_ids.contains(&spool.id))
    {
        return Err(PeopleError::Scope);
    }
    let prefix = normalized(&request.prefix);
    if request.prefix.trim() != request.prefix
        || request.prefix.chars().any(char::is_control)
        || request.prefix.len() > 256
        || prefix.len() > 256
        || !(2..=64).contains(&prefix.chars().count())
    {
        return Err(PeopleError::Prefix);
    }
    Ok(())
}

pub(crate) fn validate_person(person: &SuggestedPrincipal) -> Result<(), PeopleError> {
    if person.handle.is_empty()
        || person.handle.len() > 256
        || person.handle.trim() != person.handle
        || person.handle.chars().any(char::is_control)
        || person.display_name.len() > 1024
        || person.display_name.chars().any(char::is_control)
        || !matches!(
            HandleKind::try_from(person.kind),
            Ok(HandleKind::Native | HandleKind::Github | HandleKind::Gitlab)
        )
    {
        return Err(PeopleError::Metadata);
    }
    Ok(())
}

/// Select only current co-members, plus at most one exact public handle.
/// Hosts MUST query authorized co-member indexes and one exact handle lookup;
/// this helper is not permission to scan a global principal directory.
pub fn suggest_principals(
    request: &SuggestPrincipalsRequest,
    candidates: &[PeopleCandidate],
    context: &PeopleContext<'_>,
) -> Result<SuggestPrincipalsResponse, PeopleError> {
    validate_suggest_principals_request(request, context)?;
    let prefix = normalized(&request.prefix);
    let mut members = Vec::new();
    let mut exact = Vec::new();
    for candidate in candidates {
        if candidate.is_agent {
            continue;
        }
        let shared = candidate.spool_ids.iter().any(|id| {
            context.caller_spool_ids.contains(id)
                && request.spool.as_ref().is_none_or(|spool| &spool.id == id)
        });
        let handle = normalized(&candidate.person.handle);
        if shared
            && (handle.starts_with(&prefix)
                || normalized(&candidate.person.display_name).starts_with(&prefix))
        {
            validate_person(&candidate.person)?;
            members.push(candidate.person.clone());
        } else if candidate.is_public && handle == prefix {
            validate_person(&candidate.person)?;
            exact.push(candidate.person.clone());
        }
    }
    exact.sort_by(|a, b| a.handle.cmp(&b.handle));
    members.extend(exact.into_iter().take(1));
    members.sort_by(|a, b| a.handle.cmp(&b.handle));
    members.dedup_by(|a, b| a.handle == b.handle);
    members.truncate(MAX_SUGGESTED_PRINCIPALS);
    Ok(SuggestPrincipalsResponse {
        principals: members,
    })
}

/// Validate against host-trusted current context, never client assertions.
pub fn validate_suggest_principals_response(
    response: &SuggestPrincipalsResponse,
    request: &SuggestPrincipalsRequest,
    candidates: &[PeopleCandidate],
    context: &PeopleContext<'_>,
) -> Result<(), PeopleError> {
    if response != &suggest_principals(request, candidates, context)? {
        return Err(PeopleError::Projection);
    }
    Ok(())
}
