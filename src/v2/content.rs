//! Bounded per-file outline inputs, rows and terminal coverage.
use crate::heddle::api::v1alpha2::{
    Coverage, OutlineRead, OutlineSymbol, SectionStatus, SectionStatusReason,
};
use crate::hybrid_codec::Reject;
use prost::Message;

pub const DEFAULT_OUTLINE_PAGE_SIZE: u32 = 100;
pub const MAX_OUTLINE_PAGE_SIZE: u32 = 256;
pub const MAX_OUTLINE_SYMBOL_BYTES: usize = 16384;
fn text(value: &str, nonempty: bool) -> Result<(), Reject> {
    if value.len() > 4096 {
        return Err(Reject::Bounds);
    }
    if value.chars().any(char::is_control) || (nonempty && value.trim().is_empty()) {
        return Err(Reject::Canonical);
    }
    Ok(())
}
pub fn validate_outline_read(value: &OutlineRead) -> Result<(), Reject> {
    text(&value.path, true)?;
    if value.path.contains(['\\', ':'])
        || value.path.split('/').any(|s| matches!(s, "" | "." | ".."))
    {
        return Err(Reject::Canonical);
    }
    if value
        .page
        .as_ref()
        .is_some_and(|p| p.size > MAX_OUTLINE_PAGE_SIZE || p.after_page.len() > 4096)
    {
        return Err(Reject::Bounds);
    }
    Ok(())
}
pub fn validate_outline_symbol(value: &OutlineSymbol) -> Result<(), Reject> {
    text(&value.name, true)?;
    text(&value.container, false)?;
    text(&value.symbol_id, true)?;
    if !(1..=10).contains(&value.kind) || value.start_line == 0 || value.end_line < value.start_line
    {
        return Err(Reject::Canonical);
    }
    if value.encoded_len() > MAX_OUTLINE_SYMBOL_BYTES {
        return Err(Reject::Bounds);
    }
    Ok(())
}
pub fn validate_outline_status(value: &SectionStatus) -> Result<(), Reject> {
    if value.section != "outline" || value.computed_for.is_none() {
        return Err(Reject::Canonical);
    }
    let page = value.page.as_ref().ok_or(Reject::Canonical)?;
    let coverage = Coverage::try_from(value.coverage).map_err(|_| Reject::Canonical)?;
    if !matches!(
        coverage,
        Coverage::Complete | Coverage::Partial | Coverage::Unavailable
    ) || ((coverage == Coverage::Complete)
        != (value.reason == SectionStatusReason::Unspecified as i32))
        || (page.exhausted && !page.next_page.is_empty())
        || (coverage == Coverage::Unavailable
            && (!page.exhausted || !page.next_page.is_empty() || page.matching_count.is_some()))
    {
        return Err(Reject::Canonical);
    }
    Ok(())
}
