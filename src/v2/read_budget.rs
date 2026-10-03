//! Endpoint-independent read budgets, using the generated wire type everywhere.
use crate::heddle::api::v1alpha2::ReadBudget;

/// Minimum advertised maximum on every endpoint, including devices/providers.
pub const GUARANTEED_READ_BUDGET: ReadBudget = ReadBudget {
    max_items: 1024,
    max_frame_bytes: 524_288,
    max_snapshot_bytes: 4_194_304,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReadBudgetError {
    #[error("invalid ReadBudget advertisement")]
    Advertisement,
    #[error("structurally impossible ReadBudget shape")]
    Shape,
    #[error("retryable ReadBudget capacity shortage")]
    Capacity,
    #[error("missing or invalid accepted ReadBudget echo")]
    Echo,
}

fn nonzero(b: &ReadBudget) -> bool {
    b.max_items > 0 && b.max_frame_bytes > 0 && b.max_snapshot_bytes > 0
}

fn within(a: &ReadBudget, b: &ReadBudget) -> bool {
    a.max_items <= b.max_items
        && a.max_frame_bytes <= b.max_frame_bytes
        && a.max_snapshot_bytes <= b.max_snapshot_bytes
}

fn minimum(a: &ReadBudget, b: &ReadBudget) -> ReadBudget {
    ReadBudget {
        max_items: a.max_items.min(b.max_items),
        max_frame_bytes: a.max_frame_bytes.min(b.max_frame_bytes),
        max_snapshot_bytes: a.max_snapshot_bytes.min(b.max_snapshot_bytes),
    }
}

fn resolve(requested: &ReadBudget, defaults: &ReadBudget) -> ReadBudget {
    ReadBudget {
        max_items: if requested.max_items == 0 {
            defaults.max_items
        } else {
            requested.max_items
        },
        max_frame_bytes: if requested.max_frame_bytes == 0 {
            defaults.max_frame_bytes
        } else {
            requested.max_frame_bytes
        },
        max_snapshot_bytes: if requested.max_snapshot_bytes == 0 {
            defaults.max_snapshot_bytes
        } else {
            requested.max_snapshot_bytes
        },
    }
}

/// Clamp before querying matching data. Hosts additionally validate fixed
/// selection/control overhead against this result, never against match counts.
/// Map Shape to INVALID_ARGUMENT and Capacity to retryable UNAVAILABLE.
pub fn negotiate_read_budget(
    requested: &ReadBudget,
    defaults: &ReadBudget,
    maximum: &ReadBudget,
    capacity: &ReadBudget,
) -> Result<ReadBudget, ReadBudgetError> {
    if !nonzero(defaults)
        || !within(defaults, maximum)
        || !within(&GUARANTEED_READ_BUDGET, maximum)
        || defaults.max_frame_bytes < 1024
        || defaults.max_snapshot_bytes < u64::from(defaults.max_frame_bytes)
    {
        return Err(ReadBudgetError::Advertisement);
    }
    let resolved = resolve(requested, defaults);
    let bounded = minimum(&resolved, maximum);
    if bounded.max_frame_bytes < 1024
        || bounded.max_snapshot_bytes < u64::from(bounded.max_frame_bytes)
    {
        return Err(ReadBudgetError::Shape);
    }
    let accepted = minimum(&bounded, capacity);
    if !within(&minimum(&resolved, &GUARANTEED_READ_BUDGET), &accepted)
        || accepted.max_frame_bytes < 1024
        || accepted.max_snapshot_bytes < u64::from(accepted.max_frame_bytes)
    {
        return Err(ReadBudgetError::Capacity);
    }
    Ok(accepted)
}

/// Validate the mandatory echo without DescribeEndpoint. Zero requests leave
/// default choice to the server; a client cannot infer its advertised default.
pub fn validate_accepted_read_budget(
    requested: &ReadBudget,
    accepted: Option<&ReadBudget>,
) -> Result<(), ReadBudgetError> {
    let accepted = accepted.ok_or(ReadBudgetError::Echo)?;
    let unlimited = ReadBudget {
        max_items: u32::MAX,
        max_frame_bytes: u32::MAX,
        max_snapshot_bytes: u64::MAX,
    };
    let upper = resolve(requested, &unlimited);
    // A zero request has no client-known lower bound beyond a valid shape.
    let lower = minimum(requested, &GUARANTEED_READ_BUDGET);
    if !nonzero(accepted)
        || !within(accepted, &upper)
        || !within(&lower, accepted)
        || accepted.max_frame_bytes < 1024
        || accepted.max_snapshot_bytes < u64::from(accepted.max_frame_bytes)
    {
        return Err(ReadBudgetError::Echo);
    }
    Ok(())
}
