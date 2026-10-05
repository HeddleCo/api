//! Reference completeness only; installed trust is selected by the receiver.
use crate::{
    heddle::api::v1alpha2::{ForeignDependencyOrigin, ForeignDependencyV1, SignedRecord},
    hybrid_codec::{Reject, width},
    import_authority as import,
};

pub(crate) struct References<'a> {
    entries: &'a [ForeignDependencyV1],
    used: Vec<bool>,
}
impl<'a> References<'a> {
    pub(crate) fn new(
        entries: &'a [ForeignDependencyV1],
        carrier: ForeignDependencyOrigin,
    ) -> Result<Self, Reject> {
        for (i, entry) in entries.iter().enumerate() {
            if entry.format_version != 1 {
                return Err(Reject::Version);
            }
            if !matches!(
                ForeignDependencyOrigin::try_from(entry.origin),
                Ok(ForeignDependencyOrigin::Import | ForeignDependencyOrigin::Native)
            ) {
                return Err(Reject::Version);
            }
            if entry.origin == carrier as i32 {
                return Err(Reject::Scope);
            }
            if entry.prefix_admission_order == 0 {
                return Err(Reject::Scope);
            }
            width(&entry.thread_genesis_digest, 32)?;
            width(&entry.signed_native_digest, 32)?;
            if i > 0 && entries[i - 1].signed_native_digest >= entry.signed_native_digest {
                return Err(Reject::Canonical);
            }
        }
        Ok(Self {
            entries,
            used: vec![false; entries.len()],
        })
    }

    pub(crate) fn require(&mut self, record: &SignedRecord) -> Result<(), Reject> {
        let digest = import::signed_native_digest(record)?;
        let thread = thread(record)?;
        let index = self
            .entries
            .iter()
            .position(|entry| {
                entry.signed_native_digest == digest && entry.thread_genesis_digest == thread
            })
            .ok_or(Reject::Scope)?;
        self.used[index] = true;
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<(), Reject> {
        if self.used.iter().any(|used| !used) {
            return Err(Reject::Scope);
        }
        Ok(())
    }
}

pub(crate) fn thread(record: &SignedRecord) -> Result<Vec<u8>, Reject> {
    if record.format == "heddle-thread-genesis-v1" {
        return Ok(import::native_id(record));
    }
    if ![
        "heddle-thread-operation-v1",
        "heddle-thread-ownership-claim-v1",
        "heddle-thread-ownership-resolution-v1",
    ]
    .contains(&record.format.as_str())
    {
        return Err(Reject::Version);
    }
    #[derive(serde::Deserialize)]
    struct Selector {
        thread: [u8; 32],
    }
    let selector: Selector =
        rmp_serde::from_slice(&record.canonical_record).map_err(|_| Reject::Canonical)?;
    Ok(selector.thread.to_vec())
}
