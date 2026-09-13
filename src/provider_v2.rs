//! Canonical native provider-plan consent and exact assembly commitments.
//! Protobuf is a transport container; these bytes are the portable proof.

use crate::heddle::api::v2alpha1::{
    Coverage, EndpointKind, ProviderAssemblyRecord, ProviderExtent, ProviderOffer,
    ProviderPhysicalRange, ProviderPlan, ProviderPlanChallenge, ProviderPlanRegistration,
    ProviderReadTicket, RevisionRef, SharedFacet, ThreadRef, provider_assembly_record,
    revision_ref,
};
use std::collections::HashSet;

pub const PROVIDER_CONSENT_FORMAT: &str = "heddle.provider-consent.v2";
const CONSENT_DOMAIN: &[u8] = b"heddle.provider-consent.v2\0";
const RANGE_DOMAIN: &[u8] = b"heddle.provider-range.v2\0";
const ASSEMBLY_DOMAIN: &[u8] = b"heddle.provider-assembly.v2\0";
const EXTENT_SET_DOMAIN: &[u8] = b"heddle.provider-extent-set.v2\0";
const MAX_RECORDS: usize = 4096;
const MAX_PACK_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DECODED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CAPABILITY_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProviderCanonicalError {
    #[error("provider plan field is missing or invalid: {0}")]
    Invalid(&'static str),
    #[error("provider plan exceeds canonical bound")]
    Bound,
}

fn sized(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ProviderCanonicalError> {
    let size = u32::try_from(value.len()).map_err(|_| ProviderCanonicalError::Bound)?;
    output.extend_from_slice(&size.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn exact_32(value: &[u8], name: &'static str) -> Result<(), ProviderCanonicalError> {
    if value.len() != 32 {
        return Err(ProviderCanonicalError::Invalid(name));
    }
    Ok(())
}

fn canonical_uuid(value: &str) -> bool {
    value != "00000000-0000-0000-0000-000000000000"
        && value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn endpoint_key(
    value: &Option<crate::heddle::api::v2alpha1::EndpointRef>,
    kind: EndpointKind,
) -> Result<&[u8], ProviderCanonicalError> {
    let endpoint = value
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("endpoint"))?;
    if endpoint.kind != kind as i32 {
        return Err(ProviderCanonicalError::Invalid("endpoint kind"));
    }
    exact_32(&endpoint.public_key, "endpoint key")?;
    Ok(&endpoint.public_key)
}

fn range_bytes(
    range: &ProviderPhysicalRange,
    out: &mut Vec<u8>,
) -> Result<(), ProviderCanonicalError> {
    exact_32(&range.pack_id, "pack ID")?;
    if range.object_etag.is_empty()
        || range.object_etag.len() > 256
        || range.length == 0
        || range.offset.checked_add(range.length).is_none()
    {
        return Err(ProviderCanonicalError::Invalid("physical range"));
    }
    sized(out, &range.pack_id)?;
    sized(out, range.object_etag.as_bytes())?;
    out.extend_from_slice(&range.offset.to_be_bytes());
    out.extend_from_slice(&range.length.to_be_bytes());
    Ok(())
}

/// Commit the exact encoded records tiling one provider physical range. The
/// digest is metadata; the receiver verifies each encoded byte hash on read.
pub fn provider_record_set_commitment(
    range: &ProviderPhysicalRange,
    records: &[ProviderAssemblyRecord],
    extent_index: u32,
) -> Result<[u8; 32], ProviderCanonicalError> {
    if records.len() > MAX_RECORDS {
        return Err(ProviderCanonicalError::Bound);
    }
    commitment_from_refs(range, records.iter().filter(|record| matches!(&record.source,
        Some(provider_assembly_record::Source::Provider(source)) if source.extent_index == extent_index)))
}

fn commitment_from_refs<'a>(
    range: &ProviderPhysicalRange,
    records: impl Iterator<Item = &'a ProviderAssemblyRecord>,
) -> Result<[u8; 32], ProviderCanonicalError> {
    let mut out = RANGE_DOMAIN.to_vec();
    range_bytes(range, &mut out)?;
    let mut next = 0_u64;
    let mut count = 0_u32;
    for record in records {
        let Some(provider_assembly_record::Source::Provider(source)) = &record.source else {
            return Err(ProviderCanonicalError::Invalid("record source"));
        };
        if source.source_offset != next || record.encoded_length == 0 {
            return Err(ProviderCanonicalError::Invalid("range tiling"));
        }
        let digest = record
            .encoded_digest
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("encoded digest"))?;
        if digest.algorithm != "blake3" {
            return Err(ProviderCanonicalError::Invalid("encoded digest algorithm"));
        }
        exact_32(&digest.digest, "encoded digest")?;
        next = next
            .checked_add(record.encoded_length)
            .ok_or(ProviderCanonicalError::Bound)?;
        count = count.checked_add(1).ok_or(ProviderCanonicalError::Bound)?;
        sized(&mut out, &digest.digest)?;
        out.extend_from_slice(&record.encoded_length.to_be_bytes());
    }
    if count == 0 || next != range.length {
        return Err(ProviderCanonicalError::Invalid("range coverage"));
    }
    out.extend_from_slice(&count.to_be_bytes());
    Ok(*blake3::hash(&out).as_bytes())
}

fn grouped_commitments(plan: &ProviderPlan) -> Result<Vec<[u8; 32]>, ProviderCanonicalError> {
    if plan.extents.is_empty()
        || plan.extents.len() > MAX_RECORDS
        || plan.records.len() > MAX_RECORDS
    {
        return Err(ProviderCanonicalError::Bound);
    }
    let mut groups = vec![Vec::new(); plan.extents.len()];
    for record in &plan.records {
        if let Some(provider_assembly_record::Source::Provider(source)) = &record.source {
            let group = groups
                .get_mut(source.extent_index as usize)
                .ok_or(ProviderCanonicalError::Invalid("extent index"))?;
            group.push(record);
        }
    }
    plan.extents
        .iter()
        .zip(groups)
        .map(|(extent, group)| {
            let range = extent
                .range
                .as_ref()
                .ok_or(ProviderCanonicalError::Invalid("range"))?;
            commitment_from_refs(range, group.into_iter())
        })
        .collect()
}

/// Canonical native authorized extent set, independent of virtual output
/// placement and the later client consent. Order is the plan's exact order.
pub fn provider_extent_set_digest(plan: &ProviderPlan) -> Result<[u8; 32], ProviderCanonicalError> {
    if plan.extents.is_empty() || plan.extents.len() > MAX_RECORDS {
        return Err(ProviderCanonicalError::Bound);
    }
    let mut out = EXTENT_SET_DOMAIN.to_vec();
    out.extend_from_slice(&(plan.extents.len() as u32).to_be_bytes());
    let commitments = grouped_commitments(plan)?;
    let mut selected_root: Option<&[u8]> = None;
    for (index, extent) in plan.extents.iter().enumerate() {
        let provider = endpoint_key(&extent.provider, EndpointKind::Provider)?;
        let range = extent
            .range
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("range"))?;
        let commitment = commitments[index];
        if range.record_set_commitment != commitment {
            return Err(ProviderCanonicalError::Invalid("record set commitment"));
        }
        let ticket = extent
            .ticket
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("ticket"))?;
        if endpoint_key(&ticket.provider, EndpointKind::Provider)? != provider
            || ticket.pack_id != range.pack_id
            || ticket.object_etag != range.object_etag
            || ticket.offset != range.offset
            || ticket.length != range.length
            || ticket.record_set_commitment != commitment
        {
            return Err(ProviderCanonicalError::Invalid("ticket range binding"));
        }
        let spool = ticket
            .spool
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("ticket Spool"))?;
        if !canonical_uuid(&spool.id)
            || ticket.audience.is_empty()
            || ticket.audience.len() > 256
            || ticket.facet != SharedFacet::Source as i32
            || ticket.attenuated_capability.len() > MAX_CAPABILITY_BYTES
        {
            return Err(ProviderCanonicalError::Invalid("ticket scope"));
        }
        exact_32(&ticket.content_root, "content root")?;
        if let Some(root) = selected_root {
            if root != ticket.content_root {
                return Err(ProviderCanonicalError::Invalid("content root mismatch"));
            }
        } else {
            selected_root = Some(&ticket.content_root);
        }
        sized(&mut out, provider)?;
        range_bytes(range, &mut out)?;
        sized(&mut out, &commitment)?;
        sized(&mut out, spool.id.as_bytes())?;
        out.extend_from_slice(&ticket.facet.to_be_bytes());
        sized(&mut out, ticket.audience.as_bytes())?;
        sized(&mut out, &ticket.content_root)?;
    }
    Ok(*blake3::hash(&out).as_bytes())
}

/// Exact virtual LMPK v4 assembly commitment. Tickets and capabilities are
/// attached only after this digest exists, so neither is an input to itself.
pub fn provider_assembly_digest(plan: &ProviderPlan) -> Result<[u8; 32], ProviderCanonicalError> {
    if plan.records.is_empty()
        || plan.records.len() > MAX_RECORDS
        || plan.extents.len() > MAX_RECORDS
    {
        return Err(ProviderCanonicalError::Bound);
    }
    if plan.output_pack_length > MAX_PACK_BYTES {
        return Err(ProviderCanonicalError::Bound);
    }
    let challenge = plan
        .challenge
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("challenge"))?;
    if challenge.nonce.len() != 16 {
        return Err(ProviderCanonicalError::Invalid("nonce"));
    }
    if plan.extent_set_digest != provider_extent_set_digest(plan)? {
        return Err(ProviderCanonicalError::Invalid("extent set digest"));
    }
    if challenge.extent_set_digest != plan.extent_set_digest {
        return Err(ProviderCanonicalError::Invalid("extent set disagreement"));
    }
    let issuer = endpoint_key(&challenge.issuer, EndpointKind::Weft)?;
    let client = endpoint_key(&challenge.client, EndpointKind::Device)?;
    let thread = challenge
        .thread
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("Thread"))?;
    let thread_spool = spool_id(thread)?;
    exact_32(
        &thread
            .id
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("Thread ID"))?
            .value,
        "Thread ID",
    )?;
    let revision = challenge
        .revision
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("revision"))?;
    let (revision_spool, state_id) = state_revision(revision)?;
    if revision_spool != thread_spool {
        return Err(ProviderCanonicalError::Invalid("source Spool mismatch"));
    }
    if plan.pack_header.len() != 16
        || &plan.pack_header[..4] != b"LMPK"
        || plan.pack_header[4..8] != 4_u32.to_be_bytes()
        || plan.pack_header[8..] != (plan.records.len() as u64).to_be_bytes()
    {
        return Err(ProviderCanonicalError::Invalid("LMPK header"));
    }
    let expiry = challenge
        .expires_at
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("expiry"))?;
    if expiry.seconds <= 0 || !(0..1_000_000_000).contains(&expiry.nanos) {
        return Err(ProviderCanonicalError::Invalid("expiry"));
    }
    let mut out = ASSEMBLY_DOMAIN.to_vec();
    let commitments = grouped_commitments(plan)?;
    sized(&mut out, &challenge.nonce)?;
    sized(&mut out, thread_spool.as_bytes())?;
    sized(
        &mut out,
        &thread
            .id
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("Thread ID"))?
            .value,
    )?;
    sized(&mut out, state_id)?;
    sized(&mut out, issuer)?;
    sized(&mut out, client)?;
    out.extend_from_slice(&expiry.seconds.to_be_bytes());
    out.extend_from_slice(&expiry.nanos.to_be_bytes());
    sized(&mut out, &plan.extent_set_digest)?;
    sized(&mut out, &plan.pack_header)?;
    out.extend_from_slice(&plan.output_pack_length.to_be_bytes());
    out.extend_from_slice(&(plan.extents.len() as u32).to_be_bytes());
    for (index, extent) in plan.extents.iter().enumerate() {
        let provider = endpoint_key(&extent.provider, EndpointKind::Provider)?;
        let range = extent
            .range
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("range"))?;
        let commitment = commitments[index];
        if range.record_set_commitment != commitment {
            return Err(ProviderCanonicalError::Invalid("record set commitment"));
        }
        let ticket = extent
            .ticket
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("ticket"))?;
        if endpoint_key(&ticket.provider, EndpointKind::Provider)? != provider
            || endpoint_key(&ticket.client, EndpointKind::Device)? != client
            || ticket.pack_id != range.pack_id
            || ticket.object_etag != range.object_etag
            || ticket.offset != range.offset
            || ticket.length != range.length
            || ticket.record_set_commitment != commitment
            || ticket.extent_set_digest != plan.extent_set_digest
            || ticket.spool.as_ref().map(|s| s.id.as_str()) != Some(thread_spool)
        {
            return Err(ProviderCanonicalError::Invalid("ticket range binding"));
        }
        sized(&mut out, provider)?;
        range_bytes(range, &mut out)?;
        sized(&mut out, &commitment)?;
        sized(
            &mut out,
            ticket
                .spool
                .as_ref()
                .ok_or(ProviderCanonicalError::Invalid("ticket Spool"))?
                .id
                .as_bytes(),
        )?;
        out.extend_from_slice(&ticket.facet.to_be_bytes());
        sized(&mut out, ticket.audience.as_bytes())?;
        sized(&mut out, &ticket.content_root)?;
        let ticket_expiry = ticket
            .expires_at
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("ticket expiry"))?;
        if ticket_expiry != expiry {
            return Err(ProviderCanonicalError::Invalid("ticket expiry"));
        }
    }
    out.extend_from_slice(&(plan.records.len() as u32).to_be_bytes());
    let mut next = 16_u64;
    let mut decoded_bytes = 0_u64;
    let mut objects = HashSet::with_capacity(plan.records.len());
    for record in &plan.records {
        if record.output_offset != next || record.encoded_length == 0 {
            return Err(ProviderCanonicalError::Invalid("output tiling"));
        }
        next = next
            .checked_add(record.encoded_length)
            .ok_or(ProviderCanonicalError::Bound)?;
        let object = record
            .object
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("object"))?;
        let address = object
            .address
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("object address"))?;
        let digest = record
            .encoded_digest
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("encoded digest"))?;
        exact_32(&address.digest, "object digest")?;
        exact_32(&digest.digest, "encoded digest")?;
        if address.algorithm != "blake3"
            || digest.algorithm != "blake3"
            || !matches!(object.kind.as_str(), "blob" | "tree" | "state")
            || object.facet != SharedFacet::Source as i32
            || object.availability != Coverage::Complete as i32
        {
            return Err(ProviderCanonicalError::Invalid("source object descriptor"));
        }
        decoded_bytes = decoded_bytes
            .checked_add(object.size)
            .ok_or(ProviderCanonicalError::Bound)?;
        if decoded_bytes > MAX_DECODED_BYTES || next > MAX_PACK_BYTES {
            return Err(ProviderCanonicalError::Bound);
        }
        if !objects.insert((address.algorithm.as_str(), address.digest.as_slice())) {
            return Err(ProviderCanonicalError::Invalid("duplicate object"));
        }
        sized(&mut out, address.algorithm.as_bytes())?;
        sized(&mut out, &address.digest)?;
        sized(&mut out, object.kind.as_bytes())?;
        out.extend_from_slice(&object.facet.to_be_bytes());
        out.extend_from_slice(&object.size.to_be_bytes());
        sized(&mut out, digest.algorithm.as_bytes())?;
        sized(&mut out, &digest.digest)?;
        out.extend_from_slice(&record.output_offset.to_be_bytes());
        out.extend_from_slice(&record.encoded_length.to_be_bytes());
        match &record.source {
            Some(provider_assembly_record::Source::Provider(source))
                if (source.extent_index as usize) < plan.extents.len() =>
            {
                out.push(1);
                out.extend_from_slice(&source.extent_index.to_be_bytes());
                out.extend_from_slice(&source.source_offset.to_be_bytes());
            }
            Some(provider_assembly_record::Source::Inline(_)) => out.push(2),
            _ => return Err(ProviderCanonicalError::Invalid("record source")),
        }
    }
    if next.checked_add(32) != Some(plan.output_pack_length) {
        return Err(ProviderCanonicalError::Invalid("output length"));
    }
    Ok(*blake3::hash(&out).as_bytes())
}

/// Verify a finalized plan after the issuer has populated both digests in
/// the challenge and every ticket. The digest computation itself omits these
/// fields so the issuer can construct the plan without a circular input.
pub fn validate_provider_plan(plan: &ProviderPlan) -> Result<(), ProviderCanonicalError> {
    let assembly = provider_assembly_digest(plan)?;
    let challenge = plan
        .challenge
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("challenge"))?;
    if plan.assembly_digest != assembly || challenge.assembly_digest != assembly {
        return Err(ProviderCanonicalError::Invalid(
            "assembly digest disagreement",
        ));
    }
    for extent in &plan.extents {
        let ticket = extent
            .ticket
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("ticket"))?;
        if ticket.attenuated_capability.is_empty() || ticket.assembly_digest != assembly {
            return Err(ProviderCanonicalError::Invalid("ticket assembly digest"));
        }
    }
    Ok(())
}

/// Materialize a capability-free offer as an in-memory layout. This is never
/// a serving grant: empty capabilities make `validate_provider_plan` reject it.
/// It exists so offer and final-plan digests share one canonical implementation.
pub fn provider_offer_as_plan(
    offer: &ProviderOffer,
) -> Result<ProviderPlan, ProviderCanonicalError> {
    let challenge = offer
        .challenge
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("offer challenge"))?;
    let client = challenge
        .client
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("offer client"))?;
    let expiry = challenge
        .expires_at
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("offer expiry"))?;
    if offer.extents.is_empty() || offer.extents.len() > MAX_RECORDS {
        return Err(ProviderCanonicalError::Bound);
    }
    let extents = offer
        .extents
        .iter()
        .map(|offered| {
            let range = offered
                .range
                .as_ref()
                .ok_or(ProviderCanonicalError::Invalid("offer range"))?;
            Ok(ProviderExtent {
                provider: offered.provider.clone(),
                range: Some(range.clone()),
                ticket: Some(ProviderReadTicket {
                    attenuated_capability: Vec::new(),
                    extent_set_digest: offer.extent_set_digest.clone(),
                    spool: offered.spool.clone(),
                    facet: offered.facet,
                    audience: offered.audience.clone(),
                    content_root: offered.content_root.clone(),
                    pack_id: range.pack_id.clone(),
                    object_etag: range.object_etag.clone(),
                    offset: range.offset,
                    length: range.length,
                    provider: offered.provider.clone(),
                    client: Some(client.clone()),
                    assembly_digest: offer.assembly_digest.clone(),
                    expires_at: Some(*expiry),
                    record_set_commitment: range.record_set_commitment.clone(),
                }),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProviderPlan {
        extent_set_digest: offer.extent_set_digest.clone(),
        extents,
        challenge: offer.challenge.clone(),
        assembly_digest: offer.assembly_digest.clone(),
        pack_header: offer.pack_header.clone(),
        output_pack_length: offer.output_pack_length,
        records: offer.records.clone(),
    })
}

/// Verify an unsigned offer's exact physical and virtual layout. The offer
/// cannot authorize serving because it carries no capability-bearing ticket.
pub fn validate_provider_offer(offer: &ProviderOffer) -> Result<(), ProviderCanonicalError> {
    let layout = provider_offer_as_plan(offer)?;
    if layout.extent_set_digest != provider_extent_set_digest(&layout)?
        || layout.assembly_digest != provider_assembly_digest(&layout)?
    {
        return Err(ProviderCanonicalError::Invalid("offer digest disagreement"));
    }
    Ok(())
}

/// The issued plan must preserve exactly the candidate layout the client
/// signed. Ticket capabilities are added only after consent.
pub fn validate_plan_for_offer(
    offer: &ProviderOffer,
    plan: &ProviderPlan,
) -> Result<(), ProviderCanonicalError> {
    validate_provider_offer(offer)?;
    validate_provider_plan(plan)?;
    let candidate = provider_offer_as_plan(offer)?;
    if candidate.extent_set_digest != plan.extent_set_digest
        || candidate.assembly_digest != plan.assembly_digest
        || candidate.challenge != plan.challenge
        || candidate.pack_header != plan.pack_header
        || candidate.output_pack_length != plan.output_pack_length
        || candidate.records != plan.records
        || candidate.extents.len() != plan.extents.len()
    {
        return Err(ProviderCanonicalError::Invalid(
            "issued plan differs from offer",
        ));
    }
    for (candidate, issued) in candidate.extents.iter().zip(&plan.extents) {
        if candidate.provider != issued.provider || candidate.range != issued.range {
            return Err(ProviderCanonicalError::Invalid(
                "issued range differs from offer",
            ));
        }
        let Some(candidate_ticket) = candidate.ticket.as_ref() else {
            return Err(ProviderCanonicalError::Invalid("offer scope"));
        };
        let Some(issued_ticket) = issued.ticket.as_ref() else {
            return Err(ProviderCanonicalError::Invalid("issued ticket"));
        };
        if candidate_ticket.spool != issued_ticket.spool
            || candidate_ticket.facet != issued_ticket.facet
            || candidate_ticket.audience != issued_ticket.audience
            || candidate_ticket.content_root != issued_ticket.content_root
        {
            return Err(ProviderCanonicalError::Invalid(
                "issued scope differs from offer",
            ));
        }
    }
    Ok(())
}

/// Validate the trusted publisher's private R2 placement map. Only the
/// operator-authenticated registration path may persist this message; it is
/// never a client-visible grant or a substitute for live source admission.
pub fn validate_provider_registration(
    registration: &ProviderPlanRegistration,
) -> Result<(), ProviderCanonicalError> {
    let plan = registration
        .plan
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("registered plan"))?;
    validate_provider_plan(plan)?;
    let serving_provider = endpoint_key(&registration.serving_provider, EndpointKind::Provider)?;
    let selected = plan
        .extents
        .iter()
        .filter(|extent| {
            extent
                .provider
                .as_ref()
                .is_some_and(|provider| provider.public_key == serving_provider)
        })
        .collect::<Vec<_>>();
    if selected.is_empty()
        || registration.packs.is_empty()
        || registration.packs.len() > selected.len()
    {
        return Err(ProviderCanonicalError::Invalid("registered pack count"));
    }
    let mut locations = std::collections::HashSet::with_capacity(registration.packs.len());
    for pack in &registration.packs {
        exact_32(&pack.pack_id, "registered pack ID")?;
        if pack.object_key.is_empty()
            || pack.object_key.len() > 1024
            || pack.object_key.chars().any(char::is_control)
            || !locations.insert(pack.pack_id.as_slice())
        {
            return Err(ProviderCanonicalError::Invalid("registered pack location"));
        }
    }
    for extent in &selected {
        let range = extent
            .range
            .as_ref()
            .ok_or(ProviderCanonicalError::Invalid("registered range"))?;
        if !locations.contains(range.pack_id.as_slice()) {
            return Err(ProviderCanonicalError::Invalid("registered pack missing"));
        }
    }
    if locations.len() != registration.packs.len()
        || registration.packs.iter().any(|pack| {
            !selected.iter().any(|extent| {
                extent
                    .range
                    .as_ref()
                    .is_some_and(|range| range.pack_id == pack.pack_id)
            })
        })
    {
        return Err(ProviderCanonicalError::Invalid(
            "unreferenced registered pack",
        ));
    }
    Ok(())
}

fn spool_id(reference: &ThreadRef) -> Result<&str, ProviderCanonicalError> {
    let spool = reference
        .spool
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("Thread Spool"))?;
    if !canonical_uuid(&spool.id) {
        return Err(ProviderCanonicalError::Invalid("Spool ID"));
    }
    Ok(&spool.id)
}

fn state_revision(reference: &RevisionRef) -> Result<(&str, &[u8]), ProviderCanonicalError> {
    let spool = reference
        .spool
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("revision Spool"))?;
    let Some(revision_ref::Revision::State(state)) = reference.revision.as_ref() else {
        return Err(ProviderCanonicalError::Invalid("provider State revision"));
    };
    exact_32(&state.value, "State ID")?;
    Ok((&spool.id, &state.value))
}

/// Length-delimited, domain-separated v2 client consent. The challenge was
/// carried on the authenticated Fetch stream; this signature binds the
/// caller's stable identity and exact selected source, endpoints, expiry,
/// authorized extent set, and virtual assembly without signing protobuf bytes.
pub fn provider_consent_signing_bytes(
    challenge: &ProviderPlanChallenge,
    signing_identity: &str,
) -> Result<Vec<u8>, ProviderCanonicalError> {
    if signing_identity.is_empty() || signing_identity.len() > 256 {
        return Err(ProviderCanonicalError::Invalid("signing identity"));
    }
    if challenge.nonce.len() != 16 {
        return Err(ProviderCanonicalError::Invalid("plan nonce"));
    }
    exact_32(&challenge.extent_set_digest, "extent set digest")?;
    exact_32(&challenge.assembly_digest, "assembly digest")?;
    let thread = challenge
        .thread
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("Thread"))?;
    let thread_spool = spool_id(thread)?;
    let thread_id = &thread
        .id
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("Thread ID"))?
        .value;
    exact_32(thread_id, "Thread ID")?;
    let revision = challenge
        .revision
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("revision"))?;
    let (revision_spool, state_id) = state_revision(revision)?;
    if thread_spool != revision_spool {
        return Err(ProviderCanonicalError::Invalid("source Spool mismatch"));
    }
    let issuer = challenge
        .issuer
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("issuer"))?;
    let client = challenge
        .client
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("client"))?;
    if issuer.kind != EndpointKind::Weft as i32 || client.kind != EndpointKind::Device as i32 {
        return Err(ProviderCanonicalError::Invalid("endpoint kind"));
    }
    exact_32(&issuer.public_key, "issuer key")?;
    exact_32(&client.public_key, "client key")?;
    let expiry = challenge
        .expires_at
        .as_ref()
        .ok_or(ProviderCanonicalError::Invalid("expiry"))?;
    if expiry.seconds <= 0 || !(0..1_000_000_000).contains(&expiry.nanos) {
        return Err(ProviderCanonicalError::Invalid("expiry"));
    }
    let mut output = Vec::with_capacity(512);
    output.extend_from_slice(CONSENT_DOMAIN);
    output.extend_from_slice(&1_u32.to_be_bytes());
    sized(&mut output, signing_identity.as_bytes())?;
    sized(&mut output, &challenge.nonce)?;
    sized(&mut output, thread_spool.as_bytes())?;
    sized(&mut output, thread_id)?;
    sized(&mut output, state_id)?;
    sized(&mut output, &issuer.public_key)?;
    sized(&mut output, &client.public_key)?;
    output.extend_from_slice(&expiry.seconds.to_be_bytes());
    output.extend_from_slice(&expiry.nanos.to_be_bytes());
    sized(&mut output, &challenge.extent_set_digest)?;
    sized(&mut output, &challenge.assembly_digest)?;
    Ok(output)
}
