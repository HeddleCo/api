//! Bounded immutable SOURCE contract. Structural validation is not authorization:
//! hosts resolve handles and authenticate the exact user/principal separately.
use crate::heddle::api::v1alpha2::*;
use prost::Message;
use sha2::{Digest, Sha256};

pub const DEFAULT_MAX_CACHE_TTL_SECONDS: u32 = 60;
pub const MAX_SNAPSHOT_WIRE_BYTES: usize = 512 * 1024;
pub const MAX_REQUEST_WIRE_BYTES: usize = 64 * 1024;
pub const OBJECT_LIMITS: ImmutableObjectLimits = ImmutableObjectLimits {
    max_batch_objects: 512,
    max_response_bytes: 4 * 1024 * 1024,
    max_chunk_bytes: 512 * 1024,
    max_in_flight_batches: 4,
    max_inventory_objects: 4096,
    max_snapshot_bytes: 256 * 1024 * 1024,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ObjectContractError {
    #[error("immutable object limit exceeded or invalid")]
    Limits,
    #[error("malformed immutable object identity or snapshot")]
    Malformed,
    #[error("immutable object authority binding mismatch")]
    Binding,
    #[error("immutable object unavailable in authorized inventory")]
    Unavailable,
    #[error("immutable object authorization expired")]
    Expired,
    #[error("immutable object response integrity or continuity failure")]
    Integrity,
}
use ObjectContractError as Error;

pub fn validate_limits(l: &ImmutableObjectLimits) -> Result<(), Error> {
    let cap = &OBJECT_LIMITS;
    for (n, max) in [
        (l.max_batch_objects, cap.max_batch_objects),
        (l.max_response_bytes, cap.max_response_bytes),
        (l.max_chunk_bytes, cap.max_chunk_bytes),
        (l.max_in_flight_batches, cap.max_in_flight_batches),
        (l.max_inventory_objects, cap.max_inventory_objects),
    ] {
        if n == 0 || n > max {
            return Err(Error::Limits);
        }
    }
    if l.max_snapshot_bytes == 0
        || l.max_snapshot_bytes > cap.max_snapshot_bytes
        || l.max_chunk_bytes > l.max_response_bytes
    {
        return Err(Error::Limits);
    }
    Ok(())
}

pub fn validate_id(id: &ImmutableObjectId) -> Result<(), Error> {
    if !matches!(id.kind, 1 | 2) || id.algorithm != "blake3" || id.digest.len() != 32 {
        return Err(Error::Malformed);
    }
    Ok(())
}

fn entry_id(e: &ImmutableObjectInventoryEntry) -> Result<&ImmutableObjectId, Error> {
    let id = e.id.as_ref().ok_or(Error::Malformed)?;
    validate_id(id)?;
    Ok(id)
}

pub fn validate_snapshot(s: &ImmutableObjectSnapshot) -> Result<(), Error> {
    let l = s.limits.as_ref().ok_or(Error::Limits)?;
    validate_limits(l)?;
    if s.encoded_len() > MAX_SNAPSHOT_WIRE_BYTES
        || s.inventory.is_empty()
        || s.inventory.len() > l.max_inventory_objects as usize
    {
        return Err(Error::Limits);
    }
    if s.format_version != 1
        || s.user_id.len() != 16
        || s.spool_id.len() != 16
        || s.user_id.iter().all(|b| *b == 0)
        || s.spool_id.iter().all(|b| *b == 0)
        || [
            &s.host_public_key,
            &s.principal_sha256,
            &s.thread_id,
            &s.state_id,
            &s.view_digest,
        ]
        .iter()
        .any(|b| b.len() != 32)
    {
        return Err(Error::Malformed);
    }
    let root = s.root_tree.as_ref().ok_or(Error::Malformed)?;
    validate_id(root)?;
    if root.kind != 1 {
        return Err(Error::Malformed);
    }
    if s.max_cache_ttl_seconds == 0
        || s.expires_at_unix_seconds <= s.authorized_at_unix_seconds
        || s.expires_at_unix_seconds - s.authorized_at_unix_seconds
            > u64::from(s.max_cache_ttl_seconds)
    {
        return Err(Error::Limits);
    }
    let mut previous = None;
    let mut total = 0u64;
    let mut found_root = false;
    for entry in &s.inventory {
        let id = entry_id(entry)?;
        let key = (id.kind, id.digest.as_slice());
        if previous.is_some_and(|p| p >= key) {
            return Err(Error::Malformed);
        }
        previous = Some(key);
        total = total
            .checked_add(entry.decoded_length)
            .ok_or(Error::Limits)?;
        if total > l.max_snapshot_bytes {
            return Err(Error::Limits);
        }
        found_root |= id == root;
    }
    if !found_root {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// SHA-256 of the explicit version-1 transcript documented with the contract.
/// No protobuf serialization, session handle, or bearer token enters a cache key.
pub fn authority_binding(s: &ImmutableObjectSnapshot) -> Result<[u8; 32], Error> {
    validate_snapshot(s)?;
    let mut h = Sha256::new();
    h.update(b"heddle-object-authority-v1\0");
    for b in [
        &s.host_public_key,
        &s.user_id,
        &s.principal_sha256,
        &s.spool_id,
        &s.thread_id,
        &s.state_id,
        &s.view_digest,
    ] {
        h.update(b);
    }
    for n in [s.authorization_epoch, s.visibility_epoch] {
        h.update(n.to_be_bytes());
    }
    h.update(&s.root_tree.as_ref().ok_or(Error::Malformed)?.digest);
    h.update((s.inventory.len() as u32).to_be_bytes());
    for e in &s.inventory {
        let id = entry_id(e)?;
        h.update([id.kind as u8]);
        h.update(&id.digest);
        h.update(e.decoded_length.to_be_bytes());
    }
    let l = s.limits.as_ref().ok_or(Error::Limits)?;
    for n in [
        l.max_batch_objects,
        l.max_response_bytes,
        l.max_chunk_bytes,
        l.max_in_flight_batches,
        l.max_inventory_objects,
    ] {
        h.update(n.to_be_bytes());
    }
    for n in [
        l.max_snapshot_bytes,
        s.authorized_at_unix_seconds,
        s.expires_at_unix_seconds,
    ] {
        h.update(n.to_be_bytes());
    }
    h.update(s.max_cache_ttl_seconds.to_be_bytes());
    Ok(h.finalize().into())
}

fn live(s: &ImmutableObjectSnapshot, now: u64) -> Result<(), Error> {
    if now < s.authorized_at_unix_seconds || now >= s.expires_at_unix_seconds {
        return Err(Error::Expired);
    }
    Ok(())
}

fn thread_matches(s: &ImmutableObjectSnapshot, thread: Option<&ThreadRef>) -> bool {
    thread.is_some_and(|t| {
        t.id.as_ref().is_some_and(|id| id.value == s.thread_id)
            && t.spool
                .as_ref()
                .is_some_and(|p| p.id == uuid_string(&s.spool_id))
    })
}

fn uuid_string(bytes: &[u8]) -> String {
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// Validate a request against the HOST-AUTHENTICATED snapshot, before reads.
/// The caller must also match the authenticated user/principal and session.
pub fn validate_read_request(
    s: &ImmutableObjectSnapshot,
    r: &ReadObjectsRequest,
    now: u64,
) -> Result<(), Error> {
    let binding = authority_binding(s)?;
    if r.authority_binding != binding || !thread_matches(s, r.thread.as_ref()) {
        return Err(Error::Binding);
    }
    live(s, now)?;
    let l = s.limits.as_ref().ok_or(Error::Limits)?;
    if r.encoded_len() > MAX_REQUEST_WIRE_BYTES
        || r.objects.is_empty()
        || r.objects.len() > l.max_batch_objects as usize
        || r.session_handle.is_empty()
        || r.session_handle.len() > 256
    {
        return Err(Error::Limits);
    }
    for (i, range) in r.objects.iter().enumerate() {
        let id = range.id.as_ref().ok_or(Error::Malformed)?;
        validate_id(id)?;
        if r.objects[..i].iter().any(|p| p.id.as_ref() == Some(id)) {
            return Err(Error::Malformed);
        }
        let e = s
            .inventory
            .iter()
            .find(|e| e.id.as_ref() == Some(id))
            .ok_or(Error::Unavailable)?;
        if range.length > l.max_chunk_bytes
            || (range.length == 0 && e.decoded_length != 0)
            || range
                .offset
                .checked_add(u64::from(range.length))
                .is_none_or(|end| end > e.decoded_length)
        {
            return Err(Error::Limits);
        }
    }
    Ok(())
}

/// Verify a bounded ordered response prefix. Recheck time on every delivery,
/// including cache hits; completed ranges can resume after reopening authority.
pub fn validate_read_response(
    s: &ImmutableObjectSnapshot,
    r: &ReadObjectsRequest,
    response: &ReadObjectsResponse,
    now: u64,
) -> Result<(), Error> {
    validate_read_request(s, r, now)?;
    let l = s.limits.as_ref().ok_or(Error::Limits)?;
    if response.encoded_len() > l.max_response_bytes as usize {
        return Err(Error::Limits);
    }
    if response.authority_binding != r.authority_binding {
        return Err(Error::Binding);
    }
    let n = response.chunks.len();
    if n == 0
        || n > r.objects.len()
        || response.next_object_index as usize != n
        || response.complete != (n == r.objects.len())
    {
        return Err(Error::Integrity);
    }
    for (chunk, range) in response.chunks.iter().zip(&r.objects) {
        let e = s
            .inventory
            .iter()
            .find(|e| e.id == range.id)
            .ok_or(Error::Unavailable)?;
        if chunk.id != range.id
            || chunk.codec != "identity"
            || chunk.offset != range.offset
            || chunk.decoded_length != e.decoded_length
            || chunk.data.len() != range.length as usize
            || chunk.chunk_sha256.as_slice() != Sha256::digest(&chunk.data).as_slice()
        {
            return Err(Error::Integrity);
        }
    }
    Ok(())
}

/// Per-range cache key: authority || typed ID || codec || offset || length.
pub fn object_cache_key(binding: &[u8], range: &ImmutableObjectRange) -> Result<[u8; 32], Error> {
    if binding.len() != 32 {
        return Err(Error::Binding);
    }
    let id = range.id.as_ref().ok_or(Error::Malformed)?;
    validate_id(id)?;
    if range.length > OBJECT_LIMITS.max_chunk_bytes {
        return Err(Error::Limits);
    }
    let mut h = Sha256::new();
    h.update(b"heddle-object-cache-v1\0");
    h.update(binding);
    h.update([id.kind as u8]);
    h.update(&id.digest);
    h.update(b"identity\0");
    h.update(range.offset.to_be_bytes());
    h.update(range.length.to_be_bytes());
    Ok(h.finalize().into())
}

pub fn decode_read_request(bytes: &[u8]) -> Result<ReadObjectsRequest, Error> {
    if bytes.len() > MAX_REQUEST_WIRE_BYTES {
        return Err(Error::Limits);
    }
    preflight_count(bytes, 4, OBJECT_LIMITS.max_batch_objects)?;
    ReadObjectsRequest::decode(bytes).map_err(|_| Error::Malformed)
}

pub fn decode_snapshot(bytes: &[u8]) -> Result<ImmutableObjectSnapshot, Error> {
    if bytes.len() > MAX_SNAPSHOT_WIRE_BYTES {
        return Err(Error::Limits);
    }
    preflight_count(bytes, 12, OBJECT_LIMITS.max_inventory_objects)?;
    let snapshot = ImmutableObjectSnapshot::decode(bytes).map_err(|_| Error::Malformed)?;
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

/// Validate selection and ceilings before resolving authority or reading data.
pub fn validate_open_request(request: &OpenObjectSnapshotRequest) -> Result<(), Error> {
    validate_limits(request.limits.as_ref().ok_or(Error::Limits)?)?;
    if request.encoded_len() > MAX_REQUEST_WIRE_BYTES {
        return Err(Error::Limits);
    }
    let thread = request.thread.as_ref().ok_or(Error::Malformed)?;
    let spool = &thread.spool.as_ref().ok_or(Error::Malformed)?.id;
    if spool.len() != 36
        || !spool.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        || !spool.bytes().any(|b| b != b'0' && b != b'-')
        || thread.id.as_ref().is_none_or(|id| id.value.len() != 32)
    {
        return Err(Error::Malformed);
    }
    let revision = request.revision.as_ref().ok_or(Error::Malformed)?;
    if revision.spool.as_ref() != thread.spool.as_ref() {
        return Err(Error::Binding);
    }
    if !matches!(&revision.revision, Some(revision_ref::Revision::State(id)) if id.value.len() == 32)
    {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Bind an opening to the exact requested native revision and requested limits.
/// Hosts must resolve the Thread/State relationship and authorize SOURCE live.
pub fn validate_open_response(
    request: &OpenObjectSnapshotRequest,
    response: &OpenObjectSnapshotResponse,
    now: u64,
) -> Result<(), Error> {
    validate_open_request(request)?;
    let s = response.snapshot.as_ref().ok_or(Error::Malformed)?;
    let binding = authority_binding(s)?;
    let requested = request.limits.as_ref().ok_or(Error::Limits)?;
    let accepted = s.limits.as_ref().ok_or(Error::Limits)?;
    if response.encoded_len() > MAX_SNAPSHOT_WIRE_BYTES
        || response.session_handle.is_empty()
        || response.session_handle.len() > 256
        || accepted.max_batch_objects > requested.max_batch_objects
        || accepted.max_response_bytes > requested.max_response_bytes
        || accepted.max_chunk_bytes > requested.max_chunk_bytes
        || accepted.max_in_flight_batches > requested.max_in_flight_batches
        || accepted.max_inventory_objects > requested.max_inventory_objects
        || accepted.max_snapshot_bytes > requested.max_snapshot_bytes
    {
        return Err(Error::Limits);
    }
    if response.authority_binding != binding || !thread_matches(s, request.thread.as_ref()) {
        return Err(Error::Binding);
    }
    let revision = request.revision.as_ref().ok_or(Error::Malformed)?;
    if !revision
        .spool
        .as_ref()
        .is_some_and(|p| p.id == uuid_string(&s.spool_id))
        || !matches!(&revision.revision, Some(revision_ref::Revision::State(id)) if id.value == s.state_id)
    {
        return Err(Error::Binding);
    }
    live(s, now)
}

pub fn decode_read_response(
    bytes: &[u8],
    limits: &ImmutableObjectLimits,
) -> Result<ReadObjectsResponse, Error> {
    validate_limits(limits)?;
    if bytes.len() > limits.max_response_bytes as usize {
        return Err(Error::Limits);
    }
    preflight_count(bytes, 2, limits.max_batch_objects)?;
    ReadObjectsResponse::decode(bytes).map_err(|_| Error::Malformed)
}

// Avoid repeated-empty-message allocation amplification within a wire byte cap.
// Use Prost's wire reader; no second protobuf parser or retained field table.
fn preflight_count(mut bytes: &[u8], field: u32, maximum: u32) -> Result<(), Error> {
    use prost::encoding::{DecodeContext, decode_key, skip_field};
    let mut count = 0;
    while !bytes.is_empty() {
        let (tag, wire) = decode_key(&mut bytes).map_err(|_| Error::Malformed)?;
        if tag == field {
            count += 1;
            if count > maximum {
                return Err(Error::Limits);
            }
        }
        skip_field(wire, tag, &mut bytes, DecodeContext::default())
            .map_err(|_| Error::Malformed)?;
    }
    Ok(())
}
