use heddle_api::heddle::api::v1alpha2::*;
use heddle_api::immutable_objects::*;
use prost::Message;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/immutable-objects-v1.json")).expect("fixed vectors")
}
fn vector<T: Message + Default>(name: &str) -> T {
    let f = fixture();
    let v = f["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|v| v["name"] == name)
        .expect("named vector");
    let bytes = hex::decode(v["protobufHex"].as_str().expect("hex")).expect("valid hex");
    let decoded = T::decode(bytes.as_slice()).expect("decode");
    assert_eq!(decoded.encode_to_vec(), bytes, "{name} round trip");
    decoded
}
fn pair() -> (ImmutableObjectSnapshot, ReadObjectsRequest) {
    (vector("snapshot"), vector("request"))
}
const NOW: u64 = 1800000000;

#[test]
fn golden_round_trips_and_resumption() {
    let (s, r) = pair();
    let f = fixture();
    assert_eq!(
        hex::encode(authority_binding(&s).expect("binding")),
        f["authorityBinding"]
    );
    validate_open_response(&vector("openRequest"), &vector("openResponse"), NOW).expect("opening");
    assert_eq!(
        decode_snapshot(&s.encode_to_vec()).expect("bounded snapshot"),
        s
    );
    assert_eq!(
        decode_read_request(&r.encode_to_vec()).expect("bounded request"),
        r
    );
    for name in ["partialResponse", "response"] {
        let response: ReadObjectsResponse = vector(name);
        validate_read_response(&s, &r, &response, NOW).expect("verified prefix");
        assert_eq!(
            decode_read_response(
                &response.encode_to_vec(),
                s.limits.as_ref().expect("limits")
            )
            .expect("bounded response"),
            response
        );
    }
    validate_read_response(&s, &vector("rangeRequest"), &vector("rangeResponse"), NOW)
        .expect("nonzero-offset resume");
    for (i, range) in r.objects.iter().enumerate() {
        assert_eq!(
            hex::encode(object_cache_key(&r.authority_binding, range).expect("cache key")),
            f["cacheKeys"][i]
        );
    }
}

#[test]
fn over_limit_batch_rejects() {
    let (mut s, mut r) = pair();
    s.inventory.truncate(1);
    r.objects.clear();
    for i in 0..513u32 {
        let mut digest = vec![0; 32];
        digest[28..].copy_from_slice(&i.to_be_bytes());
        let id = ImmutableObjectId {
            kind: 2,
            algorithm: "blake3".into(),
            digest,
        };
        s.inventory.push(ImmutableObjectInventoryEntry {
            id: Some(id.clone()),
            decoded_length: 1,
        });
        r.objects.push(ImmutableObjectRange {
            id: Some(id),
            offset: 0,
            length: 1,
        });
    }
    r.authority_binding = authority_binding(&s).expect("513-entry inventory").to_vec();
    let mut boundary = r.clone();
    boundary.objects.pop();
    validate_read_request(&s, &boundary, NOW).expect("512 unique IDs accepted");
    assert_eq!(
        validate_read_request(&s, &r, NOW),
        Err(ObjectContractError::Limits)
    );
}

#[test]
fn malformed_ids_and_unavailable_members_reject() {
    let (s, mut r) = pair();
    r.objects[0].id.as_mut().expect("id").digest.pop();
    assert_eq!(
        validate_read_request(&s, &r, NOW),
        Err(ObjectContractError::Malformed)
    );
    r = vector("request");
    r.objects[0].id.as_mut().expect("id").algorithm = "sha256".into();
    assert_eq!(
        validate_read_request(&s, &r, NOW),
        Err(ObjectContractError::Malformed)
    );
    r = vector("request");
    r.objects[0].id.as_mut().expect("id").digest = vec![99; 32];
    assert_eq!(
        validate_read_request(&s, &r, NOW),
        Err(ObjectContractError::Unavailable)
    );
    r = vector("request");
    r.objects[0].id.as_mut().expect("id").kind = 0;
    assert_eq!(
        validate_read_request(&s, &r, NOW),
        Err(ObjectContractError::Malformed)
    );
}

#[test]
fn authority_and_cache_keys_bind_every_scope() {
    let (s, r) = pair();
    for field in [
        "host",
        "user",
        "principal",
        "spool",
        "thread",
        "state",
        "view",
        "authorization",
        "visibility",
        "ttl",
        "inventory",
        "limit",
    ] {
        let mut changed = s.clone();
        match field {
            "host" => changed.host_public_key[0] ^= 1,
            "user" => changed.user_id[0] ^= 1,
            "principal" => changed.principal_sha256[0] ^= 1,
            "spool" => changed.spool_id[0] ^= 1,
            "thread" => changed.thread_id[0] ^= 1,
            "state" => changed.state_id[0] ^= 1,
            "view" => changed.view_digest[0] ^= 1,
            "authorization" => changed.authorization_epoch += 1,
            "visibility" => changed.visibility_epoch += 1,
            "ttl" => changed.max_cache_ttl_seconds += 1,
            "inventory" => changed.inventory[0].decoded_length += 1,
            "limit" => changed.limits.as_mut().expect("limits").max_batch_objects -= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            validate_read_request(&changed, &r, NOW),
            Err(ObjectContractError::Binding),
            "{field}"
        );
        let binding = authority_binding(&changed).expect("valid altered snapshot");
        assert_ne!(
            object_cache_key(&binding, &r.objects[0]),
            object_cache_key(&r.authority_binding, &r.objects[0]),
            "{field}"
        );
    }
    let mut wrong = r.clone();
    wrong
        .thread
        .as_mut()
        .expect("thread")
        .id
        .as_mut()
        .expect("id")
        .value[0] ^= 1;
    assert_eq!(
        validate_read_request(&s, &wrong, NOW),
        Err(ObjectContractError::Binding)
    );
    let mut opening: OpenObjectSnapshotRequest = vector("openRequest");
    opening.revision.as_mut().expect("revision").revision =
        Some(revision_ref::Revision::GitCommitOid("a".repeat(40)));
    assert_eq!(
        validate_open_response(&opening, &vector("openResponse"), NOW),
        Err(ObjectContractError::Malformed)
    );
}

#[test]
fn ttl_is_exclusive_and_hits_cannot_extend_it() {
    let (s, r) = pair();
    validate_read_request(&s, &r, NOW + 59).expect("last second");
    assert_eq!(
        validate_read_request(&s, &r, NOW + 60),
        Err(ObjectContractError::Expired)
    );
    assert_eq!(
        validate_read_request(&s, &r, NOW - 1),
        Err(ObjectContractError::Expired)
    );
    let mut changed = s;
    changed.expires_at_unix_seconds += 1;
    assert_eq!(
        validate_snapshot(&changed),
        Err(ObjectContractError::Limits)
    );
    changed.max_cache_ttl_seconds = 120;
    validate_snapshot(&changed).expect("host-configurable TTL");
}

#[test]
fn lengths_limits_and_wire_caps_reject_before_allocation() {
    let (s, mut r) = pair();
    r.objects[0].offset = u64::MAX;
    assert_eq!(
        validate_read_request(&s, &r, NOW),
        Err(ObjectContractError::Limits)
    );
    r = vector("request");
    r.objects[0].length = OBJECT_LIMITS.max_chunk_bytes + 1;
    assert_eq!(
        validate_read_request(&s, &r, NOW),
        Err(ObjectContractError::Limits)
    );
    let mut changed = s.clone();
    changed.inventory[0].decoded_length = u64::MAX;
    assert_eq!(
        validate_snapshot(&changed),
        Err(ObjectContractError::Limits)
    );
    changed = s.clone();
    changed.inventory.swap(0, 1);
    assert_eq!(
        validate_snapshot(&changed),
        Err(ObjectContractError::Malformed)
    );
    for mut l in [OBJECT_LIMITS; 6].into_iter().enumerate() {
        match l.0 {
            0 => l.1.max_batch_objects += 1,
            1 => l.1.max_response_bytes += 1,
            2 => l.1.max_chunk_bytes += 1,
            3 => l.1.max_in_flight_batches += 1,
            4 => l.1.max_inventory_objects += 1,
            _ => l.1.max_snapshot_bytes += 1,
        }
        assert_eq!(validate_limits(&l.1), Err(ObjectContractError::Limits));
    }
    assert_eq!(
        decode_read_request(&vec![0; MAX_REQUEST_WIRE_BYTES + 1]),
        Err(ObjectContractError::Limits)
    );
    assert_eq!(
        decode_snapshot(&vec![0; MAX_SNAPSHOT_WIRE_BYTES + 1]),
        Err(ObjectContractError::Limits)
    );
    assert_eq!(
        decode_read_response(
            &vec![0; OBJECT_LIMITS.max_response_bytes as usize + 1],
            &OBJECT_LIMITS
        ),
        Err(ObjectContractError::Limits)
    );
}

#[test]
fn altered_response_codec_chunk_length_binding_and_completion_reject() {
    let (s, r) = pair();
    for field in [
        "codec", "chunk", "length", "offset", "id", "hash", "index", "complete", "binding", "empty",
    ] {
        let mut response: ReadObjectsResponse = vector("response");
        let c = &mut response.chunks[0];
        match field {
            "codec" => c.codec = "zstd".into(),
            "chunk" => c.data[0] ^= 1,
            "length" => c.decoded_length = u64::MAX,
            "offset" => c.offset += 1,
            "id" => c.id.as_mut().expect("id").kind = 2,
            "hash" => c.chunk_sha256.pop().map(|_| ()).expect("digest"),
            "index" => response.next_object_index = 1,
            "complete" => response.complete = false,
            "binding" => response.authority_binding[0] ^= 1,
            "empty" => response.chunks.clear(),
            _ => unreachable!(),
        }
        assert_eq!(
            validate_read_response(&s, &r, &response, NOW),
            Err(if field == "binding" {
                ObjectContractError::Binding
            } else {
                ObjectContractError::Integrity
            }),
            "{field}"
        );
    }
}

#[test]
fn response_budget_allows_prefix_and_refuses_full_envelope() {
    let (mut s, mut r) = pair();
    let mut partial: ReadObjectsResponse = vector("partialResponse");
    let mut full: ReadObjectsResponse = vector("response");
    let budget = partial.encoded_len() as u32;
    let l = s.limits.as_mut().expect("limits");
    l.max_response_bytes = budget;
    l.max_chunk_bytes = 32;
    r.authority_binding = authority_binding(&s).expect("narrowed budget").to_vec();
    partial.authority_binding = r.authority_binding.clone();
    full.authority_binding = r.authority_binding.clone();
    validate_read_response(&s, &r, &partial, NOW).expect("prefix fits exactly");
    assert_eq!(
        validate_read_response(&s, &r, &full, NOW),
        Err(ObjectContractError::Limits)
    );
}

#[test]
fn empty_blob_is_resumable_but_empty_progress_is_not() {
    use sha2::{Digest, Sha256};
    let (mut s, mut r) = pair();
    let id = ImmutableObjectId {
        kind: 2,
        algorithm: "blake3".into(),
        digest: blake3::hash(&[]).as_bytes().to_vec(),
    };
    s.inventory[1] = ImmutableObjectInventoryEntry {
        id: Some(id.clone()),
        decoded_length: 0,
    };
    r.authority_binding = authority_binding(&s).expect("empty blob snapshot").to_vec();
    r.objects = vec![ImmutableObjectRange {
        id: Some(id.clone()),
        offset: 0,
        length: 0,
    }];
    let response = ReadObjectsResponse {
        authority_binding: r.authority_binding.clone(),
        chunks: vec![ImmutableObjectChunk {
            id: Some(id),
            codec: "identity".into(),
            decoded_length: 0,
            offset: 0,
            data: vec![],
            chunk_sha256: Sha256::digest([]).to_vec(),
        }],
        next_object_index: 1,
        complete: true,
    };
    validate_read_response(&s, &r, &response, NOW).expect("empty object completes a range");
    r.objects[0].offset = 1;
    assert_eq!(
        validate_read_request(&s, &r, NOW),
        Err(ObjectContractError::Limits)
    );
}

#[test]
fn bounded_decoders_refuse_empty_message_amplification() {
    let request = [0x22, 0].repeat(513);
    let response = [0x12, 0].repeat(513);
    let snapshot = [0x62, 0].repeat(4097);
    assert_eq!(
        decode_read_request(&request),
        Err(ObjectContractError::Limits)
    );
    assert_eq!(
        decode_read_response(&response, &OBJECT_LIMITS),
        Err(ObjectContractError::Limits)
    );
    assert_eq!(decode_snapshot(&snapshot), Err(ObjectContractError::Limits));
}

#[test]
fn opening_selection_is_validated_before_data_lookup() {
    let mut request: OpenObjectSnapshotRequest = vector("openRequest");
    validate_open_request(&request).expect("valid native selection");
    request
        .revision
        .as_mut()
        .expect("revision")
        .spool
        .as_mut()
        .expect("spool")
        .id = "05050505-0505-0505-0505-050505050505".into();
    assert_eq!(
        validate_open_request(&request),
        Err(ObjectContractError::Binding)
    );
    request = vector("openRequest");
    request
        .thread
        .as_mut()
        .expect("thread")
        .spool
        .as_mut()
        .expect("spool")
        .id = "not-a-uuid".into();
    assert_eq!(
        validate_open_request(&request),
        Err(ObjectContractError::Malformed)
    );
    request = vector("openRequest");
    request.limits.as_mut().expect("limits").max_batch_objects = 0;
    assert_eq!(
        validate_open_request(&request),
        Err(ObjectContractError::Limits)
    );
}
