use heddle_api::heddle::api::v2alpha1::{
    EndpointKind, EndpointRef, ObjectAddress, ProviderAssemblyRecord, ProviderExtent,
    ProviderInlineSource, ProviderOffer, ProviderOfferExtent, ProviderPackLocation,
    ProviderPhysicalRange, ProviderPlan, ProviderPlanChallenge, ProviderPlanRegistration,
    ProviderRangeSource, ProviderReadTicket, RevisionRef, SpoolRef, ThreadId, ThreadRef,
    TransferObject, provider_assembly_record, revision_ref,
};
use heddle_api::provider_v2::{
    provider_assembly_digest, provider_consent_signing_bytes, provider_extent_set_digest,
    provider_offer_as_plan, provider_record_set_commitment, validate_plan_for_offer,
    validate_provider_offer, validate_provider_plan, validate_provider_registration,
};

fn offer_from(plan: &ProviderPlan) -> ProviderOffer {
    ProviderOffer {
        extent_set_digest: plan.extent_set_digest.clone(),
        extents: plan
            .extents
            .iter()
            .map(|extent| {
                let ticket = extent.ticket.as_ref().expect("fixture ticket");
                ProviderOfferExtent {
                    provider: extent.provider.clone(),
                    range: extent.range.clone(),
                    spool: ticket.spool.clone(),
                    facet: ticket.facet,
                    audience: ticket.audience.clone(),
                    content_root: ticket.content_root.clone(),
                }
            })
            .collect(),
        challenge: plan.challenge.clone(),
        assembly_digest: plan.assembly_digest.clone(),
        pack_header: plan.pack_header.clone(),
        output_pack_length: plan.output_pack_length,
        records: plan.records.clone(),
    }
}

#[test]
fn capability_free_offer_and_ticketed_plan_share_exact_layout() {
    let plan = fixture();
    let offer = offer_from(&plan);
    validate_provider_offer(&offer).expect("candidate layout");
    validate_plan_for_offer(&offer, &plan).expect("issued exact offer");
    assert!(
        validate_provider_plan(&provider_offer_as_plan(&offer).expect("layout")).is_err(),
        "offer never serves bytes"
    );

    let mut moved = offer.clone();
    moved.records[0].output_offset += 1;
    assert!(
        validate_provider_offer(&moved).is_err(),
        "changed candidate placement"
    );
    let mut other = plan.clone();
    other.extents[0]
        .ticket
        .as_mut()
        .expect("ticket")
        .content_root = vec![12; 32];
    assert!(
        validate_plan_for_offer(&offer, &other).is_err(),
        "changed issued scope"
    );
    let mut no_cap = plan;
    no_cap.extents[0]
        .ticket
        .as_mut()
        .expect("ticket")
        .attenuated_capability
        .clear();
    assert!(
        validate_provider_plan(&no_cap).is_err(),
        "issued plan needs capability"
    );
}

#[test]
fn private_pack_registration_covers_exact_plan_without_duplicate_or_extra_keys() {
    let plan = fixture();
    let mut registration = ProviderPlanRegistration {
        packs: vec![ProviderPackLocation {
            pack_id: plan.extents[0]
                .range
                .as_ref()
                .expect("range")
                .pack_id
                .clone(),
            object_key: "source/pack-1".into(),
        }],
        plan: Some(plan),
    };
    validate_provider_registration(&registration).expect("trusted placement map");
    registration.packs.push(registration.packs[0].clone());
    assert!(
        validate_provider_registration(&registration).is_err(),
        "duplicate private key"
    );
    registration.packs.pop();
    registration.packs[0].pack_id = vec![99; 32];
    assert!(matches!(
        validate_provider_registration(&registration),
        Err(heddle_api::provider_v2::ProviderCanonicalError::Invalid("registered pack missing"))
    ));
}

fn endpoint(kind: EndpointKind, byte: u8) -> EndpointRef {
    EndpointRef {
        kind: kind as i32,
        public_key: vec![byte; 32],
    }
}

fn fixture() -> ProviderPlan {
    let spool = SpoolRef {
        id: "123e4567-e89b-12d3-a456-426614174000".into(),
    };
    let provider = endpoint(EndpointKind::Provider, 4);
    let client = endpoint(EndpointKind::Device, 3);
    let expiry = prost_types::Timestamp {
        seconds: 1_800_000_000,
        nanos: 500,
    };
    let object = |byte: u8| TransferObject {
        address: Some(ObjectAddress {
            algorithm: "blake3".into(),
            digest: vec![byte; 32],
        }),
        kind: "blob".into(),
        facet: 1,
        size: 8,
        availability: 4,
    };
    let records = vec![
        ProviderAssemblyRecord {
            object: Some(object(8)),
            encoded_length: 8,
            encoded_digest: Some(ObjectAddress {
                algorithm: "blake3".into(),
                digest: vec![9; 32],
            }),
            output_offset: 16,
            source: Some(provider_assembly_record::Source::Provider(
                ProviderRangeSource {
                    extent_index: 0,
                    source_offset: 0,
                },
            )),
        },
        ProviderAssemblyRecord {
            object: Some(object(10)),
            encoded_length: 8,
            encoded_digest: Some(ObjectAddress {
                algorithm: "blake3".into(),
                digest: vec![11; 32],
            }),
            output_offset: 24,
            source: Some(provider_assembly_record::Source::Inline(
                ProviderInlineSource {},
            )),
        },
    ];
    let mut range = ProviderPhysicalRange {
        pack_id: vec![5; 32],
        object_etag: "etag-1".into(),
        offset: 128,
        length: 8,
        record_set_commitment: vec![],
    };
    range.record_set_commitment = provider_record_set_commitment(&range, &records, 0)
        .expect("valid tiled range")
        .to_vec();
    let ticket = ProviderReadTicket {
        attenuated_capability: vec![99],
        extent_set_digest: vec![],
        spool: Some(spool.clone()),
        facet: 1,
        audience: "Public".into(),
        content_root: vec![6; 32],
        pack_id: range.pack_id.clone(),
        object_etag: range.object_etag.clone(),
        offset: range.offset,
        length: range.length,
        provider: Some(provider.clone()),
        client: Some(client.clone()),
        assembly_digest: vec![],
        expires_at: Some(expiry),
        record_set_commitment: range.record_set_commitment.clone(),
    };
    let mut header = b"LMPK".to_vec();
    header.extend_from_slice(&4_u32.to_be_bytes());
    header.extend_from_slice(&2_u64.to_be_bytes());
    let mut plan = ProviderPlan {
        extent_set_digest: vec![],
        extents: vec![ProviderExtent {
            provider: Some(provider),
            ticket: Some(ticket),
            range: Some(range),
        }],
        challenge: Some(ProviderPlanChallenge {
            nonce: vec![7; 16],
            thread: Some(ThreadRef {
                spool: Some(spool.clone()),
                id: Some(ThreadId { value: vec![1; 32] }),
            }),
            revision: Some(RevisionRef {
                spool: Some(spool),
                revision: Some(revision_ref::Revision::State(
                    heddle_api::heddle::api::v1alpha1::StateId { value: vec![2; 32] },
                )),
            }),
            issuer: Some(endpoint(EndpointKind::Weft, 2)),
            client: Some(client),
            expires_at: Some(expiry),
            extent_set_digest: vec![],
            assembly_digest: vec![],
        }),
        assembly_digest: vec![],
        pack_header: header,
        output_pack_length: 64,
        records,
    };
    let set = provider_extent_set_digest(&plan).expect("canonical extent set");
    plan.extent_set_digest = set.to_vec();
    plan.challenge
        .as_mut()
        .expect("fixture challenge")
        .extent_set_digest = set.to_vec();
    plan.extents[0]
        .ticket
        .as_mut()
        .expect("fixture ticket")
        .extent_set_digest = set.to_vec();
    let assembly = provider_assembly_digest(&plan).expect("canonical assembly");
    plan.assembly_digest = assembly.to_vec();
    plan.challenge
        .as_mut()
        .expect("fixture challenge")
        .assembly_digest = assembly.to_vec();
    plan.extents[0]
        .ticket
        .as_mut()
        .expect("fixture ticket")
        .assembly_digest = assembly.to_vec();
    plan
}

#[test]
fn mixed_provider_inline_plan_has_portable_commitments_and_rejects_gaps() {
    let plan = fixture();
    validate_provider_plan(&plan).expect("exact mixed plan");
    assert_eq!(
        hex::encode(
            &plan.extents[0]
                .range
                .as_ref()
                .expect("range")
                .record_set_commitment
        ),
        "649331f1c9636feebfff83e12f0fe9c8f0206a9c2d91446a970f0e3be1226fa7"
    );
    assert_eq!(
        hex::encode(&plan.extent_set_digest),
        "41fc120dd82033542f7edc7a7a9940f780658167bd620785292edece604708ca"
    );
    assert_eq!(
        hex::encode(&plan.assembly_digest),
        "31c288e8d2e806e3937bee7a3eaafc9d273438d16d034de54e0d0fa6dff1ce5c"
    );
    assert_eq!(
        blake3::hash(
            &provider_consent_signing_bytes(plan.challenge.as_ref().expect("challenge"), "user:1")
                .expect("consent")
        )
        .to_hex()
        .as_str(),
        "7be03a24e3ef1a654bb4ad3adc3675d407b690b2dd3467713df72b90a69d82c6"
    );
    let mut gap = plan.clone();
    gap.records[0].output_offset += 1;
    assert!(
        provider_assembly_digest(&gap).is_err(),
        "output gap must be rejected"
    );
    let mut wrong_ticket = plan;
    wrong_ticket.extents[0]
        .ticket
        .as_mut()
        .expect("ticket")
        .assembly_digest[0] ^= 1;
    assert!(
        validate_provider_plan(&wrong_ticket).is_err(),
        "ticket must bind exact assembly"
    );
    let mut wrong_scope = wrong_ticket.clone();
    wrong_scope.extents[0]
        .ticket
        .as_mut()
        .expect("ticket")
        .assembly_digest[0] ^= 1;
    wrong_scope.extents[0]
        .ticket
        .as_mut()
        .expect("ticket")
        .spool
        .as_mut()
        .expect("Spool")
        .id = "123e4567-e89b-12d3-a456-426614174001".into();
    assert!(
        provider_assembly_digest(&wrong_scope).is_err(),
        "ticket must name selected Spool"
    );
    let mut duplicate = fixture();
    duplicate.records[1].object = duplicate.records[0].object.clone();
    assert!(
        provider_assembly_digest(&duplicate).is_err(),
        "object identity cannot occur twice"
    );
    let mut split = fixture();
    if let Some(provider_assembly_record::Source::Provider(source)) = &mut split.records[0].source {
        source.source_offset = 1;
    }
    assert!(
        provider_extent_set_digest(&split).is_err(),
        "provider range cannot have a gap"
    );
    let mut bad_uuid = fixture();
    bad_uuid
        .challenge
        .as_mut()
        .expect("challenge")
        .thread
        .as_mut()
        .expect("Thread")
        .spool
        .as_mut()
        .expect("Spool")
        .id = "zzze4567-e89b-12d3-a456-426614174000".into();
    assert!(
        provider_assembly_digest(&bad_uuid).is_err(),
        "same-length non-UUID must fail"
    );
    let mut inline_algorithm = fixture();
    inline_algorithm.records[1]
        .encoded_digest
        .as_mut()
        .expect("digest")
        .algorithm = "sha256".into();
    assert!(
        provider_assembly_digest(&inline_algorithm).is_err(),
        "inline digest algorithm must be native BLAKE3"
    );
    let mut bad_facet = fixture();
    bad_facet.extents[0].ticket.as_mut().expect("ticket").facet = 2;
    assert!(
        provider_extent_set_digest(&bad_facet).is_err(),
        "provider source ticket cannot cover collaboration"
    );
    let mut oversized = fixture();
    oversized.output_pack_length = 512 * 1024 * 1024 + 1;
    assert!(
        provider_assembly_digest(&oversized).is_err(),
        "output capacity bound must fail before hashing"
    );
    let mut two_roots = fixture();
    two_roots.records[1].source = Some(provider_assembly_record::Source::Provider(
        ProviderRangeSource {
            extent_index: 1,
            source_offset: 0,
        },
    ));
    let mut second = two_roots.extents[0].clone();
    second.range.as_mut().expect("range").offset = 256;
    second.range.as_mut().expect("range").record_set_commitment = provider_record_set_commitment(
        second.range.as_ref().expect("range"),
        &two_roots.records,
        1,
    )
    .expect("second range")
    .to_vec();
    second.ticket.as_mut().expect("ticket").offset = 256;
    second
        .ticket
        .as_mut()
        .expect("ticket")
        .record_set_commitment = second
        .range
        .as_ref()
        .expect("range")
        .record_set_commitment
        .clone();
    second.ticket.as_mut().expect("ticket").content_root = vec![7; 32];
    two_roots.extents.push(second);
    assert!(
        provider_extent_set_digest(&two_roots).is_err(),
        "one source plan cannot combine different content roots"
    );
}
