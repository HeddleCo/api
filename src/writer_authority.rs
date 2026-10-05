//! Portable writer binding and retained device checks. Owner-history/Biscuit
//! verification remains the native verifier's responsibility. Expected issuer
//! facts and admission inventories MUST come from independently verified state.
use crate::heddle::api::{common as host, v1alpha2 as api};
use crate::hybrid_codec::{Reject, counted, hash, key_id, strict_decode, verify, width};

pub fn decode_authority(envelope: &[u8]) -> Result<api::ThreadControlAuthority, Reject> {
    let authority: api::ThreadControlAuthority = strict_decode(envelope, 65536)?;
    if authority.format != 1 {
        return Err(Reject::Version);
    }
    Ok(authority)
}
/// Bind the actor's OWN root account; preserve exact owner identity when the
/// actor is the Spool owner. This does not authenticate a carried owner history.
pub fn verify_account_binding(
    authority: &api::ThreadControlAuthority,
    actor_account: &[u8],
    spool_account: &[u8],
    spool_owner_id: &[u8],
) -> Result<(), Reject> {
    width(actor_account, 16)?;
    if actor_account.iter().all(|b| *b == 0) {
        return Err(Reject::Canonical);
    }
    width(spool_account, 16)?;
    width(spool_owner_id, 32)?;
    let root = authority
        .owner
        .as_ref()
        .and_then(|h| h.root.as_ref())
        .and_then(|s| s.root.as_ref())
        .ok_or(Reject::Root)?;
    width(&root.account_uuid, 16)?;
    width(&root.owner_id, 32)?;
    if root.account_uuid != actor_account {
        return Err(Reject::GenesisBinding);
    }
    if actor_account == spool_account && root.owner_id != spool_owner_id {
        return Err(Reject::Root);
    }
    Ok(())
}
/// Owner-signed Spool policy cuts apply to the actor's publisher AND mint root,
/// including writers whose accounts differ from the Spool governance owner.
pub fn check_writer_keys(
    authority: &api::ThreadControlAuthority,
    publisher_key_id: &[u8],
    revoked_key_ids: &[Vec<u8>],
) -> Result<(), Reject> {
    width(publisher_key_id, 32)?;
    width(&authority.mint_root_public_key, 32)?;
    if revoked_key_ids
        .iter()
        .any(|id| id == publisher_key_id || *id == key_id(&authority.mint_root_public_key))
    {
        return Err(Reject::Revoked);
    }
    Ok(())
}
/// The carrier only locates these facts. Authenticate the Spool policy and
/// selected owner history separately before durable admission.
pub(crate) fn check_witness_writer(
    statement: &host::HostedWitnessStatementV1,
    envelope: &[u8],
    histories: &[api::OwnerHistory],
    policies: &[api::SignedSpoolPolicyRecord],
    spool_account: &[u8],
    co_signers: &[api::RecordSignature],
    boundary: Option<&api::ImportBoundaryAcceptanceV1>,
) -> Result<(), Reject> {
    validate_owner_histories(histories)?;
    crate::import_authority::require_policy_history(
        policies,
        &statement.spool_uuid,
        statement.policy_sequence,
        &statement.policy_state_hash,
    )?;
    let revoked = policies
        .iter()
        .filter_map(|p| p.body.as_ref())
        .find(|p| {
            p.spool_uuid == statement.spool_uuid
                && p.sequence == statement.policy_sequence
                && p.policy_state_hash == statement.policy_state_hash
        })
        .and_then(|p| p.policy.as_ref())
        .map(|p| p.revoked_key_ids.as_slice())
        .unwrap_or(&[]);
    if statement.basis == 2 {
        // Originals remain provenance: keep their envelope/account checks, but
        // authorize and cut only the current, signature-bound accepting party.
        // P1 provenance is checked by its existing genesis binding verifier.
        // Import P1 keeps its delegated-authority path and envelope commitment.
        if statement.purpose != 1 {
            let original = decode_authority(envelope)?;
            let account = original
                .owner
                .as_ref()
                .and_then(|h| h.root.as_ref())
                .and_then(|s| s.root.as_ref())
                .ok_or(Reject::Root)?;
            verify_account_binding(
                &original,
                &account.account_uuid,
                spool_account,
                &statement.owner_id,
            )?;
        }
        let (current, acceptance) = boundary_writer(statement, boundary)?;
        verify_account_binding(
            &current,
            &acceptance.accepting_author.actor.principal_id,
            spool_account,
            &statement.owner_id,
        )?;
        return check_writer_keys(&current, &key_id(&acceptance.accepting_publisher), revoked);
    }
    if revoked.contains(&statement.publisher_key_id)
        || co_signers
            .iter()
            .any(|s| revoked.contains(&key_id(&s.public_key)))
    {
        return Err(Reject::Revoked);
    }
    if envelope.is_empty() {
        if statement.purpose != 1 {
            return Err(Reject::Bounds);
        }
        return Ok(()); // LocalKey genesis: no account envelope or mint root.
    }
    let authority = decode_authority(envelope)?;
    let actor = authority
        .owner
        .as_ref()
        .and_then(|h| h.root.as_ref())
        .and_then(|s| s.root.as_ref())
        .ok_or(Reject::Root)?;
    verify_account_binding(
        &authority,
        &actor.account_uuid,
        spool_account,
        &statement.owner_id,
    )?;
    check_writer_keys(&authority, &statement.publisher_key_id, revoked)
}

/// Select only the witness-bound, signature-bound accepting party. Callers must
/// authenticate the complete payload/boundary evidence before admission.
fn boundary_writer(
    statement: &host::HostedWitnessStatementV1,
    boundary: Option<&api::ImportBoundaryAcceptanceV1>,
) -> Result<(api::ThreadControlAuthority, NativeAcceptingWriter), Reject> {
    let evidence = boundary.ok_or(Reject::BoundaryAcceptance)?;
    if statement.basis != 2
        || statement.boundary_acceptance.is_none()
        || evidence.binding != statement.boundary_acceptance
    {
        return Err(Reject::BoundaryAcceptance);
    }
    let binding = statement
        .boundary_acceptance
        .as_ref()
        .ok_or(Reject::BoundaryAcceptance)?;
    let signed = evidence
        .signed_acceptance
        .as_ref()
        .ok_or(Reject::BoundaryAcceptance)?;
    if signed.format != "heddle-original-boundary-acceptance-v1" {
        return Err(Reject::Version);
    }
    if signed.canonical_record.is_empty() || signed.canonical_record.len() > 65536 {
        return Err(Reject::Bounds);
    }
    if crate::import_authority::native_octets_id(&signed.format, &signed.canonical_record)
        != binding.acceptance_id
        || crate::import_authority::signed_native_digest(signed)?
            != binding.signed_acceptance_digest
    {
        return Err(Reject::BoundaryAcceptance);
    }
    let acceptance: NativeAcceptingWriter =
        rmp_serde::from_slice(&signed.canonical_record).map_err(|_| Reject::Canonical)?;
    if signed.signatures.len() != 1
        || signed.signatures[0].public_key != acceptance.accepting_publisher
    {
        return Err(Reject::Signature);
    }
    let actor = &acceptance.accepting_author;
    if actor.kind != "account" || actor.spool != statement.spool_uuid {
        return Err(Reject::Scope);
    }
    if crate::import_authority::native_octets_id(
        "heddle-thread-control-authority-v1",
        &actor.authority,
    ) != actor.authority_digest
    {
        return Err(Reject::GenesisBinding);
    }
    Ok((decode_authority(&actor.authority)?, acceptance))
}

// Read authority selectors from the signed native acceptance, never the carrier
// or the immutable original. Full native model/Biscuit verification is separate.
#[derive(serde::Deserialize)]
struct NativeAcceptingWriter {
    #[serde(deserialize_with = "integer_array_32")]
    accepting_publisher: [u8; 32],
    accepting_author: NativeAcceptingAuthor,
}
#[derive(serde::Deserialize)]
struct NativeAcceptingAuthor {
    kind: String,
    spool: Vec<u8>,
    actor: NativeAcceptingActor,
    authority: Vec<u8>,
    #[serde(deserialize_with = "integer_array_32")]
    authority_digest: [u8; 32],
}
#[derive(serde::Deserialize)]
struct NativeAcceptingActor {
    principal_id: Vec<u8>,
}

// rmp-serde's tuple reader also accepts binary via a byte sequence. Use the
// actual MessagePack type so fixed native arrays agree with the TS reader.
fn integer_array_32<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<[u8; 32], D::Error> {
    struct IntegerArray;
    impl<'de> serde::de::Visitor<'de> for IntegerArray {
        type Value = [u8; 32];
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an array of 32 octet integers")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut result = [0; 32];
            for (i, byte) in result.iter_mut().enumerate() {
                *byte = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
            }
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::invalid_length(33, &self));
            }
            Ok(result)
        }
    }
    deserializer.deserialize_any(IntegerArray)
}

/// Reject ambiguous carrier lookups before resolving any owner context.
pub(crate) fn validate_owner_histories(histories: &[api::OwnerHistory]) -> Result<(), Reject> {
    for (i, history) in histories.iter().enumerate() {
        width(&history.state_hash, 32)?;
        if histories[..i]
            .iter()
            .any(|h| h.state_hash == history.state_hash)
        {
            return Err(Reject::Canonical);
        }
    }
    Ok(())
}
/// Select the Spool account from signed identities or a signed transfer, never
/// from a carrier's owner-history lookup. Native verification authenticates them.
pub(crate) fn spool_account_for_statement<'a>(
    s: &host::HostedWitnessStatementV1,
    identities: impl Iterator<Item = &'a api::ImportIdentityV1>,
    transfers: &'a [api::ResourceTransferAuditRecord],
) -> Result<&'a [u8], Reject> {
    let mut account: Option<&[u8]> = None;
    for id in identities.filter(|id| {
        id.spool_uuid == s.spool_uuid
            && id.spool_genesis_digest == s.spool_genesis_digest
            && id.owner_id == s.owner_id
            && id.ownership_transfer_sequence == s.ownership_transfer_sequence
    }) {
        if account.is_some_and(|a| a != id.owner_account_uuid) {
            return Err(Reject::Root);
        }
        account = Some(&id.owner_account_uuid);
    }
    for h in transfers.iter().filter_map(|t| {
        t.transfer
            .as_ref()?
            .acceptance
            .as_ref()?
            .signed_handoff
            .as_ref()?
            .handoff
            .as_ref()
    }) {
        if h.resource_uuid == s.spool_uuid && h.transfer_sequence == s.ownership_transfer_sequence {
            if account.is_some_and(|a| a != h.destination_owner_uuid) {
                return Err(Reject::Root);
            }
            account = Some(&h.destination_owner_uuid);
        }
    }
    let account = account.ok_or(Reject::Root)?;
    width(account, 16)?;
    Ok(account)
}
/// Receiver-mandatory after native token and request-proof verification. The
/// subject must come from the VERIFIED sealed token, not the envelope root.
pub fn verify_landing_actor_binding(
    payload: &api::HostedLandingWitnessV1,
    verified_token_subject: &[u8],
    verified_token_subject_key: &[u8],
    verified_request_proof_key: &[u8],
    spool_account: &[u8],
    spool_owner_id: &[u8],
) -> Result<(), Reject> {
    width(verified_request_proof_key, 32)?;
    let request_key = &payload
        .request
        .as_ref()
        .and_then(|r| r.signature.as_ref())
        .ok_or(Reject::Signature)?
        .public_key;
    if request_key != verified_request_proof_key
        || verified_token_subject_key != verified_request_proof_key
    {
        return Err(Reject::KeyRole);
    }
    verify_account_binding(
        &decode_authority(&payload.authority_envelope)?,
        verified_token_subject,
        spool_account,
        spool_owner_id,
    )
}
/// Receiver-mandatory: the account is resolved from the verified native operation
/// author (or ownership claim/resolution acceptance), never the envelope root.
pub fn verify_authority_actor_binding(
    payload: &api::ImportAuthorityWitnessV1,
    verified_author_or_claim_account: &[u8],
    spool_account: &[u8],
    spool_owner_id: &[u8],
) -> Result<(), Reject> {
    verify_account_binding(
        &decode_authority(&payload.authority_envelope)?,
        verified_author_or_claim_account,
        spool_account,
        spool_owner_id,
    )
}
/// Opaque facts derived exclusively from an independently VERIFIED OwnerHistory.
/// This module does not replace the native owner-history verifier.
pub struct RetainedMintRootIssuer {
    account_uuid: Vec<u8>,
    state_hash: Vec<u8>,
    sequence: u64,
    public_key: Vec<u8>,
}
/// Resolve an issuer endpoint and enforce that no subsequent Recover cut it.
/// Verified history supplies committed predecessor hashes and the tip hash.
pub fn retained_mint_root_issuer(
    verified_history: &api::OwnerHistory,
    state_hash: &[u8],
    sequence: u64,
) -> Result<RetainedMintRootIssuer, Reject> {
    width(state_hash, 32)?;
    let root = verified_history
        .root
        .as_ref()
        .and_then(|r| r.root.as_ref())
        .ok_or(Reject::Root)?;
    let mut public_key = root
        .authority_key
        .as_ref()
        .ok_or(Reject::Root)?
        .public_key
        .clone();
    let mut endpoint = verified_history.state_hash.as_slice();
    for (i, signed) in verified_history.accepted_transitions.iter().enumerate() {
        let t = signed.transition.as_ref().ok_or(Reject::Root)?;
        if t.sequence != i as u64 + 1 {
            return Err(Reject::Root);
        }
        if t.sequence <= sequence {
            public_key = t
                .next_authority_key
                .as_ref()
                .ok_or(Reject::Root)?
                .public_key
                .clone();
        } else {
            if t.kind == 2 {
                return Err(Reject::Root);
            }
            if t.sequence == sequence + 1 {
                endpoint = &t.previous_state_hash;
            }
        }
    }
    if sequence > verified_history.accepted_transitions.len() as u64 || endpoint != state_hash {
        return Err(Reject::Root);
    }
    width(&public_key, 32)?;
    Ok(RetainedMintRootIssuer {
        account_uuid: root.account_uuid.clone(),
        state_hash: endpoint.to_vec(),
        sequence,
        public_key,
    })
}
pub enum WriterWitnessPayload<'a> {
    NativeGenesis(&'a api::NativeGenesisWitnessV1),
    Import(crate::import_authority::WitnessPayload<'a>),
}
/// An exact attachment extracted from an authenticated witness and matched payload.
pub struct AdmittedMintRootAttachment(api::SignedOwnerMintRootAttachment);
/// Receiver MUST resolve witness trust/signature/retirement BEFORE calling this.
/// This helper verifies payload commitments and original/acceptance signatures.
/// Basis 1 admits the original attachment; basis 2 admits the signed acceptor's.
pub fn admitted_owner_mint_root_attachment(
    authenticated_statement: &host::HostedWitnessStatementV1,
    payload: WriterWitnessPayload<'_>,
) -> Result<AdmittedMintRootAttachment, Reject> {
    let (envelope, boundary) = match payload {
        WriterWitnessPayload::NativeGenesis(p) => {
            crate::native_witness::verify_genesis_payload(authenticated_statement, p)?;
            (
                p.creator_authority_envelope.as_slice(),
                p.boundary_acceptance.as_ref(),
            )
        }
        WriterWitnessPayload::Import(p) => {
            crate::import_authority::verify_witness_payload(authenticated_statement, p)?;
            match p {
                crate::import_authority::WitnessPayload::Genesis(p) => (
                    p.creator_authority_envelope.as_slice(),
                    p.boundary_acceptance.as_ref(),
                ),
                crate::import_authority::WitnessPayload::Authority(p) => (
                    p.authority_envelope.as_slice(),
                    p.boundary_acceptances
                        .iter()
                        .find(|e| e.binding == authenticated_statement.boundary_acceptance),
                ),
                crate::import_authority::WitnessPayload::Landing(p) => {
                    (p.authority_envelope.as_slice(), None)
                }
            }
        }
    };
    let authority = if authenticated_statement.basis == 2 {
        boundary_writer(authenticated_statement, boundary)?.0
    } else {
        decode_authority(envelope)?
    };
    match authority.mint_root_association {
        Some(api::thread_control_authority::MintRootAssociation::OwnerMintRootAttachment(a)) => {
            Ok(AdmittedMintRootAttachment(a))
        }
        _ => Err(Reject::Root),
    }
}
/// Strict untrusted certificate boundary; callers cannot supply raw issuer or
/// inventory booleans. The opaque arguments must come from the two helpers above.
pub fn verify_retained_writer_attachment(
    attachment_bytes: &[u8],
    mint_root_public_key: &[u8],
    issuer: &RetainedMintRootIssuer,
    admitted: &AdmittedMintRootAttachment,
    now_unix_seconds: i64,
) -> Result<(), Reject> {
    let signed: api::SignedOwnerMintRootAttachment = strict_decode(attachment_bytes, 65536)?;
    verify_retained_owner_mint_root_attachment(
        &signed,
        mint_root_public_key,
        issuer,
        admitted,
        now_unix_seconds,
    )
}
pub(crate) fn verify_retained_owner_mint_root_attachment(
    signed: &api::SignedOwnerMintRootAttachment,
    mint_root_public_key: &[u8],
    issuer: &RetainedMintRootIssuer,
    admitted: &AdmittedMintRootAttachment,
    now_unix_seconds: i64,
) -> Result<(), Reject> {
    if admitted.0 != *signed {
        return Err(Reject::Root);
    }
    let a = signed.attachment.as_ref().ok_or(Reject::Canonical)?;
    let owner = a.owner_key.as_ref().ok_or(Reject::Canonical)?;
    let mint = a.mint_root_key.as_ref().ok_or(Reject::Canonical)?;
    if a.account_uuid != issuer.account_uuid
        || a.owner_state_hash != issuer.state_hash
        || a.owner_sequence != issuer.sequence
        || owner.public_key != issuer.public_key
        || mint.public_key != mint_root_public_key
    {
        return Err(Reject::Root);
    }
    if a.format_version != 1
        || owner.algorithm != 1
        || mint.algorithm != 1
        || a.account_uuid.iter().all(|b| *b == 0)
        || a.not_before_unix_seconds < 0
        || a.expires_at_unix_seconds <= a.not_before_unix_seconds
    {
        return Err(Reject::Canonical);
    }
    width(&a.account_uuid, 16)?;
    for bytes in [
        &a.owner_state_hash,
        &a.nonce,
        &owner.public_key,
        &mint.public_key,
    ] {
        width(bytes, 32)?;
    }
    if now_unix_seconds < a.not_before_unix_seconds || now_unix_seconds >= a.expires_at_unix_seconds
    {
        return Err(Reject::Expired);
    }
    let mut body = a.format_version.to_be_bytes().to_vec();
    counted(&mut body, &a.account_uuid)?;
    counted(&mut body, &a.owner_state_hash)?;
    body.extend_from_slice(&a.owner_sequence.to_be_bytes());
    for k in [owner, mint] {
        body.extend_from_slice(&(k.algorithm as u32).to_be_bytes());
        counted(&mut body, &k.public_key)?;
    }
    body.extend_from_slice(&a.not_before_unix_seconds.to_be_bytes());
    body.extend_from_slice(&a.expires_at_unix_seconds.to_be_bytes());
    counted(&mut body, &a.nonce)?;
    let signature = signed.owner_signature.as_ref().ok_or(Reject::Signature)?;
    if signature.signer_key_id != key_id(&owner.public_key) {
        return Err(Reject::Signature);
    }
    verify(
        &issuer.public_key,
        &hash(&[b"heddle-mint-root-attachment-v1", &body]),
        &signature.signature,
    )
}
