//! Canonical two-layer root-attested ephemeral endpoint-descriptor contract.
//!
//! The deployment descriptor **root** signs an attestation binding an ephemeral
//! key. That ephemeral key signs its own [`SignedEndpointDescriptor`] (relay and
//! direct addresses). Consumers MUST verify both layers and bind them; unsigned
//! address hints are not part of this contract.

use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::heddle::api::v1alpha1::{EndpointDescriptor, SignedEndpointDescriptor};
use crate::signing::{canonical_with_domain, endpoint_descriptor_bytes};

/// Document version for [`EndpointDescriptorSetDocument`].
pub const SET_VERSION: u8 = 1;
/// Domain separator for root-key attestations of ephemeral descriptor keys.
/// Distinct from [`crate::signing::TRANSPORT_BOOTSTRAP_SIGNING_V1_DOMAIN`] so an
/// endpoint-descriptor signature cannot verify as an attestation and vice versa.
pub const ROOT_ATTESTATION_V1_DOMAIN: &str = "heddle-descriptor-root-attestation-v1";
/// Canonical `kind=` label inside [`ephemeral_attestation_bytes`].
pub const ROOT_ATTESTATION_KIND: &str = "descriptor-ephemeral-attestation-v1";

/// Published set of root-attested ephemeral endpoint descriptors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointDescriptorSetDocument {
    pub version: u8,
    pub root_key_id: String,
    pub entries: Vec<AttestedEndpointDescriptorEntry>,
}

/// One root-attested ephemeral key plus the descriptor that key signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedEndpointDescriptorEntry {
    pub ephemeral_key_id: String,
    /// 32-byte Ed25519 public key as 64 lowercase hex characters.
    pub ephemeral_public_key: String,
    pub not_before_unix_millis: i64,
    pub not_after_unix_millis: i64,
    pub region: String,
    /// 64-byte Ed25519 signature as 128 lowercase hex characters.
    pub attestation_signature: String,
    /// Hex-encoded [`SignedEndpointDescriptor`] protobuf.
    pub signed_descriptor: String,
}

/// Endpoint that passed both attestation and descriptor-signature layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEndpoint {
    pub ephemeral_public_key: [u8; 32],
    pub endpoint_descriptor: EndpointDescriptor,
    pub not_before_unix_millis: i64,
    pub not_after_unix_millis: i64,
    pub region: String,
}

/// Why a set entry was not promoted to [`VerifiedEndpoint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EntryReject {
    #[error("missing attestation signature")]
    MissingSignature,
    #[error("invalid attestation signature")]
    InvalidSignature,
    #[error("unattested ephemeral key")]
    Unattested,
    #[error("invalid endpoint-descriptor signature")]
    InvalidDescriptorSignature,
    #[error("descriptor identity does not match the attested ephemeral key")]
    DescriptorKeyMismatch,
    #[error("attestation is not yet valid")]
    NotYetValid,
    #[error("attestation has expired")]
    Expired,
    #[error("attestation validity window is inverted or empty")]
    InvalidWindow,
    #[error("invalid ephemeral public key")]
    InvalidKey,
    #[error("malformed signed endpoint descriptor")]
    MalformedDescriptor,
    #[error("unsupported descriptor set version")]
    UnsupportedVersion,
    #[error("unsupported endpoint descriptor version")]
    UnsupportedDescriptorVersion,
    #[error("descriptor is not yet valid")]
    DescriptorNotYetValid,
    #[error("descriptor has expired")]
    DescriptorExpired,
}

/// Errors from [`parse_endpoint_descriptor_set`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DescriptorSetError {
    #[error("malformed endpoint descriptor set: {0}")]
    Malformed(String),
    #[error("unsupported endpoint descriptor set version {0}")]
    UnsupportedVersion(u8),
}

/// Canonical bytes the deployment-descriptor root signs to attest an ephemeral key.
///
/// Field order is load-bearing:
/// `ephemeral_key_id` (utf8), `ephemeral_public_key` (raw 32 bytes),
/// `not_before_unix_millis` / `not_after_unix_millis` (i64 big-endian),
/// `region` (utf8). Integers are fixed-width; the public key is never hex.
pub fn ephemeral_attestation_bytes(
    ephemeral_key_id: &str,
    ephemeral_public_key: &[u8; 32],
    not_before_unix_millis: i64,
    not_after_unix_millis: i64,
    region: &str,
) -> Vec<u8> {
    canonical_with_domain(
        ROOT_ATTESTATION_V1_DOMAIN,
        ROOT_ATTESTATION_KIND,
        &[
            ("ephemeral_key_id", ephemeral_key_id.as_bytes().to_vec()),
            ("ephemeral_public_key", ephemeral_public_key.to_vec()),
            (
                "not_before_unix_millis",
                not_before_unix_millis.to_be_bytes().to_vec(),
            ),
            (
                "not_after_unix_millis",
                not_after_unix_millis.to_be_bytes().to_vec(),
            ),
            ("region", region.as_bytes().to_vec()),
        ],
    )
}

/// Verify both trust layers of one attested entry and bind them.
///
/// Layer 1: the `root_public_key` signed [`ephemeral_attestation_bytes`].
/// Layer 2: the attested ephemeral key signed the inner
/// [`SignedEndpointDescriptor`] over [`endpoint_descriptor_bytes`].
/// Bind: `descriptor.endpoint_id` is the hex of the attested key, and
/// `SignedEndpointDescriptor.key_id` equals `entry.ephemeral_key_id`.
pub fn verify_ephemeral_attestation(
    root_public_key: &[u8; 32],
    entry: &AttestedEndpointDescriptorEntry,
    now_unix_millis: i64,
) -> Result<VerifiedEndpoint, EntryReject> {
    if entry.ephemeral_key_id.trim().is_empty() {
        return Err(EntryReject::InvalidKey);
    }
    if entry.not_before_unix_millis >= entry.not_after_unix_millis {
        return Err(EntryReject::InvalidWindow);
    }
    let ephemeral_public_key: [u8; 32] =
        decode_lowercase_hex(&entry.ephemeral_public_key).ok_or(EntryReject::InvalidKey)?;
    if entry.attestation_signature.is_empty() {
        return Err(EntryReject::MissingSignature);
    }
    let attestation_signature: [u8; 64] =
        decode_lowercase_hex(&entry.attestation_signature).ok_or(EntryReject::InvalidSignature)?;
    if attestation_signature == [0u8; 64] {
        return Err(EntryReject::Unattested);
    }

    let root =
        VerifyingKey::from_bytes(root_public_key).map_err(|_| EntryReject::InvalidSignature)?;
    let attestation_bytes = ephemeral_attestation_bytes(
        &entry.ephemeral_key_id,
        &ephemeral_public_key,
        entry.not_before_unix_millis,
        entry.not_after_unix_millis,
        &entry.region,
    );
    root.verify_strict(
        &attestation_bytes,
        &Signature::from_bytes(&attestation_signature),
    )
    .map_err(|_| EntryReject::InvalidSignature)?;

    if now_unix_millis < entry.not_before_unix_millis {
        return Err(EntryReject::NotYetValid);
    }
    if now_unix_millis >= entry.not_after_unix_millis {
        return Err(EntryReject::Expired);
    }

    if !is_lowercase_hex(&entry.signed_descriptor) {
        return Err(EntryReject::MalformedDescriptor);
    }
    let signed_bytes =
        hex::decode(&entry.signed_descriptor).map_err(|_| EntryReject::MalformedDescriptor)?;
    let signed = SignedEndpointDescriptor::decode(signed_bytes.as_slice())
        .map_err(|_| EntryReject::MalformedDescriptor)?;
    let descriptor = signed.descriptor.ok_or(EntryReject::MalformedDescriptor)?;
    let descriptor_signature: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| EntryReject::InvalidDescriptorSignature)?;
    let ephemeral =
        VerifyingKey::from_bytes(&ephemeral_public_key).map_err(|_| EntryReject::InvalidKey)?;
    ephemeral
        .verify_strict(
            &endpoint_descriptor_bytes(&descriptor),
            &Signature::from_bytes(&descriptor_signature),
        )
        .map_err(|_| EntryReject::InvalidDescriptorSignature)?;

    if descriptor.endpoint_id != hex::encode(ephemeral_public_key) {
        return Err(EntryReject::DescriptorKeyMismatch);
    }
    if signed.key_id != entry.ephemeral_key_id {
        return Err(EntryReject::DescriptorKeyMismatch);
    }
    if descriptor.version != 1 {
        return Err(EntryReject::UnsupportedDescriptorVersion);
    }
    if now_unix_millis < descriptor.issued_at_unix_millis {
        return Err(EntryReject::DescriptorNotYetValid);
    }
    if now_unix_millis >= descriptor.expires_at_unix_millis {
        return Err(EntryReject::DescriptorExpired);
    }

    Ok(VerifiedEndpoint {
        ephemeral_public_key,
        endpoint_descriptor: descriptor,
        not_before_unix_millis: entry.not_before_unix_millis,
        not_after_unix_millis: entry.not_after_unix_millis,
        region: entry.region.clone(),
    })
}

/// Deserialize an [`EndpointDescriptorSetDocument`] and reject unknown versions.
pub fn parse_endpoint_descriptor_set(
    body: &[u8],
) -> Result<EndpointDescriptorSetDocument, DescriptorSetError> {
    let set: EndpointDescriptorSetDocument = serde_json::from_slice(body)
        .map_err(|error| DescriptorSetError::Malformed(error.to_string()))?;
    if set.version != SET_VERSION {
        return Err(DescriptorSetError::UnsupportedVersion(set.version));
    }
    Ok(set)
}

/// Verify every entry and drop rejects. Never returns a [`VerifiedEndpoint`]
/// unless both layers verified and bound.
pub fn trusted_live_entries(
    set: &EndpointDescriptorSetDocument,
    root_public_key: &[u8; 32],
    now_unix_millis: i64,
) -> (Vec<VerifiedEndpoint>, Vec<EntryReject>) {
    if set.version != SET_VERSION {
        return (vec![], vec![EntryReject::UnsupportedVersion]);
    }
    let mut live = Vec::new();
    let mut rejects = Vec::new();
    for entry in &set.entries {
        match verify_ephemeral_attestation(root_public_key, entry, now_unix_millis) {
            Ok(verified) => live.push(verified),
            Err(reject) => rejects.push(reject),
        }
    }
    (live, rejects)
}

fn is_lowercase_hex(value: &str) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn decode_lowercase_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    if !value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(value.as_bytes(), &mut out).ok()?;
    Some(out)
}

/// Fixed published vector both weft and heddle pin their tests to.
pub mod conformance {
    /// 32-byte Ed25519 seed for the deployment-descriptor root.
    pub const ROOT_SECRET_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    /// 32-byte Ed25519 seed for the attested ephemeral key.
    pub const EPHEMERAL_SECRET_SEED: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    pub const ROOT_SECRET_SEED_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    pub const EPHEMERAL_SECRET_SEED_HEX: &str =
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    pub const EPHEMERAL_KEY_ID: &str = "ephemeral-us-west-1";
    pub const NOT_BEFORE_UNIX_MILLIS: i64 = 1_700_000_000_000;
    pub const NOT_AFTER_UNIX_MILLIS: i64 = 1_800_000_000_000;
    pub const REGION: &str = "us-west";
    pub const RELAY_URL: &str = "https://relay.example.test";
    pub const DIRECT_ADDRESS: &str = "203.0.113.7:4433";

    pub const ROOT_PUBLIC_KEY_HEX: &str =
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
    pub const EPHEMERAL_PUBLIC_KEY_HEX: &str =
        "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7";
    pub const CANONICAL_BYTES_HEX: &str = "686564646c652d64657363726970746f722d726f6f742d6174746573746174696f6e2d76310a6b696e643d33353a64657363726970746f722d657068656d6572616c2d6174746573746174696f6e2d76310a657068656d6572616c5f6b65795f69643d31393a657068656d6572616c2d75732d776573742d310a657068656d6572616c5f7075626c69635f6b65793d33323a29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd70a6e6f745f6265666f72655f756e69785f6d696c6c69733d383a0000018bcfe568000a6e6f745f61667465725f756e69785f6d696c6c69733d383a000001a3185c50000a726567696f6e3d373a75732d77657374";
    pub const ATTESTATION_SIGNATURE_HEX: &str = "ca633a465754c149d13e65eaa20d885c241cd1ff4202bb26f060d51ecc307d18c040f5ecf9ee85e8d96567bb869274477e69aece3366ee2ae7b00c8ddac12e0f";
    pub const SIGNED_DESCRIPTOR_HEX: &str = "0a8e0108011240323961636261653134316263636166306232326531613934643334643062633733363165353236643062666531326338393739346263393332323936366464371a1a68747470733a2f2f72656c61792e6578616d706c652e74657374220c686564646c652d6170692f312a103230332e302e3131332e373a343433333080d095ffbc313880a0f1c2b1341213657068656d6572616c2d75732d776573742d311a407bfee156bb5e68572682c111803c7fc10d7cd18597e33ef8ee512ee24fe0118abad7c30f135b9ba6afdec2985537d0b564261067d25d36a9b9bfa09434d4cf05";
}

#[cfg(test)]
mod tests {
    use super::conformance::{
        ATTESTATION_SIGNATURE_HEX, CANONICAL_BYTES_HEX, DIRECT_ADDRESS, EPHEMERAL_KEY_ID,
        EPHEMERAL_PUBLIC_KEY_HEX, EPHEMERAL_SECRET_SEED, EPHEMERAL_SECRET_SEED_HEX,
        NOT_AFTER_UNIX_MILLIS, NOT_BEFORE_UNIX_MILLIS, REGION, RELAY_URL, ROOT_PUBLIC_KEY_HEX,
        ROOT_SECRET_SEED, ROOT_SECRET_SEED_HEX, SIGNED_DESCRIPTOR_HEX,
    };
    use super::*;
    use crate::HOSTED_ALPN_V1;
    use ed25519_dalek::{Signer, SigningKey};

    struct Regenerated {
        root_public_key: [u8; 32],
        ephemeral_public_key: [u8; 32],
        canonical_bytes: Vec<u8>,
        attestation_signature: [u8; 64],
        signed_descriptor_hex: String,
        entry: AttestedEndpointDescriptorEntry,
    }

    fn regenerate() -> Regenerated {
        let root = SigningKey::from_bytes(&ROOT_SECRET_SEED);
        let ephemeral = SigningKey::from_bytes(&EPHEMERAL_SECRET_SEED);
        let root_public_key = root.verifying_key().to_bytes();
        let ephemeral_public_key = ephemeral.verifying_key().to_bytes();
        let canonical_bytes = ephemeral_attestation_bytes(
            EPHEMERAL_KEY_ID,
            &ephemeral_public_key,
            NOT_BEFORE_UNIX_MILLIS,
            NOT_AFTER_UNIX_MILLIS,
            REGION,
        );
        let attestation_signature = root.sign(&canonical_bytes).to_bytes();
        let descriptor = conformance_descriptor(&ephemeral_public_key);
        let signed = sign_descriptor(&ephemeral, EPHEMERAL_KEY_ID, descriptor);
        let signed_descriptor_hex = hex::encode(signed.encode_to_vec());
        let entry = AttestedEndpointDescriptorEntry {
            ephemeral_key_id: EPHEMERAL_KEY_ID.to_string(),
            ephemeral_public_key: hex::encode(ephemeral_public_key),
            not_before_unix_millis: NOT_BEFORE_UNIX_MILLIS,
            not_after_unix_millis: NOT_AFTER_UNIX_MILLIS,
            region: REGION.to_string(),
            attestation_signature: hex::encode(attestation_signature),
            signed_descriptor: signed_descriptor_hex.clone(),
        };
        Regenerated {
            root_public_key,
            ephemeral_public_key,
            canonical_bytes,
            attestation_signature,
            signed_descriptor_hex,
            entry,
        }
    }

    fn conformance_descriptor(ephemeral_public_key: &[u8; 32]) -> EndpointDescriptor {
        EndpointDescriptor {
            version: 1,
            endpoint_id: hex::encode(ephemeral_public_key),
            relay_urls: vec![RELAY_URL.to_string()],
            supported_alpns: vec![HOSTED_ALPN_V1.to_vec()],
            direct_addresses: vec![DIRECT_ADDRESS.to_string()],
            issued_at_unix_millis: NOT_BEFORE_UNIX_MILLIS,
            expires_at_unix_millis: NOT_AFTER_UNIX_MILLIS,
            rotation: None,
        }
    }

    fn sign_descriptor(
        ephemeral: &SigningKey,
        key_id: &str,
        descriptor: EndpointDescriptor,
    ) -> SignedEndpointDescriptor {
        let signature = ephemeral
            .sign(&endpoint_descriptor_bytes(&descriptor))
            .to_bytes()
            .to_vec();
        SignedEndpointDescriptor {
            descriptor: Some(descriptor),
            key_id: key_id.to_string(),
            signature,
        }
    }

    fn committed_entry() -> AttestedEndpointDescriptorEntry {
        AttestedEndpointDescriptorEntry {
            ephemeral_key_id: EPHEMERAL_KEY_ID.to_string(),
            ephemeral_public_key: EPHEMERAL_PUBLIC_KEY_HEX.to_string(),
            not_before_unix_millis: NOT_BEFORE_UNIX_MILLIS,
            not_after_unix_millis: NOT_AFTER_UNIX_MILLIS,
            region: REGION.to_string(),
            attestation_signature: ATTESTATION_SIGNATURE_HEX.to_string(),
            signed_descriptor: SIGNED_DESCRIPTOR_HEX.to_string(),
        }
    }

    fn parse_hex_32(value: &str) -> [u8; 32] {
        decode_lowercase_hex(value).expect("32-byte lowercase hex")
    }

    fn now() -> i64 {
        NOT_BEFORE_UNIX_MILLIS
    }

    #[test]
    fn domains_are_separated_from_transport_bootstrap() {
        assert_eq!(SET_VERSION, 1);
        assert_eq!(
            ROOT_ATTESTATION_V1_DOMAIN,
            "heddle-descriptor-root-attestation-v1"
        );
        assert_eq!(ROOT_ATTESTATION_KIND, "descriptor-ephemeral-attestation-v1");
        assert_ne!(
            ROOT_ATTESTATION_V1_DOMAIN,
            crate::signing::TRANSPORT_BOOTSTRAP_SIGNING_V1_DOMAIN
        );
        assert_eq!(hex::encode(ROOT_SECRET_SEED), ROOT_SECRET_SEED_HEX);
        assert_eq!(
            hex::encode(EPHEMERAL_SECRET_SEED),
            EPHEMERAL_SECRET_SEED_HEX
        );
    }

    #[test]
    fn attestation_bytes_use_length_prefixed_framing_and_be_integers() {
        let pk = [0xaa; 32];
        let bytes = ephemeral_attestation_bytes("ab", &pk, 1, 2, "c");
        let expected_prefix = format!(
            "{ROOT_ATTESTATION_V1_DOMAIN}\nkind={}:{}",
            ROOT_ATTESTATION_KIND.len(),
            ROOT_ATTESTATION_KIND
        );
        assert!(bytes.starts_with(expected_prefix.as_bytes()));
        assert!(bytes.windows(32).any(|window| window == pk));
        assert!(bytes.windows(8).any(|window| window == 1_i64.to_be_bytes()));
        assert!(bytes.windows(8).any(|window| window == 2_i64.to_be_bytes()));
        assert!(
            !bytes
                .windows(64)
                .any(|window| window == hex::encode(pk).as_bytes())
        );
        let shifted_utf8 = ephemeral_attestation_bytes("a", &pk, 1, 2, "bc");
        assert_ne!(bytes, shifted_utf8);
        let shifted_window = ephemeral_attestation_bytes("ab", &pk, 0x0102, 0x03, "c");
        let original_window = ephemeral_attestation_bytes("ab", &pk, 0x01, 0x0203, "c");
        assert_ne!(shifted_window, original_window);
    }

    #[test]
    fn verify_accepts_the_committed_conformance_vector() {
        let regenerated = regenerate();
        assert_eq!(
            hex::encode(regenerated.root_public_key),
            ROOT_PUBLIC_KEY_HEX
        );
        assert_eq!(
            hex::encode(regenerated.ephemeral_public_key),
            EPHEMERAL_PUBLIC_KEY_HEX
        );
        assert_eq!(
            hex::encode(&regenerated.canonical_bytes),
            CANONICAL_BYTES_HEX
        );
        assert_eq!(
            hex::encode(regenerated.attestation_signature),
            ATTESTATION_SIGNATURE_HEX
        );
        assert_eq!(regenerated.signed_descriptor_hex, SIGNED_DESCRIPTOR_HEX);

        let root = parse_hex_32(ROOT_PUBLIC_KEY_HEX);
        let verified = verify_ephemeral_attestation(&root, &committed_entry(), now())
            .expect("committed vector must verify");
        assert_eq!(
            verified.ephemeral_public_key,
            regenerated.ephemeral_public_key
        );
        assert_eq!(
            verified.endpoint_descriptor.endpoint_id,
            EPHEMERAL_PUBLIC_KEY_HEX
        );
        assert_eq!(verified.region, REGION);
        assert_eq!(verified.not_before_unix_millis, NOT_BEFORE_UNIX_MILLIS);
        assert_eq!(verified.not_after_unix_millis, NOT_AFTER_UNIX_MILLIS);
    }

    #[test]
    fn foreign_root_attestation_is_rejected() {
        let regenerated = regenerate();
        let foreign = SigningKey::from_bytes(&[0x41; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            verify_ephemeral_attestation(&foreign, &regenerated.entry, now()),
            Err(EntryReject::InvalidSignature)
        );
    }

    #[test]
    fn tampering_any_attested_tuple_field_invalidates_the_signature() {
        let regenerated = regenerate();
        let root = regenerated.root_public_key;

        let mut pubkey = regenerated.entry.clone();
        let mut pk = parse_hex_32(&pubkey.ephemeral_public_key);
        pk[0] ^= 0x01;
        pubkey.ephemeral_public_key = hex::encode(pk);

        let mut key_id = regenerated.entry.clone();
        key_id.ephemeral_key_id.push('x');

        let mut not_before = regenerated.entry.clone();
        not_before.not_before_unix_millis += 1;

        let mut not_after = regenerated.entry.clone();
        not_after.not_after_unix_millis -= 1;

        let mut region = regenerated.entry.clone();
        region.region.push('x');

        for (label, entry) in [
            ("pubkey", pubkey),
            ("key_id", key_id),
            ("not_before", not_before),
            ("not_after", not_after),
            ("region", region),
        ] {
            assert_eq!(
                verify_ephemeral_attestation(&root, &entry, now()),
                Err(EntryReject::InvalidSignature),
                "{label} must be covered by the attestation signature"
            );
        }
    }

    #[test]
    fn descriptor_signed_by_a_different_key_is_rejected() {
        let regenerated = regenerate();
        let other = SigningKey::from_bytes(&[0x42; 32]);
        let descriptor = regenerated.entry_descriptor();
        let mut entry = regenerated.entry.clone();
        entry.signed_descriptor =
            hex::encode(sign_descriptor(&other, EPHEMERAL_KEY_ID, descriptor).encode_to_vec());
        assert_eq!(
            verify_ephemeral_attestation(&regenerated.root_public_key, &entry, now()),
            Err(EntryReject::InvalidDescriptorSignature)
        );
    }

    #[test]
    fn descriptor_endpoint_id_must_equal_the_attested_public_key() {
        let regenerated = regenerate();
        let ephemeral = SigningKey::from_bytes(&EPHEMERAL_SECRET_SEED);
        let mut descriptor = regenerated.entry_descriptor();
        descriptor.endpoint_id = "not-the-attested-key".to_string();
        let mut entry = regenerated.entry.clone();
        entry.signed_descriptor =
            hex::encode(sign_descriptor(&ephemeral, EPHEMERAL_KEY_ID, descriptor).encode_to_vec());
        assert_eq!(
            verify_ephemeral_attestation(&regenerated.root_public_key, &entry, now()),
            Err(EntryReject::DescriptorKeyMismatch)
        );
    }

    #[test]
    fn signed_descriptor_key_id_must_equal_ephemeral_key_id() {
        let regenerated = regenerate();
        let ephemeral = SigningKey::from_bytes(&EPHEMERAL_SECRET_SEED);
        let descriptor = regenerated.entry_descriptor();
        let mut entry = regenerated.entry.clone();
        entry.signed_descriptor =
            hex::encode(sign_descriptor(&ephemeral, "other-key-id", descriptor).encode_to_vec());
        assert_eq!(
            verify_ephemeral_attestation(&regenerated.root_public_key, &entry, now()),
            Err(EntryReject::DescriptorKeyMismatch)
        );
    }

    #[test]
    fn endpoint_descriptor_signature_cannot_verify_as_attestation() {
        let regenerated = regenerate();
        let root = SigningKey::from_bytes(&ROOT_SECRET_SEED);
        let descriptor = regenerated.entry_descriptor();
        let mut entry = regenerated.entry.clone();
        entry.attestation_signature = hex::encode(
            root.sign(&endpoint_descriptor_bytes(&descriptor))
                .to_bytes(),
        );
        assert_eq!(
            verify_ephemeral_attestation(&regenerated.root_public_key, &entry, now()),
            Err(EntryReject::InvalidSignature)
        );
    }

    #[test]
    fn attestation_signature_cannot_verify_as_descriptor_signature() {
        let regenerated = regenerate();
        let ephemeral = SigningKey::from_bytes(&EPHEMERAL_SECRET_SEED);
        let descriptor = regenerated.entry_descriptor();
        let mut signed = sign_descriptor(&ephemeral, EPHEMERAL_KEY_ID, descriptor);
        signed.signature = ephemeral
            .sign(&regenerated.canonical_bytes)
            .to_bytes()
            .to_vec();
        let mut entry = regenerated.entry.clone();
        entry.signed_descriptor = hex::encode(signed.encode_to_vec());
        assert_eq!(
            verify_ephemeral_attestation(&regenerated.root_public_key, &entry, now()),
            Err(EntryReject::InvalidDescriptorSignature)
        );
    }

    #[test]
    fn expired_and_not_yet_valid_entries_are_excluded() {
        let regenerated = regenerate();
        let root = regenerated.root_public_key;
        assert_eq!(
            verify_ephemeral_attestation(&root, &regenerated.entry, NOT_BEFORE_UNIX_MILLIS - 1),
            Err(EntryReject::NotYetValid)
        );
        assert_eq!(
            verify_ephemeral_attestation(&root, &regenerated.entry, NOT_AFTER_UNIX_MILLIS),
            Err(EntryReject::Expired)
        );
        assert_eq!(
            verify_ephemeral_attestation(&root, &regenerated.entry, NOT_AFTER_UNIX_MILLIS - 1)
                .map(|verified| verified.ephemeral_public_key),
            Ok(regenerated.ephemeral_public_key)
        );
    }

    #[test]
    fn inverted_window_all_zero_signature_and_malformed_descriptor_are_rejected() {
        let regenerated = regenerate();
        let root = regenerated.root_public_key;
        let mut inverted = regenerated.entry.clone();
        inverted.not_before_unix_millis = NOT_AFTER_UNIX_MILLIS;
        inverted.not_after_unix_millis = NOT_BEFORE_UNIX_MILLIS;
        assert_eq!(
            verify_ephemeral_attestation(&root, &inverted, now()),
            Err(EntryReject::InvalidWindow)
        );
        let mut missing = regenerated.entry.clone();
        missing.attestation_signature.clear();
        assert_eq!(
            verify_ephemeral_attestation(&root, &missing, now()),
            Err(EntryReject::MissingSignature)
        );
        let mut unattested = regenerated.entry.clone();
        unattested.attestation_signature = "00".repeat(64);
        assert_eq!(
            verify_ephemeral_attestation(&root, &unattested, now()),
            Err(EntryReject::Unattested)
        );
        let mut malformed = regenerated.entry.clone();
        malformed.signed_descriptor = "zz".to_string();
        assert_eq!(
            verify_ephemeral_attestation(&root, &malformed, now()),
            Err(EntryReject::MalformedDescriptor)
        );
        let mut empty_key = regenerated.entry.clone();
        empty_key.ephemeral_key_id.clear();
        assert_eq!(
            verify_ephemeral_attestation(&root, &empty_key, now()),
            Err(EntryReject::InvalidKey)
        );
        let mut uppercase = regenerated.entry.clone();
        uppercase.ephemeral_public_key = uppercase.ephemeral_public_key.to_uppercase();
        assert_eq!(
            verify_ephemeral_attestation(&root, &uppercase, now()),
            Err(EntryReject::InvalidKey)
        );
    }

    #[test]
    fn trusted_live_entries_drops_rejects_and_keeps_only_two_layer_successes() {
        let regenerated = regenerate();
        let mut tampered = regenerated.entry.clone();
        tampered.region.push('x');
        let set = EndpointDescriptorSetDocument {
            version: SET_VERSION,
            root_key_id: "root-1".to_string(),
            entries: vec![regenerated.entry.clone(), tampered],
        };
        let (live, rejects) = trusted_live_entries(&set, &regenerated.root_public_key, now());
        assert_eq!(live.len(), 1);
        assert_eq!(
            live[0].ephemeral_public_key,
            regenerated.ephemeral_public_key
        );
        assert_eq!(rejects, vec![EntryReject::InvalidSignature]);

        let (live, rejects) =
            trusted_live_entries(&set, &regenerated.root_public_key, NOT_AFTER_UNIX_MILLIS);
        assert!(live.is_empty());
        assert_eq!(
            rejects,
            vec![EntryReject::Expired, EntryReject::InvalidSignature]
        );
    }

    #[test]
    fn mismatched_document_version_is_rejected_fail_closed() {
        let regenerated = regenerate();
        for version in [0_u8, 2, 255] {
            let set = EndpointDescriptorSetDocument {
                version,
                root_key_id: "root-1".to_string(),
                entries: vec![regenerated.entry.clone()],
            };
            let (live, rejects) = trusted_live_entries(&set, &regenerated.root_public_key, now());
            assert!(
                live.is_empty(),
                "version {version} must not promote entries"
            );
            assert_eq!(rejects, vec![EntryReject::UnsupportedVersion]);
            let body = serde_json::to_vec(&set).expect("serialize set");
            assert_eq!(
                parse_endpoint_descriptor_set(&body),
                Err(DescriptorSetError::UnsupportedVersion(version))
            );
        }

        let v1 = EndpointDescriptorSetDocument {
            version: SET_VERSION,
            root_key_id: "root-1".to_string(),
            entries: vec![regenerated.entry.clone()],
        };
        let parsed = parse_endpoint_descriptor_set(&serde_json::to_vec(&v1).expect("serialize v1"))
            .expect("version 1 must parse");
        assert_eq!(parsed, v1);
    }

    #[test]
    fn inner_descriptor_version_and_validity_window_are_enforced() {
        let regenerated = regenerate();
        let ephemeral = SigningKey::from_bytes(&EPHEMERAL_SECRET_SEED);
        let root = regenerated.root_public_key;

        let mut expired = regenerated.entry_descriptor();
        expired.expires_at_unix_millis = now();
        let mut expired_entry = regenerated.entry.clone();
        expired_entry.signed_descriptor =
            hex::encode(sign_descriptor(&ephemeral, EPHEMERAL_KEY_ID, expired).encode_to_vec());
        assert_eq!(
            verify_ephemeral_attestation(&root, &expired_entry, now()),
            Err(EntryReject::DescriptorExpired)
        );

        let mut not_yet = regenerated.entry_descriptor();
        not_yet.issued_at_unix_millis = now() + 1;
        let mut not_yet_entry = regenerated.entry.clone();
        not_yet_entry.signed_descriptor =
            hex::encode(sign_descriptor(&ephemeral, EPHEMERAL_KEY_ID, not_yet).encode_to_vec());
        assert_eq!(
            verify_ephemeral_attestation(&root, &not_yet_entry, now()),
            Err(EntryReject::DescriptorNotYetValid)
        );

        let mut unsupported = regenerated.entry_descriptor();
        unsupported.version = 0;
        let mut unsupported_entry = regenerated.entry.clone();
        unsupported_entry.signed_descriptor =
            hex::encode(sign_descriptor(&ephemeral, EPHEMERAL_KEY_ID, unsupported).encode_to_vec());
        assert_eq!(
            verify_ephemeral_attestation(&root, &unsupported_entry, now()),
            Err(EntryReject::UnsupportedDescriptorVersion)
        );
    }

    #[test]
    fn signed_descriptor_hex_must_be_lowercase() {
        let regenerated = regenerate();
        let mut entry = regenerated.entry.clone();
        entry.signed_descriptor = entry.signed_descriptor.to_uppercase();
        assert_eq!(
            verify_ephemeral_attestation(&regenerated.root_public_key, &entry, now()),
            Err(EntryReject::MalformedDescriptor)
        );
    }

    #[test]
    fn whitespace_only_ephemeral_key_id_is_rejected() {
        let regenerated = regenerate();
        let mut entry = regenerated.entry.clone();
        entry.ephemeral_key_id = " \t ".to_string();
        assert_eq!(
            verify_ephemeral_attestation(&regenerated.root_public_key, &entry, now()),
            Err(EntryReject::InvalidKey)
        );
    }

    impl Regenerated {
        fn entry_descriptor(&self) -> EndpointDescriptor {
            let signed_bytes = hex::decode(&self.entry.signed_descriptor).unwrap();
            SignedEndpointDescriptor::decode(signed_bytes.as_slice())
                .unwrap()
                .descriptor
                .unwrap()
        }
    }
}
