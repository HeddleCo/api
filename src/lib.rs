//! Generated transport-neutral Rust types for the Heddle API.

pub mod framing;
pub mod signing;
mod transport;

pub use transport::{
    ALL_METHODS, HOSTED_ALPN_V1, MethodDescriptor, MethodRoute, RoutedCall, StreamingShape,
    method_descriptor,
};

/// Cross-product hosted-call framing and typed-failure fixture.
pub const HOSTED_CALL_V1_FIXTURE_JSON: &str = include_str!("../tests/fixtures/hosted-call-v1.json");
/// Cross-product canonical unary-signing fixture.
pub const UNARY_SIGNING_V1_FIXTURE_JSON: &str =
    include_str!("../tests/fixtures/unary-signing-v1.json");

/// Page size used when callers omit or pass zero for a requested size.
pub const DEFAULT_PAGE_SIZE: u32 = 50;
/// Largest page the public API permits.
pub const MAX_PAGE_SIZE: u32 = 200;

/// Applies the contract-owned default and upper bound to a requested page.
pub const fn normalize_page_size(requested: u32) -> u32 {
    if requested == 0 {
        DEFAULT_PAGE_SIZE
    } else if requested > MAX_PAGE_SIZE {
        MAX_PAGE_SIZE
    } else {
        requested
    }
}

/// Heddle API protobuf packages.
pub mod heddle {
    /// Neutral public API contract.
    pub mod api {
        /// Breaking pre-1.0 API generation.
        pub mod v1alpha1 {
            include!(concat!(env!("OUT_DIR"), "/heddle.api.v1alpha1.rs"));
        }
    }
}

/// Compiled protobuf descriptor set for reflection and contract inspection.
#[cfg(feature = "reflection")]
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/heddle_api_descriptor.bin"));

/// Errors returned while constructing fixed-width API identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidIdentifierLength {
    kind: &'static str,
    expected: usize,
    actual: usize,
}

impl std::fmt::Display for InvalidIdentifierLength {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} requires exactly {} bytes, got {}",
            self.kind, self.expected, self.actual
        )
    }
}

impl std::error::Error for InvalidIdentifierLength {}

impl heddle::api::v1alpha1::StateId {
    /// Constructs a physical state identifier from exactly 32 bytes.
    pub fn from_bytes(value: impl AsRef<[u8]>) -> Result<Self, InvalidIdentifierLength> {
        fixed_width("StateId", 32, value.as_ref()).map(|value| Self { value })
    }
}

impl heddle::api::v1alpha1::ChangeId {
    /// Constructs a rewrite-stable change identifier from exactly 16 bytes.
    pub fn from_bytes(value: impl AsRef<[u8]>) -> Result<Self, InvalidIdentifierLength> {
        fixed_width("ChangeId", 16, value.as_ref()).map(|value| Self { value })
    }
}

impl heddle::api::v1alpha1::OperationId {
    /// Constructs a durable operation identifier from exactly 16 bytes.
    pub fn from_bytes(value: impl AsRef<[u8]>) -> Result<Self, InvalidIdentifierLength> {
        fixed_width("OperationId", 16, value.as_ref()).map(|value| Self { value })
    }
}

impl heddle::api::v1alpha1::OperationBatchId {
    /// Constructs a durable operation-batch identifier from exactly 16 bytes.
    pub fn from_bytes(value: impl AsRef<[u8]>) -> Result<Self, InvalidIdentifierLength> {
        fixed_width("OperationBatchId", 16, value.as_ref()).map(|value| Self { value })
    }
}

impl heddle::api::v1alpha1::GitObjectId {
    /// Constructs and validates a Git object identifier for its hash algorithm.
    pub fn from_digest(
        algorithm: heddle::api::v1alpha1::GitObjectAlgorithm,
        digest: impl AsRef<[u8]>,
    ) -> Result<Self, InvalidIdentifierLength> {
        let expected = match algorithm {
            heddle::api::v1alpha1::GitObjectAlgorithm::Sha1 => 20,
            heddle::api::v1alpha1::GitObjectAlgorithm::Sha256 => 32,
            heddle::api::v1alpha1::GitObjectAlgorithm::Unspecified => 0,
        };
        fixed_width("GitObjectId", expected, digest.as_ref()).map(|digest| Self {
            algorithm: algorithm as i32,
            digest,
        })
    }
}

fn fixed_width(
    kind: &'static str,
    expected: usize,
    value: &[u8],
) -> Result<Vec<u8>, InvalidIdentifierLength> {
    if value.len() != expected {
        return Err(InvalidIdentifierLength {
            kind,
            expected,
            actual: value.len(),
        });
    }
    Ok(value.to_vec())
}

#[cfg(test)]
mod tests {
    use super::heddle::api::v1alpha1::{
        ChangeId, GitObjectAlgorithm, GitObjectId, OperationBatchId, OperationId, StateId,
    };

    #[test]
    fn fixed_width_identifiers_reject_ambiguous_bytes() {
        assert!(StateId::from_bytes([0; 32]).is_ok());
        assert!(StateId::from_bytes([0; 31]).is_err());
        assert!(ChangeId::from_bytes([0; 16]).is_ok());
        assert!(ChangeId::from_bytes([0; 17]).is_err());
        assert!(OperationId::from_bytes([0; 16]).is_ok());
        assert!(OperationId::from_bytes([0; 15]).is_err());
        assert!(OperationBatchId::from_bytes([0; 16]).is_ok());
        assert!(OperationBatchId::from_bytes([0; 17]).is_err());
        assert!(GitObjectId::from_digest(GitObjectAlgorithm::Sha1, [0; 20]).is_ok());
        assert!(GitObjectId::from_digest(GitObjectAlgorithm::Sha256, [0; 20]).is_err());
    }
}
