//! Canonical portable identity-management statements. Sign `format || NUL ||
//! canonical_record` with Ed25519. Every variable field is a big-endian u32
//! length followed by bytes; integers are fixed-width big-endian. No protobuf
//! serialization, JSON normalization, or transport envelope participates.
use crate::heddle::api::v2alpha1 as api;

pub const DELEGATION: &str = "heddle.delegation.v2";
pub const ISSUE_AUTHORITY: &str = "heddle.delegation-issuance-authority.v2";
pub const ISSUE_POSSESSION: &str = "heddle.delegation-issuance-possession.v2";
pub const REVOKE_DELEGATION: &str = "heddle.delegation-revocation.v2";
pub const ROOT_POSSESSION: &str = "heddle.root-registration-possession.v2";
pub const RECOVERY_TRANSITION: &str = "heddle.owner-recovery-transition.v2";
pub const RECOVERY_POLICY: &str = "heddle.owner-recovery-policy.v2";
pub const RECOVERY_POSSESSION: &str = "heddle.owner-recovery-possession.v2";
pub const OWNER_TRANSITION_POSSESSION: &str = "heddle.owner-transition-possession.v2";
pub const OWNER_TRANSITION_VETO: &str = "heddle.owner-transition-veto.v2";
pub const RECOVERY_VETO: &str = "heddle.owner-recovery-veto.v2";

#[derive(Debug, thiserror::Error)]
#[error("invalid canonical identity statement: {0}")]
pub struct Error(pub &'static str);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationStatement {
    pub account_id: String,
    pub delegation_id: String,
    pub label: String,
    pub kind: i32,
    pub root_public_key: Vec<u8>,
    pub subject_public_key: Vec<u8>,
    pub endpoint_public_key: Vec<u8>,
    /// Empty inherits the exact parent's ceiling. Nonempty uses the contract
    /// scope grammar and is enforced by an appended narrowing block.
    pub scope: String,
    pub expires_at_unix_seconds: i64,
    /// BLAKE3 of the exact parent Biscuit, never bearer material.
    pub parent_credential_digest: Vec<u8>,
}
impl DelegationStatement {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.account_id.len() != 36
            || self.delegation_id.len() != 36
            || self.label.len() > 256
            || !(1..=3).contains(&self.kind)
            || self.root_public_key.len() != 32
            || self.subject_public_key.len() != 32
            || !matches!(self.endpoint_public_key.len(), 0 | 32)
            || self.scope.len() > 4096
            || self.expires_at_unix_seconds <= 0
            || self.parent_credential_digest.len() != 32
        {
            return Err(Error("delegation bounds"));
        }
        let mut out = Encoder::default();
        out.number(1);
        for value in [&self.account_id, &self.delegation_id, &self.label] {
            out.bytes(value.as_bytes())?;
        }
        out.number(self.kind as u32);
        for value in [
            &self.root_public_key,
            &self.subject_public_key,
            &self.endpoint_public_key,
        ] {
            out.bytes(value)?;
        }
        out.bytes(self.scope.as_bytes())?;
        out.0
            .extend_from_slice(&self.expires_at_unix_seconds.to_be_bytes());
        out.bytes(&self.parent_credential_digest)?;
        Ok(out.0)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 8192 {
            return Err(Error("delegation exceeds 8 KiB"));
        }
        let mut input = Decoder(bytes);
        if input.number()? != 1 {
            return Err(Error("delegation version"));
        }
        let value = Self {
            account_id: input.string()?,
            delegation_id: input.string()?,
            label: input.string()?,
            kind: input.number()? as i32,
            root_public_key: input.bytes()?.to_vec(),
            subject_public_key: input.bytes()?.to_vec(),
            endpoint_public_key: input.bytes()?.to_vec(),
            scope: input.string()?,
            expires_at_unix_seconds: i64::from_be_bytes(
                input.take(8)?.try_into().map_err(|_| Error("expiry"))?,
            ),
            parent_credential_digest: input.bytes()?.to_vec(),
        };
        if !input.0.is_empty() || value.encode()?.as_slice() != bytes {
            return Err(Error("noncanonical delegation"));
        }
        Ok(value)
    }
    pub fn matches_record(&self, record: &api::DelegationRecord) -> bool {
        record
            .r#ref
            .as_ref()
            .is_some_and(|r| r.spool.is_none() && r.id == self.delegation_id)
            && record.label == self.label
            && record.kind == self.kind
            && record.subject.as_ref().is_some_and(|s| {
                s.root_public_key == self.root_public_key
                    && s.subject_public_key == self.subject_public_key
                    && s.device
                        .as_ref()
                        .map(|d| d.public_key.as_slice())
                        .unwrap_or_default()
                        == self.endpoint_public_key
            })
    }
}

/// Exact issuance intent; both signatures cover this statement. The parent also
/// signs the existing `pop_delegation` statement. That 64-byte signature is
/// appended to the authority record's canonical bytes, and itself covered by
/// the authority-record signature. The subject signs only the intent below.
pub fn issuance(
    account: &str,
    request: &api::IssueDelegationCredentialRequest,
) -> Result<Vec<u8>, Error> {
    let mut out = Encoder::default();
    out.number(1);
    out.bytes(account.as_bytes())?;
    out.bytes(request.client_operation_id.as_bytes())?;
    out.reference(request.delegation.as_ref())?;
    out.bytes(&request.expected_delegation_version)?;
    out.bytes(&request.proof_public_key)?;
    out.bytes(request.scope.as_bytes())?;
    match &request.expires_at {
        Some(expiry) => {
            if expiry.nanos != 0 {
                return Err(Error("whole-second expiry required"));
            }
            out.0.push(1);
            out.0.extend_from_slice(&expiry.seconds.to_be_bytes());
        }
        None => out.0.push(0),
    }
    Ok(out.0)
}
pub fn root_possession(
    account: &str,
    request: &api::RegisterRootAttachmentRequest,
) -> Result<Vec<u8>, Error> {
    let attachment = request
        .attachment
        .as_ref()
        .ok_or(Error("root attachment required"))?;
    let mut out = Encoder::default();
    out.number(1);
    out.bytes(account.as_bytes())?;
    out.bytes(request.client_operation_id.as_bytes())?;
    out.bytes(&attachment.root_public_key)?;
    out.bytes(&attachment.subject_public_key)?;
    out.bytes(
        attachment
            .device
            .as_ref()
            .map(|d| d.public_key.as_slice())
            .unwrap_or_default(),
    )?;
    if let Some(record) = &attachment.attachment {
        out.bytes(record.format.as_bytes())?;
        out.bytes(&record.canonical_record)?;
    } else {
        out.bytes(&[])?;
        out.bytes(&[])?;
    }
    out.bytes(request.label.as_bytes())?;
    Ok(out.0)
}
pub fn revocation(account: &str, request: &api::RevokeDelegationRequest) -> Result<Vec<u8>, Error> {
    let mut out = Encoder::default();
    out.number(1);
    out.bytes(account.as_bytes())?;
    out.bytes(request.client_operation_id.as_bytes())?;
    out.reference(request.delegation.as_ref())?;
    out.bytes(&request.expected_version)?;
    Ok(out.0)
}
pub fn recovery_action(
    account: &str,
    operation: &str,
    reference: Option<&api::RecordRef>,
    version: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut out = Encoder::default();
    out.number(1);
    out.bytes(account.as_bytes())?;
    out.bytes(operation.as_bytes())?;
    out.reference(reference)?;
    out.bytes(version)?;
    out.bytes(key)?;
    Ok(out.0)
}
pub fn signing_bytes(format: &str, canonical: &[u8]) -> Result<Vec<u8>, Error> {
    if !matches!(
        format,
        DELEGATION
            | ISSUE_AUTHORITY
            | ISSUE_POSSESSION
            | REVOKE_DELEGATION
            | ROOT_POSSESSION
            | RECOVERY_TRANSITION
            | RECOVERY_POLICY
            | RECOVERY_POSSESSION
            | RECOVERY_VETO
            | OWNER_TRANSITION_POSSESSION
            | OWNER_TRANSITION_VETO
    ) || canonical.len() > 128 * 1024
    {
        return Err(Error("unknown format or oversized statement"));
    }
    let mut out = Vec::with_capacity(format.len() + 1 + canonical.len());
    out.extend_from_slice(format.as_bytes());
    out.push(0);
    out.extend_from_slice(canonical);
    Ok(out)
}
#[derive(Default)]
struct Encoder(Vec<u8>);
impl Encoder {
    fn number(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    fn bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        let n = u32::try_from(value.len()).map_err(|_| Error("field length"))?;
        self.number(n);
        self.0.extend_from_slice(value);
        Ok(())
    }
    fn reference(&mut self, value: Option<&api::RecordRef>) -> Result<(), Error> {
        let value = value
            .filter(|v| v.spool.is_none() && !v.id.is_empty() && v.id.len() <= 256)
            .ok_or(Error("unscoped reference required"))?;
        self.bytes(value.id.as_bytes())
    }
}
struct Decoder<'a>(&'a [u8]);
impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(Error("truncated statement"));
        }
        let (value, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(value)
    }
    fn number(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Error("integer"))?,
        ))
    }
    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.number()? as usize;
        self.take(n)
    }
    fn string(&mut self) -> Result<String, Error> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| Error("UTF-8"))
    }
}
