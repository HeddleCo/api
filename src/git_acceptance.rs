//! Stable semantic identity for native Git acceptance. Authentication remains
//! the receiver's responsibility; these inputs alone never grant authority.
use crate::heddle::api::v1alpha2::{PublishContentClientFrame, publish_content_client_frame};
use prost::Message;

/// Exact signed original bytes. The caller must derive `operation_id` from a
/// verified canonical operation; this transport-independent helper does not
/// authenticate signatures or grant authority.
pub struct OriginalDigestEntry<'a> {
    pub operation_id: &'a [u8],
    pub canonical: &'a [u8],
    pub signature: &'a [u8],
}

/// Canonical complete-original manifest, independent of batching and order.
/// Identical repetitions across historical packs are deduplicated. Conflicting
/// evidence for an identity, malformed widths, empty manifests, and manifests
/// beyond the receiver's cumulative original budget fail closed.
pub fn originals_digest<'a>(
    entries: impl IntoIterator<Item = OriginalDigestEntry<'a>>,
) -> Option<[u8; 32]> {
    let mut originals: std::collections::BTreeMap<&'a [u8], (&'a [u8], &'a [u8])> =
        std::collections::BTreeMap::new();
    let mut bytes = 0usize;
    for entry in entries {
        if entry.operation_id.len() != 32
            || entry.canonical.is_empty()
            || entry.signature.len() != 64
        {
            return None;
        }
        if let Some(prior) = originals.get(entry.operation_id) {
            if *prior != (entry.canonical, entry.signature) {
                return None;
            }
            continue;
        }
        bytes = bytes
            .checked_add(entry.canonical.len())?
            .checked_add(entry.signature.len())?;
        if bytes > 16 * 1024 * 1024 || originals.len() >= 4096 {
            return None;
        }
        originals.insert(entry.operation_id, (entry.canonical, entry.signature));
    }
    if originals.is_empty() {
        return None;
    }
    let mut hash = blake3::Hasher::new_derive_key("heddle.git.acceptance.originals.v1");
    hash.update(&(originals.len() as u64).to_le_bytes());
    for (id, (canonical, signature)) in originals {
        for part in [id, canonical, signature] {
            hash.update(&(part.len() as u64).to_le_bytes());
            hash.update(part);
        }
    }
    Some(*hash.finalize().as_bytes())
}

pub fn request_digest(
    opening: &PublishContentClientFrame,
    actor_account_id: &str,
) -> Option<[u8; 32]> {
    let mut logical = opening.clone();
    let publish_content_client_frame::Body::Open(open) = logical.body.as_mut()? else {
        return None;
    };
    open.checkpoint = None;
    let git = open.git_acceptance.as_mut()?;
    if git.originals_digest.len() != 32 {
        return None;
    }
    git.transport_token.clear();
    for child in &mut git.history {
        let child = child.open.as_mut()?;
        if child.git_acceptance.is_some() {
            return None;
        }
        child.checkpoint = None;
    }
    let mut hash = blake3::Hasher::new_derive_key("heddle.git.acceptance.request.v1");
    for part in [
        logical.encode_to_vec().as_slice(),
        actor_account_id.as_bytes(),
    ] {
        hash.update(&(part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    Some(*hash.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heddle::api::v1alpha2::{
        GitPushAcceptance, GitPushHistoryRevision, GitTransportScope, PublishContentOpen,
        TransferCheckpoint,
    };

    fn opening() -> PublishContentClientFrame {
        PublishContentClientFrame {
            client_operation_id: "command".into(),
            body: Some(publish_content_client_frame::Body::Open(
                PublishContentOpen {
                    git_acceptance: Some(GitPushAcceptance {
                        expected_revision: vec![1; 32],
                        expected_git_commit: vec![2; 20],
                        accepted_git_commit: vec![3; 20],
                        gateway_publisher: vec![4; 32],
                        expected_native_generation: Some(0),
                        originals_digest: vec![5; 32],
                        transport_token: "first-session".into(),
                        scope: Some(GitTransportScope::default()),
                        history: vec![GitPushHistoryRevision {
                            client_operation_id: "history-command".into(),
                            open: Some(PublishContentOpen::default()),
                        }],
                    }),
                    ..Default::default()
                },
            )),
        }
    }

    fn edit(value: &mut PublishContentClientFrame) -> &mut PublishContentOpen {
        let Some(publish_content_client_frame::Body::Open(open)) = &mut value.body else {
            panic!("test opening")
        };
        open
    }

    fn entry<'a>(
        id: &'a [u8],
        canonical: &'a [u8],
        signature: &'a [u8],
    ) -> OriginalDigestEntry<'a> {
        OriginalDigestEntry {
            operation_id: id,
            canonical,
            signature,
        }
    }

    #[test]
    fn complete_originals_manifest_is_order_and_batch_independent() {
        let a = [1; 32];
        let b = [2; 32];
        let signature = [3; 64];
        let first = originals_digest([
            entry(&a, b"first", &signature),
            entry(&b, b"second", &signature),
        ]);
        assert!(first.is_some());
        assert_eq!(
            first,
            originals_digest([
                entry(&b, b"second", &signature),
                entry(&a, b"first", &signature),
                entry(&b, b"second", &signature),
            ])
        );
        assert_ne!(first, originals_digest([entry(&a, b"first", &signature)]));
        assert_ne!(
            first,
            originals_digest([
                entry(&a, b"changed", &signature),
                entry(&b, b"second", &signature)
            ])
        );
        assert_ne!(
            first,
            originals_digest([
                entry(&a, b"first", &[4; 64]),
                entry(&b, b"second", &signature)
            ])
        );
    }

    #[test]
    fn complete_originals_manifest_rejects_ambiguity_and_unbounded_evidence() {
        let a = [1; 32];
        let signature = [3; 64];
        assert_eq!(originals_digest([]), None);
        assert_eq!(originals_digest([entry(&a, b"", &signature)]), None);
        assert_eq!(
            originals_digest([entry(&[1; 31], b"first", &signature)]),
            None
        );
        assert_eq!(originals_digest([entry(&a, b"first", &[3; 63])]), None);
        assert_eq!(
            originals_digest([
                entry(&a, b"first", &signature),
                entry(&a, b"changed", &signature)
            ]),
            None
        );
        assert_eq!(
            originals_digest([
                entry(&a, b"first", &signature),
                entry(&a, b"first", &[4; 64])
            ]),
            None
        );
        let too_large = vec![0; 16 * 1024 * 1024];
        assert_eq!(originals_digest([entry(&a, &too_large, &signature)]), None);
        let ids: Vec<_> = (0u32..4097)
            .map(|n| {
                let mut id = [0; 32];
                id[..4].copy_from_slice(&n.to_le_bytes());
                id
            })
            .collect();
        assert!(
            originals_digest(ids[..4096].iter().map(|id| entry(id, b"x", &signature))).is_some()
        );
        assert_eq!(
            originals_digest(ids.iter().map(|id| entry(id, b"x", &signature))),
            None
        );
    }

    #[test]
    fn renewed_session_and_transfer_checkpoints_preserve_semantic_identity() {
        let first = opening();
        let mut retry = first.clone();
        let open = edit(&mut retry);
        open.checkpoint = Some(TransferCheckpoint::default());
        let git = open.git_acceptance.as_mut().unwrap();
        git.transport_token = "renewed-session".into();
        git.history[0].open.as_mut().unwrap().checkpoint = Some(TransferCheckpoint::default());
        assert_eq!(
            request_digest(&first, "verified-actor"),
            request_digest(&retry, "verified-actor")
        );
    }

    #[test]
    fn actor_command_heads_publisher_scope_and_ordered_history_are_bound() {
        let first = opening();
        let expected = request_digest(&first, "verified-actor");
        assert_ne!(expected, request_digest(&first, "different-actor"));
        for mutation in 0..10 {
            let mut other = first.clone();
            if mutation == 0 {
                other.client_operation_id.push('x');
            } else {
                let git = edit(&mut other).git_acceptance.as_mut().unwrap();
                match mutation {
                    1 => git.expected_revision[0] ^= 1,
                    2 => git.expected_git_commit[0] ^= 1,
                    3 => git.accepted_git_commit[0] ^= 1,
                    4 => git.gateway_publisher[0] ^= 1,
                    5 => git.scope = None,
                    6 => git.history[0].client_operation_id.push('x'),
                    7 => git.expected_native_generation = Some(1),
                    8 => git.expected_native_generation = None,
                    9 => git.originals_digest[0] ^= 1,
                    _ => unreachable!(),
                }
            }
            assert_ne!(
                expected,
                request_digest(&other, "verified-actor"),
                "mutation {mutation}"
            );
        }
        let mut other = first.clone();
        let git = edit(&mut other).git_acceptance.as_mut().unwrap();
        let mut second = git.history[0].clone();
        second.client_operation_id = "second".into();
        git.history.push(second);
        let before = request_digest(&other, "verified-actor");
        edit(&mut other)
            .git_acceptance
            .as_mut()
            .unwrap()
            .history
            .reverse();
        assert_ne!(before, request_digest(&other, "verified-actor"));
    }

    #[test]
    fn incomplete_or_recursive_openings_cannot_claim_a_semantic_identity() {
        assert_eq!(
            request_digest(&PublishContentClientFrame::default(), "actor"),
            None
        );
        let mut value = opening();
        edit(&mut value)
            .git_acceptance
            .as_mut()
            .unwrap()
            .originals_digest
            .clear();
        assert_eq!(request_digest(&value, "actor"), None);
        let mut value = opening();
        edit(&mut value).git_acceptance.as_mut().unwrap().history[0].open = None;
        assert_eq!(request_digest(&value, "actor"), None);
        let mut value = opening();
        edit(&mut value).git_acceptance.as_mut().unwrap().history[0]
            .open
            .as_mut()
            .unwrap()
            .git_acceptance = Some(GitPushAcceptance::default());
        assert_eq!(request_digest(&value, "actor"), None);
    }
}
