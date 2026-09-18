// SPDX-License-Identifier: Apache-2.0

use heddle_api::STATE_ATTACHMENT_AUTHORIZATION_CONFORMANCE;
use heddle_api::heddle::api::common::{
    StateAttachmentAuthorizationClassification, StateAttachmentKind,
};

#[test]
fn generated_attachment_authorization_classifies_every_current_kind() {
    let expected = [
        StateAttachmentKind::Context,
        StateAttachmentKind::RiskSignals,
        StateAttachmentKind::ReviewSignatures,
        StateAttachmentKind::Discussions,
        StateAttachmentKind::StructuredConflicts,
        StateAttachmentKind::SemanticIndex,
        StateAttachmentKind::Signature,
    ];
    assert_eq!(
        STATE_ATTACHMENT_AUTHORIZATION_CONFORMANCE.len(),
        expected.len()
    );
    for kind in expected {
        assert!(
            STATE_ATTACHMENT_AUTHORIZATION_CONFORMANCE
                .contains(&(kind, StateAttachmentAuthorizationClassification::SpoolWrite,))
        );
    }
}
