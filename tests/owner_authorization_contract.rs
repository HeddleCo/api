// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

use heddle_api::heddle::api::v1alpha1::{
    AnonymousKeyCredential, BootstrapOwnerRootRequest, CloneAuthorizationKeyring,
    OwnerAuthorizationBundle, OwnerKeyTransition, OwnerRoot, RecoveryGuardian,
    RecoveryGuardianKind, RecoveryPolicy, SignedOwnerCapability, SignedOwnerKeyTransition,
    SignedOwnerRoot, SubmitOwnerAuthorizationRequest,
};
use prost::Message;

fn assert_round_trip<T>(value: T)
where
    T: Message + Default + PartialEq + Debug,
{
    let encoded = value.encode_to_vec();
    let decoded = T::decode(encoded.as_slice()).expect("generated owner contract decodes");
    assert_eq!(decoded, value);
}

#[test]
fn generated_rust_round_trips_all_six_owner_contract_families() {
    assert_round_trip(SignedOwnerRoot {
        root: Some(OwnerRoot::default()),
        ..Default::default()
    });
    assert_round_trip(BootstrapOwnerRootRequest::default());
    assert_round_trip(SignedOwnerKeyTransition {
        transition: Some(OwnerKeyTransition::default()),
        ..Default::default()
    });
    assert_round_trip(SubmitOwnerAuthorizationRequest {
        authorization: Some(OwnerAuthorizationBundle {
            capability_chain: vec![SignedOwnerCapability::default()],
            ..Default::default()
        }),
        ..Default::default()
    });
    assert_round_trip(AnonymousKeyCredential::default());
    assert_round_trip(CloneAuthorizationKeyring::default());
}

#[test]
fn generated_recovery_policy_preserves_guardian_provenance() {
    let policy = RecoveryPolicy {
        threshold: 2,
        guardians: vec![
            RecoveryGuardian {
                kind: RecoveryGuardianKind::Paper as i32,
                ..Default::default()
            },
            RecoveryGuardian {
                kind: RecoveryGuardianKind::Weft as i32,
                ..Default::default()
            },
        ],
    };

    let encoded = policy.encode_to_vec();
    let decoded = RecoveryPolicy::decode(encoded.as_slice()).expect("recovery policy decodes");
    assert_eq!(decoded, policy);
    assert_ne!(decoded.guardians[0].kind, decoded.guardians[1].kind);
}
