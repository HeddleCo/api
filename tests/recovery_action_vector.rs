use heddle_api::{heddle::api::v2alpha1::RecordRef, v2::identity_management};

#[test]
fn rust_recovery_action_vector_for_browser_parity() {
    let account = "123e4567-e89b-12d3-a456-426614174000";
    let operation = "123e4567-e89b-12d3-a456-426614174001";
    let reference = RecordRef {
        id: "123e4567-e89b-12d3-a456-426614174002".into(),
        spool: None,
    };
    let version: Vec<u8> = (0u8..32).collect();
    let key: Vec<u8> = (32u8..64).collect();
    let canonical =
        identity_management::recovery_action(account, operation, Some(&reference), &version, &key)
            .expect("fixed unscoped recovery action vector");
    let signing =
        identity_management::signing_bytes(identity_management::RECOVERY_POSSESSION, &canonical)
            .expect("supported recovery possession domain");
    println!("canonical={}", hex::encode(&canonical));
    println!("signing={}", hex::encode(&signing));
    assert_eq!(canonical.len(), 196);
    assert_eq!(
        signing.len(),
        identity_management::RECOVERY_POSSESSION.len() + 1 + canonical.len()
    );
}
