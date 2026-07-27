// SPDX-License-Identifier: Apache-2.0

use heddle_api::heddle::api::v1alpha1::Entitlement;
use prost::Message;

#[test]
fn entitlement_round_trips_usage_and_subscription_projection() {
    let expected = Entitlement {
        current_storage_bytes: 83,
        storage_allowance_bytes: 500_000_000_000,
        billing_interval: Some("year".to_string()),
        billing_interval_count: Some(1),
        currency: Some("eur".to_string()),
        amount: Some(19_900),
        provider_subscription_id: Some("sub_customer".to_string()),
        ..Default::default()
    };

    let decoded = Entitlement::decode(expected.encode_to_vec().as_slice())
        .expect("decode entitlement projection");

    assert_eq!(decoded, expected);
}
