#![cfg(feature = "reflection")]

use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::v1alpha2::{InvitationResolution, PublicOwner, invitation_resolution::Status},
    v2::invitation::{InvitationResolutionError, validate_invitation_resolution},
};
use prost::Message;
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn invitation_preview_descriptor_reuses_public_owner_with_additive_tags() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid descriptor");
    let response = pool
        .get_message_by_name("heddle.api.v1alpha2.InvitationResolution")
        .expect("resolution");
    let owner = pool
        .get_message_by_name("heddle.api.v1alpha2.PublicOwner")
        .expect("public owner");
    assert_eq!(
        response
            .fields()
            .map(|field| (field.name().to_owned(), field.number()))
            .collect::<Vec<_>>(),
        [
            ("status".into(), 1),
            ("spool".into(), 2),
            ("spool_name".into(), 3),
            ("role".into(), 4),
            ("expires_at".into(), 5),
            ("inviter".into(), 6),
            ("inviter_via_agent_label".into(), 7),
        ]
    );
    assert_eq!(
        response
            .get_field_by_name("inviter")
            .expect("inviter")
            .kind(),
        Kind::Message(owner)
    );
    assert_eq!(
        response
            .get_field_by_name("inviter_via_agent_label")
            .expect("agent label")
            .kind(),
        Kind::String
    );
}

#[test]
fn preview_round_trip_and_validation_keep_agent_tied_to_public_handle() {
    let available = InvitationResolution {
        status: Status::Available as i32,
        inviter: Some(PublicOwner {
            handle: "mara".into(),
            display_name: "Mara".into(),
        }),
        inviter_via_agent_label: "build-bot".into(),
        ..Default::default()
    };
    let decoded = InvitationResolution::decode(available.encode_to_vec().as_slice())
        .expect("invitation preview");
    assert_eq!(decoded, available);
    validate_invitation_resolution(&decoded).expect("accountable human handle");

    let mut invalid = available.clone();
    invalid.inviter = None;
    assert_eq!(
        validate_invitation_resolution(&invalid),
        Err(InvitationResolutionError::AgentWithoutInviter)
    );
    invalid.inviter = Some(PublicOwner {
        handle: String::new(),
        display_name: "Heddle Support".into(),
    });
    assert_eq!(
        validate_invitation_resolution(&invalid),
        Err(InvitationResolutionError::InviterHandle)
    );

    let unavailable = InvitationResolution {
        status: Status::Unavailable as i32,
        ..Default::default()
    };
    validate_invitation_resolution(&unavailable).expect("uniform unavailable shape");
    invalid.status = Status::Unavailable as i32;
    assert_eq!(
        validate_invitation_resolution(&invalid),
        Err(InvitationResolutionError::UnavailableDetails)
    );
}
