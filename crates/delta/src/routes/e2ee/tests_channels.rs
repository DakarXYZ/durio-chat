//! Enabling encryption of direct messages and groups (BE-11, BE-12)
use std::time::Duration;

use revolt_database::{Channel, PartialChannel, User, Webhook, events::client::EventV1};
use revolt_models::v0;
use revolt_permissions::{DEFAULT_PERMISSION, DEFAULT_WEBHOOK_PERMISSIONS};
use revolt_result::ErrorType;
use rocket::http::{Method, Status};
use serde_json::{Value, json};

use super::tests::{direct_message, error_type, request};
use crate::util::test::{PubSubTestHelper, TestHarness};

/// `PUT /channels/<id>/encryption` as `session`
pub async fn encrypt(
    harness: &TestHarness,
    session: &revolt_database::Session,
    channel_id: &str,
) -> (Status, Value) {
    request(
        harness,
        Method::Put,
        session,
        &format!("/channels/{channel_id}/encryption"),
        Some(json!({ "algorithm": "m.megolm.v1.aes-sha2" })),
    )
    .await
}

/// Make two users friends and open a direct message between them (both may send)
pub async fn friendly_dm(harness: &TestHarness, a: &mut User, b: &mut User) -> Channel {
    a.add_friend(&harness.db, &harness.amqp, b).await.unwrap();
    b.add_friend(&harness.db, &harness.amqp, a).await.unwrap();
    direct_message(harness, a, b).await
}

/// Group owned by `owner` with `members`, inserted directly (no friendship needed)
#[allow(clippy::disallowed_methods)]
pub async fn group(harness: &TestHarness, owner: &User, members: &[&User]) -> Channel {
    let mut recipients = vec![owner.id.clone()];
    recipients.extend(members.iter().map(|user| user.id.clone()));

    let channel = Channel::Group {
        id: ulid::Ulid::new().to_string(),
        name: "Group".to_string(),
        owner: owner.id.clone(),
        description: None,
        recipients,
        icon: None,
        last_message_id: None,
        permissions: None,
        nsfw: false,
        encryption: None,
    };

    harness
        .db
        .insert_channel(&channel)
        .await
        .expect("`Channel`");

    channel
}

async fn stored_encryption(
    harness: &TestHarness,
    channel_id: &str,
) -> Option<v0::ChannelEncryption> {
    harness
        .db
        .fetch_channel(channel_id)
        .await
        .expect("`Channel`")
        .encryption()
        .cloned()
}

#[rocket::async_test]
async fn encrypt_direct_message() {
    let harness = TestHarness::new().await;
    let (_, session, mut user) = harness.new_user().await;
    let (_, _, mut other) = harness.new_user().await;
    let channel = friendly_dm(&harness, &mut user, &mut other).await;
    let mut events = PubSubTestHelper::new(channel.id()).await;

    let (status, body) = encrypt(&harness, &session, channel.id()).await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["channel_type"], "DirectMessage");
    assert_eq!(body["encryption"]["algorithm"], "m.megolm.v1.aes-sha2");
    assert_eq!(body["encryption"]["enabled_by"], user.id.as_str());

    let encryption = stored_encryption(&harness, channel.id())
        .await
        .expect("encrypted");
    assert_eq!(encryption.enabled_by, user.id);

    let event = tokio::time::timeout(
        Duration::from_secs(5),
        events.wait_for_event(|event| {
            matches!(event, EventV1::ChannelUpdate { data, .. } if data.encryption.is_some())
        }),
    )
    .await
    .expect("`ChannelUpdate`");

    let EventV1::ChannelUpdate { id, data, clear } = event else {
        unreachable!()
    };
    assert_eq!(id, channel.id());
    // Timestamps lose precision on the way through Redis, compare the rest
    let sent = data.encryption.expect("encryption");
    assert_eq!(sent.algorithm, encryption.algorithm);
    assert_eq!(sent.enabled_by, encryption.enabled_by);
    assert!(clear.is_empty());

    // Enabling again conflicts, the settings stay as they were
    let (status, body) = encrypt(&harness, &session, channel.id()).await;
    assert_eq!(status, Status::Conflict);
    assert!(matches!(error_type(body), ErrorType::AlreadyEncrypted));
}

/// Two concurrent requests: exactly one wins
#[rocket::async_test]
async fn encrypt_race() {
    let harness = TestHarness::new().await;
    let (_, session, mut user) = harness.new_user().await;
    let (_, other_session, mut other) = harness.new_user().await;
    let channel = friendly_dm(&harness, &mut user, &mut other).await;

    let (first, second) = futures::join!(
        encrypt(&harness, &session, channel.id()),
        encrypt(&harness, &other_session, channel.id())
    );

    let mut statuses = vec![first.0, second.0];
    statuses.sort_by_key(|status| status.code);
    assert_eq!(statuses, vec![Status::Ok, Status::Conflict]);
}

#[rocket::async_test]
async fn cannot_disable() {
    let harness = TestHarness::new().await;
    let (_, session, user) = harness.new_user().await;
    let (_, _, other) = harness.new_user().await;
    let channel = group(&harness, &user, &[&other]).await;

    let (status, _) = encrypt(&harness, &session, channel.id()).await;
    assert_eq!(status, Status::Ok);
    let encryption = stored_encryption(&harness, channel.id()).await;
    assert!(encryption.is_some());

    // There is no field to clear and no route to disable encryption
    let path = format!("/channels/{}", channel.id());
    for body in [
        json!({ "name": "Renamed", "encryption": null }),
        json!({ "remove": ["Encryption"] }),
    ] {
        request(&harness, Method::Patch, &session, &path, Some(body)).await;
    }

    let (status, _) = request(
        &harness,
        Method::Delete,
        &session,
        &format!("{path}/encryption"),
        None,
    )
    .await;
    assert_eq!(status, Status::NotFound);

    assert_eq!(stored_encryption(&harness, channel.id()).await, encryption);
}

/// Every member may encrypt a group by default, unless the owner revokes `ManageChannel`
#[rocket::async_test]
async fn group_permission() {
    let harness = TestHarness::new().await;
    let (_, owner_session, owner) = harness.new_user().await;
    let (_, member_session, member) = harness.new_user().await;

    let open = group(&harness, &owner, &[&member]).await;
    let (status, _) = encrypt(&harness, &member_session, open.id()).await;
    assert_eq!(status, Status::Ok);

    let mut restricted = group(&harness, &owner, &[&member]).await;
    restricted
        .update(
            &harness.db,
            PartialChannel {
                permissions: Some(*DEFAULT_PERMISSION as i64),
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();

    let (status, body) = encrypt(&harness, &member_session, restricted.id()).await;
    assert_eq!(status, Status::Forbidden);
    assert!(matches!(
        error_type(body),
        ErrorType::MissingPermission { .. }
    ));
    assert!(stored_encryption(&harness, restricted.id()).await.is_none());

    let (status, _) = encrypt(&harness, &owner_session, restricted.id()).await;
    assert_eq!(status, Status::Ok);

    // Outsiders cannot see the group at all
    let (_, outsider_session, _) = harness.new_user().await;
    let outsider_group = group(&harness, &owner, &[&member]).await;
    let (status, _) = encrypt(&harness, &outsider_session, outsider_group.id()).await;
    assert!(status == Status::NotFound || status == Status::Forbidden);
}

#[rocket::async_test]
async fn bots_and_webhooks_not_encryptable() {
    let harness = TestHarness::new().await;
    let (_, session, user) = harness.new_user().await;
    let (_, _, other) = harness.new_user().await;
    let (_, bot_user) = harness.new_bot(&user).await;

    let with_bot = group(&harness, &user, &[&other, &bot_user]).await;
    let (status, body) = encrypt(&harness, &session, with_bot.id()).await;
    assert_eq!(status, Status::BadRequest);
    assert!(matches!(error_type(body), ErrorType::NotEncryptable));

    let bot_dm = direct_message(&harness, &user, &bot_user).await;
    let (status, body) = encrypt(&harness, &session, bot_dm.id()).await;
    assert_eq!(status, Status::BadRequest);
    assert!(matches!(error_type(body), ErrorType::NotEncryptable));

    let with_webhook = group(&harness, &user, &[&other]).await;
    Webhook {
        id: ulid::Ulid::new().to_string(),
        name: "Webhook".to_string(),
        avatar: None,
        creator_id: user.id.clone(),
        channel_id: with_webhook.id().to_string(),
        permissions: *DEFAULT_WEBHOOK_PERMISSIONS,
        token: Some("token".to_string()),
    }
    .create(&harness.db)
    .await
    .unwrap();

    let (status, body) = encrypt(&harness, &session, with_webhook.id()).await;
    assert_eq!(status, Status::BadRequest);
    assert!(matches!(error_type(body), ErrorType::NotEncryptable));

    for channel in [&with_bot, &bot_dm, &with_webhook] {
        assert!(stored_encryption(&harness, channel.id()).await.is_none());
    }
}

#[rocket::async_test]
async fn only_direct_messages_and_groups() {
    let harness = TestHarness::new().await;
    let (_, session, user) = harness.new_user().await;

    let saved = Channel::create_dm(&harness.db, &user, &user).await.unwrap();
    let (status, body) = encrypt(&harness, &session, saved.id()).await;
    assert_eq!(status, Status::BadRequest);
    assert!(matches!(error_type(body), ErrorType::NotEncryptable));

    let (_, channels) = harness.new_server(&user).await;
    let (status, body) = encrypt(&harness, &session, channels[0].id()).await;
    assert_eq!(status, Status::BadRequest);
    assert!(matches!(error_type(body), ErrorType::NotEncryptable));

    let (_, _, other) = harness.new_user().await;
    let channel = direct_message(&harness, &user, &other).await;
    let (status, _) = request(
        &harness,
        Method::Put,
        &session,
        &format!("/channels/{}/encryption", channel.id()),
        Some(json!({ "algorithm": "m.olm.v1.curve25519-aes-sha2" })),
    )
    .await;
    assert_eq!(status, Status::BadRequest);
    assert!(stored_encryption(&harness, channel.id()).await.is_none());
}

/// `default_for_new_dms` encrypts new direct messages, except with bots
#[rocket::async_test]
async fn default_for_new_dms() {
    revolt_config::overwrite_config(|config| config.features.e2ee.default_for_new_dms = true).await;

    let harness = TestHarness::new().await;
    let (_, _, user) = harness.new_user().await;
    let (_, _, other) = harness.new_user().await;
    let (_, bot_user) = harness.new_bot(&user).await;

    let channel = Channel::create_dm(&harness.db, &user, &other)
        .await
        .unwrap();
    let encryption = channel.encryption().expect("encrypted");
    assert_eq!(encryption.enabled_by, user.id);
    let stored = stored_encryption(&harness, channel.id())
        .await
        .expect("stored");
    assert_eq!(stored.enabled_by, encryption.enabled_by);

    let bot_dm = Channel::create_dm(&harness.db, &user, &bot_user)
        .await
        .unwrap();
    assert!(!bot_dm.is_encrypted());

    // Groups are only encrypted manually
    let created = Channel::create_group(
        &harness.db,
        v0::DataCreateGroup {
            name: "Group".to_string(),
            ..Default::default()
        },
        user.id.clone(),
    )
    .await
    .unwrap();
    assert!(!created.is_encrypted());
}

/// Without the flag new direct messages are not encrypted
#[rocket::async_test]
async fn new_dms_unencrypted_by_default() {
    let harness = TestHarness::new().await;
    let (_, _, user) = harness.new_user().await;
    let (_, _, other) = harness.new_user().await;

    let channel = Channel::create_dm(&harness.db, &user, &other)
        .await
        .unwrap();
    assert!(!channel.is_encrypted());
}

/// Enabling encryption leaves an `encryption_enabled` system message
#[rocket::async_test]
async fn encryption_enabled_message() {
    let harness = TestHarness::new().await;
    let (_, session, user) = harness.new_user().await;
    let (_, _, other) = harness.new_user().await;
    let channel = group(&harness, &user, &[&other]).await;
    let mut events = PubSubTestHelper::new(channel.id()).await;

    let (status, _) = encrypt(&harness, &session, channel.id()).await;
    assert_eq!(status, Status::Ok);

    let message = tokio::time::timeout(Duration::from_secs(5), events.wait_for_message())
        .await
        .expect("`Message`");
    assert_eq!(
        message.system,
        Some(v0::SystemMessage::EncryptionEnabled {
            by: user.id.clone()
        })
    );
    assert!(message.content.is_none() && message.encrypted.is_none());

    let (status, body) = request(
        &harness,
        Method::Get,
        &session,
        &format!("/channels/{}/messages?include_users=true", channel.id()),
        None,
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["messages"][0]["system"]["type"], "encryption_enabled");
    assert_eq!(body["messages"][0]["system"]["by"], user.id.as_str());
    assert!(
        body["users"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["_id"] == user.id.as_str()),
        "{body}"
    );
}
