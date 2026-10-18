//! Encrypted messages (BE-13 … BE-19)
use std::time::Duration;

use revolt_database::{
    Channel, File, Message, Metadata, Session, SnapshotContent, User, events::client::EventV1,
    util::e2ee::legacy_placeholder,
};
use revolt_models::v0;
use revolt_result::ErrorType;
use rocket::http::{Method, Status};
use serde_json::{Value, json};

use super::tests::{error_type, request};
use super::tests_channels::{encrypt, friendly_dm, group};
use crate::util::test::{PubSubTestHelper, TestHarness};

/// Envelope v1 of a device (fake ciphertext, the server does not decrypt)
pub fn envelope(device_id: &str, ciphertext: &str) -> Value {
    json!({
        "v": 1,
        "algorithm": "m.megolm.v1.aes-sha2",
        "session_id": "megolm-session",
        "device_id": device_id,
        "ciphertext": ciphertext
    })
}

/// Two friends with an encrypted direct message
pub struct EncryptedDm {
    pub session: Session,
    pub user: User,
    pub other_session: Session,
    pub channel: Channel,
}

pub async fn encrypted_dm(harness: &TestHarness) -> EncryptedDm {
    let (_, session, mut user) = harness.new_user().await;
    let (_, other_session, mut other) = harness.new_user().await;
    let channel = friendly_dm(harness, &mut user, &mut other).await;

    let (status, _) = encrypt(harness, &session, channel.id()).await;
    assert_eq!(status, Status::Ok);

    let channel = harness.db.fetch_channel(channel.id()).await.unwrap();
    EncryptedDm {
        session,
        user,
        other_session,
        channel,
    }
}

/// `POST /channels/<id>/messages`
pub async fn send(
    harness: &TestHarness,
    session: &Session,
    channel_id: &str,
    body: Value,
) -> (Status, Value) {
    request(
        harness,
        Method::Post,
        session,
        &format!("/channels/{channel_id}/messages"),
        Some(body),
    )
    .await
}

/// `PATCH /channels/<id>/messages/<message>`
pub async fn edit(
    harness: &TestHarness,
    session: &Session,
    channel_id: &str,
    message_id: &str,
    body: Value,
) -> (Status, Value) {
    request(
        harness,
        Method::Patch,
        session,
        &format!("/channels/{channel_id}/messages/{message_id}"),
        Some(body),
    )
    .await
}

fn assert_violation(status: Status, body: Value) {
    assert_eq!(status, Status::BadRequest, "{body}");
    assert!(
        matches!(
            error_type(body.clone()),
            ErrorType::EncryptedChannelViolation
        ),
        "{body}"
    );
}

#[rocket::async_test]
async fn send_encrypted() {
    let harness = TestHarness::new().await;
    let dm = encrypted_dm(&harness).await;
    let sent = envelope(&dm.session.id, "AwgAEoAB+cipher/text==");

    let (status, body) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({ "encrypted": sent }),
    )
    .await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["encrypted"], sent);

    // Stored as is, without content or mentions
    let stored = harness
        .db
        .fetch_message(body["_id"].as_str().unwrap())
        .await
        .unwrap();
    assert!(stored.content.is_none());
    assert!(stored.mentions.is_none() && stored.role_mentions.is_none());
    assert!(stored.embeds.is_none());
    assert_eq!(
        stored.encrypted,
        Some(serde_json::from_value::<v0::EncryptedEnvelope>(sent).unwrap())
    );

    // A reply may still mention the author of the replied message
    let (status, reply) = send(
        &harness,
        &dm.other_session,
        dm.channel.id(),
        json!({
            "encrypted": envelope(&dm.other_session.id, "reply"),
            "replies": [{ "id": body["_id"], "mention": true }]
        }),
    )
    .await;
    assert_eq!(status, Status::Ok, "{reply}");
    assert_eq!(reply["replies"], json!([body["_id"]]));
    assert_eq!(reply["mentions"], json!([dm.user.id]));
}

#[rocket::async_test]
async fn plaintext_rejected() {
    let harness = TestHarness::new().await;
    let dm = encrypted_dm(&harness).await;
    let sent = envelope(&dm.session.id, "cipher");

    for body in [
        json!({ "content": "plain text" }),
        json!({ "content": "plain text", "encrypted": sent }),
        json!({ "encrypted": sent, "embeds": [{ "title": "embed" }] }),
        json!({ "encrypted": sent, "masquerade": { "name": "Someone" } }),
        json!({ "embeds": [{ "title": "embed" }] }),
        json!({ "attachments": [] }),
    ] {
        let (status, response) = send(&harness, &dm.session, dm.channel.id(), body).await;
        assert_violation(status, response);
    }

    // Another device's envelope
    let (_, other_device, _) = harness.new_user().await;
    let (status, body) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({ "encrypted": envelope(&other_device.id, "cipher") }),
    )
    .await;
    assert_violation(status, body);

    // Malformed envelopes fail validation or parsing
    for bad in [
        json!({ "v": 2, "algorithm": "m.megolm.v1.aes-sha2", "session_id": "s",
                "device_id": dm.session.id, "ciphertext": "c" }),
        json!({ "v": 1, "algorithm": "m.megolm.v1.aes-sha2", "session_id": "s",
                "device_id": dm.session.id, "ciphertext": "c", "sender_key": "k" }),
    ] {
        let (status, _) = send(
            &harness,
            &dm.session,
            dm.channel.id(),
            json!({ "encrypted": bad }),
        )
        .await;
        assert!(status.code >= 400 && status.code < 500, "{status}");
    }

    assert!(
        harness
            .db
            .fetch_messages(revolt_database::MessageQuery {
                filter: revolt_database::MessageFilter {
                    channel: Some(dm.channel.id().to_string()),
                    ..Default::default()
                },
                limit: Some(50),
                time_period: revolt_database::MessageTimePeriod::Absolute {
                    before: None,
                    after: None,
                    sort: None,
                },
            })
            .await
            .unwrap()
            .iter()
            .all(|message| message.system.is_some())
    );
}

#[rocket::async_test]
async fn envelope_size_limit() {
    let harness = TestHarness::new().await;
    let dm = encrypted_dm(&harness).await;
    let max = revolt_config::config()
        .await
        .features
        .e2ee
        .max_envelope_bytes;

    let (status, body) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({ "encrypted": envelope(&dm.session.id, &"a".repeat(max)) }),
    )
    .await;
    assert_eq!(status, Status::Ok, "{body}");

    let (status, body) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({ "encrypted": envelope(&dm.session.id, &"a".repeat(max + 1)) }),
    )
    .await;
    assert_eq!(status, Status::UnprocessableEntity);
    assert!(matches!(error_type(body), ErrorType::PayloadTooLarge));
}

/// Plain channels never take an envelope
#[rocket::async_test]
async fn envelope_in_plain_channel() {
    let harness = TestHarness::new().await;
    let (_, session, mut user) = harness.new_user().await;
    let (_, _, mut other) = harness.new_user().await;
    let channel = friendly_dm(&harness, &mut user, &mut other).await;

    let (status, body) = send(
        &harness,
        &session,
        channel.id(),
        json!({ "encrypted": envelope(&session.id, "cipher") }),
    )
    .await;
    assert_violation(status, body);

    let (status, message) = send(
        &harness,
        &session,
        channel.id(),
        json!({ "content": "hello" }),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let (status, body) = edit(
        &harness,
        &session,
        channel.id(),
        message["_id"].as_str().unwrap(),
        json!({ "encrypted": envelope(&session.id, "cipher") }),
    )
    .await;
    assert_violation(status, body);
}

#[rocket::async_test]
async fn edit_encrypted() {
    let harness = TestHarness::new().await;
    let dm = encrypted_dm(&harness).await;

    let (status, message) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({ "encrypted": envelope(&dm.session.id, "first") }),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let id = message["_id"].as_str().unwrap();

    let replaced = envelope(&dm.session.id, "second");
    let (status, body) = edit(
        &harness,
        &dm.session,
        dm.channel.id(),
        id,
        json!({ "encrypted": replaced }),
    )
    .await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["encrypted"], replaced);
    assert!(body["edited"].is_string());

    let stored = harness.db.fetch_message(id).await.unwrap();
    assert!(stored.content.is_none() && stored.embeds.is_none());
    assert!(stored.edited.is_some());
    assert_eq!(stored.encrypted.unwrap().ciphertext, "second");

    for body in [
        json!({ "content": "plain" }),
        json!({ "content": "plain", "encrypted": replaced }),
        json!({ "encrypted": replaced, "embeds": [{ "title": "embed" }] }),
        json!({}),
        json!({ "encrypted": envelope(&dm.other_session.id, "foreign") }),
    ] {
        let (status, response) = edit(&harness, &dm.session, dm.channel.id(), id, body).await;
        assert_violation(status, response);
    }

    assert_eq!(
        harness
            .db
            .fetch_message(id)
            .await
            .unwrap()
            .encrypted
            .unwrap()
            .ciphertext,
        "second"
    );

    // Only the author edits
    let (status, _) = edit(
        &harness,
        &dm.other_session,
        dm.channel.id(),
        id,
        json!({ "encrypted": envelope(&dm.other_session.id, "takeover") }),
    )
    .await;
    assert_eq!(status, Status::Forbidden);
}

/// Plain text sent before encryption was enabled stays as it is
#[rocket::async_test]
async fn edit_plain_message_after_encryption() {
    let harness = TestHarness::new().await;
    let (_, session, user) = harness.new_user().await;
    let (_, _, other) = harness.new_user().await;
    let channel = group(&harness, &user, &[&other]).await;

    let (status, message) = send(
        &harness,
        &session,
        channel.id(),
        json!({ "content": "old" }),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let id = message["_id"].as_str().unwrap();

    let (status, _) = encrypt(&harness, &session, channel.id()).await;
    assert_eq!(status, Status::Ok);

    for body in [
        json!({ "content": "new" }),
        json!({ "encrypted": envelope(&session.id, "cipher") }),
    ] {
        let (status, response) = edit(&harness, &session, channel.id(), id, body).await;
        assert_violation(status, response);
    }

    let stored = harness.db.fetch_message(id).await.unwrap();
    assert_eq!(stored.content.as_deref(), Some("old"));
    assert!(stored.encrypted.is_none() && stored.edited.is_none());
}

/// Code paths that build messages themselves still cannot put text into an encrypted channel
#[rocket::async_test]
async fn send_guard() {
    let harness = TestHarness::new().await;
    let dm = encrypted_dm(&harness).await;
    let author: v0::User = dm.user.clone().into(&harness.db, None).await;

    let mut plain = Message {
        id: ulid::Ulid::new().to_string(),
        channel: dm.channel.id().to_string(),
        author: dm.user.id.clone(),
        content: Some("plain".to_string()),
        ..Default::default()
    };
    let error = plain
        .send(
            &harness.db,
            None,
            v0::MessageAuthor::User(&author),
            None,
            None,
            &dm.channel,
            false,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.error_type,
        ErrorType::EncryptedChannelViolation
    ));
    assert!(harness.db.fetch_message(&plain.id).await.is_err());

    // And plain channels never store an envelope
    let (_, _, mut a) = harness.new_user().await;
    let (_, _, mut b) = harness.new_user().await;
    let plain_channel = friendly_dm(&harness, &mut a, &mut b).await;
    let mut encrypted = Message {
        id: ulid::Ulid::new().to_string(),
        channel: plain_channel.id().to_string(),
        author: a.id.clone(),
        encrypted: Some(serde_json::from_value(envelope(&dm.session.id, "cipher")).unwrap()),
        ..Default::default()
    };
    let error = encrypted
        .send(
            &harness.db,
            None,
            v0::MessageAuthor::User(&author),
            None,
            None,
            &plain_channel,
            false,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.error_type,
        ErrorType::EncryptedChannelViolation
    ));
}

/// An unused attachment as autumn stores it (`?encrypted=true` sets the flag)
#[allow(clippy::disallowed_methods)]
pub async fn attachment(harness: &TestHarness, user: &User, encrypted: bool) -> String {
    let id = ulid::Ulid::new().to_string();
    harness
        .db
        .insert_attachment(&File {
            id: id.clone(),
            tag: "attachments".to_string(),
            filename: "file.bin".to_string(),
            hash: Some("hash".to_string()),
            uploaded_at: None,
            uploader_id: Some(user.id.clone()),
            used_for: None,
            deleted: None,
            reported: None,
            encrypted: encrypted.then_some(true),
            metadata: Metadata::File,
            content_type: "application/octet-stream".to_string(),
            size: 1,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        })
        .await
        .unwrap();
    id
}

async fn is_used(harness: &TestHarness, id: &str) -> bool {
    harness
        .db
        .fetch_attachment("attachments", id)
        .await
        .unwrap()
        .used_for
        .is_some()
}

/// Encrypted channels take only encrypted blobs, plain channels never take them
#[rocket::async_test]
async fn encrypted_attachments() {
    let harness = TestHarness::new().await;
    let dm = encrypted_dm(&harness).await;

    let file = attachment(&harness, &dm.user, true).await;
    let thumbnail = attachment(&harness, &dm.user, true).await;
    let (status, body) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({
            "encrypted": envelope(&dm.session.id, "cipher"),
            "attachments": [file, thumbnail]
        }),
    )
    .await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["attachments"][0]["_id"], file.as_str());
    assert_eq!(body["attachments"][0]["encrypted"], true);
    assert!(is_used(&harness, &file).await && is_used(&harness, &thumbnail).await);

    let plain = attachment(&harness, &dm.user, false).await;
    let (status, _) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({
            "encrypted": envelope(&dm.session.id, "cipher"),
            "attachments": [plain]
        }),
    )
    .await;
    assert_eq!(status, Status::NotFound);
    assert!(!is_used(&harness, &plain).await);

    let (_, session, mut user) = harness.new_user().await;
    let (_, _, mut other) = harness.new_user().await;
    let plain_channel = friendly_dm(&harness, &mut user, &mut other).await;
    let blob = attachment(&harness, &user, true).await;
    let (status, _) = send(
        &harness,
        &session,
        plain_channel.id(),
        json!({ "content": "file", "attachments": [blob] }),
    )
    .await;
    assert_eq!(status, Status::NotFound);
    assert!(!is_used(&harness, &blob).await);

    let plain = attachment(&harness, &user, false).await;
    let (status, _) = send(
        &harness,
        &session,
        plain_channel.id(),
        json!({ "content": "file", "attachments": [plain] }),
    )
    .await;
    assert_eq!(status, Status::Ok);
}

/// Encrypted messages carry up to twice the attachments (files and their thumbnails)
#[rocket::async_test]
async fn encrypted_attachment_limit() {
    let harness = TestHarness::new().await;
    let dm = encrypted_dm(&harness).await;
    let limit = dm.user.limits().await.message_attachments * 2;

    let mut files = vec![];
    for _ in 0..=limit {
        files.push(attachment(&harness, &dm.user, true).await);
    }

    let (status, body) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({
            "encrypted": envelope(&dm.session.id, "cipher"),
            "attachments": files
        }),
    )
    .await;
    assert_eq!(status, Status::BadRequest);
    assert!(matches!(
        error_type(body),
        ErrorType::TooManyAttachments { max } if max == limit
    ));

    let (status, body) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({
            "encrypted": envelope(&dm.session.id, "cipher"),
            "attachments": files[..limit]
        }),
    )
    .await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["attachments"].as_array().unwrap().len(), limit);
}

/// Push notifications of encrypted messages carry no text and no attachment link
#[rocket::async_test]
async fn push_without_text() {
    let harness = TestHarness::new().await;
    let dm = encrypted_dm(&harness).await;
    let file = attachment(&harness, &dm.user, true).await;

    let (status, body) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({
            "encrypted": envelope(&dm.session.id, "cipher"),
            "attachments": [file]
        }),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let stored = harness
        .db
        .fetch_message(body["_id"].as_str().unwrap())
        .await
        .unwrap();
    let author: v0::User = dm.user.clone().into(&harness.db, None).await;
    let notification = v0::PushNotification::from(
        stored.into_model(None, None),
        Some(v0::MessageAuthor::User(&author)),
        dm.channel.clone().into(),
    )
    .await;

    assert_eq!(
        notification.body,
        format!("New message from {}", dm.user.username)
    );
    assert!(notification.image.is_none());
    assert!(notification.raw_body.is_none());
    assert!(notification.message.encrypted.is_some());
}

/// Full-text search is unavailable, listing pinned messages still works
#[rocket::async_test]
async fn search_disabled() {
    let harness = TestHarness::new().await;
    let dm = encrypted_dm(&harness).await;

    let (status, message) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({ "encrypted": envelope(&dm.session.id, "cipher") }),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let (status, _) = request(
        &harness,
        Method::Post,
        &dm.session,
        &format!(
            "/channels/{}/messages/{}/pin",
            dm.channel.id(),
            message["_id"].as_str().unwrap()
        ),
        None,
    )
    .await;
    assert!(status.code < 300, "{status}");

    let path = format!("/channels/{}/search", dm.channel.id());
    let (status, body) = request(
        &harness,
        Method::Post,
        &dm.session,
        &path,
        Some(json!({ "query": "cipher" })),
    )
    .await;
    assert_eq!(status, Status::BadRequest);
    assert!(matches!(
        error_type(body),
        ErrorType::SearchUnavailableInEncryptedChannel
    ));

    let (status, body) = request(
        &harness,
        Method::Post,
        &dm.session,
        &path,
        Some(json!({ "pinned": true })),
    )
    .await;
    assert_eq!(status, Status::Ok, "{body}");
    let pinned = body.as_array().expect("messages");
    assert_eq!(pinned.len(), 1, "{body}");
    assert_eq!(pinned[0]["_id"], message["_id"]);
}

/// Old clients see the placeholder as content, new clients the envelope as well
#[rocket::async_test]
async fn legacy_placeholder_content() {
    let harness = TestHarness::new().await;
    let dm = encrypted_dm(&harness).await;
    let placeholder = revolt_config::config()
        .await
        .features
        .e2ee
        .legacy_placeholder;
    assert_eq!(legacy_placeholder(), placeholder);
    let mut events = PubSubTestHelper::new(dm.channel.id()).await;

    let sent = envelope(&dm.session.id, "cipher");
    let (status, body) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({ "encrypted": sent }),
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["content"], placeholder.as_str());
    assert_eq!(body["encrypted"], sent);
    let id = body["_id"].as_str().unwrap().to_string();

    let event = tokio::time::timeout(Duration::from_secs(5), events.wait_for_message())
        .await
        .expect("`Message`");
    assert_eq!(event.content.as_deref(), Some(placeholder.as_str()));
    assert!(event.encrypted.is_some());

    let (status, body) = request(
        &harness,
        Method::Get,
        &dm.other_session,
        &format!("/channels/{}/messages", dm.channel.id()),
        None,
    )
    .await;
    assert_eq!(status, Status::Ok);
    let fetched = body
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["_id"] == id.as_str())
        .expect("message");
    assert_eq!(fetched["content"], placeholder.as_str());
    assert_eq!(fetched["encrypted"], sent);

    let (status, body) = request(
        &harness,
        Method::Get,
        &dm.other_session,
        &format!("/channels/{}/messages/{id}", dm.channel.id()),
        None,
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["content"], placeholder.as_str());

    let (status, _) = edit(
        &harness,
        &dm.session,
        dm.channel.id(),
        &id,
        json!({ "encrypted": envelope(&dm.session.id, "edited") }),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let update = tokio::time::timeout(
        Duration::from_secs(5),
        events.wait_for_event(|event| matches!(event, EventV1::MessageUpdate { .. })),
    )
    .await
    .expect("`MessageUpdate`");
    let EventV1::MessageUpdate { data, .. } = update else {
        unreachable!()
    };
    assert_eq!(data.content.as_deref(), Some(placeholder.as_str()));
    assert_eq!(data.encrypted.unwrap().ciphertext, "edited");

    // Never stored
    assert!(
        harness
            .db
            .fetch_message(&id)
            .await
            .unwrap()
            .content
            .is_none()
    );
}

/// Bots cannot join an encrypted group, through any route
#[rocket::async_test]
async fn bots_kept_out() {
    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let (_, _, member) = harness.new_user().await;
    let (bot, bot_user) = harness.new_bot(&owner).await;
    let channel = group(&harness, &owner, &[&member]).await;

    let (status, _) = encrypt(&harness, &session, channel.id()).await;
    assert_eq!(status, Status::Ok);

    let (status, body) = request(
        &harness,
        Method::Post,
        &session,
        &format!("/bots/{}/invite", bot.id),
        Some(json!({ "group": channel.id() })),
    )
    .await;
    assert_eq!(status, Status::BadRequest);
    assert!(matches!(error_type(body), ErrorType::NotEncryptable));

    // The same check guards group_add_member and invites
    let mut channel = harness.db.fetch_channel(channel.id()).await.unwrap();
    let error = channel
        .add_user_to_group(&harness.db, &harness.amqp, &bot_user, &owner.id)
        .await
        .unwrap_err();
    assert!(matches!(error.error_type, ErrorType::NotEncryptable));

    let recipients = match harness.db.fetch_channel(channel.id()).await.unwrap() {
        Channel::Group { recipients, .. } => recipients,
        _ => unreachable!(),
    };
    assert!(!recipients.contains(&bot_user.id));

    // People can still be added
    let (_, _, newcomer) = harness.new_user().await;
    channel
        .add_user_to_group(&harness.db, &harness.amqp, &newcomer, &owner.id)
        .await
        .unwrap();
}

/// Webhooks can neither be created in nor post to encrypted channels
#[rocket::async_test]
async fn webhooks_kept_out() {
    let harness = TestHarness::new().await;
    let (_, session, owner) = harness.new_user().await;
    let (_, _, member) = harness.new_user().await;

    let encrypted = group(&harness, &owner, &[&member]).await;
    let (status, _) = encrypt(&harness, &session, encrypted.id()).await;
    assert_eq!(status, Status::Ok);

    let (status, body) = request(
        &harness,
        Method::Post,
        &session,
        &format!("/channels/{}/webhooks", encrypted.id()),
        Some(json!({ "name": "Hook" })),
    )
    .await;
    assert_eq!(status, Status::BadRequest, "{body}");
    assert!(matches!(error_type(body), ErrorType::NotEncryptable));

    // A webhook from before encryption (only possible by writing to the database directly)
    let channel = group(&harness, &owner, &[&member]).await;
    let (status, webhook) = request(
        &harness,
        Method::Post,
        &session,
        &format!("/channels/{}/webhooks", channel.id()),
        Some(json!({ "name": "Hook" })),
    )
    .await;
    assert_eq!(status, Status::Ok, "{webhook}");
    let hook = format!(
        "/webhooks/{}/{}",
        webhook["id"].as_str().unwrap(),
        webhook["token"].as_str().unwrap()
    );

    let (status, message) = request(
        &harness,
        Method::Post,
        &session,
        &hook,
        Some(json!({ "content": "before" })),
    )
    .await;
    assert_eq!(status, Status::Ok, "{message}");

    assert!(
        harness
            .db
            .set_channel_encryption(channel.id(), &Channel::new_encryption(&owner.id))
            .await
            .unwrap()
    );

    for body in [
        json!({ "content": "after" }),
        json!({ "encrypted": envelope(&session.id, "cipher") }),
    ] {
        let (status, response) = request(&harness, Method::Post, &session, &hook, Some(body)).await;
        assert_violation(status, response);
    }

    let (status, response) = request(
        &harness,
        Method::Patch,
        &session,
        &format!("{hook}/{}", message["_id"].as_str().unwrap()),
        Some(json!({ "content": "edited" })),
    )
    .await;
    assert_violation(status, response);
}

/// Snapshots of a reported message, as stored for moderators
async fn snapshot_of(harness: &TestHarness, message_id: &str) -> Message {
    let content = match &harness.db {
        revolt_database::Database::Reference(db) => db
            .safety_snapshots
            .lock()
            .await
            .values()
            .map(|snapshot| snapshot.content.clone())
            .find(|content| {
                matches!(content, SnapshotContent::Message { message, .. } if message.id == message_id)
            }),
        revolt_database::Database::MongoDb(db) => db
            .col::<revolt_database::Snapshot>("safety_snapshots")
            .find_one(revolt_database::mongodb::bson::doc! { "content._id": message_id })
            .await
            .unwrap()
            .map(|snapshot| snapshot.content),
    };

    match content.expect("snapshot") {
        SnapshotContent::Message { message, .. } => message,
        _ => unreachable!(),
    }
}

/// A reported encrypted message is kept as ciphertext, moderators see it is encrypted
#[rocket::async_test]
async fn report_encrypted_message() {
    let harness = TestHarness::new().await;
    let dm = encrypted_dm(&harness).await;

    let sent = envelope(&dm.session.id, "cipher");
    let (status, message) = send(
        &harness,
        &dm.session,
        dm.channel.id(),
        json!({ "encrypted": sent }),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let id = message["_id"].as_str().unwrap();

    let (status, body) = request(
        &harness,
        Method::Post,
        &dm.other_session,
        "/safety/report",
        Some(json!({
            "content": { "type": "Message", "id": id, "report_reason": "NoneSpecified" }
        })),
    )
    .await;
    assert_eq!(status, Status::NoContent, "{body}");

    let snapshot = snapshot_of(&harness, id).await;
    assert!(snapshot.content.is_none());
    assert_eq!(
        snapshot.encrypted,
        Some(serde_json::from_value::<v0::EncryptedEnvelope>(sent).unwrap())
    );
}

/// With `features.e2ee.enabled = false` nothing takes envelopes and encrypted channels
/// become read-only
#[rocket::async_test]
async fn disabled_read_only() {
    revolt_config::overwrite_config(|config| config.features.e2ee.enabled = false).await;

    let harness = TestHarness::new().await;
    let (_, session, mut user) = harness.new_user().await;
    let (_, _, mut other) = harness.new_user().await;
    let channel = friendly_dm(&harness, &mut user, &mut other).await;

    let (status, body) = send(
        &harness,
        &session,
        channel.id(),
        json!({ "encrypted": envelope(&session.id, "cipher") }),
    )
    .await;
    assert_violation(status, body);

    // Encrypted while the feature was on
    assert!(
        harness
            .db
            .set_channel_encryption(channel.id(), &Channel::new_encryption(&user.id))
            .await
            .unwrap()
    );

    for body in [
        json!({ "content": "plain" }),
        json!({ "encrypted": envelope(&session.id, "cipher") }),
    ] {
        let (status, response) = send(&harness, &session, channel.id(), body).await;
        assert_violation(status, response);
    }
}

/// A retried send answers with the stored message instead of 400/409 (B2)
#[rocket::async_test]
async fn send_retry_returns_stored_message() {
    use rocket::http::Header;

    use super::tests::request_with;

    use revolt_database::{MessageFilter, MessageQuery, MessageTimePeriod};

    let harness = TestHarness::new().await;
    let dm = encrypted_dm(&harness).await;
    let channel_id = dm.channel.id().to_string();
    let post = async |session: &Session, body: Value, key: Option<&str>| {
        let headers = key
            .map(|key| vec![Header::new("Idempotency-Key", key.to_string())])
            .unwrap_or_default();
        request_with(
            &harness,
            Method::Post,
            session,
            &format!("/channels/{channel_id}/messages"),
            Some(body),
            headers,
        )
        .await
    };

    // Same body nonce
    let nonce = ulid::Ulid::new().to_string();
    let body = json!({ "encrypted": envelope(&dm.session.id, "one"), "nonce": nonce });
    let (status, first) = post(&dm.session, body.clone(), None).await;
    assert_eq!(status, Status::Ok, "{first}");
    let (status, retry) = post(&dm.session, body, None).await;
    assert_eq!(status, Status::Ok, "{retry}");
    assert_eq!(retry["_id"], first["_id"]);
    assert_eq!(retry["nonce"], json!(nonce));

    // Same Idempotency-Key header and body nonce, as the clients send them
    let key = ulid::Ulid::new().to_string();
    let body = json!({
        "encrypted": envelope(&dm.session.id, "two"),
        "nonce": ulid::Ulid::new().to_string()
    });
    let (status, second) = post(&dm.session, body.clone(), Some(&key)).await;
    assert_eq!(status, Status::Ok, "{second}");
    let (status, retry) = post(&dm.session, body, Some(&key)).await;
    assert_eq!(status, Status::Ok, "{retry}");
    assert_eq!(retry["_id"], second["_id"]);

    // Only the header: it is the nonce
    let key = ulid::Ulid::new().to_string();
    let body = json!({ "encrypted": envelope(&dm.session.id, "three") });
    let (status, third) = post(&dm.session, body.clone(), Some(&key)).await;
    assert_eq!(status, Status::Ok, "{third}");
    let (status, retry) = post(&dm.session, body, Some(&key)).await;
    assert_eq!(status, Status::Ok, "{retry}");
    assert_eq!(retry["_id"], third["_id"]);

    // Someone else's nonce or header is still refused, as upstream does
    let body = json!({ "encrypted": envelope(&dm.other_session.id, "four"), "nonce": nonce });
    let (status, other) = post(&dm.other_session, body, None).await;
    assert_eq!(status, Status::BadRequest, "{other}");
    assert!(
        matches!(error_type(other.clone()), ErrorType::InvalidOperation),
        "{other}"
    );
    let body = json!({ "encrypted": envelope(&dm.other_session.id, "five") });
    let (status, other) = post(&dm.other_session, body, Some(&key)).await;
    assert_eq!(status, Status::Conflict, "{other}");

    // No retry stored a second message
    let stored = harness
        .db
        .fetch_messages(MessageQuery {
            limit: Some(100),
            filter: MessageFilter {
                channel: Some(dm.channel.id().to_string()),
                author: Some(dm.user.id.clone()),
                ..Default::default()
            },
            time_period: MessageTimePeriod::Absolute {
                before: None,
                after: None,
                sort: None,
            },
        })
        .await
        .unwrap();
    let mut ids: Vec<_> = stored.into_iter().map(|message| message.id).collect();
    ids.sort();
    let mut expected: Vec<_> = [first, second, third]
        .iter()
        .map(|message| message["_id"].as_str().unwrap().to_string())
        .collect();
    expected.sort();
    assert_eq!(ids, expected);
}
