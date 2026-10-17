//! Encrypted messages (BE-13 … BE-19)
use revolt_database::{Channel, File, Message, Metadata, Session, User};
use revolt_models::v0;
use revolt_result::ErrorType;
use rocket::http::{Method, Status};
use serde_json::{Value, json};

use super::tests::{error_type, request};
use super::tests_channels::{encrypt, friendly_dm, group};
use crate::util::test::TestHarness;

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
