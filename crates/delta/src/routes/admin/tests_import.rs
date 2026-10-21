//! Instance admins import message history from other chats (dur.io fork)
use revolt_database::{File, Metadata, User};
use revolt_result::ErrorType;
use rocket::http::Status;
use serde_json::{json, Value};

use super::super::e2ee::tests::{error_type, post};
use super::tests::{new_admin, new_plain_admin};
use crate::util::test::TestHarness;

/// An unused upload as autumn stores it
#[allow(clippy::disallowed_methods)]
async fn upload(harness: &TestHarness, user: &User, tag: &str) -> String {
    let id = ulid::Ulid::new().to_string();
    harness
        .db
        .insert_attachment(&File {
            id: id.clone(),
            tag: tag.to_string(),
            filename: "file.png".to_string(),
            hash: Some("hash".to_string()),
            uploaded_at: None,
            uploader_id: Some(user.id.clone()),
            used_for: None,
            deleted: None,
            reported: None,
            encrypted: None,
            metadata: Metadata::File,
            content_type: "image/png".to_string(),
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

fn batch(attachment: &str, avatar: &str) -> Value {
    json!({
        "source": "discord",
        "messages": [
            {
                "original_id": "1001",
                "timestamp": "2023-02-13T16:19:45.369+04:00",
                "author": { "original_id": "42", "name": "CatPower", "avatar": avatar },
                "content": "first",
                "pinned": true
            },
            {
                "original_id": "1002",
                "timestamp": "2023-02-13T16:23:58.339+04:00",
                "edited": "2023-02-13T16:25:00.000+04:00",
                "author": { "original_id": "43", "name": "alyssa" },
                "content": "",
                "attachments": [attachment],
                "reply_to": [{ "original_id": "1001", "timestamp": "2023-02-13T16:19:45.369+04:00" }]
            },
            {
                "original_id": "1003",
                "timestamp": "2023-02-13T16:30:00.000+04:00",
                "author": { "original_id": "42", "name": "CatPower", "avatar": avatar },
                "content": "third"
            }
        ]
    })
}

#[rocket::async_test]
async fn only_elevated_admins_import() {
    let harness = TestHarness::new().await;
    let (_, session, user) = harness.new_user().await;
    let (_, plain_session, _) = new_plain_admin(&harness).await;
    let (_, channels) = harness.new_server(&user).await;
    let path = format!("/admin/import/channels/{}/messages", channels[0].id());
    let body = json!({
        "source": "discord",
        "messages": [{
            "original_id": "1",
            "timestamp": "2023-02-13T16:19:45.369Z",
            "author": { "original_id": "1", "name": "a" },
            "content": "x"
        }]
    });

    let (status, _) = post(&harness, &session, &path, body.clone()).await;
    assert_eq!(status, Status::Forbidden);

    let (status, body) = post(&harness, &plain_session, &path, body).await;
    assert_eq!(status, Status::Forbidden);
    assert!(matches!(
        error_type(body),
        ErrorType::AdminElevationRequired
    ));
}

#[rocket::async_test]
async fn import_keeps_time_author_files_and_replies_and_skips_repeats() {
    let harness = TestHarness::new().await;
    let (session, admin) = new_admin(&harness).await;
    let (_, channels) = harness.new_server(&admin).await;
    let channel = channels[0].id().to_string();
    let path = format!("/admin/import/channels/{channel}/messages");

    let attachment = upload(&harness, &admin, "attachments").await;
    let avatar = upload(&harness, &admin, "avatars").await;

    let (status, body) = post(&harness, &session, &path, batch(&attachment, &avatar)).await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["imported"], 3);
    assert_eq!(body["skipped"], 0);

    let mut messages = harness
        .db
        .fetch_messages(revolt_database::MessageQuery {
            filter: revolt_database::MessageFilter {
                channel: Some(channel.clone()),
                author: None,
                query: None,
                pinned: None,
            },
            limit: Some(10),
            time_period: revolt_database::MessageTimePeriod::Absolute {
                before: None,
                after: None,
                sort: Some(revolt_models::v0::MessageSort::Oldest),
            },
        })
        .await
        .unwrap();
    messages.retain(|message| message.imported.is_some());
    // the reference database does not sort
    messages.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(messages.len(), 3);
    let (first, second, third) = (&messages[0], &messages[1], &messages[2]);

    // original times in the ids, in order
    let time = |id: &str| ulid::Ulid::from_string(id).unwrap().timestamp_ms();
    assert_eq!(time(&first.id), 1_676_290_785_369);
    assert!(first.id < second.id && second.id < third.id);

    // phantom authors: stable per original author, name and avatar on the message
    assert_eq!(first.author, third.author);
    assert_ne!(first.author, second.author);
    let webhook = first.webhook.as_ref().unwrap();
    assert_eq!(webhook.name, "CatPower");
    assert_eq!(webhook.avatar.as_deref(), Some(avatar.as_str()));
    assert_eq!(
        third.webhook.as_ref().unwrap().avatar.as_deref(),
        Some(avatar.as_str())
    );
    assert!(second.webhook.as_ref().unwrap().avatar.is_none());
    assert_eq!(first.imported.as_ref().unwrap().source, "discord");
    assert!(harness.db.fetch_user(&first.author).await.is_err());

    assert_eq!(first.pinned, Some(true));
    assert_eq!(first.content.as_deref(), Some("first"));
    assert!(second.content.is_none());
    assert!(second.edited.is_some());
    assert_eq!(second.replies.as_deref(), Some(&[first.id.clone()][..]));
    let files = second.attachments.as_ref().unwrap();
    assert_eq!(files[0].id, attachment);
    let stored = harness
        .db
        .fetch_attachment("attachments", &attachment)
        .await
        .unwrap();
    assert_eq!(stored.used_for.unwrap().id, second.id);

    // the channel's last message is the newest imported one
    let fetched = harness.db.fetch_channel(&channel).await.unwrap();
    match fetched {
        revolt_database::Channel::TextChannel {
            last_message_id, ..
        } => assert_eq!(last_message_id.as_deref(), Some(third.id.as_str())),
        _ => unreachable!(),
    }

    // the same batch again: nothing new, files not claimed twice
    let (status, body) = post(&harness, &session, &path, batch(&attachment, &avatar)).await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["imported"], 0);
    assert_eq!(body["skipped"], 3);
}

#[rocket::async_test]
async fn bad_batches_change_nothing() {
    let harness = TestHarness::new().await;
    let (session, admin) = new_admin(&harness).await;
    let (_, channels) = harness.new_server(&admin).await;
    let path = format!("/admin/import/channels/{}/messages", channels[0].id());

    let message = |content: &str, timestamp: &str| {
        json!({
            "original_id": "1",
            "timestamp": timestamp,
            "author": { "original_id": "1", "name": "a" },
            "content": content
        })
    };
    let cases = [
        json!({ "source": "Discord", "messages": [message("x", "2023-01-01T00:00:00Z")] }),
        json!({ "source": "discord", "messages": [] }),
        json!({ "source": "discord", "messages": [message("", "2023-01-01T00:00:00Z")] }),
        json!({ "source": "discord", "messages": [message("x", "1990-01-01T00:00:00Z")] }),
        json!({ "source": "discord", "messages": [message("x", "2023-01-01T00:00:00Z"), {
            "original_id": "2",
            "timestamp": "2023-01-01T00:00:01Z",
            "author": { "original_id": "1", "name": "a" },
            "content": "y".repeat(10_001)
        }] }),
    ];
    for case in cases {
        let (status, body) = post(&harness, &session, &path, case.clone()).await;
        assert_eq!(status, Status::BadRequest, "{case} → {body}");
    }

    // an unknown file fails the batch
    let (status, _) = post(
        &harness,
        &session,
        &path,
        json!({ "source": "discord", "messages": [{
            "original_id": "1",
            "timestamp": "2023-01-01T00:00:00Z",
            "author": { "original_id": "1", "name": "a" },
            "attachments": ["01ARZ3NDEKTSV4RRFFQ69G5FAV"]
        }] }),
    )
    .await;
    assert_eq!(status, Status::NotFound);
}

#[rocket::async_test]
async fn previews_are_set_on_imported_messages_only() {
    let harness = TestHarness::new().await;
    let (session, admin) = new_admin(&harness).await;
    let (_, channels) = harness.new_server(&admin).await;
    let channel = channels[0].id().to_string();

    let message = |id: &str, content: &str| {
        json!({
            "original_id": id,
            "timestamp": "2023-02-13T16:19:45.369+04:00",
            "author": { "original_id": "42", "name": "CatPower" },
            "content": content
        })
    };
    let (status, body) = post(
        &harness,
        &session,
        &format!("/admin/import/channels/{channel}/messages"),
        json!({ "source": "discord", "messages": [
            message("2001", "https://example.com/news"),
            message("2002", "https://example.com/cat.png"),
        ] }),
    )
    .await;
    assert_eq!(status, Status::Ok, "{body}");

    let picture = upload(&harness, &admin, "attachments").await;
    let path = format!("/admin/import/channels/{channel}/embeds");
    let previews = json!({ "source": "discord", "messages": [
        {
            "original_id": "2001",
            "timestamp": "2023-02-13T16:19:45.369+04:00",
            "embeds": [{
                "url": "https://example.com/news",
                "title": "News",
                "description": "What happened",
                "site_name": "Example",
                "image": { "file": picture, "width": 640, "height": 360, "small": true }
            }]
        },
        {
            "original_id": "2002",
            "timestamp": "2023-02-13T16:19:45.369+04:00",
            "embeds": [{
                "url": "https://example.com/cat.png",
                "image": { "url": "https://example.com/cat.png", "width": 10, "height": 20 }
            }]
        },
        {
            "original_id": "9999",
            "timestamp": "2023-02-13T16:19:45.369+04:00",
            "embeds": [{ "title": "nobody" }]
        }
    ] });

    let (_, plain_session, _) = new_plain_admin(&harness).await;
    let (status, _) = post(&harness, &plain_session, &path, previews.clone()).await;
    assert_eq!(status, Status::Forbidden);

    let (status, body) = post(&harness, &session, &path, previews.clone()).await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["updated"], 2);
    assert_eq!(body["missing"], 1);

    let mut messages = harness
        .db
        .fetch_messages(revolt_database::MessageQuery {
            filter: revolt_database::MessageFilter {
                channel: Some(channel.clone()),
                author: None,
                query: None,
                pinned: None,
            },
            limit: Some(10),
            time_period: revolt_database::MessageTimePeriod::Absolute {
                before: None,
                after: None,
                sort: Some(revolt_models::v0::MessageSort::Oldest),
            },
        })
        .await
        .unwrap();
    messages.retain(|message| message.imported.is_some());
    messages.sort_by(|a, b| a.content.cmp(&b.content));
    let (cat, news) = (&messages[0], &messages[1]);

    let autumn = revolt_config::config().await.hosts.autumn;
    match &news.embeds.as_ref().unwrap()[0] {
        revolt_models::v0::Embed::Website(site) => {
            assert_eq!(site.title.as_deref(), Some("News"));
            assert_eq!(
                site.original_url.as_deref(),
                Some("https://example.com/news")
            );
            assert_eq!(site.site_name.as_deref(), Some("Example"));
            let image = site.image.as_ref().unwrap();
            assert_eq!(image.url, format!("{autumn}/attachments/{picture}"));
            assert_eq!((image.width, image.height), (640, 360));
            assert!(matches!(image.size, revolt_models::v0::ImageSize::Preview));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        &cat.embeds.as_ref().unwrap()[0],
        revolt_models::v0::Embed::Image(image) if image.url == "https://example.com/cat.png"
    ));
    let stored = harness
        .db
        .fetch_attachment("attachments", &picture)
        .await
        .unwrap();
    assert_eq!(stored.used_for.unwrap().id, news.id);

    // again: the file is already the message's, the previews are replaced
    let (status, body) = post(&harness, &session, &path, previews).await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["updated"], 2);

    // a preview that shows nothing is refused
    let (status, _) = post(
        &harness,
        &session,
        &path,
        json!({ "source": "discord", "messages": [{
            "original_id": "2001",
            "timestamp": "2023-02-13T16:19:45.369+04:00",
            "embeds": [{ "url": "https://example.com/news" }]
        }] }),
    )
    .await;
    assert_eq!(status, Status::BadRequest);
}
