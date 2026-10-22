//! Threads of server channels (dur.io fork)
use revolt_database::{
    AMQP, Channel, Database, PartialChannel, User,
    util::{permissions::DatabasePermissionQuery, reference::Reference},
};
use revolt_models::v0;
use revolt_permissions::{ChannelPermission, calculate_channel_permissions};
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use validator::Validate;

/// # Start a Thread
///
/// Start a thread in a server channel, from one of its messages or, without
/// one, from a new `thread_created` system message. Needs `SendMessage`.
#[openapi(tag = "Channel Information")]
#[post("/<target>/threads", data = "<data>")]
pub async fn create_thread(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataCreateThread>,
) -> Result<Json<v0::Channel>> {
    let mut data = data.into_inner();
    data.name = data.name.trim().to_string();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let channel = target.as_channel(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    channel
        .create_thread(db, Some(amqp), &user, data)
        .await
        .map(|thread| Json(thread.into()))
}

/// # Fetch Threads
///
/// Fetch the threads of a channel, archived ones too.
#[openapi(tag = "Channel Information")]
#[get("/<target>/threads")]
pub async fn fetch_threads(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<Vec<v0::Channel>>> {
    let channel = target.as_channel(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    Ok(Json(
        db.fetch_channel_threads(channel.id())
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

/// # Edit a Thread
///
/// Rename, archive or close a thread. Its starter, or anyone with
/// `ManageChannel`, may do so; a new message brings an archived thread back,
/// a closed one stays closed until opened again.
#[openapi(tag = "Channel Information")]
#[patch("/<target>/thread", data = "<data>")]
pub async fn edit_thread(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataEditThread>,
) -> Result<Json<v0::Channel>> {
    let mut data = data.into_inner();
    data.name = data.name.map(|name| name.trim().to_string());
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let mut channel = target.as_channel(db).await?;
    let mut thread = channel
        .thread()
        .cloned()
        .ok_or_else(|| create_error!(InvalidOperation))?;

    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    if thread.owner != user.id {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
    }

    let mut partial = PartialChannel {
        name: data.name,
        ..Default::default()
    };

    let before = thread.clone();
    if let Some(archived) = data.archived {
        thread.archived = archived;
    }

    if let Some(locked) = data.locked {
        thread.locked = locked;
        thread.archived = locked;
    }

    // a closed thread is an archived one
    thread.archived |= thread.locked;

    if thread != before {
        partial.thread = Some(thread);
    }

    if partial.name.is_some() || partial.thread.is_some() {
        channel.update(db, partial, vec![]).await?;
    }

    Ok(Json(channel.into()))
}

/// Server channels that are threads are edited through `edit_thread`
pub fn refuse_thread(channel: &Channel) -> Result<()> {
    if channel.thread().is_some() {
        Err(create_error!(InvalidOperation))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{Channel, Member, PartialChannel, util::reference::Reference};
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};

    async fn post(
        harness: &TestHarness,
        token: &str,
        path: String,
        body: serde_json::Value,
    ) -> (Status, Option<serde_json::Value>) {
        let response = harness
            .client
            .post(path)
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(body.to_string())
            .dispatch()
            .await;

        let status = response.status();
        (status, response.into_json().await)
    }

    async fn patch(
        harness: &TestHarness,
        token: &str,
        thread: &str,
        body: serde_json::Value,
    ) -> Status {
        harness
            .client
            .patch(format!("/channels/{thread}/thread"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(body.to_string())
            .dispatch()
            .await
            .status()
    }

    async fn send(harness: &TestHarness, token: &str, channel: &str, text: &str) -> String {
        let (status, message) = post(
            harness,
            token,
            format!("/channels/{channel}/messages"),
            json!({ "content": text }),
        )
        .await;
        assert_eq!(status, Status::Ok);
        message.unwrap()["_id"].as_str().unwrap().to_string()
    }

    async fn thread_of(harness: &TestHarness, id: &str) -> v0::ThreadInfo {
        Reference::from_unchecked(id)
            .as_channel(&harness.db)
            .await
            .expect("`Channel`")
            .thread()
            .cloned()
            .expect("`ThreadInfo`")
    }

    async fn message_thread(harness: &TestHarness, id: &str) -> Option<String> {
        Reference::from_unchecked(id)
            .as_message(&harness.db)
            .await
            .expect("`Message`")
            .thread
    }

    #[rocket::async_test]
    async fn thread_from_a_message_counts_its_messages() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, channels) = harness.new_server(&user).await;
        let parent = channels[0].id().to_string();
        let token = session.token.to_string();

        let message = send(&harness, &token, &parent, "Let's talk about this").await;
        let (status, thread) = post(
            &harness,
            &token,
            format!("/channels/{parent}/threads"),
            json!({ "name": "  Talk  ", "message": message }),
        )
        .await;
        assert_eq!(status, Status::Ok);
        let thread = thread.unwrap();
        let id = thread["_id"].as_str().unwrap().to_string();
        assert_eq!(thread["name"], "Talk");
        assert_eq!(thread["thread"]["parent"], parent.as_str());
        assert_eq!(thread["thread"]["message"], message.as_str());
        assert_eq!(thread["thread"]["owner"], user.id.as_str());
        assert_eq!(message_thread(&harness, &message).await, Some(id.clone()));

        // one thread per message, none in a thread
        let (status, _) = post(
            &harness,
            &token,
            format!("/channels/{parent}/threads"),
            json!({ "name": "Again", "message": message }),
        )
        .await;
        assert_eq!(status, Status::BadRequest);
        let (status, _) = post(
            &harness,
            &token,
            format!("/channels/{id}/threads"),
            json!({ "name": "Nested" }),
        )
        .await;
        assert_eq!(status, Status::BadRequest);

        let first = send(&harness, &token, &id, "one").await;
        send(&harness, &token, &id, "two").await;
        assert_eq!(thread_of(&harness, &id).await.message_count, 2);

        let response = harness
            .client
            .delete(format!("/channels/{id}/messages/{first}"))
            .header(Header::new("x-session-token", token.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        assert_eq!(thread_of(&harness, &id).await.message_count, 1);

        // the server's channel list stays as it was
        let server = Reference::from_unchecked(channels[0].server().unwrap())
            .as_server(&harness.db)
            .await
            .unwrap();
        assert!(!server.channels.contains(&id));
    }

    #[rocket::async_test]
    async fn thread_without_a_message_hangs_off_a_system_message() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, channels) = harness.new_server(&user).await;
        let parent = channels[0].id().to_string();
        let token = session.token.to_string();

        let (status, thread) = post(
            &harness,
            &token,
            format!("/channels/{parent}/threads"),
            json!({ "name": "Plans" }),
        )
        .await;
        assert_eq!(status, Status::Ok);
        let thread = thread.unwrap();
        let id = thread["_id"].as_str().unwrap();
        let anchor = thread["thread"]["message"].as_str().unwrap();

        let message = Reference::from_unchecked(anchor)
            .as_message(&harness.db)
            .await
            .unwrap();
        assert_eq!(message.channel, parent);
        assert_eq!(message.thread.as_deref(), Some(id));
        assert!(matches!(
            message.system,
            Some(revolt_database::SystemMessage::ThreadCreated { ref by, ref name }) if by == &user.id && name == "Plans"
        ));

        // deleting the thread drops its system message
        let response = harness
            .client
            .delete(format!("/channels/{id}"))
            .header(Header::new("x-session-token", token.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        assert!(
            Reference::from_unchecked(anchor)
                .as_message(&harness.db)
                .await
                .is_err()
        );
    }

    #[rocket::async_test]
    async fn threads_take_the_permissions_of_their_channel() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (server, channels) = harness.new_server(&owner).await;
        let parent = channels[0].id().to_string();
        let token = session.token.to_string();

        let (_, other_session, other) = harness.new_user().await;
        Member::create(&harness.db, &server, &other, None)
            .await
            .unwrap();
        let other_token = other_session.token.to_string();

        let message = send(&harness, &token, &parent, "Topic").await;
        let (_, thread) = post(
            &harness,
            &token,
            format!("/channels/{parent}/threads"),
            json!({ "name": "Topic", "message": message }),
        )
        .await;
        let id = thread.unwrap()["_id"].as_str().unwrap().to_string();

        // a member writes in the thread, but may not archive someone else's
        send(&harness, &other_token, &id, "hi").await;
        assert_eq!(
            patch(&harness, &other_token, &id, json!({ "archived": true })).await,
            Status::Forbidden
        );

        // the starter may; a new message brings it back
        assert_eq!(
            patch(
                &harness,
                &token,
                &id,
                json!({ "archived": true, "name": "Done" })
            )
            .await,
            Status::Ok
        );
        assert!(thread_of(&harness, &id).await.archived);
        send(&harness, &other_token, &id, "one more thing").await;
        assert!(!thread_of(&harness, &id).await.archived);

        // hiding the channel hides its threads
        let mut channel = channels[0].clone();
        channel
            .update(
                &harness.db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ViewChannel as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();

        let response = harness
            .client
            .get(format!("/channels/{id}"))
            .header(Header::new("x-session-token", other_token.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        let (status, _) = post(
            &harness,
            &other_token,
            format!("/channels/{id}/messages"),
            json!({ "content": "x" }),
        )
        .await;
        assert_eq!(status, Status::Forbidden);
    }

    #[rocket::async_test]
    async fn threads_go_with_their_channel() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, channels) = harness.new_server(&user).await;
        let parent = channels[0].id().to_string();
        let token = session.token.to_string();

        let (_, thread) = post(
            &harness,
            &token,
            format!("/channels/{parent}/threads"),
            json!({ "name": "A" }),
        )
        .await;
        let id = thread.unwrap()["_id"].as_str().unwrap().to_string();

        let response = harness
            .client
            .get(format!("/channels/{parent}/threads"))
            .header(Header::new("x-session-token", token.clone()))
            .dispatch()
            .await;
        let threads: Vec<v0::Channel> = response.into_json().await.unwrap();
        assert_eq!(threads.len(), 1);

        let response = harness
            .client
            .delete(format!("/channels/{parent}"))
            .header(Header::new("x-session-token", token.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        assert!(
            Reference::from_unchecked(&id)
                .as_channel(&harness.db)
                .await
                .is_err()
        );
    }

    #[rocket::async_test]
    async fn closed_threads_take_messages_from_moderators_only() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (server, channels) = harness.new_server(&owner).await;
        let parent = channels[0].id().to_string();
        let token = session.token.to_string();

        let (_, other_session, other) = harness.new_user().await;
        Member::create(&harness.db, &server, &other, None)
            .await
            .unwrap();
        let other_token = other_session.token.to_string();

        let (_, thread) = post(
            &harness,
            &other_token,
            format!("/channels/{parent}/threads"),
            json!({ "name": "Question" }),
        )
        .await;
        let id = thread.unwrap()["_id"].as_str().unwrap().to_string();

        // the owner of the server closes the member's thread
        assert_eq!(
            patch(&harness, &token, &id, json!({ "locked": true })).await,
            Status::Ok
        );
        let info = thread_of(&harness, &id).await;
        assert!(info.locked && info.archived);

        // the starter still writes, as does the moderator, and it stays closed
        send(&harness, &other_token, &id, "thanks").await;
        send(&harness, &token, &id, "closing this").await;
        let info = thread_of(&harness, &id).await;
        assert!(info.locked && info.archived);

        // not unarchived behind the lock's back
        assert_eq!(
            patch(&harness, &other_token, &id, json!({ "archived": false })).await,
            Status::Ok
        );
        assert!(thread_of(&harness, &id).await.archived);

        // someone else may not write in it
        let (_, third_session, third) = harness.new_user().await;
        Member::create(&harness.db, &server, &third, None)
            .await
            .unwrap();
        let (status, _) = post(
            &harness,
            &third_session.token,
            format!("/channels/{id}/messages"),
            json!({ "content": "me too" }),
        )
        .await;
        assert_eq!(status, Status::Forbidden);

        // open again
        assert_eq!(
            patch(&harness, &token, &id, json!({ "locked": false })).await,
            Status::Ok
        );
        let info = thread_of(&harness, &id).await;
        assert!(!info.locked && !info.archived);
        send(&harness, &third_session.token, &id, "me too").await;
    }

    #[rocket::async_test]
    async fn inactive_threads_are_deleted_when_the_channel_says_so() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, channels) = harness.new_server(&user).await;
        let parent = channels[0].id().to_string();
        let token = session.token.to_string();

        let (_, thread) = post(
            &harness,
            &token,
            format!("/channels/{parent}/threads"),
            json!({ "name": "Old" }),
        )
        .await;
        let id = thread.unwrap()["_id"].as_str().unwrap().to_string();
        send(&harness, &token, &id, "last words").await;

        let day = 24 * 60 * 60 * 1000;
        let active_at = Reference::from_unchecked(&id)
            .as_channel(&harness.db)
            .await
            .unwrap()
            .thread_active_at()
            .unwrap();

        // kept forever by default
        assert_eq!(
            Channel::delete_inactive_threads(&harness.db, active_at + 400 * day)
                .await
                .unwrap(),
            0
        );

        let response = harness
            .client
            .patch(format!("/channels/{parent}"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.clone()))
            .body(json!({ "thread_auto_delete": 3 }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let channel: v0::Channel = response.into_json().await.unwrap();
        assert!(matches!(
            channel,
            v0::Channel::TextChannel {
                thread_auto_delete: Some(3),
                ..
            }
        ));

        // two days in: kept; four days in: gone
        assert_eq!(
            Channel::delete_inactive_threads(&harness.db, active_at + 2 * day)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            Channel::delete_inactive_threads(&harness.db, active_at + 4 * day)
                .await
                .unwrap(),
            1
        );
        assert!(
            Reference::from_unchecked(&id)
                .as_channel(&harness.db)
                .await
                .is_err()
        );
        assert!(
            Reference::from_unchecked(&parent)
                .as_channel(&harness.db)
                .await
                .is_ok()
        );
    }
}
