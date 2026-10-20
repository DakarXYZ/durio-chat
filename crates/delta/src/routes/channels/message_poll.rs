//! Polls on messages (dur.io fork)
use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

/// # Vote in a Poll
///
/// Pick answers in the poll of a message; the picks replace the user's earlier ones, an
/// empty list takes the vote back. Needs the `React` permission.
#[openapi(tag = "Interactions")]
#[put("/<target>/messages/<msg>/poll", data = "<data>")]
pub async fn vote_poll(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
    data: Json<v0::DataPollVote>,
) -> Result<EmptyResponse> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let channel = target.as_channel(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::React)?;

    let message = msg.as_message_in_channel(db, channel.id()).await?;
    message
        .vote_poll(db, &user, data.into_inner().answers)
        .await
        .map(|_| EmptyResponse)
}

/// # Close a Poll
///
/// Stop the poll of a message from taking votes. Its author, or anyone with
/// `ManageMessages`, may close it.
#[openapi(tag = "Interactions")]
#[post("/<target>/messages/<msg>/poll/close")]
pub async fn close_poll(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
) -> Result<EmptyResponse> {
    let channel = target.as_channel(db).await?;
    let message = msg.as_message_in_channel(db, channel.id()).await?;

    if message.author != user.id {
        let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
        calculate_channel_permissions(&mut query)
            .await
            .throw_if_lacking_channel_permission(ChannelPermission::ManageMessages)?;
    }

    message.close_poll(db).await.map(|_| EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{util::reference::Reference, Member};
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};

    /// A poll in a new server, sent through the API by the server's owner
    async fn poll_message(
        harness: &TestHarness,
        multiple: bool,
    ) -> (String, String, v0::Message, revolt_database::Server) {
        let (_, session, user) = harness.new_user().await;
        let (server, channels) = harness.new_server(&user).await;
        let channel = channels[0].id().to_string();

        let response = harness
            .client
            .post(format!("/channels/{channel}/messages"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.to_string()))
            .body(
                json!({
                    "poll": {
                        "question": "  Where do we meet?  ",
                        "answers": ["Park", "Cafe", "Online"],
                        "multiple": multiple
                    }
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let message: v0::Message = response.into_json().await.expect("`Message`");
        (channel, session.token, message, server)
    }

    /// Another member of the server: their session token
    async fn member(harness: &TestHarness, server: &revolt_database::Server) -> (String, String) {
        let (_, session, user) = harness.new_user().await;
        Member::create(&harness.db, server, &user, None)
            .await
            .expect("`Member`");
        (session.token, user.id)
    }

    async fn vote(
        harness: &TestHarness,
        token: &str,
        channel: &str,
        message: &str,
        answers: &[&str],
    ) -> Status {
        harness
            .client
            .put(format!("/channels/{channel}/messages/{message}/poll"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(json!({ "answers": answers }).to_string())
            .dispatch()
            .await
            .status()
    }

    async fn poll_of(harness: &TestHarness, message: &str) -> v0::Poll {
        Reference::from_unchecked(message)
            .as_message(&harness.db)
            .await
            .expect("`Message`")
            .poll
            .expect("`Poll`")
    }

    #[rocket::async_test]
    async fn send_a_poll() {
        let harness = TestHarness::new().await;
        let (_, _, message, _) = poll_message(&harness, false).await;

        let poll = message.poll.expect("`Poll`");
        assert_eq!(poll.question, "Where do we meet?");
        assert_eq!(
            poll.answers
                .iter()
                .map(|answer| (answer.id.as_str(), answer.text.as_str()))
                .collect::<Vec<_>>(),
            vec![("0", "Park"), ("1", "Cafe"), ("2", "Online")]
        );
        assert!(!poll.multiple && !poll.closed);
        assert!(message.content.is_none());
    }

    #[rocket::async_test]
    async fn a_poll_needs_two_answers() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, channels) = harness.new_server(&user).await;

        for answers in [json!(["Only one"]), json!(["Fine", "  "])] {
            let response = harness
                .client
                .post(format!("/channels/{}/messages", channels[0].id()))
                .header(ContentType::JSON)
                .header(Header::new("x-session-token", session.token.to_string()))
                .body(json!({ "poll": { "question": "Q?", "answers": answers } }).to_string())
                .dispatch()
                .await;

            assert_eq!(response.status(), Status::BadRequest, "{answers}");
        }
    }

    #[rocket::async_test]
    async fn votes_replace_earlier_picks() {
        let harness = TestHarness::new().await;
        let (channel, owner, message, server) = poll_message(&harness, false).await;
        let (friend, friend_id) = member(&harness, &server).await;

        assert_eq!(vote(&harness, &friend, &channel, &message.id, &["0"]).await, Status::NoContent);
        assert_eq!(vote(&harness, &owner, &channel, &message.id, &["0"]).await, Status::NoContent);
        assert_eq!(vote(&harness, &friend, &channel, &message.id, &["2"]).await, Status::NoContent);

        let poll = poll_of(&harness, &message.id).await;
        assert_eq!(poll.answers[0].votes.len(), 1);
        assert!(poll.answers[2].votes.contains(&friend_id));

        // one answer only, and only known ones
        assert_eq!(
            vote(&harness, &friend, &channel, &message.id, &["0", "1"]).await,
            Status::BadRequest
        );
        assert_eq!(vote(&harness, &friend, &channel, &message.id, &["7"]).await, Status::BadRequest);

        // an empty pick takes the vote back
        assert_eq!(vote(&harness, &friend, &channel, &message.id, &[]).await, Status::NoContent);
        let poll = poll_of(&harness, &message.id).await;
        assert!(poll.answers.iter().all(|answer| !answer.votes.contains(&friend_id)));
    }

    #[rocket::async_test]
    async fn multiple_choice() {
        let harness = TestHarness::new().await;
        let (channel, owner, message, _) = poll_message(&harness, true).await;

        assert_eq!(
            vote(&harness, &owner, &channel, &message.id, &["0", "2", "2"]).await,
            Status::NoContent
        );
        let poll = poll_of(&harness, &message.id).await;
        assert_eq!(
            poll.answers.iter().map(|answer| answer.votes.len()).collect::<Vec<_>>(),
            vec![1, 0, 1]
        );
    }

    #[rocket::async_test]
    async fn only_the_author_closes_and_then_no_votes() {
        let harness = TestHarness::new().await;
        let (channel, owner, message, server) = poll_message(&harness, false).await;
        let (friend, _) = member(&harness, &server).await;

        let close = |token: String| {
            harness
                .client
                .post(format!("/channels/{channel}/messages/{}/poll/close", message.id))
                .header(Header::new("x-session-token", token))
                .dispatch()
        };

        assert_eq!(close(friend.clone()).await.status(), Status::Forbidden);
        assert_eq!(close(owner.clone()).await.status(), Status::NoContent);
        assert!(poll_of(&harness, &message.id).await.closed);

        assert_eq!(vote(&harness, &friend, &channel, &message.id, &["1"]).await, Status::BadRequest);
    }
}
