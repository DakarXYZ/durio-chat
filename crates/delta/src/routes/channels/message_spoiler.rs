//! Moderators hide messages behind a spoiler (dur.io fork)
use revolt_database::{
    Database, FieldsMessage, PartialMessage, User,
    util::{permissions::DatabasePermissionQuery, reference::Reference},
};
use revolt_models::v0;
use revolt_permissions::{ChannelPermission, calculate_channel_permissions};
use revolt_result::Result;
use rocket::{State, serde::json::Json};
use rocket_empty::EmptyResponse;

/// # Hide a Message behind a Spoiler
///
/// Hide any message behind a "spoiler alert" or an NSFW cover; everyone sees the
/// cover until they open it. Needs `ManageMessages`.
#[openapi(tag = "Messaging")]
#[put("/<target>/messages/<msg>/spoiler", data = "<data>")]
pub async fn spoiler_message(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
    data: Json<v0::DataMessageSpoiler>,
) -> Result<EmptyResponse> {
    let channel = target.as_channel(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageMessages)?;

    let mut message = msg.as_message_in_channel(db, channel.id()).await?;
    message
        .update(
            db,
            PartialMessage {
                spoiler: Some(v0::MessageSpoiler {
                    kind: data.into_inner().kind,
                    by: user.id,
                }),
                ..Default::default()
            },
            vec![],
        )
        .await
        .map(|_| EmptyResponse)
}

/// # Take a Message out from behind a Spoiler
///
/// Needs `ManageMessages`.
#[openapi(tag = "Messaging")]
#[delete("/<target>/messages/<msg>/spoiler")]
pub async fn unspoiler_message(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
) -> Result<EmptyResponse> {
    let channel = target.as_channel(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageMessages)?;

    let mut message = msg.as_message_in_channel(db, channel.id()).await?;
    if message.spoiler.is_some() {
        message
            .update(db, PartialMessage::default(), vec![FieldsMessage::Spoiler])
            .await?;
    }

    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{Member, util::reference::Reference};
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};

    #[rocket::async_test]
    async fn moderators_hide_messages() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (server, channels) = harness.new_server(&owner).await;
        let channel = channels[0].id().to_string();
        let (_, other_session, other) = harness.new_user().await;
        Member::create(&harness.db, &server, &other, None)
            .await
            .unwrap();

        let response = harness
            .client
            .post(format!("/channels/{channel}/messages"))
            .header(ContentType::JSON)
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .body(json!({ "content": "the ending" }).to_string())
            .dispatch()
            .await;
        let message: v0::Message = response.into_json().await.unwrap();
        let path = format!("/channels/{channel}/messages/{}/spoiler", message.id);

        // a member may not
        let response = harness
            .client
            .put(path.clone())
            .header(ContentType::JSON)
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .body(json!({ "kind": "nsfw" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        drop(response);

        // the owner may
        let response = harness
            .client
            .put(path.clone())
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.to_string()))
            .body(json!({ "kind": "nsfw" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        let stored = Reference::from_unchecked(&message.id)
            .as_message(&harness.db)
            .await
            .unwrap();
        let spoiler = stored.spoiler.expect("`MessageSpoiler`");
        assert_eq!(spoiler.kind, v0::SpoilerKind::Nsfw);
        assert_eq!(spoiler.by, owner.id);

        let response = harness
            .client
            .delete(path)
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        let stored = Reference::from_unchecked(&message.id)
            .as_message(&harness.db)
            .await
            .unwrap();
        assert!(stored.spoiler.is_none());
    }
}
