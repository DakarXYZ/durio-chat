//! Permissions of single members in a server channel (dur.io fork)
use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, PartialChannel, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, Override};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// Change the override of one member, `None` drops it
async fn set_user_override(
    db: &Database,
    user: &User,
    target: Reference<'_>,
    member_id: &str,
    next: Option<Override>,
) -> Result<v0::Channel> {
    let mut channel = target.as_channel(db).await?;
    super::threads::refuse_thread(&channel)?;

    let mut query = DatabasePermissionQuery::new(db, user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ManagePermissions)?;

    let Channel::TextChannel {
        server,
        user_permissions,
        ..
    } = &channel
    else {
        return Err(create_error!(InvalidOperation));
    };

    db.fetch_member(server, member_id).await?;

    let mut overrides = user_permissions.clone();
    let current: Option<Override> = overrides.get(member_id).map(|value| (*value).into());
    permissions
        .throw_permission_override(current, &next.clone().unwrap_or_default())
        .await?;

    match next {
        Some(value) => {
            overrides.insert(member_id.to_string(), value.into());
        }
        None => {
            if overrides.remove(member_id).is_none() {
                return Ok(channel.into());
            }
        }
    }

    channel
        .update(
            db,
            PartialChannel {
                user_permissions: Some(overrides),
                ..Default::default()
            },
            vec![],
        )
        .await?;

    Ok(channel.into())
}

/// # Set Member Permission
///
/// Sets permissions for one member in this channel: for example, read-only, or
/// no reactions. Needs `ManagePermissions`; the member who made the channel for
/// themselves has it there.
///
/// Channel must be a `TextChannel`.
#[openapi(tag = "Channel Permissions")]
#[put("/<target>/permissions/users/<member_id>", data = "<data>")]
pub async fn set_user_permissions(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    member_id: String,
    data: Json<v0::DataSetRolePermissions>,
) -> Result<Json<v0::Channel>> {
    set_user_override(db, &user, target, &member_id, Some(data.into_inner().permissions))
        .await
        .map(Json)
}

/// # Remove Member Permission
///
/// Drops the permissions set for one member in this channel.
#[openapi(tag = "Channel Permissions")]
#[delete("/<target>/permissions/users/<member_id>")]
pub async fn remove_user_permissions(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    member_id: String,
) -> Result<Json<v0::Channel>> {
    set_user_override(db, &user, target, &member_id, None)
        .await
        .map(Json)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{util::reference::Reference, Member, PartialMember, PartialServer};
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};

    async fn request(
        harness: &TestHarness,
        method: rocket::http::Method,
        token: &str,
        path: String,
        body: Option<serde_json::Value>,
    ) -> (Status, Option<serde_json::Value>) {
        let mut request = harness
            .client
            .req(method, path)
            .header(Header::new("x-session-token", token.to_string()));
        if let Some(body) = body {
            request = request.header(ContentType::JSON).body(body.to_string());
        }

        let response = request.dispatch().await;
        let status = response.status();
        (status, response.into_json().await)
    }

    #[rocket::async_test]
    async fn members_run_channels_of_their_own() {
        use rocket::http::Method::{Delete, Get, Post, Put};

        let harness = TestHarness::new().await;
        let (_, admin_session, admin) = harness.new_user().await;
        let (mut server, channels) = harness.new_server(&admin).await;
        let admin_token = admin_session.token.to_string();

        let (_, maker_session, maker) = harness.new_user().await;
        let (_, other_session, other) = harness.new_user().await;
        for user in [&maker, &other] {
            Member::create(&harness.db, &server, user, None)
                .await
                .unwrap();
        }
        let maker_token = maker_session.token.to_string();
        let other_token = other_session.token.to_string();

        // a moderator: `ManageChannel` from a role
        let (_, moderator_session, moderator) = harness.new_user().await;
        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::ManageChannel as i64,
                    d: 0,
                }),
            )
            .await;
        let (mut member, _) = Member::create(&harness.db, &server, &moderator, None)
            .await
            .unwrap();
        member
            .update(
                &harness.db,
                PartialMember {
                    roles: Some(vec![role.id.clone()]),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();
        let moderator_token = moderator_session.token.to_string();

        let create = json!({ "type": "Text", "name": "maker's corner" });

        // off by default
        let (status, _) = request(
            &harness,
            Post,
            &maker_token,
            format!("/servers/{}/channels", server.id),
            Some(create.clone()),
        )
        .await;
        assert_eq!(status, Status::Forbidden);

        server
            .update(
                &harness.db,
                PartialServer {
                    user_channel_limit: Some(1),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();

        let (status, channel) = request(
            &harness,
            Post,
            &maker_token,
            format!("/servers/{}/channels", server.id),
            Some(create.clone()),
        )
        .await;
        assert_eq!(status, Status::Ok);
        let channel = channel.unwrap();
        let id = channel["_id"].as_str().unwrap().to_string();
        assert_eq!(channel["owner"], maker.id.as_str());

        // one each, and text only
        let (status, _) = request(
            &harness,
            Post,
            &maker_token,
            format!("/servers/{}/channels", server.id),
            Some(create.clone()),
        )
        .await;
        assert_eq!(status, Status::BadRequest);

        // the maker makes another member read-only, and may not touch other channels
        let read_only = json!({ "permissions": { "allow": 0, "deny": 1u64 << 22 | 1u64 << 29 } });
        let (status, _) = request(
            &harness,
            Put,
            &maker_token,
            format!("/channels/{id}/permissions/users/{}", other.id),
            Some(read_only.clone()),
        )
        .await;
        assert_eq!(status, Status::Ok);

        let (status, _) = request(
            &harness,
            Put,
            &maker_token,
            format!("/channels/{}/permissions/users/{}", channels[0].id(), other.id),
            Some(read_only.clone()),
        )
        .await;
        assert_eq!(status, Status::Forbidden);

        let (status, _) = request(
            &harness,
            Post,
            &other_token,
            format!("/channels/{id}/messages"),
            Some(json!({ "content": "hi" })),
        )
        .await;
        assert_eq!(status, Status::Forbidden);

        // the maker deletes anyone's message there
        let (_, message) = request(
            &harness,
            Post,
            &admin_token,
            format!("/channels/{id}/messages"),
            Some(json!({ "content": "from the admin" })),
        )
        .await;
        let message = message.unwrap()["_id"].as_str().unwrap().to_string();
        let (status, _) = request(
            &harness,
            Delete,
            &maker_token,
            format!("/channels/{id}/messages/{message}"),
            None,
        )
        .await;
        assert_eq!(status, Status::NoContent);

        // but runs no members of the server
        let (status, _) = request(
            &harness,
            Delete,
            &maker_token,
            format!("/servers/{}/members/{}", server.id, other.id),
            None,
        )
        .await;
        assert_eq!(status, Status::Forbidden);

        // a server moderator is not locked out of a member's channel
        let (status, _) = request(
            &harness,
            Put,
            &maker_token,
            format!("/channels/{id}/permissions/default"),
            Some(json!({ "permissions": { "allow": 0, "deny": 1u64 << 20 } })),
        )
        .await;
        assert_eq!(status, Status::Ok);
        let (status, _) = request(
            &harness,
            Get,
            &moderator_token,
            format!("/channels/{id}"),
            None,
        )
        .await;
        assert_eq!(status, Status::Ok);
        let (status, _) = request(
            &harness,
            Post,
            &moderator_token,
            format!("/channels/{id}/messages"),
            Some(json!({ "content": "moderator here" })),
        )
        .await;
        assert_eq!(status, Status::Ok);
        let (status, _) = request(
            &harness,
            Get,
            &other_token,
            format!("/channels/{id}"),
            None,
        )
        .await;
        assert_eq!(status, Status::Forbidden);

        // the override goes again
        let (status, _) = request(
            &harness,
            Delete,
            &maker_token,
            format!("/channels/{id}/permissions/users/{}", other.id),
            None,
        )
        .await;
        assert_eq!(status, Status::Ok);
        let stored = Reference::from_unchecked(&id)
            .as_channel(&harness.db)
            .await
            .unwrap();
        let v0::Channel::TextChannel {
            user_permissions, ..
        } = stored.into()
        else {
            panic!("`TextChannel`");
        };
        assert!(user_permissions.is_empty());
    }
}
