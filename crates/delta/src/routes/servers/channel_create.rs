use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::AuditLogEntryAction;
use revolt_database::{util::reference::Reference, Channel, Database, User};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

use crate::util::audit_log_reason::AuditLogReason;

/// # Create Channel
///
/// Create a new Text or Voice channel.
///
/// Without `ManageChannel`, members make text channels of their own, as many as
/// the server's `user_channel_limit` allows (dur.io fork).
#[openapi(tag = "Server Information")]
#[post("/<server>/channels", data = "<data>")]
pub async fn create_server_channel(
    db: &State<Database>,
    user: User,
    reason: AuditLogReason,
    server: Reference<'_>,
    data: Json<v0::DataCreateServerChannel>,
) -> Result<Json<v0::Channel>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let mut server = server.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    let permissions = calculate_server_permissions(&mut query).await;

    // dur.io fork: a member's own text channel
    let owner = if permissions.has_channel_permission(ChannelPermission::ManageChannel) {
        None
    } else {
        db.fetch_member(&server.id, &user.id).await?;

        if server.user_channel_limit == 0
            || !matches!(data.channel_type, v0::LegacyServerChannelType::Text)
            || data.voice.is_some()
        {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
        }

        let made = db
            .fetch_channels(&server.channels)
            .await?
            .iter()
            .filter(|channel| channel.user_channel_owner() == Some(user.id.as_str()))
            .count();

        if made >= server.user_channel_limit as usize {
            return Err(create_error!(TooManyChannels {
                max: server.user_channel_limit as usize,
            }));
        }

        Some(user.id.clone())
    };

    let channel_name = data.name.clone();

    let channel =
        Channel::create_owned_server_channel(db, &mut server, data, true, owner).await?;

    AuditLogEntryAction::ChannelCreate {
        channel: channel.id().to_string(),
        name: channel_name,
    }
    .insert(db, server.id, reason, user.id, None)
    .await;

    Ok(Json(channel.into()))
}
