use revolt_database::{
    Database,
    util::{permissions::DatabasePermissionQuery, reference::Reference},
};
use revolt_models::v0::{self, E2EE_ALGORITHM_MEGOLM};
use revolt_permissions::{ChannelPermission, calculate_channel_permissions};
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};

use crate::routes::e2ee::E2eeSession;

/// # Enable Encryption
///
/// Enables end-to-end encryption of a direct message or group (dur.io fork).
///
/// Requires `ManageChannel`. Encryption cannot be disabled afterwards.
/// Groups with bots and channels with webhooks cannot be encrypted.
#[openapi(tag = "Channel Information")]
#[put("/<target>/encryption", data = "<data>")]
pub async fn enable_encryption(
    db: &State<Database>,
    e2ee: E2eeSession,
    target: Reference<'_>,
    data: Json<v0::DataChannelEncryption>,
) -> Result<Json<v0::Channel>> {
    if data.algorithm != E2EE_ALGORITHM_MEGOLM {
        return Err(create_error!(FailedValidation {
            error: "unsupported algorithm".to_string()
        }));
    }

    let mut channel = target.as_channel(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &e2ee.user).channel(&channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;

    channel.enable_encryption(db, &e2ee.user).await?;

    Ok(Json(channel.into()))
}
