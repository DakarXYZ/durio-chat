use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};

use super::require_admin;

/// # Find User
///
/// Find a user by id or `username#discriminator` (dur.io fork, instance admins only).
#[openapi(tag = "Admin")]
#[get("/users?<options..>")]
pub async fn find_user(
    db: &State<Database>,
    user: User,
    options: v0::OptionsAdminFindUser,
) -> Result<Json<v0::AdminUser>> {
    require_admin(&user).await?;

    let query = options.query.trim().trim_start_matches('@');
    let found = match query.rsplit_once('#') {
        Some((username, discriminator)) => {
            db.fetch_user_by_username(username, discriminator).await?
        }
        None if !query.is_empty() => db.fetch_user(query).await?,
        None => return Err(create_error!(NotFound)),
    };

    Ok(Json(v0::AdminUser {
        id: found.id,
        username: found.username,
        discriminator: found.discriminator,
        display_name: found.display_name,
        bot: found.bot.is_some(),
    }))
}
