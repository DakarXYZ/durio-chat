use revolt_database::User;
use revolt_models::v0;
use revolt_result::Result;
use rocket::serde::json::Json;

use super::is_instance_admin;

/// # Admin Status
///
/// Whether the current user is an admin of this instance (dur.io fork).
/// Clients show the admin tools only when this is true.
#[openapi(tag = "Admin")]
#[get("/@me")]
pub async fn status(user: User) -> Result<Json<v0::AdminStatus>> {
    Ok(Json(v0::AdminStatus {
        admin: is_instance_admin(&user).await,
    }))
}
