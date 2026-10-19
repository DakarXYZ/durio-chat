use revolt_database::{Session, User};
use revolt_models::v0;
use revolt_result::Result;
use rocket::serde::json::Json;

use super::{active_elevation, is_instance_admin};

/// # Admin Status
///
/// Whether the current user is an admin of this instance (dur.io fork) and, if admin
/// actions are allowed from this session, until when. Clients show the admin tools
/// only when `admin` is true and ask for 2FA (`POST /admin/elevate`) without `elevated_until`.
#[openapi(tag = "Admin")]
#[get("/@me")]
pub async fn status(user: User, session: Option<Session>) -> Result<Json<v0::AdminStatus>> {
    let admin = is_instance_admin(&user).await;
    let elevated_until = session
        .filter(|session| admin && session.user_id == user.id)
        .and_then(|session| active_elevation(&session));

    Ok(Json(v0::AdminStatus {
        admin,
        elevated_until,
    }))
}
