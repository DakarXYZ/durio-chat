use revolt_database::{Database, User, util::reference::Reference};
use revolt_models::v0;
use revolt_result::Result;
use rocket::{State, serde::json::Json};

use super::{require_admin, session_owner};

/// # Fetch User Sessions
///
/// Sessions (devices) of a user, without tokens (dur.io fork, instance admins only).
#[openapi(tag = "Admin")]
#[get("/users/<target>/sessions")]
pub async fn fetch_sessions(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<Vec<v0::SessionInfo>>> {
    require_admin(&user).await?;
    let owner = session_owner(db, target.id).await?;

    db.fetch_sessions(&owner.id)
        .await
        .map(|sessions| sessions.into_iter().map(Into::into).collect())
        .map(Json)
}
