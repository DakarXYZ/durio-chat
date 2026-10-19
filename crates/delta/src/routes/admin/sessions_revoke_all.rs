use revolt_database::{Database, User, util::reference::Reference};
use revolt_result::Result;
use rocket::State;
use rocket_empty::EmptyResponse;

use super::{require_admin, session_owner};

/// # End All User Sessions
///
/// End every session of a user (dur.io fork, instance admins only).
/// Like "log out everywhere": all E2EE devices are removed and all sockets are closed.
#[openapi(tag = "Admin")]
#[delete("/users/<target>/sessions")]
pub async fn revoke_all_sessions(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    require_admin(&user).await?;
    let owner = session_owner(db, target.id).await?;

    let account = db.fetch_account(&owner.id).await?;
    account.delete_all_sessions(db, None).await?;
    log::info!("Admin {} ended all sessions of user {}", user.id, owner.id);

    Ok(EmptyResponse)
}
