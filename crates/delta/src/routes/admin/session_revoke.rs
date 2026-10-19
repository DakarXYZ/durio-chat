use revolt_database::{Database, Session, User, util::reference::Reference};
use revolt_result::{Result, create_error};
use rocket::State;
use rocket_empty::EmptyResponse;

use super::{require_elevated_admin, session_owner};

/// # End User Session
///
/// End one session of a user (dur.io fork, instance admins only).
/// Like a logout: the session's E2EE device is removed and its sockets are closed.
#[openapi(tag = "Admin")]
#[delete("/users/<target>/sessions/<session>")]
pub async fn revoke_session(
    db: &State<Database>,
    user: User,
    current: Session,
    target: Reference<'_>,
    session: &str,
) -> Result<EmptyResponse> {
    require_elevated_admin(&user, &current).await?;
    let owner = session_owner(db, target.id).await?;

    let session = db.fetch_session(session).await?;
    if session.user_id != owner.id {
        return Err(create_error!(NotFound));
    }

    let session_id = session.id.clone();
    session.delete(db).await?;
    log::info!(
        "Admin {} ended session {} of user {}",
        user.id,
        session_id,
        owner.id
    );

    Ok(EmptyResponse)
}
