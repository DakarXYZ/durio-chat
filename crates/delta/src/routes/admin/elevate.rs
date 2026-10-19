use iso8601_timestamp::{Duration, Timestamp};
use revolt_config::config;
use revolt_database::{Database, MFATicket, Session, User};
use revolt_models::v0;
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use rocket_empty::EmptyResponse;

use super::require_admin;

/// # Elevate Admin Session
///
/// Allow admin actions from the current session for `[api.admins] elevation_minutes`
/// (dur.io fork, instance admins only). Needs a validated MFA ticket (`PUT /auth/mfa/ticket`)
/// in `x-mfa-ticket` and an authenticator app (TOTP) on the account; the ticket is used up.
#[openapi(tag = "Admin")]
#[post("/elevate")]
pub async fn elevate(
    db: &State<Database>,
    user: User,
    session: Session,
    ticket: Option<MFATicket>,
) -> Result<Json<v0::AdminElevation>> {
    require_admin(&user).await?;

    // A password-only ticket is not 2FA: with TOTP on, tickets need a code
    let account = db.fetch_account(&user.id).await?;
    if !account.mfa.is_active() {
        return Err(create_error!(TotpRequired));
    }

    // Checked here rather than by `ValidatedTicket`, so a refused request keeps the ticket
    let ticket = ticket
        .filter(|ticket| ticket.validated && ticket.account_id == session.user_id)
        .ok_or_else(|| create_error!(InvalidToken))?;
    ticket.claim(db).await?;

    // Whole seconds, the same in both databases and in the response
    let minutes = config().await.api.admins.elevation_minutes as i64;
    let now = Timestamp::now_utc()
        .duration_since(Timestamp::UNIX_EPOCH)
        .whole_seconds();
    let expires_at = Timestamp::UNIX_EPOCH
        .checked_add(Duration::seconds(now) + Duration::minutes(minutes))
        .ok_or_else(|| create_error!(InternalError))?;
    db.set_session_admin_elevation(&session.id, Some(expires_at))
        .await?;
    log::info!(
        "Admin {} elevated session {} until {}",
        user.id,
        session.id,
        expires_at
    );

    Ok(Json(v0::AdminElevation { expires_at }))
}

/// # End Admin Elevation
///
/// Stop allowing admin actions from the current session before the elevation runs out (dur.io fork).
#[openapi(tag = "Admin")]
#[delete("/elevate")]
pub async fn end_elevation(
    db: &State<Database>,
    user: User,
    session: Session,
) -> Result<EmptyResponse> {
    if session.user_id == user.id && session.admin_elevated_until.is_some() {
        db.set_session_admin_elevation(&session.id, None).await?;
        log::info!(
            "Admin {} ended the elevation of session {}",
            user.id,
            session.id
        );
    }

    Ok(EmptyResponse)
}
