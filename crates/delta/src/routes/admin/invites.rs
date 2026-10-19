use iso8601_timestamp::{Duration, Timestamp};
use nanoid::nanoid;
use revolt_database::{AccountInvite, Database, Session, User};
use revolt_models::v0;
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use rocket_empty::EmptyResponse;

use super::require_elevated_admin;

/// Lifetimes an admin can choose for an invite (hours)
const INVITE_TTL_HOURS: [u32; 4] = [1, 4, 12, 24];

/// Letters and digits only, so the code survives being selected and copied as one word
const INVITE_ALPHABET: [char; 62] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
    'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
    'v', 'w', 'x', 'y', 'z',
];

/// Code length, about 95 bits of entropy
const INVITE_CODE_LENGTH: usize = 16;

/// Start of an invite code that is safe to log, the rest of it stays secret
fn code_prefix(code: &str) -> String {
    code.chars().take(4).collect()
}

/// API view of an invite generated in the app, `None` for a manual one
fn admin_invite(invite: AccountInvite) -> Option<v0::AdminInvite> {
    Some(v0::AdminInvite {
        expires_at: invite.expires_at?,
        created_by: invite.created_by?,
        created_at: invite.created_at?,
        multi_use: invite.multi_use,
        uses: invite.uses,
        id: invite.id,
    })
}

/// # Create Account Invite
///
/// Make an invite for registration (dur.io fork, instance admins only): it works for
/// `ttl_hours` (1, 4, 12 or 24) and either once or, with `multi_use`, for any number
/// of accounts until it expires.
#[openapi(tag = "Admin")]
#[post("/invites", data = "<data>")]
pub async fn create_invite(
    db: &State<Database>,
    user: User,
    session: Session,
    data: Json<v0::DataCreateAdminInvite>,
) -> Result<Json<v0::AdminInvite>> {
    require_elevated_admin(&user, &session).await?;

    let data = data.into_inner();
    if !INVITE_TTL_HOURS.contains(&data.ttl_hours) {
        return Err(create_error!(InvalidOperation));
    }

    // Whole seconds, the same in both databases and in the response
    let now = Timestamp::UNIX_EPOCH
        .checked_add(Duration::seconds(
            Timestamp::now_utc()
                .duration_since(Timestamp::UNIX_EPOCH)
                .whole_seconds(),
        ))
        .ok_or_else(|| create_error!(InternalError))?;
    let expires_at = now
        .checked_add(Duration::hours(data.ttl_hours as i64))
        .ok_or_else(|| create_error!(InternalError))?;

    let invite = AccountInvite {
        id: nanoid!(INVITE_CODE_LENGTH, &INVITE_ALPHABET),
        expires_at: Some(expires_at),
        multi_use: data.multi_use,
        created_by: Some(user.id.clone()),
        created_at: Some(now),
        ..Default::default()
    };
    invite.save(db).await?;
    log::info!(
        "Admin {} created invite {}... ({} h, {})",
        user.id,
        code_prefix(&invite.id),
        data.ttl_hours,
        if invite.multi_use {
            "multi-use"
        } else {
            "single-use"
        }
    );

    admin_invite(invite)
        .map(Json)
        .ok_or_else(|| create_error!(InternalError))
}

/// # Fetch Account Invites
///
/// Invites made in the app that still work, newest first (dur.io fork, instance admins only).
#[openapi(tag = "Admin")]
#[get("/invites")]
pub async fn fetch_invites(
    db: &State<Database>,
    user: User,
    session: Session,
) -> Result<Json<Vec<v0::AdminInvite>>> {
    require_elevated_admin(&user, &session).await?;

    let now = Timestamp::now_utc();
    let mut invites: Vec<v0::AdminInvite> = db
        .fetch_admin_account_invites()
        .await?
        .into_iter()
        .filter(|invite| invite.is_active(now))
        .filter_map(admin_invite)
        .collect();
    invites.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));

    Ok(Json(invites))
}

/// # Revoke Account Invite
///
/// Delete an invite so nobody can register with it (dur.io fork, instance admins only).
/// Accounts already created with it stay.
#[openapi(tag = "Admin")]
#[delete("/invites/<code>")]
pub async fn revoke_invite(
    db: &State<Database>,
    user: User,
    session: Session,
    code: &str,
) -> Result<EmptyResponse> {
    require_elevated_admin(&user, &session).await?;

    db.delete_account_invite(code).await?;
    log::info!("Admin {} revoked invite {}...", user.id, code_prefix(code));

    Ok(EmptyResponse)
}

#[cfg(test)]
mod unit {
    use super::code_prefix;

    #[test]
    fn prefix_hides_the_code() {
        assert_eq!(code_prefix("AbCdEfGhIjKlMnOp"), "AbCd");
        assert_eq!(code_prefix("ab"), "ab");
        assert_eq!(code_prefix("ёжикёжик"), "ёжик");
    }
}
