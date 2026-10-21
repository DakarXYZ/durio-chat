//! Instance administration from the client (dur.io fork)
//!
//! Admins are the users listed in `[api.admins] users` and users with `privileged` set.
//! They can find any user and end their sessions, e.g. after a lost phone. Every action
//! is logged with the admin's id; tokens never leave the server.
//!
//! Admin actions need 2FA: `POST /admin/elevate` with an MFA ticket (the account must have
//! TOTP on) allows them from the current session for `[api.admins] elevation_minutes`.
//! The elevation is stored on the session, so it ends with it (logout, revoke).
//!
//! Admins also make registration invites (`/admin/invites`) for `invite_only` instances
//! and import message history from other chats (`/admin/import`).
use iso8601_timestamp::Timestamp;
use revolt_config::config;
use revolt_database::{Session, User};
use revolt_result::{Result, create_error};
use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod elevate;
mod find_user;
mod import;
mod invites;
mod session_revoke;
mod sessions_fetch;
mod sessions_revoke_all;
mod status;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_elevation;
#[cfg(test)]
mod tests_import;
#[cfg(test)]
mod tests_invites;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        status::status,
        elevate::elevate,
        elevate::end_elevation,
        find_user::find_user,
        sessions_fetch::fetch_sessions,
        session_revoke::revoke_session,
        sessions_revoke_all::revoke_all_sessions,
        invites::create_invite,
        invites::fetch_invites,
        invites::revoke_invite,
        import::import_messages,
        import::import_embeds
    ]
}

/// Whether `user` is an instance admin given the configured admin ids
fn is_admin(user: &User, admins: &[String]) -> bool {
    user.bot.is_none() && (user.privileged || admins.iter().any(|id| id == &user.id))
}

/// Whether `user` is an instance admin
pub async fn is_instance_admin(user: &User) -> bool {
    is_admin(user, &config().await.api.admins.users)
}

/// Fail with `NotPrivileged` unless `user` is an instance admin
async fn require_admin(user: &User) -> Result<()> {
    if is_instance_admin(user).await {
        Ok(())
    } else {
        Err(create_error!(NotPrivileged))
    }
}

/// Whether an elevation lasting `until` is still active at `now`
fn elevation_active(until: Option<Timestamp>, now: Timestamp) -> bool {
    until.is_some_and(|until| until > now)
}

/// Until when `session` may use admin actions, if it still may
fn active_elevation(session: &Session) -> Option<Timestamp> {
    session
        .admin_elevated_until
        .filter(|until| elevation_active(Some(*until), Timestamp::now_utc()))
}

/// Fail unless `user` is an instance admin with an active elevation on `session`
async fn require_elevated_admin(user: &User, session: &Session) -> Result<()> {
    require_admin(user).await?;

    if session.user_id == user.id && active_elevation(session).is_some() {
        Ok(())
    } else {
        Err(create_error!(AdminElevationRequired))
    }
}

/// Target user of an admin action, bots have no sessions
async fn session_owner(db: &revolt_database::Database, id: &str) -> Result<User> {
    let user = db.fetch_user(id).await?;
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    Ok(user)
}

#[cfg(test)]
mod unit {
    use revolt_database::{BotInformation, User};

    use iso8601_timestamp::{Duration, Timestamp};

    use super::{elevation_active, is_admin};

    fn user(id: &str) -> User {
        User {
            id: id.to_string(),
            username: id.to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn configured_ids_and_privileged_users_are_admins() {
        let admins = vec!["A".to_string()];

        assert!(is_admin(&user("A"), &admins));
        assert!(!is_admin(&user("B"), &admins));
        assert!(!is_admin(&user("B"), &[]));

        let mut privileged = user("B");
        privileged.privileged = true;
        assert!(is_admin(&privileged, &[]));
    }

    #[test]
    fn bots_are_never_admins() {
        let mut bot = user("A");
        bot.privileged = true;
        bot.bot = Some(BotInformation {
            owner: "B".to_string(),
        });

        assert!(!is_admin(&bot, &["A".to_string()]));
    }

    #[test]
    fn elevation_expires() {
        let now = Timestamp::now_utc();
        let later = now.checked_add(Duration::minutes(60)).unwrap();
        let earlier = now.checked_sub(Duration::seconds(1)).unwrap();

        assert!(elevation_active(Some(later), now));
        assert!(!elevation_active(Some(earlier), now));
        assert!(!elevation_active(Some(now), now));
        assert!(!elevation_active(None, now));
    }
}
