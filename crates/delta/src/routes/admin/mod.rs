//! Instance administration from the client (dur.io fork)
//!
//! Admins are the users listed in `[api.admins] users` and users with `privileged` set.
//! They can find any user and end their sessions, e.g. after a lost phone. Every action
//! is logged with the admin's id; tokens never leave the server.
use revolt_config::config;
use revolt_database::User;
use revolt_result::{Result, create_error};
use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod find_user;
mod session_revoke;
mod sessions_fetch;
mod sessions_revoke_all;
mod status;

#[cfg(test)]
mod tests;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        status::status,
        find_user::find_user,
        sessions_fetch::fetch_sessions,
        session_revoke::revoke_session,
        sessions_revoke_all::revoke_all_sessions
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

    use super::is_admin;

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
}
