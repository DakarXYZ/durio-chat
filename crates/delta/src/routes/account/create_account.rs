//! Create a new account
//! POST /account/create
use std::time::Duration;

use iso8601_timestamp::Timestamp;
use tokio::time::sleep;
use revolt_config::config;
use revolt_database::{
    util::{
        captcha::check_captcha,
        email::validate_email,
        password::assert_safe,
        shield::{validate_shield, ShieldValidationInput},
    },
    Account, AccountInvite, Database,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Create Account
///
/// Create a new account.
#[openapi(tag = "Account")]
#[post("/create", data = "<data>")]
pub async fn create_account(
    db: &State<Database>,
    data: Json<v0::DataCreateAccount>,
    mut shield: ShieldValidationInput,
) -> Result<EmptyResponse> {
    let data = data.into_inner();

    // Random jitter from 0-1000ms
    sleep(Duration::from_millis((rand::random::<f32>() * 1000.) as u64)).await;

    // Check Captcha token
    check_captcha(data.captcha.as_deref()).await?;

    // Validate the request
    shield.email = Some(data.email.to_string());
    validate_shield(shield).await?;

    // Make sure email is valid and not blocked
    validate_email(&data.email)?;

    // Ensure password is safe to use
    assert_safe(&data.password).await?;

    // If required, take a valid invite (dur.io fork). An invite to a server or group works
    // too: friends get one link, `/invite/<code>`, sign up with it and then join with it
    // (joining counts its use, signing up does not). Otherwise an account invite: an expired
    // one is refused; a single-use one is claimed, so concurrent registrations with the same
    // code cannot both get past this; a multi-use one is only counted once the account exists
    let invite = if config().await.api.registration.invite_only {
        if let Some(invite) = data.invite {
            match db.fetch_invite(&invite).await {
                Ok(server_invite) => {
                    if !server_invite.is_usable(Timestamp::now_utc()) {
                        return Err(create_error!(InvalidInvite));
                    }

                    None
                }
                Err(_) => {
                    let invite = db.fetch_account_invite(&invite).await?;
                    if invite.is_expired(Timestamp::now_utc()) {
                        return Err(create_error!(InvalidInvite));
                    }

                    if !invite.multi_use {
                        db.claim_account_invite(&invite.id).await?;
                    }

                    Some(invite)
                }
            }
        } else {
            return Err(create_error!(MissingInvite));
        }
    } else {
        None
    };

    // Create account
    let account = match Account::new(db, data.email, data.password, true).await {
        Ok(account) => account,
        Err(error) => {
            if let Some(invite) = invite.as_ref().filter(|invite| !invite.multi_use) {
                db.release_account_invite(&invite.id).await.ok();
            }

            return Err(error);
        }
    };

    // Count the use of a multi-use invite, or record who used up a single-use one
    if let Some(invite) = invite {
        if invite.multi_use {
            db.count_account_invite_use(&invite.id).await?;
        } else {
            db.save_account_invite(&AccountInvite {
                used: true,
                claimed_by: Some(account.id),
                ..invite
            })
            .await?;
        }
    }

    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_config::overwrite_config;
    use iso8601_timestamp::{Duration as Span, Timestamp};
    use revolt_database::{events::client::EventV1, AccountInvite, Invite};
    use revolt_result::{Error, ErrorType};
    use rocket::http::{ContentType, Status};
    use crate::util::test::PubSubTestHelper;

    #[rocket::async_test]
    async fn success() {
        let harness = TestHarness::new().await;
        let mut pubsub = PubSubTestHelper::new("global").await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "success@validemail.com",
                    "password": "valid password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
        drop(res);

        pubsub
            .wait_for_event(|event| match event {
                EventV1::CreateAccount { account } => account.email == "success@validemail.com",
                _ => false,
            }).await;
    }

    #[rocket::async_test]
    async fn fail_invalid_email() {
        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "invalid",
                    "password": "valid password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::IncorrectData { .. },
        ));
    }

    #[rocket::async_test]
    async fn fail_invalid_password() {
        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "fail_invalid_password@validemail.com",
                    "password": "password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::CompromisedPassword,
        ));
    }

    #[rocket::async_test]
    async fn fail_invalid_invite() {
        overwrite_config(|config| config.api.registration.invite_only = true).await;

        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "fail_invalid_invite@validemail.com",
                    "password": "valid password",
                    "invite": "invalid"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidInvite,
        ));
    }

    #[rocket::async_test]
    async fn success_valid_invite() {
        overwrite_config(|config| config.api.registration.invite_only = true).await;

        let harness = TestHarness::new().await;

        let invite = AccountInvite {
            id: "invite".to_string(),
            used: false,
            claimed_by: None,
            ..Default::default()
        };

        invite.save(&harness.db).await.unwrap();

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "success_valid_invite@validemail.com",
                    "password": "valid password",
                    "invite": "invite"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let invite = harness
            .db
            .fetch_account_invite("invite")
            .await
            .expect("`Invite`");

        assert!(invite.used);
    }

    /// dur.io: a server invite lets a friend sign up on an invite-only server; signing up does
    /// not count a use, joining does
    #[rocket::async_test]
    async fn success_server_invite() {
        overwrite_config(|config| config.api.registration.invite_only = true).await;

        let harness = TestHarness::new().await;

        harness
            .db
            .insert_invite(&Invite::Server {
                code: "srvinvite".to_string(),
                server: "server".to_string(),
                creator: "creator".to_string(),
                channel: "channel".to_string(),
                max_uses: Some(1),
                uses: 0,
                expires: None,
            })
            .await
            .unwrap();

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "success_server_invite@validemail.com",
                    "password": "valid password",
                    "invite": "srvinvite"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let invite = harness.db.fetch_invite("srvinvite").await.expect("`Invite`");
        assert!(matches!(invite, Invite::Server { uses: 0, .. }));
    }

    /// dur.io: an expired or used-up server invite is refused like an unknown code
    #[rocket::async_test]
    async fn fail_server_invite_used_up() {
        overwrite_config(|config| config.api.registration.invite_only = true).await;

        let harness = TestHarness::new().await;

        let past = Timestamp::now_utc().checked_add(Span::seconds(-60)).unwrap();
        for (code, max_uses, uses, expires) in [
            ("srvused", Some(2), 2, None),
            ("srvexpired", None, 0, Some(past)),
        ] {
            harness
                .db
                .insert_invite(&Invite::Server {
                    code: code.to_string(),
                    server: "server".to_string(),
                    creator: "creator".to_string(),
                    channel: "channel".to_string(),
                    max_uses,
                    uses,
                    expires,
                })
                .await
                .unwrap();

            let res = harness
                .client
                .post("/auth/account/create")
                .header(ContentType::JSON)
                .body(
                    json!({
                        "email": format!("fail_{code}@validemail.com"),
                        "password": "valid password",
                        "invite": code
                    })
                    .to_string(),
                )
                .dispatch()
                .await;

            assert_eq!(res.status(), Status::BadRequest, "{code}");
            assert!(matches!(
                res.into_json::<Error>().await.unwrap().error_type,
                ErrorType::InvalidInvite,
            ));
        }
    }

    #[rocket::async_test]
    async fn fail_missing_captcha() {
        overwrite_config(|config| {
            config.api.security.captcha.hcaptcha_key =
                "0x0000000000000000000000000000000000000000".to_string()
        })
        .await;

        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "fail_missing_captcha@validemail.com",
                    "password": "valid password",
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::CaptchaFailed,
        ));
    }

    #[rocket::async_test]
    async fn fail_captcha_invalid() {
        overwrite_config(|config| {
            config.api.security.captcha.hcaptcha_key =
                "0x0000000000000000000000000000000000000000".to_string()
        })
        .await;

        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "fail_captcha_invalid@validemail.com",
                    "password": "valid password",
                    "captcha": "00000000-aaaa-bbbb-cccc-000000000000"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::CaptchaFailed,
        ));
    }

    #[rocket::async_test]
    async fn success_captcha_valid() {
        overwrite_config(|config| {
            config.api.security.captcha.hcaptcha_key =
                "0x0000000000000000000000000000000000000000".to_string()
        })
        .await;

        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "success_captcha_valid@validemail.com",
                    "password": "valid password",
                    "captcha": "20000000-aaaa-bbbb-cccc-000000000002"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
    }

    #[rocket::async_test]
    async fn success_smtp_sent() {
        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "success_smtp_sent@smtp.test",
                    "password": "valid password",
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let (_, code) = harness.assert_email("success_smtp_sent@smtp.test").await;
        let res = harness
            .client
            .post(format!("/auth/account/verify/{code}"))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
    }

    /// Sign up with `invite`, the error type if it failed (dur.io fork)
    async fn register(harness: &TestHarness, email: &str, invite: &str) -> Option<ErrorType> {
        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": email,
                    "password": "valid password",
                    "invite": invite
                })
                .to_string(),
            )
            .dispatch()
            .await;

        if res.status() == Status::NoContent {
            None
        } else {
            assert_eq!(res.status(), Status::BadRequest);
            Some(res.into_json::<Error>().await.unwrap().error_type)
        }
    }

    /// Invites required; no SMTP, so accounts are made without a verification email
    fn invite_only_without_email(config: &mut revolt_config::Settings) {
        config.api.registration.invite_only = true;
        config.api.smtp.host = String::new();
    }

    async fn new_invite(harness: &TestHarness) -> String {
        let invite = AccountInvite {
            id: TestHarness::rand_string(),
            used: false,
            claimed_by: None,
            ..Default::default()
        };
        invite.save(&harness.db).await.unwrap();
        invite.id
    }

    async fn account_id(harness: &TestHarness, email: &str) -> String {
        harness
            .db
            .fetch_account_by_normalised_email(email)
            .await
            .unwrap()
            .expect("account")
            .id
    }

    #[rocket::async_test]
    async fn invite_works_once() {
        overwrite_config(invite_only_without_email).await;
        let harness = TestHarness::new().await;
        let code = new_invite(&harness).await;

        assert!(
            register(&harness, "invite_once_a@validemail.com", &code)
                .await
                .is_none()
        );
        let first = account_id(&harness, "invite_once_a@validemail.com").await;
        let invite = harness.db.fetch_account_invite(&code).await.unwrap();
        assert!(invite.used);
        assert_eq!(invite.claimed_by, Some(first.clone()));

        // A used invite is refused like an unknown one, and no account is made
        assert!(matches!(
            register(&harness, "invite_once_b@validemail.com", &code).await,
            Some(ErrorType::InvalidInvite)
        ));
        assert!(
            harness
                .db
                .fetch_account_by_normalised_email("invite_once_b@validemail.com")
                .await
                .unwrap()
                .is_none()
        );
        let invite = harness.db.fetch_account_invite(&code).await.unwrap();
        assert_eq!(invite.claimed_by, Some(first));
    }

    #[rocket::async_test]
    async fn invite_used_before() {
        overwrite_config(|config| config.api.registration.invite_only = true).await;
        let harness = TestHarness::new().await;
        let invite = AccountInvite {
            id: TestHarness::rand_string(),
            used: true,
            claimed_by: None,
            ..Default::default()
        };
        invite.save(&harness.db).await.unwrap();

        assert!(matches!(
            register(&harness, "invite_used_before@validemail.com", &invite.id).await,
            Some(ErrorType::InvalidInvite)
        ));
    }

    #[rocket::async_test]
    async fn concurrent_registrations_share_no_invite() {
        overwrite_config(invite_only_without_email).await;
        let harness = TestHarness::new().await;
        let code = new_invite(&harness).await;

        let emails: Vec<String> = (0..4)
            .map(|i| format!("invite_race_{i}@validemail.com"))
            .collect();
        let results =
            futures::future::join_all(emails.iter().map(|email| register(&harness, email, &code)))
                .await;

        assert_eq!(results.iter().filter(|result| result.is_none()).count(), 1);
        assert!(
            results
                .iter()
                .flatten()
                .all(|error| matches!(error, ErrorType::InvalidInvite))
        );

        let winner = emails
            .iter()
            .zip(&results)
            .find(|(_, result)| result.is_none())
            .map(|(email, _)| email)
            .unwrap();
        let invite = harness.db.fetch_account_invite(&code).await.unwrap();
        assert_eq!(invite.claimed_by, Some(account_id(&harness, winner).await));
    }

    #[rocket::async_test]
    async fn invite_claims_are_atomic() {
        let harness = TestHarness::new().await;
        let code = new_invite(&harness).await;

        let claims =
            futures::future::join_all((0..8).map(|_| harness.db.claim_account_invite(&code))).await;
        assert_eq!(claims.iter().filter(|claim| claim.is_ok()).count(), 1);
        assert!(
            claims
                .iter()
                .filter_map(|claim| claim.as_ref().err())
                .all(|error| matches!(error.error_type, ErrorType::InvalidInvite))
        );
        assert!(matches!(
            harness
                .db
                .claim_account_invite("unknown")
                .await
                .unwrap_err()
                .error_type,
            ErrorType::InvalidInvite
        ));

        // A released claim (account creation failed) makes the invite usable again
        harness.db.release_account_invite(&code).await.unwrap();
        let invite = harness.db.fetch_account_invite(&code).await.unwrap();
        assert!(!invite.used && invite.claimed_by.is_none());
        assert!(harness.db.claim_account_invite(&code).await.is_ok());
    }

    /// Invite as made by an admin in the app, expiring in `ttl` (negative: already expired)
    async fn app_invite(harness: &TestHarness, multi_use: bool, ttl: Span) -> String {
        let now = Timestamp::now_utc();
        let invite = AccountInvite {
            id: TestHarness::rand_string(),
            expires_at: Some(now.checked_add(ttl).unwrap()),
            multi_use,
            created_by: Some("admin".to_string()),
            created_at: Some(now),
            ..Default::default()
        };
        invite.save(&harness.db).await.unwrap();
        invite.id
    }

    #[rocket::async_test]
    async fn expired_invites_are_refused() {
        overwrite_config(invite_only_without_email).await;
        let harness = TestHarness::new().await;

        for multi_use in [false, true] {
            let code = app_invite(&harness, multi_use, Span::seconds(-1)).await;
            let email = format!("invite_expired_{multi_use}@validemail.com");
            assert!(matches!(
                register(&harness, &email, &code).await,
                Some(ErrorType::InvalidInvite)
            ));
            assert!(
                harness
                    .db
                    .fetch_account_by_normalised_email(&email)
                    .await
                    .unwrap()
                    .is_none()
            );

            let invite = harness.db.fetch_account_invite(&code).await.unwrap();
            assert!(!invite.used && invite.uses == 0);
        }
    }

    #[rocket::async_test]
    async fn single_use_app_invite_works_once() {
        overwrite_config(invite_only_without_email).await;
        let harness = TestHarness::new().await;
        let code = app_invite(&harness, false, Span::hours(1)).await;

        assert!(
            register(&harness, "invite_app_once_a@validemail.com", &code)
                .await
                .is_none()
        );
        assert!(matches!(
            register(&harness, "invite_app_once_b@validemail.com", &code).await,
            Some(ErrorType::InvalidInvite)
        ));

        // Claiming keeps the rest of the invite
        let invite = harness.db.fetch_account_invite(&code).await.unwrap();
        assert!(invite.used && invite.expires_at.is_some() && invite.created_by.is_some());
        assert_eq!(
            invite.claimed_by,
            Some(account_id(&harness, "invite_app_once_a@validemail.com").await)
        );
    }

    #[rocket::async_test]
    async fn multi_use_invite_counts_accounts() {
        overwrite_config(invite_only_without_email).await;
        let harness = TestHarness::new().await;
        let code = app_invite(&harness, true, Span::hours(1)).await;

        for i in 0..3 {
            assert!(
                register(&harness, &format!("invite_multi_{i}@validemail.com"), &code)
                    .await
                    .is_none()
            );
        }

        let invite = harness.db.fetch_account_invite(&code).await.unwrap();
        assert_eq!(invite.uses, 3);
        assert!(!invite.used && invite.claimed_by.is_none());

        // A multi-use invite is never claimed like a single-use one
        assert!(matches!(
            harness
                .db
                .claim_account_invite(&code)
                .await
                .unwrap_err()
                .error_type,
            ErrorType::InvalidInvite
        ));
    }

    #[rocket::async_test]
    async fn concurrent_registrations_count_every_use() {
        overwrite_config(invite_only_without_email).await;
        let harness = TestHarness::new().await;
        let code = app_invite(&harness, true, Span::hours(1)).await;

        let emails: Vec<String> = (0..5)
            .map(|i| format!("invite_multi_race_{i}@validemail.com"))
            .collect();
        let results =
            futures::future::join_all(emails.iter().map(|email| register(&harness, email, &code)))
                .await;
        assert!(results.iter().all(|result| result.is_none()));

        let invite = harness.db.fetch_account_invite(&code).await.unwrap();
        assert_eq!(invite.uses, 5);

        // The increments themselves are atomic
        futures::future::join_all((0..8).map(|_| harness.db.count_account_invite_use(&code)))
            .await
            .into_iter()
            .for_each(|result| result.unwrap());
        let invite = harness.db.fetch_account_invite(&code).await.unwrap();
        assert_eq!(invite.uses, 13);
    }
}
