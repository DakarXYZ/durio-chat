//! Create a new account
//! POST /account/create
use std::time::Duration;

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

    // If required, claim a valid invite: each one works once (dur.io fork), concurrent
    // registrations with the same code cannot both get past this
    let invite = if config().await.api.registration.invite_only {
        if let Some(invite) = data.invite {
            db.claim_account_invite(&invite).await?;
            Some(invite)
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
            if let Some(invite) = &invite {
                db.release_account_invite(invite).await.ok();
            }

            return Err(error);
        }
    };

    // Record who used up the invite
    if let Some(id) = invite {
        db.save_account_invite(&AccountInvite {
            id,
            used: true,
            claimed_by: Some(account.id),
        })
        .await?;
    }

    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_config::overwrite_config;
    use revolt_database::{events::client::EventV1, AccountInvite};
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
}
