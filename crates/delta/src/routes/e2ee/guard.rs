//! Request guard shared by all `/e2ee` routes
use revolt_config::config;
use revolt_database::{Session, User};
use revolt_result::{Error, ErrorType, Result, create_error};
use revolt_rocket_okapi::{
    r#gen::OpenApiGenerator,
    request::{OpenApiFromRequest, RequestHeaderInput},
    revolt_okapi::openapi3::{SecurityScheme, SecuritySchemeData},
};
use rocket::{
    Request,
    http::Status,
    request::{FromRequest, Outcome},
};

/// User and session (= E2EE device) of a request to `/e2ee`
///
/// Fails with `E2eeDisabled` when `features.e2ee.enabled` is off, `IsBot` for bots
/// (bots have no session, hence no device) and `InvalidSession` without a session.
pub struct E2eeSession {
    pub user: User,
    pub session: Session,
}

impl E2eeSession {
    /// Device id of this request
    pub fn device_id(&self) -> &str {
        &self.session.id
    }
}

/// Decide the outcome from what the request carries
fn authorise(enabled: bool, user: Option<User>, session: Option<Session>) -> Result<E2eeSession> {
    if !enabled {
        return Err(create_error!(E2eeDisabled));
    }

    let user = user.ok_or_else(|| create_error!(InvalidSession))?;
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    match session {
        Some(session) if session.user_id == user.id => Ok(E2eeSession { user, session }),
        _ => Err(create_error!(InvalidSession)),
    }
}

fn status(error: &Error) -> Status {
    match error.error_type {
        ErrorType::E2eeDisabled => Status::NotFound,
        ErrorType::IsBot => Status::BadRequest,
        _ => Status::Unauthorized,
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for E2eeSession {
    type Error = Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let enabled = config().await.features.e2ee.enabled;

        // Both guards are cached per request, no extra database queries
        let (user, session) = if enabled {
            let user = request.guard::<User>().await.succeeded();
            let session = match &user {
                Some(user) if user.bot.is_none() => request.guard::<Session>().await.succeeded(),
                _ => None,
            };

            (user, session)
        } else {
            (None, None)
        };

        match authorise(enabled, user, session) {
            Ok(e2ee) => Outcome::Success(e2ee),
            Err(error) => Outcome::Error((status(&error), error)),
        }
    }
}

impl<'r> OpenApiFromRequest<'r> for E2eeSession {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> revolt_rocket_okapi::Result<RequestHeaderInput> {
        let mut requirements = schemars::Map::new();
        requirements.insert("Session Token".to_owned(), vec![]);

        Ok(RequestHeaderInput::Security(
            "Session Token".to_owned(),
            SecurityScheme {
                data: SecuritySchemeData::ApiKey {
                    name: "x-session-token".to_owned(),
                    location: "header".to_owned(),
                },
                description: Some("Used to authenticate as a user.".to_owned()),
                extensions: schemars::Map::new(),
            },
            requirements,
        ))
    }
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::Timestamp;
    use revolt_database::{Bot, Database, DatabaseInfo, Session, User};
    use revolt_result::ErrorType;
    use rocket::{
        http::{Header, Status},
        local::asynchronous::Client,
    };

    use super::{E2eeSession, authorise};

    #[rocket::get("/probe")]
    fn probe(e2ee: E2eeSession) -> String {
        format!("{} {}", e2ee.user.id, e2ee.device_id())
    }

    fn session(user: &User) -> Session {
        Session {
            id: ulid::Ulid::new().to_string(),
            user_id: user.id.clone(),
            token: format!("token-{}", user.id),
            name: "test".to_string(),
            last_seen: Timestamp::now_utc(),
            origin: None,
            subscription: None,
            admin_elevated_until: None,
        }
    }

    fn error(result: revolt_result::Result<E2eeSession>) -> ErrorType {
        result.err().expect("should fail").error_type
    }

    #[test]
    fn decisions() {
        let user = User {
            id: "U".to_string(),
            ..Default::default()
        };
        let bot = User {
            id: "B".to_string(),
            bot: Some(revolt_database::BotInformation {
                owner: "U".to_string(),
            }),
            ..Default::default()
        };

        let ok = authorise(true, Some(user.clone()), Some(session(&user))).unwrap();
        assert_eq!(ok.user.id, "U");

        assert!(matches!(
            error(authorise(false, Some(user.clone()), Some(session(&user)))),
            ErrorType::E2eeDisabled
        ));
        assert!(matches!(
            error(authorise(true, Some(bot.clone()), None)),
            ErrorType::IsBot
        ));
        assert!(matches!(
            error(authorise(true, None, None)),
            ErrorType::InvalidSession
        ));
        assert!(matches!(
            error(authorise(true, Some(user.clone()), None)),
            ErrorType::InvalidSession
        ));
        assert!(matches!(
            error(authorise(true, Some(user), Some(session(&bot)))),
            ErrorType::InvalidSession
        ));
    }

    /// Through Rocket with the test config (`features.e2ee.enabled = true`)
    #[rocket::async_test]
    async fn guard() {
        let db = DatabaseInfo::Test(format!("revolt_test_e2ee_guard_{}", ulid::Ulid::new()))
            .connect()
            .await
            .expect("Database connection failed.");

        let user = User::create(&db, "e2eeguard".to_string(), None, None)
            .await
            .unwrap();
        let session = session(&user);
        db.save_session(&session).await.unwrap();
        let (bot, _) = Bot::create(&db, "e2eeguardbot".to_string(), &user, None)
            .await
            .unwrap();

        let rocket = rocket::build()
            .manage::<Database>(db.clone())
            .mount("/", rocket::routes![probe]);
        let client = Client::tracked(rocket).await.unwrap();

        let response = client
            .get("/probe")
            .header(Header::new("x-session-token", session.token.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_string().await.unwrap(),
            format!("{} {}", user.id, session.id)
        );

        let response = client
            .get("/probe")
            .header(Header::new("x-bot-token", bot.token.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        let response = client.get("/probe").dispatch().await;
        assert_eq!(response.status(), Status::Unauthorized);

        let response = client
            .get("/probe")
            .header(Header::new("x-session-token", "wrong"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized);
    }
}
