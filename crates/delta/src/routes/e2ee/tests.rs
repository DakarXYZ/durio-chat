//! Helpers and cross-route tests for `/e2ee`
use revolt_database::{Account, Channel, Session, User};
use revolt_models::v0::e2ee_user_id;
use revolt_result::{Error, ErrorType};
use rocket::http::{ContentType, Header, Method, Status};
use serde_json::{Value, json};

use crate::util::test::TestHarness;

/// Send a request as `session`, returns the status and the JSON body (`null` if empty)
pub async fn request(
    harness: &TestHarness,
    method: Method,
    session: &Session,
    path: &str,
    body: Option<Value>,
) -> (Status, Value) {
    let mut request = harness
        .client
        .req(method, path.to_string())
        .header(Header::new("x-session-token", session.token.clone()));

    if let Some(body) = body {
        request = request.header(ContentType::JSON).body(body.to_string());
    }

    let response = request.dispatch().await;
    let status = response.status();
    let body = response
        .into_string()
        .await
        .filter(|body| !body.is_empty())
        .map(|body| serde_json::from_str(&body).unwrap_or(Value::String(body)))
        .unwrap_or(Value::Null);

    (status, body)
}

pub async fn post(
    harness: &TestHarness,
    session: &Session,
    path: &str,
    body: Value,
) -> (Status, Value) {
    request(harness, Method::Post, session, path, Some(body)).await
}

pub async fn get(harness: &TestHarness, session: &Session, path: &str) -> (Status, Value) {
    request(harness, Method::Get, session, path, None).await
}

/// Error type of an error response body
pub fn error_type(body: Value) -> ErrorType {
    serde_json::from_value::<Error>(body)
        .expect("error body")
        .error_type
}

/// Signed device keys of a device (fake key material, the server does not verify it)
pub fn device_keys(user_id: &str, device_id: &str) -> Value {
    let user = e2ee_user_id(user_id);
    json!({
        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
        "device_id": device_id,
        "keys": {
            format!("curve25519:{device_id}"): format!("curve-{device_id}"),
            format!("ed25519:{device_id}"): format!("ed-{device_id}")
        },
        "signatures": {
            user.clone(): { format!("ed25519:{device_id}"): "signature" }
        },
        "user_id": user
    })
}

/// Signed key as uploaded by a client
pub fn signed_key(user_id: &str, device_id: &str, key: &str, fallback: bool) -> Value {
    let mut signed = json!({
        "key": key,
        "signatures": {
            e2ee_user_id(user_id): { format!("ed25519:{device_id}"): "signature" }
        }
    });

    if fallback {
        signed["fallback"] = json!(true);
    }

    signed
}

/// `count` one-time keys with ids `<prefix><n>`
pub fn one_time_keys(user_id: &str, device_id: &str, prefix: &str, count: usize) -> Value {
    Value::Object(
        (0..count)
            .map(|n| {
                (
                    format!("signed_curve25519:{prefix}{n}"),
                    signed_key(user_id, device_id, &format!("otk-{prefix}{n}"), false),
                )
            })
            .collect(),
    )
}

/// Fallback key with id `key_id`
pub fn fallback_keys(user_id: &str, device_id: &str, key_id: &str) -> Value {
    json!({
        format!("signed_curve25519:{key_id}"):
            signed_key(user_id, device_id, &format!("fallback-{key_id}"), true)
    })
}

/// Upload device keys of a session
pub async fn upload_device(harness: &TestHarness, session: &Session) {
    let (status, _) = post(
        harness,
        session,
        "/e2ee/keys/upload",
        json!({ "device_keys": device_keys(&session.user_id, &session.id) }),
    )
    .await;
    assert_eq!(status, Status::Ok);
}

/// New user whose session has device keys
pub async fn new_device_user(harness: &TestHarness) -> (Account, Session, User) {
    let (account, session, user) = harness.new_user().await;
    upload_device(harness, &session).await;
    (account, session, user)
}

/// Another session of an account, with device keys
pub async fn new_device(harness: &TestHarness, account: &Account) -> Session {
    let session = account
        .create_session(&harness.db, String::new())
        .await
        .expect("`Session`");
    upload_device(harness, &session).await;
    session
}

/// Direct message between two users, makes their devices visible to each other
#[allow(clippy::disallowed_methods)]
pub async fn direct_message(harness: &TestHarness, a: &User, b: &User) {
    harness
        .db
        .insert_channel(&Channel::DirectMessage {
            id: ulid::Ulid::new().to_string(),
            active: true,
            recipients: vec![a.id.clone(), b.id.clone()],
            last_message_id: None,
            encryption: None,
        })
        .await
        .expect("`Channel`");
}

/// Every `/e2ee` route with a valid body
fn all_routes(user_id: &str, device_id: &str) -> Vec<(Method, String, Option<Value>)> {
    vec![
        (
            Method::Post,
            "/e2ee/keys/upload".to_string(),
            Some(json!({ "device_keys": device_keys(user_id, device_id) })),
        ),
        (
            Method::Post,
            "/e2ee/keys/query".to_string(),
            Some(json!({ "device_keys": { e2ee_user_id(user_id): [] } })),
        ),
        (
            Method::Post,
            "/e2ee/keys/claim".to_string(),
            Some(json!({
                "one_time_keys": { e2ee_user_id(user_id): { device_id: "signed_curve25519" } }
            })),
        ),
        (Method::Get, "/e2ee/keys/count".to_string(), None),
    ]
}

/// Bots have no session, hence no device
#[rocket::async_test]
async fn bots_rejected() {
    let harness = TestHarness::new().await;
    let (_, _, user) = harness.new_user().await;
    let (bot, bot_user) = harness.new_bot(&user).await;

    for (method, path, body) in all_routes(&bot_user.id, "BOTDEVICE") {
        let mut request = harness
            .client
            .req(method, path.clone())
            .header(Header::new("x-bot-token", bot.token.clone()));

        if let Some(body) = body {
            request = request.header(ContentType::JSON).body(body.to_string());
        }

        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::BadRequest, "{method} {path}");
    }
}

/// Without a session every route fails
#[rocket::async_test]
async fn unauthenticated() {
    let harness = TestHarness::new().await;

    for (method, path, body) in all_routes("01KAAAAAAAAAAAAAAAAAAAAAAA", "DEVICE") {
        let mut request = harness.client.req(method, path.clone());
        if let Some(body) = body {
            request = request.header(ContentType::JSON).body(body.to_string());
        }

        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Unauthorized, "{method} {path}");
    }
}

/// With `features.e2ee.enabled = false` every route is missing
#[rocket::async_test]
async fn disabled() {
    revolt_config::overwrite_config(|config| config.features.e2ee.enabled = false).await;

    let harness = TestHarness::new().await;
    let (_, session, user) = harness.new_user().await;

    for (method, path, body) in all_routes(&user.id, &session.id) {
        // Guard failures go to the default catcher, only the status is kept
        let (status, _) = request(&harness, method, &session, &path, body).await;
        assert_eq!(status, Status::NotFound, "{method} {path}");
    }
}
