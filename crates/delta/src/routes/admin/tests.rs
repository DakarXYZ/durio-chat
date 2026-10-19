//! Instance admins end sessions of other users (dur.io fork)
use std::time::Duration;

use iso8601_timestamp::{Duration as Span, Timestamp};
use revolt_database::{Account, PartialUser, Session, User, events::client::EventV1};
use revolt_models::v0;
use rocket::http::{Method, Status};

use super::super::e2ee::tests::{get, new_device, new_device_user, request};
use crate::util::test::{PubSubTestHelper, TestHarness};

/// New instance admin whose session may use admin actions (as after `POST /admin/elevate`)
pub(super) async fn new_admin(harness: &TestHarness) -> (Session, User) {
    let (_, session, user) = new_plain_admin(harness).await;
    let until = Timestamp::now_utc().checked_add(Span::minutes(60)).unwrap();
    harness
        .db
        .set_session_admin_elevation(&session.id, Some(until))
        .await
        .expect("elevation");

    (session, user)
}

/// New user with `privileged` set, i.e. an instance admin, without an elevation
pub(super) async fn new_plain_admin(harness: &TestHarness) -> (Account, Session, User) {
    let (account, session, mut user) = harness.new_user().await;
    user.update(
        &harness.db,
        PartialUser {
            privileged: Some(true),
            ..Default::default()
        },
        vec![],
    )
    .await
    .expect("privileged");

    (account, session, user)
}

/// Whether an event matching `predicate` arrives within 5 seconds
async fn saw_event<F: Fn(&EventV1) -> bool>(events: &mut PubSubTestHelper, predicate: F) -> bool {
    tokio::time::timeout(Duration::from_secs(5), events.wait_for_event(predicate))
        .await
        .is_ok()
}

async fn device_exists(harness: &TestHarness, device_id: &str) -> bool {
    harness.db.fetch_e2ee_device(device_id).await.is_ok()
}

async fn session_exists(harness: &TestHarness, session_id: &str) -> bool {
    harness.db.fetch_session(session_id).await.is_ok()
}

#[rocket::async_test]
async fn status_tells_admins_apart() {
    let harness = TestHarness::new().await;
    let (_, session, _) = harness.new_user().await;
    let (admin_session, _) = new_admin(&harness).await;

    let (status, body) = get(&harness, &session, "/admin/@me").await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["admin"], false);

    let (status, body) = get(&harness, &admin_session, "/admin/@me").await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["admin"], true);
}

#[rocket::async_test]
async fn non_admin_is_forbidden() {
    let harness = TestHarness::new().await;
    let (_, session, _) = harness.new_user().await;
    let (account, target_session, target) = new_device_user(&harness).await;
    let second = new_device(&harness, &account).await;

    let routes = [
        (Method::Get, format!("/admin/users?query={}", target.id)),
        (Method::Get, format!("/admin/users/{}/sessions", target.id)),
        (
            Method::Delete,
            format!("/admin/users/{}/sessions/{}", target.id, second.id),
        ),
        (
            Method::Delete,
            format!("/admin/users/{}/sessions", target.id),
        ),
    ];

    for (method, path) in routes {
        let (status, _) = request(&harness, method, &session, &path, None).await;
        assert_eq!(status, Status::Forbidden, "{method} {path}");
    }

    assert!(session_exists(&harness, &target_session.id).await);
    assert!(session_exists(&harness, &second.id).await);
    assert!(device_exists(&harness, &second.id).await);
}

#[rocket::async_test]
async fn find_user_by_id_or_username() {
    let harness = TestHarness::new().await;
    let (admin_session, _) = new_admin(&harness).await;
    let (_, _, target) = harness.new_user().await;

    let (status, body) = get(
        &harness,
        &admin_session,
        &format!("/admin/users?query={}", target.id),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let found: v0::AdminUser = serde_json::from_value(body).unwrap();
    assert_eq!(found.id, target.id);
    assert_eq!(found.username, target.username);
    assert!(!found.bot);

    // `#` must be percent-encoded in the query string, the name is case-insensitive
    let (status, body) = get(
        &harness,
        &admin_session,
        &format!(
            "/admin/users?query=%40{}%23{}",
            target.username.to_uppercase(),
            target.discriminator
        ),
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["_id"], target.id);

    for query in ["01ARZ3NDEKTSV4RRFFQ69G5FAV", "nobody%230000", "%20"] {
        let (status, _) = get(
            &harness,
            &admin_session,
            &format!("/admin/users?query={query}"),
        )
        .await;
        assert_eq!(status, Status::NotFound, "{query}");
    }
}

#[rocket::async_test]
async fn list_sessions_without_tokens() {
    let harness = TestHarness::new().await;
    let (admin_session, _) = new_admin(&harness).await;
    let (account, session, target) = harness.new_user().await;
    let second = account
        .create_session(&harness.db, "Phone".to_string())
        .await
        .unwrap();

    let (status, body) = get(
        &harness,
        &admin_session,
        &format!("/admin/users/{}/sessions", target.id),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let text = body.to_string();
    assert!(!text.contains(&session.token) && !text.contains(&second.token));

    let mut sessions: Vec<v0::SessionInfo> = serde_json::from_value(body).unwrap();
    sessions.sort_by(|a, b| a.id.cmp(&b.id));
    let mut expected = vec![session.id.clone(), second.id.clone()];
    expected.sort();
    assert_eq!(
        sessions.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
        expected
    );
    assert!(sessions.iter().any(|s| s.name == "Phone"));

    let (status, _) = get(&harness, &admin_session, "/admin/users/nobody/sessions").await;
    assert_eq!(status, Status::NotFound);
}

#[rocket::async_test]
async fn end_one_session() {
    let harness = TestHarness::new().await;
    let (admin_session, _) = new_admin(&harness).await;
    let (account, kept, target) = new_device_user(&harness).await;
    let lost = new_device(&harness, &account).await;

    // Session events go to the user's private topic `<id>!`
    let mut events = PubSubTestHelper::new(&target.id).await;
    let mut private = PubSubTestHelper::new(&format!("{}!", target.id)).await;
    let (status, _) = request(
        &harness,
        Method::Delete,
        &admin_session,
        &format!("/admin/users/{}/sessions/{}", target.id, lost.id),
        None,
    )
    .await;
    assert_eq!(status, Status::NoContent);

    // Same path as a logout: session and E2EE device gone, the device's sockets get Logout
    assert!(!session_exists(&harness, &lost.id).await);
    assert!(!device_exists(&harness, &lost.id).await);
    assert!(session_exists(&harness, &kept.id).await);
    assert!(device_exists(&harness, &kept.id).await);
    assert!(
        saw_event(&mut private, |event| matches!(
            event,
            EventV1::DeleteSession { session_id, .. } if session_id == &lost.id
        ))
        .await
    );
    assert!(
        saw_event(&mut events, |event| matches!(
            event,
            EventV1::E2eeDeviceListUpdate { user } if user == &target.id
        ))
        .await
    );
}

#[rocket::async_test]
async fn end_session_of_another_user_is_not_found() {
    let harness = TestHarness::new().await;
    let (admin_session, _) = new_admin(&harness).await;
    let (_, _, target) = harness.new_user().await;
    let (_, other_session, _) = harness.new_user().await;

    let (status, _) = request(
        &harness,
        Method::Delete,
        &admin_session,
        &format!("/admin/users/{}/sessions/{}", target.id, other_session.id),
        None,
    )
    .await;
    assert_eq!(status, Status::NotFound);
    assert!(session_exists(&harness, &other_session.id).await);
}

#[rocket::async_test]
async fn end_all_sessions() {
    let harness = TestHarness::new().await;
    let (admin_session, _) = new_admin(&harness).await;
    let (account, first, target) = new_device_user(&harness).await;
    let second = new_device(&harness, &account).await;

    let mut events = PubSubTestHelper::new(&target.id).await;
    let mut private = PubSubTestHelper::new(&format!("{}!", target.id)).await;
    let (status, _) = request(
        &harness,
        Method::Delete,
        &admin_session,
        &format!("/admin/users/{}/sessions", target.id),
        None,
    )
    .await;
    assert_eq!(status, Status::NoContent);

    for device in [&first.id, &second.id] {
        assert!(!session_exists(&harness, device).await);
        assert!(!device_exists(&harness, device).await);
    }
    assert!(
        harness
            .db
            .fetch_sessions(&target.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        saw_event(&mut private, |event| matches!(
            event,
            EventV1::DeleteAllSessions { user_id, exclude_session_id: None } if user_id == &target.id
        ))
        .await
    );
    assert!(
        saw_event(&mut events, |event| matches!(
            event,
            EventV1::E2eeDeviceListUpdate { user } if user == &target.id
        ))
        .await
    );

    // The admin's own session is untouched
    assert!(session_exists(&harness, &admin_session.id).await);
}

#[rocket::async_test]
async fn bots_have_no_sessions() {
    let harness = TestHarness::new().await;
    let (admin_session, admin) = new_admin(&harness).await;
    let (_, bot) = harness.new_bot(&admin).await;

    let (status, _) = request(
        &harness,
        Method::Delete,
        &admin_session,
        &format!("/admin/users/{}/sessions", bot.id),
        None,
    )
    .await;
    assert_eq!(status, Status::BadRequest);
}

#[rocket::async_test]
async fn admin_routes_in_openapi() {
    let harness = TestHarness::new().await;
    let response = harness.client.get("/openapi.json").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let spec: serde_json::Value =
        serde_json::from_str(&response.into_string().await.unwrap()).unwrap();

    let routes = [
        ("get", "/admin/@me"),
        ("get", "/admin/users"),
        ("get", "/admin/users/{target}/sessions"),
        ("delete", "/admin/users/{target}/sessions/{session}"),
        ("delete", "/admin/users/{target}/sessions"),
        ("post", "/admin/elevate"),
        ("delete", "/admin/elevate"),
    ];
    for (method, path) in routes {
        assert!(spec["paths"][path][method].is_object(), "{method} {path}");
        assert_eq!(spec["paths"][path][method]["tags"][0], "Admin");
    }

    for schema in ["AdminStatus", "AdminUser", "AdminElevation"] {
        assert!(
            spec["components"]["schemas"][schema].is_object(),
            "{schema}"
        );
    }
    let schemas = &spec["components"]["schemas"];
    assert!(schemas["AdminStatus"]["properties"]["elevated_until"].is_object());
    assert!(schemas["AdminElevation"]["properties"]["expires_at"].is_object());

    // `POST /admin/elevate` takes the MFA ticket header
    let security = spec["paths"]["/admin/elevate"]["post"]["security"].to_string();
    assert!(security.contains("MFA Ticket"), "{security}");

    let errors = schemas["Error"].to_string();
    for error in ["TotpRequired", "AdminElevationRequired"] {
        assert!(errors.contains(&format!("\"{error}\"")), "{error}");
    }
}
