//! Admin actions need 2FA: an elevation of the session with an MFA ticket (dur.io fork)
use iso8601_timestamp::{Duration as Span, Timestamp};
use revolt_database::{Account, MFATicket, Session, Totp, User};
use revolt_models::v0;
use revolt_result::ErrorType;
use rocket::http::{Header, Method, Status};
use serde_json::{Value, json};

use super::super::e2ee::tests::{error_type, get, request, request_with};
use super::tests::{new_admin, new_plain_admin};
use crate::util::test::TestHarness;

const TOTP_SECRET: &str = "secret";

/// Turn on an authenticator app for `account`
async fn enable_totp(harness: &TestHarness, account: &mut Account) {
    account.mfa.totp_token = Totp::Enabled {
        secret: TOTP_SECRET.to_string(),
    };
    account.save(&harness.db).await.unwrap();
}

/// Ticket validated with a TOTP code, the real `PUT /auth/mfa/ticket` flow
async fn totp_ticket(harness: &TestHarness, session: &Session) -> String {
    let code = Totp::Enabled {
        secret: TOTP_SECRET.to_string(),
    }
    .generate_code()
    .unwrap();
    let (status, body) = request(
        harness,
        Method::Put,
        session,
        "/auth/mfa/ticket",
        Some(json!({ "totp_code": code })),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let ticket: v0::MFATicket = serde_json::from_value(body).unwrap();
    assert!(ticket.validated);
    ticket.token
}

async fn elevate(
    harness: &TestHarness,
    session: &Session,
    ticket: Option<&str>,
) -> (Status, Value) {
    let headers = ticket
        .map(|ticket| vec![Header::new("x-mfa-ticket", ticket.to_string())])
        .unwrap_or_default();
    request_with(
        harness,
        Method::Post,
        session,
        "/admin/elevate",
        None,
        headers,
    )
    .await
}

async fn elevated_until(harness: &TestHarness, session: &Session) -> Option<Timestamp> {
    harness
        .db
        .fetch_session(&session.id)
        .await
        .unwrap()
        .admin_elevated_until
}

/// Whether `session` may use the admin routes; refusals must be `AdminElevationRequired`
async fn admin_routes_allowed(harness: &TestHarness, session: &Session, target: &User) -> bool {
    let routes = [
        format!("/admin/users?query={}", target.id),
        format!("/admin/users/{}/sessions", target.id),
    ];

    let mut allowed = true;
    for path in routes {
        let (status, body) = get(harness, session, &path).await;
        if status != Status::Ok {
            assert_eq!(status, Status::Forbidden, "{path}");
            assert!(matches!(
                error_type(body),
                ErrorType::AdminElevationRequired
            ));
            allowed = false;
        }
    }

    allowed
}

#[rocket::async_test]
async fn status_shows_the_elevation() {
    let harness = TestHarness::new().await;
    let (elevated, _) = new_admin(&harness).await;
    let (_, plain, _) = new_plain_admin(&harness).await;

    let (status, body) = get(&harness, &elevated, "/admin/@me").await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["admin"], true);
    let status: v0::AdminStatus = serde_json::from_value(body).unwrap();
    assert!(status.elevated_until.is_some());

    let (_, body) = get(&harness, &plain, "/admin/@me").await;
    assert_eq!(body, json!({ "admin": true }));
}

#[rocket::async_test]
async fn elevate_with_totp_ticket() {
    let harness = TestHarness::new().await;
    let (mut account, session, _) = new_plain_admin(&harness).await;
    let (target_account, _, target) = harness.new_user().await;
    let kept = target_account
        .create_session(&harness.db, "Phone".to_string())
        .await
        .unwrap();
    enable_totp(&harness, &mut account).await;

    // Without an elevation every admin action is refused, also ending sessions
    assert!(!admin_routes_allowed(&harness, &session, &target).await);
    for path in [
        format!("/admin/users/{}/sessions/{}", target.id, kept.id),
        format!("/admin/users/{}/sessions", target.id),
    ] {
        let (status, body) = request(&harness, Method::Delete, &session, &path, None).await;
        assert_eq!(status, Status::Forbidden, "{path}");
        assert!(matches!(
            error_type(body),
            ErrorType::AdminElevationRequired
        ));
    }
    assert!(harness.db.fetch_session(&kept.id).await.is_ok());

    let ticket = totp_ticket(&harness, &session).await;
    let before = Timestamp::now_utc();
    let (status, body) = elevate(&harness, &session, Some(&ticket)).await;
    assert_eq!(status, Status::Ok);
    let elevation: v0::AdminElevation = serde_json::from_value(body).unwrap();

    let minutes = revolt_config::config().await.api.admins.elevation_minutes as i64;
    let earliest = before.checked_add(Span::minutes(minutes) - Span::seconds(1));
    assert!(elevation.expires_at >= earliest.unwrap());
    let latest = Timestamp::now_utc()
        .checked_add(Span::minutes(minutes))
        .unwrap();
    assert!(elevation.expires_at <= latest);
    assert_eq!(
        elevated_until(&harness, &session).await,
        Some(elevation.expires_at)
    );

    assert!(admin_routes_allowed(&harness, &session, &target).await);
    let (_, body) = get(&harness, &session, "/admin/@me").await;
    let status: v0::AdminStatus = serde_json::from_value(body).unwrap();
    assert_eq!(status.elevated_until, Some(elevation.expires_at));

    // The ticket is used up
    let (status, body) = elevate(&harness, &session, Some(&ticket)).await;
    assert_eq!(status, Status::Unauthorized);
    assert!(matches!(error_type(body), ErrorType::InvalidToken));

    // Ending early
    let (status, _) = request(&harness, Method::Delete, &session, "/admin/elevate", None).await;
    assert_eq!(status, Status::NoContent);
    assert!(!admin_routes_allowed(&harness, &session, &target).await);
    let (_, body) = get(&harness, &session, "/admin/@me").await;
    assert_eq!(body, json!({ "admin": true }));

    // Ending again is fine
    let (status, _) = request(&harness, Method::Delete, &session, "/admin/elevate", None).await;
    assert_eq!(status, Status::NoContent);
}

#[rocket::async_test]
async fn elevate_needs_admin() {
    let harness = TestHarness::new().await;
    let (mut account, session, _) = harness.new_user().await;
    enable_totp(&harness, &mut account).await;
    let ticket = totp_ticket(&harness, &session).await;

    let (status, body) = elevate(&harness, &session, Some(&ticket)).await;
    assert_eq!(status, Status::Forbidden);
    assert!(matches!(error_type(body), ErrorType::NotPrivileged));
    assert_eq!(elevated_until(&harness, &session).await, None);
}

#[rocket::async_test]
async fn elevate_needs_totp() {
    let harness = TestHarness::new().await;
    let (_, session, _) = new_plain_admin(&harness).await;

    // A password ticket is all an account without TOTP can get, and it is not 2FA
    let (status, body) = request(
        &harness,
        Method::Put,
        &session,
        "/auth/mfa/ticket",
        Some(json!({ "password": "password_insecure" })),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let ticket: v0::MFATicket = serde_json::from_value(body).unwrap();

    for header in [Some(ticket.token.as_str()), None] {
        let (status, body) = elevate(&harness, &session, header).await;
        assert_eq!(status, Status::Forbidden, "{header:?}");
        assert!(matches!(error_type(body), ErrorType::TotpRequired));
    }

    // The refused request did not use up the ticket
    assert!(
        harness
            .db
            .fetch_ticket_by_token(&ticket.token)
            .await
            .is_ok()
    );
    assert_eq!(elevated_until(&harness, &session).await, None);
}

#[rocket::async_test]
async fn elevate_rejects_bad_tickets() {
    let harness = TestHarness::new().await;
    let (mut account, session, _) = new_plain_admin(&harness).await;
    enable_totp(&harness, &mut account).await;
    let (mut other, other_session, target) = harness.new_user().await;
    enable_totp(&harness, &mut other).await;

    // A ticket of the admin with no code entered yet, and a good ticket of someone else
    let unvalidated = MFATicket::new(account.id.clone(), false);
    unvalidated.save(&harness.db).await.unwrap();
    let foreign = totp_ticket(&harness, &other_session).await;

    let tickets = [
        None,
        Some("nonsense"),
        Some(unvalidated.token.as_str()),
        Some(foreign.as_str()),
    ];
    for ticket in tickets {
        let (status, body) = elevate(&harness, &session, ticket).await;
        assert_eq!(status, Status::Unauthorized, "{ticket:?}");
        assert!(
            matches!(error_type(body), ErrorType::InvalidToken),
            "{ticket:?}"
        );
    }

    assert_eq!(elevated_until(&harness, &session).await, None);
    assert!(!admin_routes_allowed(&harness, &session, &target).await);
    // The other user's ticket still works for them
    assert!(harness.db.fetch_ticket_by_token(&foreign).await.is_ok());
}

#[rocket::async_test]
async fn elevation_expires() {
    let harness = TestHarness::new().await;
    let (session, _) = new_admin(&harness).await;
    let (_, _, target) = harness.new_user().await;
    assert!(admin_routes_allowed(&harness, &session, &target).await);

    let past = Timestamp::now_utc().checked_sub(Span::seconds(1)).unwrap();
    harness
        .db
        .set_session_admin_elevation(&session.id, Some(past))
        .await
        .unwrap();

    assert!(!admin_routes_allowed(&harness, &session, &target).await);
    let (_, body) = get(&harness, &session, "/admin/@me").await;
    assert_eq!(body, json!({ "admin": true }));
}

#[rocket::async_test]
async fn elevation_belongs_to_the_session() {
    let harness = TestHarness::new().await;
    let (mut account, session, _) = new_plain_admin(&harness).await;
    enable_totp(&harness, &mut account).await;
    let (_, _, target) = harness.new_user().await;
    let laptop = account
        .create_session(&harness.db, "Laptop".to_string())
        .await
        .unwrap();

    let ticket = totp_ticket(&harness, &session).await;
    let (status, _) = elevate(&harness, &session, Some(&ticket)).await;
    assert_eq!(status, Status::Ok);

    // Other sessions of the same admin are not elevated
    assert!(admin_routes_allowed(&harness, &session, &target).await);
    assert!(!admin_routes_allowed(&harness, &laptop, &target).await);

    // Editing the session keeps the elevation
    let (status, _) = request(
        &harness,
        Method::Patch,
        &session,
        &format!("/auth/session/{}", session.id),
        Some(json!({ "friendly_name": "Desk" })),
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert!(admin_routes_allowed(&harness, &session, &target).await);

    // Logging out ends the elevation with the session, a new login starts without one
    let (status, _) = request(
        &harness,
        Method::Post,
        &session,
        "/auth/session/logout",
        None,
    )
    .await;
    assert_eq!(status, Status::NoContent);
    let (status, _) = get(
        &harness,
        &session,
        &format!("/admin/users?query={}", target.id),
    )
    .await;
    assert_eq!(status, Status::Unauthorized);

    let phone = account
        .create_session(&harness.db, "Phone".to_string())
        .await
        .unwrap();
    assert!(!admin_routes_allowed(&harness, &phone, &target).await);
    assert_eq!(elevated_until(&harness, &phone).await, None);
}
