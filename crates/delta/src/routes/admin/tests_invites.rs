//! Instance admins make registration invites (dur.io fork)
use iso8601_timestamp::{Duration as Span, Timestamp};
use revolt_database::AccountInvite;
use revolt_models::v0;
use revolt_result::ErrorType;
use rocket::http::{Method, Status};
use serde_json::{Value, json};

use super::super::e2ee::tests::{error_type, get, post, request};
use super::tests::{new_admin, new_plain_admin};
use crate::util::test::TestHarness;

async fn create(
    harness: &TestHarness,
    session: &revolt_database::Session,
    body: Value,
) -> (Status, Value) {
    post(harness, session, "/admin/invites", body).await
}

async fn list(harness: &TestHarness, session: &revolt_database::Session) -> Vec<v0::AdminInvite> {
    let (status, body) = get(harness, session, "/admin/invites").await;
    assert_eq!(status, Status::Ok);
    serde_json::from_value(body).unwrap()
}

#[rocket::async_test]
async fn non_admins_and_plain_admins_are_refused() {
    let harness = TestHarness::new().await;
    let (_, session, _) = harness.new_user().await;
    let (_, plain_session, _) = new_plain_admin(&harness).await;
    let (admin_session, _) = new_admin(&harness).await;

    let (status, body) = create(
        &harness,
        &admin_session,
        json!({ "ttl_hours": 1, "multi_use": false }),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let code = body["_id"].as_str().unwrap().to_string();

    let routes = [
        (
            Method::Post,
            "/admin/invites".to_string(),
            Some(json!({ "ttl_hours": 1, "multi_use": false })),
        ),
        (Method::Get, "/admin/invites".to_string(), None),
        (Method::Delete, format!("/admin/invites/{code}"), None),
    ];

    for (method, path, body) in routes {
        let (status, _) = request(&harness, method, &session, &path, body.clone()).await;
        assert_eq!(status, Status::Forbidden, "{method} {path}");

        let (status, body) = request(&harness, method, &plain_session, &path, body).await;
        assert_eq!(status, Status::Forbidden, "{method} {path}");
        assert!(matches!(
            error_type(body),
            ErrorType::AdminElevationRequired
        ));
    }

    // Nothing was made or revoked by the refused requests
    let invites = list(&harness, &admin_session).await;
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].id, code);
}

#[rocket::async_test]
async fn create_with_each_lifetime() {
    let harness = TestHarness::new().await;
    let (session, admin) = new_admin(&harness).await;

    for (ttl, multi_use) in [(1, false), (4, true), (12, false), (24, true)] {
        let before = Timestamp::now_utc();
        let (status, body) = create(
            &harness,
            &session,
            json!({ "ttl_hours": ttl, "multi_use": multi_use }),
        )
        .await;
        assert_eq!(status, Status::Ok);

        for field in [
            "_id",
            "expires_at",
            "multi_use",
            "uses",
            "created_by",
            "created_at",
        ] {
            assert!(body.get(field).is_some(), "{field}");
        }

        let invite: v0::AdminInvite = serde_json::from_value(body).unwrap();
        assert!(invite.id.len() >= 12);
        assert!(invite.id.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(invite.multi_use, multi_use);
        assert_eq!(invite.uses, 0);
        assert_eq!(invite.created_by, admin.id);
        assert_eq!(
            invite.expires_at.duration_since(invite.created_at),
            Span::hours(ttl)
        );
        assert!(invite.created_at.duration_since(before) > Span::seconds(-2));

        // Stored as a working invite
        let stored = harness.db.fetch_account_invite(&invite.id).await.unwrap();
        assert_eq!(stored.expires_at, Some(invite.expires_at));
        assert_eq!(stored.multi_use, multi_use);
        assert!(!stored.used);
    }

    // Codes are random
    let codes: std::collections::HashSet<String> = list(&harness, &session)
        .await
        .into_iter()
        .map(|invite| invite.id)
        .collect();
    assert_eq!(codes.len(), 4);
}

#[rocket::async_test]
async fn other_lifetimes_are_refused() {
    let harness = TestHarness::new().await;
    let (session, _) = new_admin(&harness).await;

    for ttl in [0, 2, 23, 25, 48, 168] {
        let (status, body) = create(
            &harness,
            &session,
            json!({ "ttl_hours": ttl, "multi_use": false }),
        )
        .await;
        assert_eq!(status, Status::BadRequest, "{ttl}");
        assert!(matches!(error_type(body), ErrorType::InvalidOperation));
    }

    for body in [json!({ "ttl_hours": -1 }), json!({ "ttl_hours": "1" })] {
        let (status, _) = create(&harness, &session, body).await;
        assert!(status.code >= 400 && status.code < 500);
    }

    assert!(list(&harness, &session).await.is_empty());
}

#[rocket::async_test]
async fn list_shows_working_invites_newest_first() {
    let harness = TestHarness::new().await;
    let (session, admin) = new_admin(&harness).await;
    let now = Timestamp::now_utc();

    let invite = |id: &str, age: i64, ttl: i64, multi_use: bool, used: bool| AccountInvite {
        id: id.to_string(),
        used,
        expires_at: Some(now.checked_add(Span::hours(ttl - age)).unwrap()),
        multi_use,
        uses: if multi_use && used { 2 } else { 0 },
        created_by: Some(admin.id.clone()),
        created_at: Some(now.checked_sub(Span::hours(age)).unwrap()),
        ..Default::default()
    };

    for invite in [
        invite("old_multi_used_xx", 3, 4, true, true),
        invite("new_single_xxxxxx", 0, 1, false, false),
        invite("mid_single_xxxxxx", 2, 4, false, false),
        invite("expired_single_xx", 2, 1, false, false),
        invite("expired_multi_xxx", 5, 4, true, false),
        invite("used_single_xxxxx", 1, 4, false, true),
        // Manual invites have no place in the list
        AccountInvite {
            id: "manual_xxxxxxxxxx".to_string(),
            ..Default::default()
        },
    ] {
        invite.save(&harness.db).await.unwrap();
    }

    let invites = list(&harness, &session).await;
    let ids: Vec<&str> = invites.iter().map(|invite| invite.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "new_single_xxxxxx",
            "mid_single_xxxxxx",
            "old_multi_used_xx"
        ]
    );
    assert_eq!(invites[2].uses, 2);
}

#[rocket::async_test]
async fn revoke_invite() {
    let harness = TestHarness::new().await;
    let (session, _) = new_admin(&harness).await;

    let (_, body) = create(
        &harness,
        &session,
        json!({ "ttl_hours": 24, "multi_use": true }),
    )
    .await;
    let code = body["_id"].as_str().unwrap().to_string();

    let path = format!("/admin/invites/{code}");
    let (status, _) = request(&harness, Method::Delete, &session, &path, None).await;
    assert_eq!(status, Status::NoContent);
    assert!(harness.db.fetch_account_invite(&code).await.is_err());
    assert!(list(&harness, &session).await.is_empty());

    // Gone already, or never existed
    let (status, _) = request(&harness, Method::Delete, &session, &path, None).await;
    assert_eq!(status, Status::NotFound);
    let (status, _) = request(
        &harness,
        Method::Delete,
        &session,
        "/admin/invites/unknown",
        None,
    )
    .await;
    assert_eq!(status, Status::NotFound);

    // Manual invites can be revoked too
    AccountInvite {
        id: "manual_revoke".to_string(),
        ..Default::default()
    }
    .save(&harness.db)
    .await
    .unwrap();
    let (status, _) = request(
        &harness,
        Method::Delete,
        &session,
        "/admin/invites/manual_revoke",
        None,
    )
    .await;
    assert_eq!(status, Status::NoContent);
}

#[rocket::async_test]
async fn openapi_has_the_invite_routes() {
    let harness = TestHarness::new().await;
    let res = harness.client.get("/openapi.json").dispatch().await;
    assert_eq!(res.status(), Status::Ok);
    let spec: Value = serde_json::from_str(&res.into_string().await.unwrap()).unwrap();

    let invites = &spec["paths"]["/admin/invites"];
    assert!(invites["post"].is_object());
    assert!(invites["get"].is_object());
    assert!(spec["paths"]["/admin/invites/{code}"]["delete"].is_object());

    let schemas = &spec["components"]["schemas"];
    let invite = &schemas["AdminInvite"]["properties"];
    for field in [
        "_id",
        "expires_at",
        "multi_use",
        "uses",
        "created_by",
        "created_at",
    ] {
        assert!(invite[field].is_object(), "{field}");
    }
    let data = &schemas["DataCreateAdminInvite"]["properties"];
    assert!(data["ttl_hours"].is_object() && data["multi_use"].is_object());
    assert!(
        schemas["RevoltFeatures"]["properties"]["invite_only"].is_object(),
        "root config tells clients whether registration needs an invite"
    );
}
