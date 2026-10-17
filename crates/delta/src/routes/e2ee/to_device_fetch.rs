//! Fetch to-device messages of the current device
//! GET /e2ee/to_device?limit
use iso8601_timestamp::{Duration, Timestamp};
use revolt_database::Database;
use revolt_models::v0::{self, e2ee_user_id};
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use validator::Validate;

use super::E2eeSession;

/// Messages returned when no limit is given
const DEFAULT_LIMIT: i64 = 100;

/// `last_seen` of the session is refreshed at most this often (hours)
const LAST_SEEN_INTERVAL_HOURS: i64 = 1;

/// # Fetch To-Device Messages
///
/// Oldest messages in the mailbox of the current device. Messages stay in the mailbox
/// until acknowledged, clients deduplicate by id.
#[openapi(tag = "E2EE")]
#[get("/to_device?<options..>")]
pub async fn fetch(
    db: &State<Database>,
    e2ee: E2eeSession,
    options: v0::OptionsE2eeToDeviceFetch,
) -> Result<Json<v0::E2eeToDeviceFetchResponse>> {
    options.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Mobile clients fetch the mailbox on push without keeping a socket open,
    // the device list shows when a device was last active
    let now = Timestamp::now_utc();
    if now
        .checked_sub(Duration::hours(LAST_SEEN_INTERVAL_HOURS))
        .is_some_and(|threshold| e2ee.session.last_seen < threshold)
    {
        db.update_session_last_seen(e2ee.device_id(), now)
            .await
            .ok();
    }

    let limit = options.limit.unwrap_or(DEFAULT_LIMIT) as usize;
    let messages = db
        .fetch_to_device(e2ee.device_id(), limit)
        .await?
        .into_iter()
        .map(|message| v0::E2eeToDeviceMessage {
            id: message.id,
            sender: e2ee_user_id(&message.sender_user),
            sender_device: message.sender_device,
            event_type: message.event_type,
            content: serde_json::from_str(&message.content).unwrap_or_default(),
        })
        .collect();

    Ok(Json(v0::E2eeToDeviceFetchResponse { messages }))
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_models::v0::e2ee_user_id;
    use rocket::http::{Method, Status};
    use serde_json::json;

    use crate::routes::e2ee::tests::{get, new_device, new_device_user, request};
    use crate::util::test::TestHarness;

    /// `last_seen` is refreshed when it is older than an hour (BE-31)
    #[rocket::async_test]
    async fn refreshes_last_seen() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let last_seen = |minutes: i64| {
            Timestamp::now_utc()
                .checked_sub(Duration::minutes(minutes))
                .unwrap()
        };

        // Recent enough: unchanged
        let recent = last_seen(30);
        harness
            .db
            .update_session_last_seen(&session.id, recent)
            .await
            .unwrap();
        get(&harness, &session, "/e2ee/to_device").await;
        assert_eq!(
            harness
                .db
                .fetch_session(&session.id)
                .await
                .unwrap()
                .last_seen,
            recent
        );

        // Stale: refreshed and listed with the sessions
        harness
            .db
            .update_session_last_seen(&session.id, last_seen(120))
            .await
            .unwrap();
        let before = Timestamp::now_utc();
        get(&harness, &session, "/e2ee/to_device").await;
        let refreshed = harness
            .db
            .fetch_session(&session.id)
            .await
            .unwrap()
            .last_seen;
        assert!(refreshed >= before.checked_sub(Duration::seconds(1)).unwrap());

        let (status, body) = get(&harness, &session, "/auth/session/all").await;
        assert_eq!(status, Status::Ok);
        let listed: Timestamp =
            serde_json::from_value(body[0]["last_seen"].clone()).expect("last_seen");
        assert!(listed >= before.checked_sub(Duration::seconds(1)).unwrap());
    }

    #[rocket::async_test]
    async fn limit_and_order() {
        let harness = TestHarness::new().await;
        let (account, session, user) = new_device_user(&harness).await;
        let second = new_device(&harness, &account).await;

        for n in 0..3 {
            let (status, _) = request(
                &harness,
                Method::Put,
                &session,
                &format!("/e2ee/to_device/txn{n}"),
                Some(json!({
                    "type": "m.dummy",
                    "messages": { e2ee_user_id(&user.id): { second.id.clone(): { "n": n } } }
                })),
            )
            .await;
            assert_eq!(status, Status::Ok);
        }

        let (status, body) = get(&harness, &second, "/e2ee/to_device?limit=2").await;
        assert_eq!(status, Status::Ok);
        let contents: Vec<_> = body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|message| message["content"]["n"].clone())
            .collect();
        assert_eq!(contents, [json!(0), json!(1)]);

        let (_, body) = get(&harness, &second, "/e2ee/to_device").await;
        assert_eq!(body["messages"].as_array().unwrap().len(), 3);

        for limit in ["0", "101"] {
            let (status, _) =
                get(&harness, &second, &format!("/e2ee/to_device?limit={limit}")).await;
            assert_eq!(status, Status::BadRequest);
        }
    }
}
