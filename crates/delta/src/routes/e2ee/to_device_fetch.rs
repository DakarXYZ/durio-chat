//! Fetch to-device messages of the current device
//! GET /e2ee/to_device?limit
use revolt_database::Database;
use revolt_models::v0::{self, e2ee_user_id};
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use validator::Validate;

use super::E2eeSession;

/// Messages returned when no limit is given
const DEFAULT_LIMIT: i64 = 100;

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
    use revolt_models::v0::e2ee_user_id;
    use rocket::http::{Method, Status};
    use serde_json::json;

    use crate::routes::e2ee::tests::{get, new_device, new_device_user, request};
    use crate::util::test::TestHarness;

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
