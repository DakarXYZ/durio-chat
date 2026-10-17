//! Acknowledge to-device messages of the current device
//! POST /e2ee/to_device/ack
use revolt_database::Database;
use revolt_models::v0;
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use rocket_empty::EmptyResponse;
use validator::Validate;

use super::E2eeSession;

/// # Acknowledge To-Device Messages
///
/// Delete processed messages from the mailbox of the current device.
/// Unknown ids and messages of other devices are ignored.
#[openapi(tag = "E2EE")]
#[post("/to_device/ack", data = "<data>")]
pub async fn ack(
    db: &State<Database>,
    e2ee: E2eeSession,
    data: Json<v0::DataE2eeToDeviceAck>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    db.ack_to_device(e2ee.device_id(), &data.ids)
        .await
        .map(|_| EmptyResponse)
}

#[cfg(test)]
mod tests {
    use revolt_models::v0::e2ee_user_id;
    use rocket::http::{Method, Status};
    use serde_json::json;

    use crate::routes::e2ee::tests::{get, new_device, new_device_user, post, request};
    use crate::util::test::TestHarness;

    #[rocket::async_test]
    async fn ack_only_listed() {
        let harness = TestHarness::new().await;
        let (account, session, user) = new_device_user(&harness).await;
        let second = new_device(&harness, &account).await;

        for n in 0..3 {
            request(
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
        }

        let (_, body) = get(&harness, &second, "/e2ee/to_device").await;
        let ids: Vec<String> = body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|message| message["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids.len(), 3);

        // Another device cannot acknowledge them
        let (status, _) = post(
            &harness,
            &session,
            "/e2ee/to_device/ack",
            json!({ "ids": ids.clone() }),
        )
        .await;
        assert_eq!(status, Status::NoContent);

        let (status, _) = post(
            &harness,
            &second,
            "/e2ee/to_device/ack",
            json!({ "ids": [ids[0].clone(), ids[2].clone(), "unknown"] }),
        )
        .await;
        assert_eq!(status, Status::NoContent);

        let (_, body) = get(&harness, &second, "/e2ee/to_device").await;
        assert_eq!(body["messages"].as_array().unwrap().len(), 1);
        assert_eq!(body["messages"][0]["id"], ids[1]);

        for ids in [json!([]), json!(vec!["id"; 101])] {
            let (status, _) = post(
                &harness,
                &second,
                "/e2ee/to_device/ack",
                json!({ "ids": ids }),
            )
            .await;
            assert_eq!(status, Status::BadRequest);
        }
    }
}
