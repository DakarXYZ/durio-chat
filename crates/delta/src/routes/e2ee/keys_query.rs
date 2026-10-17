//! Query device keys of users
//! POST /e2ee/keys/query
use std::collections::HashMap;

use revolt_config::config;
use revolt_database::{Database, e2ee_visible_users};
use revolt_models::v0::{self, e2ee_user_id, user_id_from_e2ee};
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use serde_json::Value;

use super::E2eeSession;

/// # Query Keys
///
/// Fetch device keys of users. Only users sharing a direct message or group, friends,
/// pending friend requests and the user themselves are visible, others come back empty.
#[openapi(tag = "E2EE")]
#[post("/keys/query", data = "<data>")]
pub async fn query(
    db: &State<Database>,
    e2ee: E2eeSession,
    data: Json<v0::DataE2eeKeysQuery>,
) -> Result<Json<v0::E2eeKeysQueryResponse>> {
    let data = data.into_inner();
    let max = config().await.features.e2ee.max_devices_per_request;

    if data.device_keys.len() > max || data.device_keys.values().any(|ids| ids.len() > max) {
        return Err(create_error!(PayloadTooLarge));
    }

    let visible = e2ee_visible_users(db, &e2ee.user).await?;
    let user_ids: Vec<String> = data
        .device_keys
        .keys()
        .filter_map(|id| user_id_from_e2ee(id))
        .filter(|id| visible.contains(id))
        .collect();

    let devices = if user_ids.is_empty() {
        vec![]
    } else {
        db.fetch_e2ee_devices(&user_ids).await?
    };

    // Every requested user is answered, unknown and invisible ones with no devices
    let mut device_keys: HashMap<String, HashMap<String, Value>> = data
        .device_keys
        .keys()
        .map(|id| (id.clone(), HashMap::new()))
        .collect();

    for device in devices {
        let id = e2ee_user_id(&device.user_id);
        let wanted = data
            .device_keys
            .get(&id)
            .is_some_and(|ids| ids.is_empty() || ids.contains(&device.id));

        if wanted && let Ok(keys) = serde_json::from_str(&device.keys) {
            device_keys.entry(id).or_default().insert(device.id, keys);
        }
    }

    Ok(Json(v0::E2eeKeysQueryResponse {
        device_keys,
        failures: HashMap::new(),
        master_keys: HashMap::new(),
        self_signing_keys: HashMap::new(),
        user_signing_keys: HashMap::new(),
    }))
}

#[cfg(test)]
mod tests {
    use revolt_models::v0::e2ee_user_id;
    use rocket::http::Status;
    use serde_json::json;

    use crate::routes::e2ee::tests::{
        device_keys, direct_message, new_device, new_device_user, post,
    };
    use crate::util::test::TestHarness;

    #[rocket::async_test]
    async fn visibility() {
        let harness = TestHarness::new().await;
        let (account, session, user) = new_device_user(&harness).await;
        let second = new_device(&harness, &account).await;
        let (_, peer_session, peer) = new_device_user(&harness).await;
        let (_, _, stranger) = new_device_user(&harness).await;
        direct_message(&harness, &user, &peer).await;

        let (status, body) = post(
            &harness,
            &peer_session,
            "/e2ee/keys/query",
            json!({
                "device_keys": {
                    e2ee_user_id(&user.id): [],
                    e2ee_user_id(&stranger.id): [],
                    "@not-a-user:stoat.invalid": []
                }
            }),
        )
        .await;

        assert_eq!(status, Status::Ok);
        assert_eq!(
            body,
            json!({
                "device_keys": {
                    e2ee_user_id(&user.id): {
                        session.id.clone(): device_keys(&user.id, &session.id),
                        second.id.clone(): device_keys(&user.id, &second.id)
                    },
                    e2ee_user_id(&stranger.id): {},
                    "@not-a-user:stoat.invalid": {}
                },
                "failures": {},
                "master_keys": {},
                "self_signing_keys": {},
                "user_signing_keys": {}
            })
        );

        // Own devices, filtered by device id
        let (status, body) = post(
            &harness,
            &session,
            "/e2ee/keys/query",
            json!({ "device_keys": { e2ee_user_id(&user.id): [second.id.clone()] } }),
        )
        .await;

        assert_eq!(status, Status::Ok);
        assert_eq!(
            body["device_keys"],
            json!({
                e2ee_user_id(&user.id): { second.id.clone(): device_keys(&user.id, &second.id) }
            })
        );

        // The stranger sees nothing of the user
        let (_, stranger_session, _) = harness.new_user().await;
        let (_, body) = post(
            &harness,
            &stranger_session,
            "/e2ee/keys/query",
            json!({ "device_keys": { e2ee_user_id(&user.id): [] } }),
        )
        .await;
        assert_eq!(body["device_keys"], json!({ e2ee_user_id(&user.id): {} }));
    }

    #[rocket::async_test]
    async fn too_many_users() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        // 256 in the default config
        let users: serde_json::Map<String, serde_json::Value> = (0..257)
            .map(|n| (format!("@user{n}:stoat.invalid"), json!([])))
            .collect();

        let (status, _) = post(
            &harness,
            &session,
            "/e2ee/keys/query",
            json!({ "device_keys": users }),
        )
        .await;
        assert_eq!(status, Status::UnprocessableEntity);
    }
}
