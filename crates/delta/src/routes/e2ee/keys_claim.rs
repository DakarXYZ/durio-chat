//! Claim one-time keys of devices
//! POST /e2ee/keys/claim
use std::collections::HashMap;

use futures::StreamExt;
use revolt_config::config;
use revolt_database::{Database, e2ee_visible_users};
use revolt_models::v0::{self, E2EE_KEY_ALGORITHM_SIGNED_CURVE25519, user_id_from_e2ee};
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use serde_json::Value;

use super::E2eeSession;

/// Concurrent claims per request
const CLAIM_CONCURRENCY: usize = 8;

/// # Claim Keys
///
/// Take one one-time key of each device to start an Olm session with it. When a device
/// has no one-time keys left its fallback key is handed out (again, until replaced).
/// Devices of invisible users are skipped.
#[openapi(tag = "E2EE")]
#[post("/keys/claim", data = "<data>")]
pub async fn claim(
    db: &State<Database>,
    e2ee: E2eeSession,
    data: Json<v0::DataE2eeKeysClaim>,
) -> Result<Json<v0::E2eeKeysClaimResponse>> {
    let data = data.into_inner();
    let max = config().await.features.e2ee.max_devices_per_request;

    if data.one_time_keys.values().map(HashMap::len).sum::<usize>() > max {
        return Err(create_error!(PayloadTooLarge));
    }

    let visible = e2ee_visible_users(db, &e2ee.user).await?;
    let user_ids: Vec<String> = data
        .one_time_keys
        .keys()
        .filter_map(|id| user_id_from_e2ee(id))
        .filter(|id| visible.contains(id))
        .collect();

    // Device id → owner, a device must belong to the user it is requested under
    let owners: HashMap<String, String> = if user_ids.is_empty() {
        HashMap::new()
    } else {
        db.fetch_e2ee_devices(&user_ids)
            .await?
            .into_iter()
            .map(|device| (device.id, device.user_id))
            .collect()
    };

    let mut targets = vec![];
    for (matrix_id, devices) in data.one_time_keys {
        let Some(user_id) = user_id_from_e2ee(&matrix_id) else {
            continue;
        };

        for (device_id, algorithm) in devices {
            if algorithm == E2EE_KEY_ALGORITHM_SIGNED_CURVE25519
                && owners.get(&device_id) == Some(&user_id)
            {
                targets.push((matrix_id.clone(), device_id, algorithm));
            }
        }
    }

    let db: &Database = db;
    let claimed: Vec<_> = futures::stream::iter(targets)
        .map(|(matrix_id, device_id, algorithm)| async move {
            db.claim_one_time_key(&device_id, &algorithm)
                .await
                .map(|key| (matrix_id, device_id, key))
        })
        .buffer_unordered(CLAIM_CONCURRENCY)
        .collect()
        .await;

    let mut one_time_keys: HashMap<String, HashMap<String, HashMap<String, Value>>> =
        HashMap::new();

    for result in claimed {
        let (matrix_id, device_id, key) = result?;
        let Some(key) = key else {
            continue;
        };

        if let Ok(signed) = serde_json::from_str(&key.key) {
            one_time_keys
                .entry(matrix_id)
                .or_default()
                .entry(device_id)
                .or_default()
                .insert(format!("{}:{}", key.algorithm, key.key_id), signed);
        }
    }

    Ok(Json(v0::E2eeKeysClaimResponse {
        failures: HashMap::new(),
        one_time_keys,
    }))
}

#[cfg(test)]
mod tests {
    use revolt_models::v0::e2ee_user_id;
    use rocket::http::Status;
    use serde_json::json;

    use crate::routes::e2ee::tests::{
        direct_message, fallback_keys, get, new_device_user, one_time_keys, post, signed_key,
    };
    use crate::util::test::TestHarness;

    #[rocket::async_test]
    async fn claim_until_fallback() {
        let harness = TestHarness::new().await;
        let (_, session, user) = new_device_user(&harness).await;
        let (_, peer_session, peer) = harness.new_user().await;
        direct_message(&harness, &user, &peer).await;

        let (status, _) = post(
            &harness,
            &session,
            "/e2ee/keys/upload",
            json!({
                "one_time_keys": one_time_keys(&user.id, &session.id, "A", 2),
                "fallback_keys": fallback_keys(&user.id, &session.id, "F")
            }),
        )
        .await;
        assert_eq!(status, Status::Ok);

        let body = json!({
            "one_time_keys": { e2ee_user_id(&user.id): { session.id.clone(): "signed_curve25519" } }
        });

        let mut claimed = vec![];
        for _ in 0..2 {
            let (status, response) =
                post(&harness, &peer_session, "/e2ee/keys/claim", body.clone()).await;
            assert_eq!(status, Status::Ok);
            assert_eq!(response["failures"], json!({}));

            let keys = response["one_time_keys"][e2ee_user_id(&user.id)][&session.id]
                .as_object()
                .unwrap()
                .clone();
            assert_eq!(keys.len(), 1);
            claimed.extend(keys);
        }

        claimed.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            claimed,
            vec![
                (
                    "signed_curve25519:A0".to_string(),
                    signed_key(&user.id, &session.id, "otk-A0", false)
                ),
                (
                    "signed_curve25519:A1".to_string(),
                    signed_key(&user.id, &session.id, "otk-A1", false)
                ),
            ]
        );

        // One-time keys are exhausted, the fallback key is handed out again and again
        for _ in 0..2 {
            let (_, response) =
                post(&harness, &peer_session, "/e2ee/keys/claim", body.clone()).await;
            assert_eq!(
                response["one_time_keys"],
                json!({
                    e2ee_user_id(&user.id): {
                        session.id.clone(): {
                            "signed_curve25519:F": signed_key(&user.id, &session.id, "fallback-F", true)
                        }
                    }
                })
            );
        }

        let (_, counts) = get(&harness, &session, "/e2ee/keys/count").await;
        assert_eq!(
            counts,
            json!({
                "one_time_key_counts": { "signed_curve25519": 0 },
                "device_unused_fallback_key_types": []
            })
        );
    }

    #[rocket::async_test]
    async fn invisible_and_foreign_devices() {
        let harness = TestHarness::new().await;
        let (_, session, user) = new_device_user(&harness).await;
        let (_, peer_session, peer) = new_device_user(&harness).await;
        let (_, stranger_session, stranger) = new_device_user(&harness).await;
        direct_message(&harness, &user, &peer).await;

        for (session, user) in [(&session, &user), (&stranger_session, &stranger)] {
            let (status, _) = post(
                &harness,
                session,
                "/e2ee/keys/upload",
                json!({ "one_time_keys": one_time_keys(&user.id, &session.id, "A", 1) }),
            )
            .await;
            assert_eq!(status, Status::Ok);
        }

        let (status, response) = post(
            &harness,
            &peer_session,
            "/e2ee/keys/claim",
            json!({
                "one_time_keys": {
                    // Not visible
                    e2ee_user_id(&stranger.id): { stranger_session.id.clone(): "signed_curve25519" },
                    // Device of the stranger under a visible user
                    e2ee_user_id(&user.id): {
                        stranger_session.id.clone(): "signed_curve25519",
                        session.id.clone(): "curve25519"
                    }
                }
            }),
        )
        .await;

        assert_eq!(status, Status::Ok);
        assert_eq!(response, json!({ "failures": {}, "one_time_keys": {} }));

        // Nothing was taken
        for session in [&session, &stranger_session] {
            let (_, counts) = get(&harness, session, "/e2ee/keys/count").await;
            assert_eq!(counts["one_time_key_counts"]["signed_curve25519"], 1);
        }
    }

    #[rocket::async_test]
    async fn too_many_devices() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        // 256 in the default config
        let devices: serde_json::Map<String, serde_json::Value> = (0..257)
            .map(|n| (format!("DEVICE{n}"), json!("signed_curve25519")))
            .collect();

        let (status, _) = post(
            &harness,
            &session,
            "/e2ee/keys/claim",
            json!({ "one_time_keys": { e2ee_user_id(&user.id): devices } }),
        )
        .await;
        assert_eq!(status, Status::UnprocessableEntity);
    }
}
