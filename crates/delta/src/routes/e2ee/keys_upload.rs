//! Upload keys of the current device
//! POST /e2ee/keys/upload
use iso8601_timestamp::Timestamp;
use revolt_config::config;
use revolt_database::{
    Database, E2eeDevice, E2eeFallbackKey, E2eeOneTimeKey, events::client::EventV1,
};
use revolt_models::v0::{self, E2EE_KEY_ALGORITHM_SIGNED_CURVE25519, e2ee_user_id};
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use serde_json::Value;

use super::{E2eeSession, invalid, json_size, key_counts};

/// Upper bound of signed device keys (two keys, one signature in v1)
const MAX_DEVICE_KEYS_BYTES: usize = 8 * 1024;

/// Upper bound of a signed one-time or fallback key
const MAX_SIGNED_KEY_BYTES: usize = 2 * 1024;

/// Upper bound of a key id
const MAX_KEY_ID_LENGTH: usize = 64;

/// # Upload Keys
///
/// Upload device keys (once per device), one-time keys and the fallback key
/// of the current device. Device keys are immutable: a new device is a new session.
#[openapi(tag = "E2EE")]
#[post("/keys/upload", data = "<data>")]
pub async fn upload(
    db: &State<Database>,
    e2ee: E2eeSession,
    data: Json<v0::DataE2eeKeysUpload>,
) -> Result<Json<v0::E2eeKeysUploadResponse>> {
    let data = data.into_inner();
    let config = config().await;
    let user_id = &e2ee.user.id;
    let device_id = e2ee.device_id();

    // Validate the whole request before writing anything
    let device = data
        .device_keys
        .map(|keys| device_from_keys(keys, user_id, device_id))
        .transpose()?;

    let one_time_keys = data.one_time_keys.unwrap_or_default();
    if one_time_keys.len() > config.features.e2ee.max_otk_per_device {
        return Err(create_error!(PayloadTooLarge));
    }

    let one_time_keys = one_time_keys
        .into_iter()
        .map(|(name, key)| {
            let (algorithm, key_id) = parse_signed_key(&name, &key, "one_time_keys")?;
            Ok(E2eeOneTimeKey {
                id: E2eeOneTimeKey::make_id(device_id, &algorithm, &key_id),
                user_id: user_id.clone(),
                device_id: device_id.to_string(),
                algorithm,
                key_id,
                key: key.to_string(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let fallback_keys = data.fallback_keys.unwrap_or_default();
    if fallback_keys.len() > 1 {
        return Err(invalid("fallback_keys"));
    }

    let fallback_key = fallback_keys
        .into_iter()
        .next()
        .map(|(name, key)| {
            let (algorithm, key_id) = parse_signed_key(&name, &key, "fallback_keys")?;
            Ok::<_, revolt_result::Error>(E2eeFallbackKey {
                id: device_id.to_string(),
                user_id: user_id.clone(),
                algorithm,
                key_id,
                key: key.to_string(),
                used: false,
            })
        })
        .transpose()?;

    if let Some(device) = device {
        if db.insert_e2ee_device(&device).await? {
            EventV1::E2eeDeviceListUpdate {
                user: user_id.clone(),
            }
            .p(user_id.clone())
            .await;
        } else {
            // Repeated upload of the same keys is fine (compared as JSON, not as text)
            let existing = db.fetch_e2ee_device(device_id).await?;
            if serde_json::from_str::<Value>(&existing.keys).ok()
                != serde_json::from_str::<Value>(&device.keys).ok()
            {
                return Err(create_error!(DeviceKeysMismatch));
            }
        }
    } else if !one_time_keys.is_empty() || fallback_key.is_some() {
        // Keys of a device without device keys could never be used
        db.fetch_e2ee_device(device_id).await?;
    }

    if !one_time_keys.is_empty() {
        let stored: usize = db.count_one_time_keys(device_id).await?.values().sum();
        if stored + one_time_keys.len() > config.features.e2ee.max_otk_per_device {
            return Err(create_error!(PayloadTooLarge));
        }

        db.insert_one_time_keys(one_time_keys).await?;
    }

    if let Some(fallback_key) = fallback_key {
        db.set_fallback_key(&fallback_key).await?;
    }

    let (one_time_key_counts, device_unused_fallback_key_types) = key_counts(db, device_id).await?;

    Ok(Json(v0::E2eeKeysUploadResponse {
        one_time_key_counts,
        device_unused_fallback_key_types,
    }))
}

/// Check the structure of signed device keys (signatures are verified by clients)
fn device_from_keys(keys: Value, user_id: &str, device_id: &str) -> Result<E2eeDevice> {
    if json_size(&keys) > MAX_DEVICE_KEYS_BYTES {
        return Err(create_error!(PayloadTooLarge));
    }

    let object = keys.as_object().ok_or_else(|| invalid("device_keys"))?;

    if object.get("user_id").and_then(Value::as_str) != Some(e2ee_user_id(user_id).as_str()) {
        return Err(invalid("device_keys.user_id"));
    }

    if object.get("device_id").and_then(Value::as_str) != Some(device_id) {
        return Err(invalid("device_keys.device_id"));
    }

    let algorithms_valid = object
        .get("algorithms")
        .and_then(Value::as_array)
        .is_some_and(|algorithms| {
            !algorithms.is_empty() && algorithms.iter().all(|algorithm| algorithm.is_string())
        });

    if !algorithms_valid {
        return Err(invalid("device_keys.algorithms"));
    }

    let device_keys = object
        .get("keys")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("device_keys.keys"))?;

    for algorithm in ["curve25519", "ed25519"] {
        if !device_keys
            .get(&format!("{algorithm}:{device_id}"))
            .is_some_and(Value::is_string)
        {
            return Err(invalid("device_keys.keys"));
        }
    }

    if !object.get("signatures").is_some_and(Value::is_object) {
        return Err(invalid("device_keys.signatures"));
    }

    Ok(E2eeDevice {
        id: device_id.to_string(),
        user_id: user_id.to_string(),
        keys: keys.to_string(),
        display_name: None,
        created_at: Timestamp::now_utc(),
    })
}

/// Parse `signed_curve25519:<key id>` and check the structure of a signed key
fn parse_signed_key(name: &str, key: &Value, field: &str) -> Result<(String, String)> {
    let (algorithm, key_id) = name.split_once(':').ok_or_else(|| invalid(field))?;

    if algorithm != E2EE_KEY_ALGORITHM_SIGNED_CURVE25519
        || key_id.is_empty()
        || key_id.len() > MAX_KEY_ID_LENGTH
    {
        return Err(invalid(field));
    }

    if json_size(key) > MAX_SIGNED_KEY_BYTES {
        return Err(create_error!(PayloadTooLarge));
    }

    let valid = key.as_object().is_some_and(|object| {
        object.get("key").is_some_and(Value::is_string)
            && object.get("signatures").is_some_and(Value::is_object)
    });

    if !valid {
        return Err(invalid(field));
    }

    Ok((algorithm.to_string(), key_id.to_string()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use revolt_database::events::client::EventV1;
    use revolt_result::ErrorType;
    use rocket::http::Status;
    use serde_json::json;

    use crate::routes::e2ee::tests::{
        device_keys, error_type, fallback_keys, new_device_user, one_time_keys, post,
    };
    use crate::util::test::{PubSubTestHelper, TestHarness};

    #[rocket::async_test]
    async fn success_initial_and_fallback() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let mut events = PubSubTestHelper::new(&user.id).await;

        let (status, body) = post(
            &harness,
            &session,
            "/e2ee/keys/upload",
            json!({
                "device_keys": device_keys(&user.id, &session.id),
                "one_time_keys": one_time_keys(&user.id, &session.id, "A", 3),
            }),
        )
        .await;

        assert_eq!(status, Status::Ok);
        assert_eq!(
            body,
            json!({
                "one_time_key_counts": { "signed_curve25519": 3 },
                "device_unused_fallback_key_types": []
            })
        );

        let event = tokio::time::timeout(
            Duration::from_secs(5),
            events.wait_for_event(|event| matches!(event, EventV1::E2eeDeviceListUpdate { .. })),
        )
        .await
        .expect("device list update");
        assert!(matches!(event, EventV1::E2eeDeviceListUpdate { user: id } if id == user.id));

        // Fallback key arrives in a separate upload (contract v1)
        let (status, body) = post(
            &harness,
            &session,
            "/e2ee/keys/upload",
            json!({ "fallback_keys": fallback_keys(&user.id, &session.id, "F") }),
        )
        .await;

        assert_eq!(status, Status::Ok);
        assert_eq!(
            body,
            json!({
                "one_time_key_counts": { "signed_curve25519": 3 },
                "device_unused_fallback_key_types": ["signed_curve25519"]
            })
        );
    }

    #[rocket::async_test]
    async fn repeated_upload() {
        let harness = TestHarness::new().await;
        let (_, session, user) = new_device_user(&harness).await;

        // Same keys and the same one-time keys twice
        for _ in 0..2 {
            let (status, body) = post(
                &harness,
                &session,
                "/e2ee/keys/upload",
                json!({
                    "device_keys": device_keys(&user.id, &session.id),
                    "one_time_keys": one_time_keys(&user.id, &session.id, "A", 3),
                }),
            )
            .await;
            assert_eq!(status, Status::Ok);
            assert_eq!(body["one_time_key_counts"]["signed_curve25519"], 3);
        }

        // Other keys under the same session
        let mut keys = device_keys(&user.id, &session.id);
        keys["keys"][format!("curve25519:{}", session.id)] = json!("other");

        let (status, body) = post(
            &harness,
            &session,
            "/e2ee/keys/upload",
            json!({ "device_keys": keys }),
        )
        .await;
        assert_eq!(status, Status::Conflict);
        assert!(matches!(error_type(body), ErrorType::DeviceKeysMismatch));
    }

    #[rocket::async_test]
    async fn foreign_ids() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, other, other_user) = harness.new_user().await;

        for keys in [
            device_keys(&other_user.id, &session.id),
            device_keys(&user.id, &other.id),
            {
                // Not the canonical (lowercase) form
                let mut keys = device_keys(&user.id, &session.id);
                keys["user_id"] = json!(format!("@{}:stoat.invalid", user.id));
                keys
            },
            {
                let mut keys = device_keys(&user.id, &session.id);
                keys["algorithms"] = json!([]);
                keys
            },
            json!({ "user_id": format!("@{}:stoat.invalid", user.id.to_lowercase()) }),
        ] {
            let (status, body) = post(
                &harness,
                &session,
                "/e2ee/keys/upload",
                json!({ "device_keys": keys }),
            )
            .await;
            assert_eq!(status, Status::BadRequest);
            assert!(matches!(
                error_type(body),
                ErrorType::FailedValidation { .. }
            ));
        }

        // Nothing was stored
        assert!(harness.db.fetch_e2ee_device(&session.id).await.is_err());
    }

    #[rocket::async_test]
    async fn keys_without_device() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        let (status, body) = post(
            &harness,
            &session,
            "/e2ee/keys/upload",
            json!({ "one_time_keys": one_time_keys(&user.id, &session.id, "A", 1) }),
        )
        .await;
        assert_eq!(status, Status::NotFound);
        assert!(matches!(error_type(body), ErrorType::DeviceNotFound));
    }

    #[rocket::async_test]
    async fn invalid_keys() {
        let harness = TestHarness::new().await;
        let (_, session, user) = new_device_user(&harness).await;

        for body in [
            json!({ "one_time_keys": { "curve25519:A": { "key": "k", "signatures": {} } } }),
            json!({ "one_time_keys": { "signed_curve25519:": { "key": "k", "signatures": {} } } }),
            json!({ "one_time_keys": { "signed_curve25519:A": { "signatures": {} } } }),
            json!({ "one_time_keys": { "signed_curve25519:A": "k" } }),
            json!({
                "fallback_keys": {
                    "signed_curve25519:A": { "key": "k", "signatures": {} },
                    "signed_curve25519:B": { "key": "k", "signatures": {} }
                }
            }),
        ] {
            let (status, _) = post(&harness, &session, "/e2ee/keys/upload", body).await;
            assert_eq!(status, Status::BadRequest);
        }

        // Limit of stored one-time keys (100 in the default config)
        let (status, _) = post(
            &harness,
            &session,
            "/e2ee/keys/upload",
            json!({ "one_time_keys": one_time_keys(&user.id, &session.id, "B", 100) }),
        )
        .await;
        assert_eq!(status, Status::Ok);

        let (status, body) = post(
            &harness,
            &session,
            "/e2ee/keys/upload",
            json!({ "one_time_keys": one_time_keys(&user.id, &session.id, "C", 3) }),
        )
        .await;
        assert_eq!(status, Status::UnprocessableEntity);
        assert!(matches!(error_type(body), ErrorType::PayloadTooLarge));

        let (status, _) = post(
            &harness,
            &session,
            "/e2ee/keys/upload",
            json!({ "one_time_keys": one_time_keys(&user.id, &session.id, "D", 101) }),
        )
        .await;
        assert_eq!(status, Status::UnprocessableEntity);
    }
}
