//! Count keys of the current device
//! GET /e2ee/keys/count
use revolt_database::Database;
use revolt_models::v0;
use revolt_result::Result;
use rocket::{State, serde::json::Json};

use super::{E2eeSession, key_counts};

/// # Count Keys
///
/// Number of unclaimed one-time keys and algorithms of the unused fallback key
/// of the current device.
#[openapi(tag = "E2EE")]
#[get("/keys/count")]
pub async fn count(
    db: &State<Database>,
    e2ee: E2eeSession,
) -> Result<Json<v0::E2eeKeysCountResponse>> {
    let (one_time_key_counts, device_unused_fallback_key_types) =
        key_counts(db, e2ee.device_id()).await?;

    Ok(Json(v0::E2eeKeysCountResponse {
        one_time_key_counts,
        device_unused_fallback_key_types,
    }))
}

#[cfg(test)]
mod tests {
    use rocket::http::Status;
    use serde_json::{Value, json};

    use crate::routes::e2ee::tests::{get, new_device_user, one_time_keys, post};
    use crate::util::test::TestHarness;

    /// Same fields as `fixtures/e2ee/api/keys/count.json`
    #[rocket::async_test]
    async fn count() {
        let harness = TestHarness::new().await;
        let (_, session, user) = new_device_user(&harness).await;

        let (status, body) = get(&harness, &session, "/e2ee/keys/count").await;
        assert_eq!(status, Status::Ok);
        assert_eq!(
            body,
            json!({
                "one_time_key_counts": { "signed_curve25519": 0 },
                "device_unused_fallback_key_types": []
            })
        );

        post(
            &harness,
            &session,
            "/e2ee/keys/upload",
            json!({ "one_time_keys": one_time_keys(&user.id, &session.id, "A", 50) }),
        )
        .await;

        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../core/models/tests/fixtures/e2ee/api/keys/count.json"
        ))
        .unwrap();

        let (_, body) = get(&harness, &session, "/e2ee/keys/count").await;
        assert_eq!(body, fixture["response"]);
    }
}
