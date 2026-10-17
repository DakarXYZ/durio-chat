//! Secret storage (opaque to the server)
//! GET /e2ee/secrets/<type>
//! PUT /e2ee/secrets/<type>
use revolt_config::config;
use revolt_database::{Database, ValidatedTicket};
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use rocket_empty::EmptyResponse;
use serde_json::Value;

use super::{E2eeSession, invalid, json_size};

/// Secret types with a fixed name
const SECRET_TYPES: [&str; 5] = [
    "m.megolm_backup.v1",
    "m.cross_signing.master",
    "m.cross_signing.self_signing",
    "m.cross_signing.user_signing",
    "m.secret_storage.default_key",
];

/// Prefix of secret storage key descriptions, followed by the key id
const SECRET_STORAGE_KEY_PREFIX: &str = "m.secret_storage.key.";

/// Upper bound of a secret storage key id
const MAX_KEY_ID_LENGTH: usize = 64;

/// Upper bound of secrets per user
const MAX_SECRETS: usize = 32;

/// Whether the secret type may be stored
fn is_allowed(secret_type: &str) -> bool {
    SECRET_TYPES.contains(&secret_type)
        || secret_type
            .strip_prefix(SECRET_STORAGE_KEY_PREFIX)
            .is_some_and(|id| !id.is_empty() && id.len() <= MAX_KEY_ID_LENGTH)
}

/// # Fetch Secret
///
/// Fetch an entry of the secret storage.
#[openapi(tag = "E2EE")]
#[get("/secrets/<secret_type>")]
pub async fn fetch(
    db: &State<Database>,
    e2ee: E2eeSession,
    secret_type: String,
) -> Result<Json<Value>> {
    if !is_allowed(&secret_type) {
        return Err(invalid("type"));
    }

    let content = db
        .fetch_e2ee_secret(&e2ee.user.id, &secret_type)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;

    Ok(Json(serde_json::from_str(&content).unwrap_or_default()))
}

/// # Store Secret
///
/// Create or replace an entry of the secret storage. Cross-signing keys
/// (`m.cross_signing.*`) require an MFA ticket.
#[openapi(tag = "E2EE")]
#[put("/secrets/<secret_type>", data = "<data>")]
pub async fn store(
    db: &State<Database>,
    e2ee: E2eeSession,
    ticket: Option<ValidatedTicket>,
    secret_type: String,
    data: Json<Value>,
) -> Result<EmptyResponse> {
    let content = data.into_inner();

    if !is_allowed(&secret_type) {
        return Err(invalid("type"));
    }

    if !content.is_object() {
        return Err(invalid("content"));
    }

    if json_size(&content) > config().await.features.e2ee.max_secret_bytes {
        return Err(create_error!(PayloadTooLarge));
    }

    if secret_type.starts_with("m.cross_signing.") && ticket.is_none() {
        return Err(create_error!(InvalidToken));
    }

    let types = db.fetch_e2ee_secret_types(&e2ee.user.id).await?;
    if !types.contains(&secret_type) && types.len() >= MAX_SECRETS {
        return Err(create_error!(InvalidOperation));
    }

    db.set_e2ee_secret(&e2ee.user.id, &secret_type, &content.to_string())
        .await
        .map(|_| EmptyResponse)
}

#[cfg(test)]
mod tests {
    use revolt_database::MFATicket;
    use rocket::http::{Header, Method, Status};
    use serde_json::json;

    use crate::routes::e2ee::tests::{get, request, request_with};
    use crate::util::test::TestHarness;

    #[rocket::async_test]
    async fn store_and_fetch() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        let path = "/e2ee/secrets/m.secret_storage.key.ABCDEF";
        let content = json!({ "algorithm": "m.secret_storage.v1.aes-hmac-sha2", "iv": "x" });

        let (status, _) = get(&harness, &session, path).await;
        assert_eq!(status, Status::NotFound);

        let (status, _) =
            request(&harness, Method::Put, &session, path, Some(content.clone())).await;
        assert_eq!(status, Status::NoContent);

        let (status, body) = get(&harness, &session, path).await;
        assert_eq!(status, Status::Ok);
        assert_eq!(body, content);

        // Not visible to anyone else
        let (_, other, _) = harness.new_user().await;
        let (status, _) = get(&harness, &other, path).await;
        assert_eq!(status, Status::NotFound);
    }

    #[rocket::async_test]
    async fn invalid_secrets() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        let long_key = format!("/e2ee/secrets/m.secret_storage.key.{}", "k".repeat(65));

        for (path, content, status) in [
            ("/e2ee/secrets/m.anything", json!({}), Status::BadRequest),
            (
                "/e2ee/secrets/m.secret_storage.key.",
                json!({}),
                Status::BadRequest,
            ),
            (long_key.as_str(), json!({}), Status::BadRequest),
            (
                "/e2ee/secrets/m.megolm_backup.v1",
                json!("text"),
                Status::BadRequest,
            ),
            (
                // 16 KiB in the default config
                "/e2ee/secrets/m.megolm_backup.v1",
                json!({ "data": "x".repeat(16_384) }),
                Status::UnprocessableEntity,
            ),
        ] {
            let (actual, _) = request(&harness, Method::Put, &session, path, Some(content)).await;
            assert_eq!(actual, status, "{path}");
        }
    }

    #[rocket::async_test]
    async fn cross_signing_requires_mfa() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        let path = "/e2ee/secrets/m.cross_signing.master";

        let (status, _) = request(&harness, Method::Put, &session, path, Some(json!({}))).await;
        assert_eq!(status, Status::Unauthorized);

        let ticket = MFATicket::new(session.user_id.clone(), true);
        ticket.save(&harness.db).await.unwrap();

        let (status, _) = request_with(
            &harness,
            Method::Put,
            &session,
            path,
            Some(json!({ "encrypted": {} })),
            vec![Header::new("x-mfa-ticket", ticket.token)],
        )
        .await;
        assert_eq!(status, Status::NoContent);

        let (_, body) = get(&harness, &session, path).await;
        assert_eq!(body, json!({ "encrypted": {} }));
    }

    #[rocket::async_test]
    async fn too_many_secrets() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        for n in 0..32 {
            let (status, _) = request(
                &harness,
                Method::Put,
                &session,
                &format!("/e2ee/secrets/m.secret_storage.key.K{n}"),
                Some(json!({})),
            )
            .await;
            assert_eq!(status, Status::NoContent);
        }

        let (status, _) = request(
            &harness,
            Method::Put,
            &session,
            "/e2ee/secrets/m.secret_storage.key.K32",
            Some(json!({})),
        )
        .await;
        assert_eq!(status, Status::BadRequest);

        // Replacing an existing one is fine
        let (status, _) = request(
            &harness,
            Method::Put,
            &session,
            "/e2ee/secrets/m.secret_storage.key.K0",
            Some(json!({ "replaced": true })),
        )
        .await;
        assert_eq!(status, Status::NoContent);
    }
}
