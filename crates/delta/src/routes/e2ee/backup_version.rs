//! Key backup versions
//! POST /e2ee/backup/version
//! GET /e2ee/backup/version
//! GET /e2ee/backup/version/<version>
//! PUT /e2ee/backup/version/<version>
//! DELETE /e2ee/backup/version/<version>
use revolt_config::config;
use revolt_database::{Database, E2eeBackupVersion, ValidatedTicket};
use revolt_models::v0::{self, E2EE_BACKUP_ALGORITHMS};
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use rocket_empty::EmptyResponse;
use serde_json::Value;

use super::{E2eeSession, invalid, json_size};

/// Backup version in API form
pub async fn version_response(
    db: &Database,
    version: E2eeBackupVersion,
) -> Result<v0::E2eeBackupVersion> {
    let count = db
        .count_e2ee_backup_keys(&version.user_id, &version.id)
        .await?;

    Ok(v0::E2eeBackupVersion {
        algorithm: version.algorithm,
        auth_data: serde_json::from_str(&version.auth_data).unwrap_or_default(),
        count,
        etag: version.etag.to_string(),
        version: version.id,
    })
}

/// Check algorithm and `auth_data` of a backup version
async fn check_version_data(data: &v0::DataE2eeBackupVersion) -> Result<()> {
    if !E2EE_BACKUP_ALGORITHMS.contains(&data.algorithm.as_str()) {
        return Err(invalid("algorithm"));
    }

    let valid = data
        .auth_data
        .as_object()
        .is_some_and(|auth_data| auth_data.get("public_key").is_some_and(Value::is_string));

    if !valid {
        return Err(invalid("auth_data"));
    }

    if json_size(&data.auth_data) > config().await.features.e2ee.max_secret_bytes {
        return Err(create_error!(PayloadTooLarge));
    }

    Ok(())
}

/// # Create Backup Version
///
/// Create a new key backup version. Replacing an existing version deletes its keys
/// and requires an MFA ticket.
#[openapi(tag = "E2EE")]
#[post("/backup/version", data = "<data>")]
pub async fn create(
    db: &State<Database>,
    e2ee: E2eeSession,
    ticket: Option<ValidatedTicket>,
    data: Json<v0::DataE2eeBackupVersion>,
) -> Result<Json<v0::E2eeBackupVersionCreateResponse>> {
    let data = data.into_inner();
    check_version_data(&data).await?;

    // A stolen session token must not be able to wipe the backup
    if ticket.is_none()
        && db
            .fetch_e2ee_backup_version(&e2ee.user.id, None)
            .await?
            .is_some()
    {
        return Err(create_error!(InvalidToken));
    }

    let version = E2eeBackupVersion {
        id: ulid::Ulid::new().to_string(),
        user_id: e2ee.user.id.clone(),
        algorithm: data.algorithm,
        auth_data: data.auth_data.to_string(),
        etag: 0,
        deleted: false,
    };

    db.create_e2ee_backup_version(&version).await?;

    Ok(Json(v0::E2eeBackupVersionCreateResponse {
        version: version.id,
    }))
}

/// # Fetch Current Backup Version
///
/// Fetch the active key backup version.
#[openapi(tag = "E2EE")]
#[get("/backup/version")]
pub async fn fetch_current(
    db: &State<Database>,
    e2ee: E2eeSession,
) -> Result<Json<v0::E2eeBackupVersion>> {
    let version = db
        .fetch_e2ee_backup_version(&e2ee.user.id, None)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;

    version_response(db, version).await.map(Json)
}

/// # Fetch Backup Version
///
/// Fetch a key backup version by its id, only if it was not replaced or deleted.
#[openapi(tag = "E2EE")]
#[get("/backup/version/<version>")]
pub async fn fetch(
    db: &State<Database>,
    e2ee: E2eeSession,
    version: String,
) -> Result<Json<v0::E2eeBackupVersion>> {
    let version = db
        .fetch_e2ee_backup_version(&e2ee.user.id, Some(&version))
        .await?
        .ok_or_else(|| create_error!(NotFound))?;

    version_response(db, version).await.map(Json)
}

/// # Update Backup Version
///
/// Update `auth_data` of a key backup version (for example its signatures).
/// The algorithm and the public key cannot change, create a new version instead.
#[openapi(tag = "E2EE")]
#[put("/backup/version/<version>", data = "<data>")]
pub async fn update(
    db: &State<Database>,
    e2ee: E2eeSession,
    version: String,
    data: Json<v0::DataE2eeBackupVersion>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();
    check_version_data(&data).await?;

    if data.version.as_ref().is_some_and(|id| id != &version) {
        return Err(invalid("version"));
    }

    let current = db
        .fetch_e2ee_backup_version(&e2ee.user.id, Some(&version))
        .await?
        .ok_or_else(|| create_error!(NotFound))?;

    if current.algorithm != data.algorithm {
        return Err(invalid("algorithm"));
    }

    let current_auth_data: Value = serde_json::from_str(&current.auth_data).unwrap_or_default();
    if current_auth_data.get("public_key") != data.auth_data.get("public_key") {
        return Err(invalid("auth_data.public_key"));
    }

    if db
        .update_e2ee_backup_version(&e2ee.user.id, &version, &data.auth_data.to_string())
        .await?
    {
        Ok(EmptyResponse)
    } else {
        Err(create_error!(NotFound))
    }
}

/// # Delete Backup Version
///
/// Delete a key backup version and its keys, requires an MFA ticket.
#[openapi(tag = "E2EE")]
#[delete("/backup/version/<version>")]
pub async fn delete(
    db: &State<Database>,
    e2ee: E2eeSession,
    _ticket: ValidatedTicket,
    version: String,
) -> Result<EmptyResponse> {
    if db
        .delete_e2ee_backup_version(&e2ee.user.id, &version)
        .await?
    {
        Ok(EmptyResponse)
    } else {
        Err(create_error!(NotFound))
    }
}

#[cfg(test)]
mod tests {
    use revolt_database::{MFATicket, Session};
    use rocket::http::{Header, Method, Status};
    use serde_json::{Value, json};

    use crate::routes::e2ee::tests::{get, post, request_with};
    use crate::util::test::TestHarness;

    fn fixture(name: &str) -> Value {
        let fixture = match name {
            "version.create" => include_str!(
                "../../../../core/models/tests/fixtures/e2ee/api/backup/version.create.json"
            ),
            "keys.put" => {
                include_str!("../../../../core/models/tests/fixtures/e2ee/api/backup/keys.put.json")
            }
            _ => unreachable!(),
        };

        serde_json::from_str(fixture).unwrap()
    }

    async fn ticket(harness: &TestHarness, session: &Session) -> Header<'static> {
        let ticket = MFATicket::new(session.user_id.clone(), true);
        ticket.save(&harness.db).await.unwrap();
        Header::new("x-mfa-ticket", ticket.token)
    }

    #[rocket::async_test]
    async fn create_and_fetch() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let (status, _) = get(&harness, &session, "/e2ee/backup/version").await;
        assert_eq!(status, Status::NotFound);

        let request = fixture("version.create")["request"].clone();
        let (status, body) =
            post(&harness, &session, "/e2ee/backup/version", request.clone()).await;
        assert_eq!(status, Status::Ok);
        let version = body["version"].as_str().unwrap().to_string();
        assert_eq!(version.len(), 26);

        let expected = json!({
            "algorithm": request["algorithm"],
            "auth_data": request["auth_data"],
            "count": 0,
            "etag": "0",
            "version": version.clone()
        });

        let (status, body) = get(&harness, &session, "/e2ee/backup/version").await;
        assert_eq!(status, Status::Ok);
        assert_eq!(body, expected);

        let (_, body) = get(
            &harness,
            &session,
            &format!("/e2ee/backup/version/{version}"),
        )
        .await;
        assert_eq!(body, expected);

        // Another user sees nothing of it
        let (_, other, _) = harness.new_user().await;
        let (status, _) = get(&harness, &other, &format!("/e2ee/backup/version/{version}")).await;
        assert_eq!(status, Status::NotFound);

        for body in [
            json!({ "algorithm": "m.megolm_backup.v2", "auth_data": request["auth_data"] }),
            json!({ "algorithm": request["algorithm"], "auth_data": {} }),
        ] {
            let (status, _) = post(&harness, &other, "/e2ee/backup/version", body).await;
            assert_eq!(status, Status::BadRequest);
        }
    }

    #[rocket::async_test]
    async fn replace_requires_mfa() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        let request = fixture("version.create")["request"].clone();

        let (_, body) = post(&harness, &session, "/e2ee/backup/version", request.clone()).await;
        let old = body["version"].as_str().unwrap().to_string();

        let keys = fixture("keys.put")["request"].clone();
        let (status, _) = crate::routes::e2ee::tests::request(
            &harness,
            Method::Put,
            &session,
            &format!("/e2ee/backup/keys?version={old}"),
            Some(keys),
        )
        .await;
        assert_eq!(status, Status::Ok);

        let (status, _) = post(&harness, &session, "/e2ee/backup/version", request.clone()).await;
        assert_eq!(status, Status::Unauthorized);

        let ticket = ticket(&harness, &session).await;
        let (status, body) = request_with(
            &harness,
            Method::Post,
            &session,
            "/e2ee/backup/version",
            Some(request),
            vec![ticket],
        )
        .await;
        assert_eq!(status, Status::Ok);
        let new = body["version"].as_str().unwrap().to_string();
        assert_ne!(old, new);

        // The old version and its keys are gone
        let (status, _) = get(&harness, &session, &format!("/e2ee/backup/version/{old}")).await;
        assert_eq!(status, Status::NotFound);
        assert_eq!(
            harness
                .db
                .count_e2ee_backup_keys(&session.user_id, &old)
                .await
                .unwrap(),
            0
        );

        let (_, body) = get(&harness, &session, "/e2ee/backup/version").await;
        assert_eq!(body["version"], new);
        assert_eq!(body["count"], 0);
    }

    #[rocket::async_test]
    async fn update() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        let request = fixture("version.create")["request"].clone();

        let (_, body) = post(&harness, &session, "/e2ee/backup/version", request.clone()).await;
        let version = body["version"].as_str().unwrap().to_string();
        let path = format!("/e2ee/backup/version/{version}");

        let mut signed = request.clone();
        signed["auth_data"]["signatures"] =
            json!({ "@someone:stoat.invalid": { "ed25519:X": "sig" } });
        signed["version"] = json!(version.clone());

        let mut other_key = request.clone();
        other_key["auth_data"]["public_key"] = json!("another key");

        let mut other_version = signed.clone();
        other_version["version"] = json!("01KZ0000000000000000000009");

        for body in [other_key, other_version] {
            let (status, _) =
                request_with(&harness, Method::Put, &session, &path, Some(body), vec![]).await;
            assert_eq!(status, Status::BadRequest);
        }

        let (status, _) = request_with(
            &harness,
            Method::Put,
            &session,
            &path,
            Some(signed.clone()),
            vec![],
        )
        .await;
        assert_eq!(status, Status::NoContent);

        let (_, body) = get(&harness, &session, &path).await;
        assert_eq!(body["auth_data"], signed["auth_data"]);

        let (status, _) = request_with(
            &harness,
            Method::Put,
            &session,
            "/e2ee/backup/version/01KZ0000000000000000000009",
            Some(request),
            vec![],
        )
        .await;
        assert_eq!(status, Status::NotFound);
    }

    #[rocket::async_test]
    async fn delete_requires_mfa() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        let request = fixture("version.create")["request"].clone();

        let (_, body) = post(&harness, &session, "/e2ee/backup/version", request).await;
        let version = body["version"].as_str().unwrap().to_string();
        let path = format!("/e2ee/backup/version/{version}");

        let (status, _) =
            crate::routes::e2ee::tests::request(&harness, Method::Delete, &session, &path, None)
                .await;
        assert_eq!(status, Status::Unauthorized);

        let ticket = ticket(&harness, &session).await;
        let (status, _) = request_with(
            &harness,
            Method::Delete,
            &session,
            &path,
            None,
            vec![ticket],
        )
        .await;
        assert_eq!(status, Status::NoContent);

        let (status, _) = get(&harness, &session, "/e2ee/backup/version").await;
        assert_eq!(status, Status::NotFound);

        // Without an active version a new one needs no ticket
        let request = fixture("version.create")["request"].clone();
        let (status, _) = post(&harness, &session, "/e2ee/backup/version", request).await;
        assert_eq!(status, Status::Ok);
    }
}
