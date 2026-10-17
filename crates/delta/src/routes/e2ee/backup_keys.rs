//! Backed up Megolm sessions of the current backup version
//! PUT|GET|DELETE /e2ee/backup/keys?version
//! PUT|GET|DELETE /e2ee/backup/keys/<room>?version
//! PUT|GET|DELETE /e2ee/backup/keys/<room>/<session>?version
use std::collections::HashMap;

use revolt_config::config;
use revolt_database::{Database, E2eeBackupKey, E2eeBackupKeyId, E2eeBackupVersion};
use revolt_models::v0::{self, channel_id_from_e2ee};
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use validator::Validate;

use super::{E2eeSession, invalid, json_size};

/// Upper bound of a Megolm session id
const MAX_SESSION_ID_LENGTH: usize = 128;

/// Upper bound of sessions stored by a single request (clients back up in small batches)
const MAX_KEYS_PER_REQUEST: usize = 1_000;

/// Active backup version of the user, which must be the requested one
async fn current_version(
    db: &Database,
    user_id: &str,
    options: &v0::OptionsE2eeBackupKeys,
) -> Result<E2eeBackupVersion> {
    options.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let current = db
        .fetch_e2ee_backup_version(user_id, None)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;

    if current.id != options.version {
        return Err(create_error!(BackupVersionMismatch {
            current_version: current.id
        }));
    }

    Ok(current)
}

/// Room ids are kept exactly as sent, but must be a channel id in Matrix form
fn check_room(room: &str) -> Result<()> {
    channel_id_from_e2ee(room)
        .map(|_| ())
        .ok_or_else(|| invalid("room_id"))
}

fn check_session(session: &str) -> Result<()> {
    if session.is_empty() || session.len() > MAX_SESSION_ID_LENGTH {
        Err(invalid("session_id"))
    } else {
        Ok(())
    }
}

/// Count and etag of the version after a change
async fn update_response(
    db: &Database,
    user_id: &str,
    version: &str,
) -> Result<Json<v0::E2eeKeysBackupUpdateResponse>> {
    let etag = db
        .fetch_e2ee_backup_version(user_id, Some(version))
        .await?
        .map(|version| version.etag)
        .unwrap_or_default();

    Ok(Json(v0::E2eeKeysBackupUpdateResponse {
        count: db.count_e2ee_backup_keys(user_id, version).await?,
        etag: etag.to_string(),
    }))
}

/// Store sessions given as (room, session, data)
async fn store(
    db: &Database,
    e2ee: &E2eeSession,
    options: &v0::OptionsE2eeBackupKeys,
    keys: Vec<(String, String, v0::E2eeKeyBackupData)>,
) -> Result<Json<v0::E2eeKeysBackupUpdateResponse>> {
    let user_id = &e2ee.user.id;
    let version = current_version(db, user_id, options).await?;

    if keys.len() > MAX_KEYS_PER_REQUEST {
        return Err(create_error!(PayloadTooLarge));
    }

    let max_bytes = config().await.features.e2ee.max_backup_key_bytes;
    let keys = keys
        .into_iter()
        .map(|(room, session, data)| {
            check_room(&room)?;
            check_session(&session)?;

            if !data.session_data.is_object() {
                return Err(invalid("session_data"));
            }

            if json_size(&data.session_data) > max_bytes {
                return Err(create_error!(PayloadTooLarge));
            }

            Ok(E2eeBackupKey {
                id: E2eeBackupKeyId {
                    user: user_id.clone(),
                    version: version.id.clone(),
                    room,
                    session,
                },
                first_message_index: data.first_message_index,
                forwarded_count: data.forwarded_count,
                is_verified: data.is_verified,
                session_data: data.session_data.to_string(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    if !keys.is_empty() {
        db.upsert_e2ee_backup_keys(user_id, &version.id, keys)
            .await?;
    }

    update_response(db, user_id, &version.id).await
}

/// Group backed up sessions by room
fn group(keys: Vec<E2eeBackupKey>) -> HashMap<String, v0::E2eeRoomKeyBackup> {
    let mut rooms: HashMap<String, v0::E2eeRoomKeyBackup> = HashMap::new();
    for key in keys {
        let data = key.data();
        rooms
            .entry(key.id.room)
            .or_insert_with(|| v0::E2eeRoomKeyBackup {
                sessions: HashMap::new(),
            })
            .sessions
            .insert(key.id.session, data);
    }

    rooms
}

/// # Store Backup Keys
///
/// Store sessions of any rooms. An existing session is only replaced by a better one
/// (lower first message index, then verified, then fewer forwards).
#[openapi(tag = "E2EE")]
#[put("/backup/keys?<options..>", data = "<data>")]
pub async fn put_all(
    db: &State<Database>,
    e2ee: E2eeSession,
    options: v0::OptionsE2eeBackupKeys,
    data: Json<v0::E2eeKeysBackup>,
) -> Result<Json<v0::E2eeKeysBackupUpdateResponse>> {
    let keys = data
        .into_inner()
        .rooms
        .into_iter()
        .flat_map(|(room, backup)| {
            backup
                .sessions
                .into_iter()
                .map(move |(session, data)| (room.clone(), session, data))
        })
        .collect();

    store(db, &e2ee, &options, keys).await
}

/// # Store Room Backup Keys
///
/// Store sessions of one room.
#[openapi(tag = "E2EE")]
#[put("/backup/keys/<room>?<options..>", data = "<data>")]
pub async fn put_room(
    db: &State<Database>,
    e2ee: E2eeSession,
    room: String,
    options: v0::OptionsE2eeBackupKeys,
    data: Json<v0::E2eeRoomKeyBackup>,
) -> Result<Json<v0::E2eeKeysBackupUpdateResponse>> {
    let keys = data
        .into_inner()
        .sessions
        .into_iter()
        .map(|(session, data)| (room.clone(), session, data))
        .collect();

    store(db, &e2ee, &options, keys).await
}

/// # Store Session Backup Key
///
/// Store a single session.
#[openapi(tag = "E2EE")]
#[put("/backup/keys/<room>/<session>?<options..>", data = "<data>")]
pub async fn put_session(
    db: &State<Database>,
    e2ee: E2eeSession,
    room: String,
    session: String,
    options: v0::OptionsE2eeBackupKeys,
    data: Json<v0::E2eeKeyBackupData>,
) -> Result<Json<v0::E2eeKeysBackupUpdateResponse>> {
    store(
        db,
        &e2ee,
        &options,
        vec![(room, session, data.into_inner())],
    )
    .await
}

/// # Fetch Backup Keys
///
/// Fetch all backed up sessions.
#[openapi(tag = "E2EE")]
#[get("/backup/keys?<options..>")]
pub async fn get_all(
    db: &State<Database>,
    e2ee: E2eeSession,
    options: v0::OptionsE2eeBackupKeys,
) -> Result<Json<v0::E2eeKeysBackup>> {
    let version = current_version(db, &e2ee.user.id, &options).await?;
    let keys = db
        .fetch_e2ee_backup_keys(&e2ee.user.id, &version.id, None, None)
        .await?;

    Ok(Json(v0::E2eeKeysBackup { rooms: group(keys) }))
}

/// # Fetch Room Backup Keys
///
/// Fetch backed up sessions of one room.
#[openapi(tag = "E2EE")]
#[get("/backup/keys/<room>?<options..>")]
pub async fn get_room(
    db: &State<Database>,
    e2ee: E2eeSession,
    room: String,
    options: v0::OptionsE2eeBackupKeys,
) -> Result<Json<v0::E2eeRoomKeyBackup>> {
    check_room(&room)?;
    let version = current_version(db, &e2ee.user.id, &options).await?;
    let keys = db
        .fetch_e2ee_backup_keys(&e2ee.user.id, &version.id, Some(&room), None)
        .await?;

    Ok(Json(group(keys).remove(&room).unwrap_or_else(|| {
        v0::E2eeRoomKeyBackup {
            sessions: HashMap::new(),
        }
    })))
}

/// # Fetch Session Backup Key
///
/// Fetch a single backed up session.
#[openapi(tag = "E2EE")]
#[get("/backup/keys/<room>/<session>?<options..>")]
pub async fn get_session(
    db: &State<Database>,
    e2ee: E2eeSession,
    room: String,
    session: String,
    options: v0::OptionsE2eeBackupKeys,
) -> Result<Json<v0::E2eeKeyBackupData>> {
    check_room(&room)?;
    let version = current_version(db, &e2ee.user.id, &options).await?;
    db.fetch_e2ee_backup_keys(&e2ee.user.id, &version.id, Some(&room), Some(&session))
        .await?
        .into_iter()
        .next()
        .map(|key| Json(key.data()))
        .ok_or_else(|| create_error!(NotFound))
}

/// Delete sessions, optionally of one room or one session
async fn remove(
    db: &Database,
    e2ee: &E2eeSession,
    options: &v0::OptionsE2eeBackupKeys,
    room: Option<&str>,
    session: Option<&str>,
) -> Result<Json<v0::E2eeKeysBackupUpdateResponse>> {
    if let Some(room) = room {
        check_room(room)?;
    }

    let user_id = &e2ee.user.id;
    let version = current_version(db, user_id, options).await?;
    db.delete_e2ee_backup_keys(user_id, &version.id, room, session)
        .await?;

    update_response(db, user_id, &version.id).await
}

/// # Delete Backup Keys
///
/// Delete all backed up sessions.
#[openapi(tag = "E2EE")]
#[delete("/backup/keys?<options..>")]
pub async fn delete_all(
    db: &State<Database>,
    e2ee: E2eeSession,
    options: v0::OptionsE2eeBackupKeys,
) -> Result<Json<v0::E2eeKeysBackupUpdateResponse>> {
    remove(db, &e2ee, &options, None, None).await
}

/// # Delete Room Backup Keys
///
/// Delete backed up sessions of one room.
#[openapi(tag = "E2EE")]
#[delete("/backup/keys/<room>?<options..>")]
pub async fn delete_room(
    db: &State<Database>,
    e2ee: E2eeSession,
    room: String,
    options: v0::OptionsE2eeBackupKeys,
) -> Result<Json<v0::E2eeKeysBackupUpdateResponse>> {
    remove(db, &e2ee, &options, Some(&room), None).await
}

/// # Delete Session Backup Key
///
/// Delete a single backed up session.
#[openapi(tag = "E2EE")]
#[delete("/backup/keys/<room>/<session>?<options..>")]
pub async fn delete_session(
    db: &State<Database>,
    e2ee: E2eeSession,
    room: String,
    session: String,
    options: v0::OptionsE2eeBackupKeys,
) -> Result<Json<v0::E2eeKeysBackupUpdateResponse>> {
    remove(db, &e2ee, &options, Some(&room), Some(&session)).await
}

#[cfg(test)]
mod tests {
    use revolt_database::Session;
    use revolt_result::ErrorType;
    use rocket::http::{Method, Status};
    use serde_json::{Value, json};

    use crate::routes::e2ee::tests::{error_type, get, post, request};
    use crate::util::test::TestHarness;

    const ROOM: &str = "!01kccccccccccccccccccccccc:stoat.invalid";
    const ROOM_PATH: &str = "!01kccccccccccccccccccccccc%3Astoat.invalid";

    fn fixture(name: &str) -> Value {
        let fixture = match name {
            "version.create" => include_str!(
                "../../../../core/models/tests/fixtures/e2ee/api/backup/version.create.json"
            ),
            "keys.put" => {
                include_str!("../../../../core/models/tests/fixtures/e2ee/api/backup/keys.put.json")
            }
            "keys.get" => {
                include_str!("../../../../core/models/tests/fixtures/e2ee/api/backup/keys.get.json")
            }
            _ => unreachable!(),
        };

        serde_json::from_str(fixture).unwrap()
    }

    /// Session id with `/` and `+`, sent percent-encoded in paths
    fn encode(session: &str) -> String {
        session.replace('/', "%2F").replace('+', "%2B")
    }

    async fn new_version(harness: &TestHarness, session: &Session) -> String {
        let (status, body) = post(
            harness,
            session,
            "/e2ee/backup/version",
            fixture("version.create")["request"].clone(),
        )
        .await;
        assert_eq!(status, Status::Ok);
        body["version"].as_str().unwrap().to_string()
    }

    /// Fixture flow: two sessions in one room, read back in every shape
    #[rocket::async_test]
    async fn store_and_fetch() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        let version = new_version(&harness, &session).await;

        let put = fixture("keys.put");
        let (status, body) = request(
            &harness,
            Method::Put,
            &session,
            &format!("/e2ee/backup/keys?version={version}"),
            Some(put["request"].clone()),
        )
        .await;
        assert_eq!(status, Status::Ok);
        assert_eq!(body, put["response"]);

        // The second session of keys.get.json, stored on the session level
        let expected = fixture("keys.get")["response"].clone();
        let sessions = expected["rooms"][ROOM]["sessions"].as_object().unwrap();
        let (second_id, second) = sessions
            .iter()
            .find(|(id, _)| !put["request"]["rooms"][ROOM]["sessions"][*id].is_object())
            .unwrap();

        let (status, body) = request(
            &harness,
            Method::Put,
            &session,
            &format!(
                "/e2ee/backup/keys/{ROOM_PATH}/{}?version={version}",
                encode(second_id)
            ),
            Some(second.clone()),
        )
        .await;
        assert_eq!(status, Status::Ok);
        assert_eq!(body, json!({ "count": 2, "etag": "2" }));

        let (_, body) = get(
            &harness,
            &session,
            &format!("/e2ee/backup/keys?version={version}"),
        )
        .await;
        assert_eq!(body, expected);

        let (_, body) = get(
            &harness,
            &session,
            &format!("/e2ee/backup/keys/{ROOM_PATH}?version={version}"),
        )
        .await;
        assert_eq!(body, expected["rooms"][ROOM]);

        let (status, body) = get(
            &harness,
            &session,
            &format!(
                "/e2ee/backup/keys/{ROOM_PATH}/{}?version={version}",
                encode(second_id)
            ),
        )
        .await;
        assert_eq!(status, Status::Ok);
        assert_eq!(&body, second);

        let (_, body) = get(&harness, &session, "/e2ee/backup/version").await;
        assert_eq!(body["count"], 2);
        assert_eq!(body["etag"], "2");

        // Unknown room and session
        let other_room = "!01kddddddddddddddddddddddd:stoat.invalid";
        let (status, body) = get(
            &harness,
            &session,
            &format!("/e2ee/backup/keys/{other_room}?version={version}"),
        )
        .await;
        assert_eq!(status, Status::Ok);
        assert_eq!(body, json!({ "sessions": {} }));

        let (status, _) = get(
            &harness,
            &session,
            &format!("/e2ee/backup/keys/{ROOM_PATH}/unknown?version={version}"),
        )
        .await;
        assert_eq!(status, Status::NotFound);
    }

    #[rocket::async_test]
    async fn better_key_wins() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        let version = new_version(&harness, &session).await;
        let path = format!("/e2ee/backup/keys/{ROOM_PATH}/S?version={version}");

        let key = |first_message_index: u64, data: &str| {
            json!({
                "first_message_index": first_message_index,
                "forwarded_count": 0,
                "is_verified": false,
                "session_data": { "ciphertext": data }
            })
        };

        let (_, body) = request(
            &harness,
            Method::Put,
            &session,
            &path,
            Some(key(5, "first")),
        )
        .await;
        assert_eq!(body, json!({ "count": 1, "etag": "1" }));

        // Worse key: nothing changes, not even the etag
        let (_, body) = request(
            &harness,
            Method::Put,
            &session,
            &path,
            Some(key(7, "worse")),
        )
        .await;
        assert_eq!(body, json!({ "count": 1, "etag": "1" }));

        let (_, body) = get(&harness, &session, &path).await;
        assert_eq!(body["session_data"]["ciphertext"], "first");

        let (_, body) = request(
            &harness,
            Method::Put,
            &session,
            &path,
            Some(key(2, "better")),
        )
        .await;
        assert_eq!(body, json!({ "count": 1, "etag": "2" }));

        let (_, body) = get(&harness, &session, &path).await;
        assert_eq!(body["session_data"]["ciphertext"], "better");
    }

    #[rocket::async_test]
    async fn version_must_be_current() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let (status, _) = get(
            &harness,
            &session,
            "/e2ee/backup/keys?version=01KZ0000000000000000000001",
        )
        .await;
        assert_eq!(status, Status::NotFound);

        let version = new_version(&harness, &session).await;
        let (status, body) = request(
            &harness,
            Method::Put,
            &session,
            "/e2ee/backup/keys?version=01KZ0000000000000000000001",
            Some(fixture("keys.put")["request"].clone()),
        )
        .await;
        assert_eq!(status, Status::Conflict);
        assert!(matches!(
            error_type(body),
            ErrorType::BackupVersionMismatch { current_version } if current_version == version
        ));

        // The version is required (form error)
        let (status, _) = get(&harness, &session, "/e2ee/backup/keys").await;
        assert_eq!(status, Status::UnprocessableEntity);
    }

    #[rocket::async_test]
    async fn invalid_keys() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        let version = new_version(&harness, &session).await;

        let key = |session_data: Value| {
            json!({
                "first_message_index": 0,
                "forwarded_count": 0,
                "is_verified": false,
                "session_data": session_data
            })
        };

        for (room, data, status) in [
            (
                "!01KCCCCCCCCCCCCCCCCCCCCCCC:stoat.invalid",
                key(json!({})),
                Status::BadRequest,
            ),
            (
                "01kccccccccccccccccccccccc",
                key(json!({})),
                Status::BadRequest,
            ),
            (ROOM, key(json!("text")), Status::BadRequest),
            // 4 KiB in the default config
            (
                ROOM,
                key(json!({ "ciphertext": "x".repeat(4_096) })),
                Status::UnprocessableEntity,
            ),
        ] {
            let (actual, _) = request(
                &harness,
                Method::Put,
                &session,
                &format!("/e2ee/backup/keys?version={version}"),
                Some(json!({ "rooms": { room: { "sessions": { "S": data } } } })),
            )
            .await;
            assert_eq!(actual, status, "{room}");
        }

        let (status, _) = request(
            &harness,
            Method::Put,
            &session,
            &format!(
                "/e2ee/backup/keys/{ROOM_PATH}/{}?version={version}",
                "S".repeat(129)
            ),
            Some(key(json!({}))),
        )
        .await;
        assert_eq!(status, Status::BadRequest);

        let (_, body) = get(&harness, &session, "/e2ee/backup/version").await;
        assert_eq!(body["count"], 0);
    }

    #[rocket::async_test]
    async fn delete_levels() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        let version = new_version(&harness, &session).await;

        let key = json!({
            "first_message_index": 0,
            "forwarded_count": 0,
            "is_verified": false,
            "session_data": {}
        });

        let other_room = "!01kddddddddddddddddddddddd:stoat.invalid";
        let (status, body) = request(
            &harness,
            Method::Put,
            &session,
            &format!("/e2ee/backup/keys?version={version}"),
            Some(json!({
                "rooms": {
                    ROOM: { "sessions": { "A": key.clone(), "B": key.clone() } },
                    other_room: { "sessions": { "C": key.clone(), "D": key } }
                }
            })),
        )
        .await;
        assert_eq!(status, Status::Ok);
        assert_eq!(body, json!({ "count": 4, "etag": "1" }));

        let (_, body) = request(
            &harness,
            Method::Delete,
            &session,
            &format!("/e2ee/backup/keys/{ROOM_PATH}/A?version={version}"),
            None,
        )
        .await;
        assert_eq!(body, json!({ "count": 3, "etag": "2" }));

        let (_, body) = request(
            &harness,
            Method::Delete,
            &session,
            &format!("/e2ee/backup/keys/{ROOM_PATH}?version={version}"),
            None,
        )
        .await;
        assert_eq!(body, json!({ "count": 2, "etag": "3" }));

        let (_, body) = request(
            &harness,
            Method::Delete,
            &session,
            &format!("/e2ee/backup/keys?version={version}"),
            None,
        )
        .await;
        assert_eq!(body, json!({ "count": 0, "etag": "4" }));
    }
}
