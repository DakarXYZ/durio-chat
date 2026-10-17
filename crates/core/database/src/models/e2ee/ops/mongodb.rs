use std::collections::HashMap;

use bson::{Bson, Document, to_bson, to_document};
use futures::StreamExt;
use mongodb::{
    error::{Error, ErrorKind, WriteFailure},
    options::{
        FindOneAndDeleteOptions, FindOneAndUpdateOptions, FindOptions, InsertManyOptions,
        ReturnDocument,
    },
};
use revolt_models::v0::ChannelEncryption;
use revolt_result::Result;

use crate::{
    AbstractE2ee, E2eeBackupKey, E2eeBackupKeyId, E2eeBackupVersion, E2eeClaimedKey, E2eeDevice,
    E2eeFallbackKey, E2eeOneTimeKey, E2eeSecret, E2eeSecretId, E2eeToDeviceMessage, File,
    FileUsedFor, FileUsedForType, MongoDb,
};

const DEVICES: &str = "e2ee_devices";
const ONE_TIME_KEYS: &str = "e2ee_one_time_keys";
const FALLBACK_KEYS: &str = "e2ee_fallback_keys";
const TO_DEVICE: &str = "e2ee_to_device";
const BACKUP_VERSIONS: &str = "e2ee_backup_versions";
const BACKUP_KEYS: &str = "e2ee_backup_keys";
const SECRETS: &str = "e2ee_secrets";
const CHANNELS: &str = "channels";
const ATTACHMENTS: &str = "attachments";

/// Attempts to store a single backed up session against concurrent writers
const BACKUP_KEY_ATTEMPTS: usize = 3;

/// Whether the error only consists of duplicate key violations (E11000)
fn is_duplicate_key(error: &Error) -> bool {
    match error.kind.as_ref() {
        ErrorKind::Write(WriteFailure::WriteError(error)) => error.code == 11000,
        ErrorKind::Command(error) => error.code == 11000,
        ErrorKind::InsertMany(error) => {
            error.write_concern_error.is_none()
                && error
                    .write_errors
                    .as_ref()
                    .is_some_and(|errors| errors.iter().all(|error| error.code == 11000))
        }
        _ => false,
    }
}

/// Indices of documents rejected as duplicates by `insert_many`
fn duplicate_indices(error: &Error) -> Vec<usize> {
    match error.kind.as_ref() {
        ErrorKind::InsertMany(error) => error
            .write_errors
            .iter()
            .flatten()
            .filter(|error| error.code == 11000)
            .map(|error| error.index)
            .collect(),
        _ => vec![],
    }
}

/// Count documents grouped by a field
async fn count_by(
    db: &MongoDb,
    collection: &'static str,
    filter: Document,
    field: &str,
) -> Result<HashMap<String, u64>> {
    let mut cursor = db
        .col::<Document>(collection)
        .aggregate(vec![
            doc! { "$match": filter },
            doc! { "$group": { "_id": format!("${field}"), "count": { "$sum": 1_i32 } } },
        ])
        .await
        .map_err(|_| create_database_error!("aggregate", collection))?;

    let mut counts = HashMap::new();
    while let Some(entry) = cursor.next().await {
        let entry = entry.map_err(|_| create_database_error!("aggregate", collection))?;
        let count = match entry.get("count") {
            Some(Bson::Int32(n)) => *n as u64,
            Some(Bson::Int64(n)) => *n as u64,
            _ => 0,
        };

        if let Ok(key) = entry.get_str("_id") {
            counts.insert(key.to_string(), count);
        }
    }

    Ok(counts)
}

/// Filter for backed up sessions of a version, optionally of one room or one session
fn backup_keys_filter(
    user_id: &str,
    version: &str,
    room: Option<&str>,
    session: Option<&str>,
) -> Document {
    let mut filter = doc! {
        "_id.user": user_id,
        "_id.version": version,
    };

    if let Some(room) = room {
        filter.insert("_id.room", room);
    }

    if let Some(session) = session {
        filter.insert("_id.session", session);
    }

    filter
}

impl MongoDb {
    /// Store one backed up session, retrying against concurrent writers
    async fn upsert_e2ee_backup_key(&self, key: &E2eeBackupKey) -> Result<()> {
        let id = to_bson(&key.id).map_err(|_| create_database_error!("to_bson", BACKUP_KEYS))?;

        for _ in 0..BACKUP_KEY_ATTEMPTS {
            let existing = self
                .col::<E2eeBackupKey>(BACKUP_KEYS)
                .find_one(doc! { "_id": id.clone() })
                .await
                .map_err(|_| create_database_error!("find_one", BACKUP_KEYS))?;

            match existing {
                None => match self.col::<E2eeBackupKey>(BACKUP_KEYS).insert_one(key).await {
                    Ok(_) => return Ok(()),
                    Err(error) if is_duplicate_key(&error) => continue,
                    Err(_) => return Err(create_database_error!("insert_one", BACKUP_KEYS)),
                },
                Some(existing) => {
                    if !key.is_better_than(&existing) {
                        return Ok(());
                    }

                    // Optimistic lock on the values the decision was based on
                    let result = self
                        .col::<E2eeBackupKey>(BACKUP_KEYS)
                        .replace_one(
                            doc! {
                                "_id": id.clone(),
                                "first_message_index": existing.first_message_index as i64,
                                "forwarded_count": existing.forwarded_count as i64,
                                "is_verified": existing.is_verified,
                            },
                            key,
                        )
                        .await
                        .map_err(|_| create_database_error!("replace_one", BACKUP_KEYS))?;

                    if result.matched_count > 0 {
                        return Ok(());
                    }
                }
            }
        }

        Ok(())
    }

    /// Increment the etag of a backup version
    async fn bump_e2ee_backup_etag(&self, user_id: &str, version: &str) -> Result<()> {
        self.col::<Document>(BACKUP_VERSIONS)
            .update_one(
                doc! { "_id": version, "user_id": user_id },
                doc! { "$inc": { "etag": 1_i64 } },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", BACKUP_VERSIONS))
    }
}

#[async_trait]
impl AbstractE2ee for MongoDb {
    async fn insert_e2ee_device(&self, device: &E2eeDevice) -> Result<bool> {
        match self.col::<E2eeDevice>(DEVICES).insert_one(device).await {
            Ok(_) => Ok(true),
            Err(error) if is_duplicate_key(&error) => Ok(false),
            Err(_) => Err(create_database_error!("insert_one", DEVICES)),
        }
    }

    async fn fetch_e2ee_device(&self, device_id: &str) -> Result<E2eeDevice> {
        query!(self, find_one_by_id, DEVICES, device_id)?
            .ok_or_else(|| create_error!(DeviceNotFound))
    }

    async fn fetch_e2ee_devices(&self, user_ids: &[String]) -> Result<Vec<E2eeDevice>> {
        query!(
            self,
            find,
            DEVICES,
            doc! {
                "user_id": {
                    "$in": user_ids
                }
            }
        )
    }

    async fn delete_e2ee_devices(
        &self,
        user_id: &str,
        only: Option<&str>,
        except: Option<&str>,
    ) -> Result<Vec<String>> {
        let mut id = doc! {};
        if let Some(only) = only {
            id.insert("$eq", only);
        }

        if let Some(except) = except {
            id.insert("$ne", except);
        }

        let mut filter = doc! { "user_id": user_id };
        if !id.is_empty() {
            filter.insert("_id", id);
        }

        let devices: Vec<E2eeDevice> = query!(self, find, DEVICES, filter)?;
        let ids: Vec<String> = devices.into_iter().map(|device| device.id).collect();

        if !ids.is_empty() {
            self.col::<Document>(DEVICES)
                .delete_many(doc! {
                    "_id": { "$in": &ids },
                    "user_id": user_id
                })
                .await
                .map_err(|_| create_database_error!("delete_many", DEVICES))?;
        }

        Ok(ids)
    }

    async fn delete_e2ee_device_data(&self, device_ids: &[String]) -> Result<()> {
        if device_ids.is_empty() {
            return Ok(());
        }

        for (collection, field) in [
            (ONE_TIME_KEYS, "device_id"),
            (FALLBACK_KEYS, "_id"),
            (TO_DEVICE, "recipient_device"),
        ] {
            self.col::<Document>(collection)
                .delete_many(doc! { field: { "$in": device_ids } })
                .await
                .map_err(|_| create_database_error!("delete_many", collection))?;
        }

        Ok(())
    }

    async fn insert_one_time_keys(&self, keys: Vec<E2eeOneTimeKey>) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }

        match self
            .col::<E2eeOneTimeKey>(ONE_TIME_KEYS)
            .insert_many(keys)
            .with_options(InsertManyOptions::builder().ordered(false).build())
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if is_duplicate_key(&error) => Ok(()),
            Err(_) => Err(create_database_error!("insert_many", ONE_TIME_KEYS)),
        }
    }

    async fn claim_one_time_key(
        &self,
        device_id: &str,
        algorithm: &str,
    ) -> Result<Option<E2eeClaimedKey>> {
        let key = self
            .col::<E2eeOneTimeKey>(ONE_TIME_KEYS)
            .find_one_and_delete(doc! {
                "device_id": device_id,
                "algorithm": algorithm
            })
            .with_options(
                FindOneAndDeleteOptions::builder()
                    .sort(doc! { "_id": 1_i32 })
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_one_and_delete", ONE_TIME_KEYS))?;

        if let Some(key) = key {
            return Ok(Some(E2eeClaimedKey {
                algorithm: key.algorithm,
                key_id: key.key_id,
                key: key.key,
                fallback: false,
            }));
        }

        Ok(self
            .col::<E2eeFallbackKey>(FALLBACK_KEYS)
            .find_one_and_update(
                doc! {
                    "_id": device_id,
                    "algorithm": algorithm
                },
                doc! {
                    "$set": {
                        "used": true
                    }
                },
            )
            .await
            .map_err(|_| create_database_error!("find_one_and_update", FALLBACK_KEYS))?
            .map(|key| E2eeClaimedKey {
                algorithm: key.algorithm,
                key_id: key.key_id,
                key: key.key,
                fallback: true,
            }))
    }

    async fn count_one_time_keys(&self, device_id: &str) -> Result<HashMap<String, usize>> {
        Ok(count_by(
            self,
            ONE_TIME_KEYS,
            doc! { "device_id": device_id },
            "algorithm",
        )
        .await?
        .into_iter()
        .map(|(algorithm, count)| (algorithm, count as usize))
        .collect())
    }

    async fn set_fallback_key(&self, key: &E2eeFallbackKey) -> Result<()> {
        // Same key id already stored → upsert hits the existing _id, nothing changes
        match self
            .col::<E2eeFallbackKey>(FALLBACK_KEYS)
            .replace_one(
                doc! {
                    "_id": &key.id,
                    "key_id": { "$ne": &key.key_id }
                },
                key,
            )
            .upsert(true)
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if is_duplicate_key(&error) => Ok(()),
            Err(_) => Err(create_database_error!("replace_one", FALLBACK_KEYS)),
        }
    }

    async fn fetch_unused_fallback_key_types(&self, device_id: &str) -> Result<Vec<String>> {
        let keys: Vec<E2eeFallbackKey> = query!(
            self,
            find,
            FALLBACK_KEYS,
            doc! {
                "_id": device_id,
                "used": false
            }
        )?;

        Ok(keys.into_iter().map(|key| key.algorithm).collect())
    }

    async fn insert_to_device(&self, messages: Vec<E2eeToDeviceMessage>) -> Result<()> {
        if messages.is_empty() {
            return Ok(());
        }

        // `expires_at` must be a BSON date for the TTL index, Timestamp would
        // serialise as a string or a number
        let documents = messages
            .iter()
            .map(|message| {
                let mut document = to_document(message)?;
                document.insert(
                    "expires_at",
                    bson::DateTime::from_millis(
                        message
                            .expires_at
                            .duration_since(iso8601_timestamp::Timestamp::UNIX_EPOCH)
                            .whole_milliseconds() as i64,
                    ),
                );
                Ok(document)
            })
            .collect::<std::result::Result<Vec<Document>, bson::ser::Error>>()
            .map_err(|_| create_database_error!("to_document", TO_DEVICE))?;

        match self
            .col::<Document>(TO_DEVICE)
            .insert_many(documents)
            .with_options(InsertManyOptions::builder().ordered(false).build())
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if is_duplicate_key(&error) => Ok(()),
            Err(_) => Err(create_database_error!("insert_many", TO_DEVICE)),
        }
    }

    async fn fetch_to_device(
        &self,
        device_id: &str,
        limit: usize,
    ) -> Result<Vec<E2eeToDeviceMessage>> {
        query!(
            self,
            find_with_options,
            TO_DEVICE,
            doc! {
                "recipient_device": device_id
            },
            FindOptions::builder()
                .sort(doc! { "_id": 1_i32 })
                .limit(limit as i64)
                .build()
        )
    }

    async fn ack_to_device(&self, device_id: &str, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }

        self.col::<Document>(TO_DEVICE)
            .delete_many(doc! {
                "_id": { "$in": ids },
                "recipient_device": device_id
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", TO_DEVICE))
    }

    async fn count_pending_to_device(&self, device_ids: &[String]) -> Result<HashMap<String, u64>> {
        if device_ids.is_empty() {
            return Ok(HashMap::new());
        }

        count_by(
            self,
            TO_DEVICE,
            doc! { "recipient_device": { "$in": device_ids } },
            "recipient_device",
        )
        .await
    }

    async fn fetch_e2ee_backup_version(
        &self,
        user_id: &str,
        version: Option<&str>,
    ) -> Result<Option<E2eeBackupVersion>> {
        let mut filter = doc! {
            "user_id": user_id,
            "deleted": false
        };

        if let Some(version) = version {
            filter.insert("_id", version);
        }

        query!(self, find_one, BACKUP_VERSIONS, filter)
    }

    async fn create_e2ee_backup_version(&self, version: &E2eeBackupVersion) -> Result<()> {
        // Retire the active version and drop its keys
        let active: Vec<E2eeBackupVersion> = query!(
            self,
            find,
            BACKUP_VERSIONS,
            doc! {
                "user_id": &version.user_id,
                "deleted": false
            }
        )?;
        let replaced: Vec<String> = active.into_iter().map(|version| version.id).collect();

        if !replaced.is_empty() {
            self.col::<Document>(BACKUP_VERSIONS)
                .update_many(
                    doc! { "_id": { "$in": &replaced } },
                    doc! { "$set": { "deleted": true } },
                )
                .await
                .map_err(|_| create_database_error!("update_many", BACKUP_VERSIONS))?;

            self.col::<Document>(BACKUP_KEYS)
                .delete_many(doc! {
                    "_id.user": &version.user_id,
                    "_id.version": { "$in": &replaced }
                })
                .await
                .map_err(|_| create_database_error!("delete_many", BACKUP_KEYS))?;
        }

        // Unique partial index: one active version per user
        match self
            .col::<E2eeBackupVersion>(BACKUP_VERSIONS)
            .insert_one(version)
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if is_duplicate_key(&error) => Err(create_error!(BackupVersionMismatch {
                current_version: self
                    .fetch_e2ee_backup_version(&version.user_id, None)
                    .await?
                    .map(|version| version.id)
                    .unwrap_or_default()
            })),
            Err(_) => Err(create_database_error!("insert_one", BACKUP_VERSIONS)),
        }
    }

    async fn update_e2ee_backup_version(
        &self,
        user_id: &str,
        version: &str,
        auth_data: &str,
    ) -> Result<bool> {
        self.col::<Document>(BACKUP_VERSIONS)
            .update_one(
                doc! {
                    "_id": version,
                    "user_id": user_id,
                    "deleted": false
                },
                doc! {
                    "$set": {
                        "auth_data": auth_data
                    }
                },
            )
            .await
            .map(|result| result.matched_count > 0)
            .map_err(|_| create_database_error!("update_one", BACKUP_VERSIONS))
    }

    async fn delete_e2ee_backup_version(&self, user_id: &str, version: &str) -> Result<bool> {
        let result = self
            .col::<Document>(BACKUP_VERSIONS)
            .update_one(
                doc! {
                    "_id": version,
                    "user_id": user_id,
                    "deleted": false
                },
                doc! {
                    "$set": {
                        "deleted": true
                    }
                },
            )
            .await
            .map_err(|_| create_database_error!("update_one", BACKUP_VERSIONS))?;

        if result.matched_count == 0 {
            return Ok(false);
        }

        self.col::<Document>(BACKUP_KEYS)
            .delete_many(backup_keys_filter(user_id, version, None, None))
            .await
            .map_err(|_| create_database_error!("delete_many", BACKUP_KEYS))?;

        Ok(true)
    }

    async fn upsert_e2ee_backup_keys(
        &self,
        user_id: &str,
        version: &str,
        keys: Vec<E2eeBackupKey>,
    ) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }

        let ids = keys
            .iter()
            .map(|key| to_bson(&key.id))
            .collect::<std::result::Result<Vec<Bson>, bson::ser::Error>>()
            .map_err(|_| create_database_error!("to_bson", BACKUP_KEYS))?;

        let existing: Vec<E2eeBackupKey> =
            query!(self, find, BACKUP_KEYS, doc! { "_id": { "$in": ids } })?;
        let existing: HashMap<E2eeBackupKeyId, E2eeBackupKey> = existing
            .into_iter()
            .map(|key| (key.id.clone(), key))
            .collect();

        let mut new = vec![];
        let mut contested = vec![];
        for key in keys {
            match existing.get(&key.id) {
                None => new.push(key),
                Some(existing) if key.is_better_than(existing) => contested.push(key),
                Some(_) => {}
            }
        }

        if new.is_empty() && contested.is_empty() {
            return Ok(());
        }

        if !new.is_empty()
            && let Err(error) = self
                .col::<E2eeBackupKey>(BACKUP_KEYS)
                .insert_many(&new)
                .with_options(InsertManyOptions::builder().ordered(false).build())
                .await
        {
            if !is_duplicate_key(&error) {
                return Err(create_database_error!("insert_many", BACKUP_KEYS));
            }

            // Inserted concurrently by someone else, compare against theirs
            for index in duplicate_indices(&error) {
                if let Some(key) = new.get(index) {
                    contested.push(key.clone());
                }
            }
        }

        for key in &contested {
            self.upsert_e2ee_backup_key(key).await?;
        }

        self.bump_e2ee_backup_etag(user_id, version).await
    }

    async fn fetch_e2ee_backup_keys(
        &self,
        user_id: &str,
        version: &str,
        room: Option<&str>,
        session: Option<&str>,
    ) -> Result<Vec<E2eeBackupKey>> {
        query!(
            self,
            find,
            BACKUP_KEYS,
            backup_keys_filter(user_id, version, room, session)
        )
    }

    async fn delete_e2ee_backup_keys(
        &self,
        user_id: &str,
        version: &str,
        room: Option<&str>,
        session: Option<&str>,
    ) -> Result<()> {
        self.col::<Document>(BACKUP_KEYS)
            .delete_many(backup_keys_filter(user_id, version, room, session))
            .await
            .map_err(|_| create_database_error!("delete_many", BACKUP_KEYS))?;

        self.bump_e2ee_backup_etag(user_id, version).await
    }

    async fn count_e2ee_backup_keys(&self, user_id: &str, version: &str) -> Result<u64> {
        query!(
            self,
            count_documents,
            BACKUP_KEYS,
            backup_keys_filter(user_id, version, None, None)
        )
    }

    async fn fetch_e2ee_secret(&self, user_id: &str, secret_type: &str) -> Result<Option<String>> {
        let id = to_bson(&E2eeSecretId {
            user: user_id.to_string(),
            secret_type: secret_type.to_string(),
        })
        .map_err(|_| create_database_error!("to_bson", SECRETS))?;

        let secret: Option<E2eeSecret> = query!(self, find_one, SECRETS, doc! { "_id": id })?;
        Ok(secret.map(|secret| secret.content))
    }

    async fn set_e2ee_secret(&self, user_id: &str, secret_type: &str, content: &str) -> Result<()> {
        let secret = E2eeSecret {
            id: E2eeSecretId {
                user: user_id.to_string(),
                secret_type: secret_type.to_string(),
            },
            content: content.to_string(),
        };

        let id = to_bson(&secret.id).map_err(|_| create_database_error!("to_bson", SECRETS))?;
        self.col::<E2eeSecret>(SECRETS)
            .replace_one(doc! { "_id": id }, &secret)
            .upsert(true)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("replace_one", SECRETS))
    }

    async fn fetch_e2ee_secret_types(&self, user_id: &str) -> Result<Vec<String>> {
        let secrets: Vec<E2eeSecret> = query!(self, find, SECRETS, doc! { "_id.user": user_id })?;
        Ok(secrets
            .into_iter()
            .map(|secret| secret.id.secret_type)
            .collect())
    }

    async fn delete_e2ee_user_data(&self, user_id: &str) -> Result<()> {
        let devices = self.delete_e2ee_devices(user_id, None, None).await?;
        self.delete_e2ee_device_data(&devices).await?;

        // Keys of devices deleted earlier without the cascade are matched by user too
        for (collection, filter) in [
            (ONE_TIME_KEYS, doc! { "user_id": user_id }),
            (FALLBACK_KEYS, doc! { "user_id": user_id }),
            (TO_DEVICE, doc! { "recipient_user": user_id }),
            (BACKUP_KEYS, doc! { "_id.user": user_id }),
            (BACKUP_VERSIONS, doc! { "user_id": user_id }),
            (SECRETS, doc! { "_id.user": user_id }),
        ] {
            self.col::<Document>(collection)
                .delete_many(filter)
                .await
                .map_err(|_| create_database_error!("delete_many", collection))?;
        }

        Ok(())
    }

    async fn set_channel_encryption(
        &self,
        channel_id: &str,
        encryption: &ChannelEncryption,
    ) -> Result<bool> {
        let encryption =
            to_bson(encryption).map_err(|_| create_database_error!("to_bson", CHANNELS))?;

        self.col::<Document>(CHANNELS)
            .update_one(
                doc! {
                    "_id": channel_id,
                    "channel_type": { "$in": ["DirectMessage", "Group"] },
                    "encryption": { "$exists": false }
                },
                doc! {
                    "$set": {
                        "encryption": encryption
                    }
                },
            )
            .await
            .map(|result| result.matched_count > 0)
            .map_err(|_| create_database_error!("update_one", CHANNELS))
    }

    async fn use_message_attachment(
        &self,
        id: &str,
        encrypted: bool,
        message_id: &str,
        uploader_id: &str,
    ) -> Result<File> {
        let used_for = to_document(&FileUsedFor {
            object_type: FileUsedForType::Message,
            id: message_id.to_string(),
        })
        .map_err(|_| create_database_error!("to_document", ATTACHMENTS))?;

        let encrypted = if encrypted {
            Bson::Boolean(true)
        } else {
            Bson::Document(doc! { "$ne": true })
        };

        self.col::<File>(ATTACHMENTS)
            .find_one_and_update(
                doc! {
                    "_id": id,
                    "tag": "attachments",
                    "used_for": { "$exists": false },
                    "encrypted": encrypted
                },
                doc! {
                    "$set": {
                        "used_for": used_for,
                        "uploader_id": uploader_id
                    }
                },
            )
            .with_options(
                FindOneAndUpdateOptions::builder()
                    .return_document(ReturnDocument::After)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_one_and_update", ATTACHMENTS))?
            .ok_or_else(|| create_error!(NotFound))
    }
}
