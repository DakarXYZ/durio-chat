use std::collections::{BTreeMap, HashMap};

use futures::lock::Mutex;

use revolt_models::v0::ChannelEncryption;
use revolt_result::Result;

use crate::{
    AbstractE2ee, Channel, E2eeBackupKey, E2eeBackupKeyId, E2eeBackupVersion, E2eeClaimedKey,
    E2eeDevice, E2eeFallbackKey, E2eeOneTimeKey, E2eeSecret, E2eeSecretId, E2eeToDeviceMessage,
    ReferenceDb,
};

/// E2EE collections of the reference database
///
/// Locks are taken one at a time, in the order
/// devices → one_time_keys → fallback_keys → to_device.
#[derive(Default, Debug)]
pub struct E2eeReferenceDb {
    pub devices: Mutex<HashMap<String, E2eeDevice>>,
    /// Ordered like the `_id` sort of a claim in MongoDB
    pub one_time_keys: Mutex<BTreeMap<String, E2eeOneTimeKey>>,
    pub fallback_keys: Mutex<HashMap<String, E2eeFallbackKey>>,
    /// Ordered by ULID like the mailbox index in MongoDB
    pub to_device: Mutex<BTreeMap<String, E2eeToDeviceMessage>>,
    pub backup_versions: Mutex<HashMap<String, E2eeBackupVersion>>,
    pub backup_keys: Mutex<HashMap<E2eeBackupKeyId, E2eeBackupKey>>,
    pub secrets: Mutex<HashMap<E2eeSecretId, E2eeSecret>>,
}

fn matches_key(
    key: &E2eeBackupKey,
    user_id: &str,
    version: &str,
    room: Option<&str>,
    session: Option<&str>,
) -> bool {
    key.id.user == user_id
        && key.id.version == version
        && room.is_none_or(|room| key.id.room == room)
        && session.is_none_or(|session| key.id.session == session)
}

#[async_trait]
impl AbstractE2ee for ReferenceDb {
    async fn insert_e2ee_device(&self, device: &E2eeDevice) -> Result<bool> {
        let mut devices = self.e2ee.devices.lock().await;
        if devices.contains_key(&device.id) {
            Ok(false)
        } else {
            devices.insert(device.id.clone(), device.clone());
            Ok(true)
        }
    }

    async fn fetch_e2ee_device(&self, device_id: &str) -> Result<E2eeDevice> {
        let devices = self.e2ee.devices.lock().await;
        devices
            .get(device_id)
            .cloned()
            .ok_or_else(|| create_error!(DeviceNotFound))
    }

    async fn fetch_e2ee_devices(&self, user_ids: &[String]) -> Result<Vec<E2eeDevice>> {
        let devices = self.e2ee.devices.lock().await;
        Ok(devices
            .values()
            .filter(|device| user_ids.contains(&device.user_id))
            .cloned()
            .collect())
    }

    async fn delete_e2ee_devices(
        &self,
        user_id: &str,
        only: Option<&str>,
        except: Option<&str>,
    ) -> Result<Vec<String>> {
        let mut devices = self.e2ee.devices.lock().await;
        let ids: Vec<String> = devices
            .values()
            .filter(|device| {
                device.user_id == user_id
                    && only.is_none_or(|id| device.id == id)
                    && except.is_none_or(|id| device.id != id)
            })
            .map(|device| device.id.clone())
            .collect();

        for id in &ids {
            devices.remove(id);
        }

        Ok(ids)
    }

    async fn delete_e2ee_device_data(&self, device_ids: &[String]) -> Result<()> {
        self.e2ee
            .one_time_keys
            .lock()
            .await
            .retain(|_, key| !device_ids.contains(&key.device_id));

        self.e2ee
            .fallback_keys
            .lock()
            .await
            .retain(|id, _| !device_ids.contains(id));

        self.e2ee
            .to_device
            .lock()
            .await
            .retain(|_, message| !device_ids.contains(&message.recipient_device));

        Ok(())
    }

    async fn insert_one_time_keys(&self, keys: Vec<E2eeOneTimeKey>) -> Result<()> {
        let mut otks = self.e2ee.one_time_keys.lock().await;
        for key in keys {
            otks.entry(key.id.clone()).or_insert(key);
        }

        Ok(())
    }

    async fn claim_one_time_key(
        &self,
        device_id: &str,
        algorithm: &str,
    ) -> Result<Option<E2eeClaimedKey>> {
        {
            let mut otks = self.e2ee.one_time_keys.lock().await;
            let id = otks
                .values()
                .find(|key| key.device_id == device_id && key.algorithm == algorithm)
                .map(|key| key.id.clone());

            if let Some(key) = id.and_then(|id| otks.remove(&id)) {
                return Ok(Some(E2eeClaimedKey {
                    algorithm: key.algorithm,
                    key_id: key.key_id,
                    key: key.key,
                    fallback: false,
                }));
            }
        }

        let mut fallback_keys = self.e2ee.fallback_keys.lock().await;
        Ok(fallback_keys
            .get_mut(device_id)
            .filter(|key| key.algorithm == algorithm)
            .map(|key| {
                key.used = true;
                E2eeClaimedKey {
                    algorithm: key.algorithm.clone(),
                    key_id: key.key_id.clone(),
                    key: key.key.clone(),
                    fallback: true,
                }
            }))
    }

    async fn count_one_time_keys(&self, device_id: &str) -> Result<HashMap<String, usize>> {
        let otks = self.e2ee.one_time_keys.lock().await;
        let mut counts = HashMap::new();
        for key in otks.values().filter(|key| key.device_id == device_id) {
            *counts.entry(key.algorithm.clone()).or_default() += 1;
        }

        Ok(counts)
    }

    async fn set_fallback_key(&self, key: &E2eeFallbackKey) -> Result<()> {
        let mut fallback_keys = self.e2ee.fallback_keys.lock().await;
        if fallback_keys
            .get(&key.id)
            .is_none_or(|existing| existing.key_id != key.key_id)
        {
            fallback_keys.insert(key.id.clone(), key.clone());
        }

        Ok(())
    }

    async fn fetch_unused_fallback_key_types(&self, device_id: &str) -> Result<Vec<String>> {
        let fallback_keys = self.e2ee.fallback_keys.lock().await;
        Ok(fallback_keys
            .get(device_id)
            .filter(|key| !key.used)
            .map(|key| key.algorithm.clone())
            .into_iter()
            .collect())
    }

    async fn insert_to_device(&self, messages: Vec<E2eeToDeviceMessage>) -> Result<()> {
        let mut mailbox = self.e2ee.to_device.lock().await;
        for message in messages {
            let duplicate = mailbox.values().any(|existing| {
                existing.id == message.id
                    || (existing.sender_device == message.sender_device
                        && existing.txn_id == message.txn_id
                        && existing.recipient_device == message.recipient_device)
            });

            if !duplicate {
                mailbox.insert(message.id.clone(), message);
            }
        }

        Ok(())
    }

    async fn fetch_to_device(
        &self,
        device_id: &str,
        limit: usize,
    ) -> Result<Vec<E2eeToDeviceMessage>> {
        let mailbox = self.e2ee.to_device.lock().await;
        Ok(mailbox
            .values()
            .filter(|message| message.recipient_device == device_id)
            .take(limit)
            .cloned()
            .collect())
    }

    async fn ack_to_device(&self, device_id: &str, ids: &[String]) -> Result<()> {
        let mut mailbox = self.e2ee.to_device.lock().await;
        for id in ids {
            if mailbox
                .get(id)
                .is_some_and(|message| message.recipient_device == device_id)
            {
                mailbox.remove(id);
            }
        }

        Ok(())
    }

    async fn count_pending_to_device(&self, device_ids: &[String]) -> Result<HashMap<String, u64>> {
        let mailbox = self.e2ee.to_device.lock().await;
        let mut counts = HashMap::new();
        for message in mailbox
            .values()
            .filter(|message| device_ids.contains(&message.recipient_device))
        {
            *counts.entry(message.recipient_device.clone()).or_default() += 1;
        }

        Ok(counts)
    }

    async fn fetch_e2ee_backup_version(
        &self,
        user_id: &str,
        version: Option<&str>,
    ) -> Result<Option<E2eeBackupVersion>> {
        let versions = self.e2ee.backup_versions.lock().await;
        Ok(versions
            .values()
            .find(|entry| {
                entry.user_id == user_id
                    && !entry.deleted
                    && version.is_none_or(|version| entry.id == version)
            })
            .cloned())
    }

    async fn create_e2ee_backup_version(&self, version: &E2eeBackupVersion) -> Result<()> {
        let replaced: Vec<String> = {
            let mut versions = self.e2ee.backup_versions.lock().await;
            let replaced = versions
                .values_mut()
                .filter(|entry| entry.user_id == version.user_id && !entry.deleted)
                .map(|entry| {
                    entry.deleted = true;
                    entry.id.clone()
                })
                .collect();

            versions.insert(version.id.clone(), version.clone());
            replaced
        };

        self.e2ee
            .backup_keys
            .lock()
            .await
            .retain(|id, _| !(id.user == version.user_id && replaced.contains(&id.version)));

        Ok(())
    }

    async fn update_e2ee_backup_version(
        &self,
        user_id: &str,
        version: &str,
        auth_data: &str,
    ) -> Result<bool> {
        let mut versions = self.e2ee.backup_versions.lock().await;
        if let Some(entry) = versions
            .get_mut(version)
            .filter(|entry| entry.user_id == user_id && !entry.deleted)
        {
            entry.auth_data = auth_data.to_string();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn delete_e2ee_backup_version(&self, user_id: &str, version: &str) -> Result<bool> {
        {
            let mut versions = self.e2ee.backup_versions.lock().await;
            match versions
                .get_mut(version)
                .filter(|entry| entry.user_id == user_id && !entry.deleted)
            {
                Some(entry) => entry.deleted = true,
                None => return Ok(false),
            }
        }

        self.e2ee
            .backup_keys
            .lock()
            .await
            .retain(|id, _| !(id.user == user_id && id.version == version));

        Ok(true)
    }

    async fn upsert_e2ee_backup_keys(
        &self,
        user_id: &str,
        version: &str,
        keys: Vec<E2eeBackupKey>,
    ) -> Result<()> {
        let mut changed = false;
        {
            let mut backup = self.e2ee.backup_keys.lock().await;
            for key in keys {
                if backup
                    .get(&key.id)
                    .is_none_or(|existing| key.is_better_than(existing))
                {
                    backup.insert(key.id.clone(), key);
                    changed = true;
                }
            }
        }

        if changed {
            let mut versions = self.e2ee.backup_versions.lock().await;
            if let Some(entry) = versions
                .get_mut(version)
                .filter(|entry| entry.user_id == user_id)
            {
                entry.etag += 1;
            }
        }

        Ok(())
    }

    async fn fetch_e2ee_backup_keys(
        &self,
        user_id: &str,
        version: &str,
        room: Option<&str>,
        session: Option<&str>,
    ) -> Result<Vec<E2eeBackupKey>> {
        let backup = self.e2ee.backup_keys.lock().await;
        Ok(backup
            .values()
            .filter(|key| matches_key(key, user_id, version, room, session))
            .cloned()
            .collect())
    }

    async fn delete_e2ee_backup_keys(
        &self,
        user_id: &str,
        version: &str,
        room: Option<&str>,
        session: Option<&str>,
    ) -> Result<()> {
        self.e2ee
            .backup_keys
            .lock()
            .await
            .retain(|_, key| !matches_key(key, user_id, version, room, session));

        let mut versions = self.e2ee.backup_versions.lock().await;
        if let Some(entry) = versions
            .get_mut(version)
            .filter(|entry| entry.user_id == user_id)
        {
            entry.etag += 1;
        }

        Ok(())
    }

    async fn count_e2ee_backup_keys(&self, user_id: &str, version: &str) -> Result<u64> {
        let backup = self.e2ee.backup_keys.lock().await;
        Ok(backup
            .values()
            .filter(|key| matches_key(key, user_id, version, None, None))
            .count() as u64)
    }

    async fn fetch_e2ee_secret(&self, user_id: &str, secret_type: &str) -> Result<Option<String>> {
        let secrets = self.e2ee.secrets.lock().await;
        Ok(secrets
            .get(&E2eeSecretId {
                user: user_id.to_string(),
                secret_type: secret_type.to_string(),
            })
            .map(|secret| secret.content.clone()))
    }

    async fn set_e2ee_secret(&self, user_id: &str, secret_type: &str, content: &str) -> Result<()> {
        let id = E2eeSecretId {
            user: user_id.to_string(),
            secret_type: secret_type.to_string(),
        };

        self.e2ee.secrets.lock().await.insert(
            id.clone(),
            E2eeSecret {
                id,
                content: content.to_string(),
            },
        );

        Ok(())
    }

    async fn fetch_e2ee_secret_types(&self, user_id: &str) -> Result<Vec<String>> {
        let secrets = self.e2ee.secrets.lock().await;
        Ok(secrets
            .keys()
            .filter(|id| id.user == user_id)
            .map(|id| id.secret_type.clone())
            .collect())
    }

    async fn set_channel_encryption(
        &self,
        channel_id: &str,
        encryption: &ChannelEncryption,
    ) -> Result<bool> {
        let mut channels = self.channels.lock().await;
        match channels.get_mut(channel_id) {
            Some(Channel::DirectMessage {
                encryption: current,
                ..
            })
            | Some(Channel::Group {
                encryption: current,
                ..
            }) if current.is_none() => {
                current.replace(encryption.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
