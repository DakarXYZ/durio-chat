use std::collections::HashMap;

use revolt_models::v0::ChannelEncryption;
use revolt_result::Result;

use crate::{
    E2eeBackupKey, E2eeBackupVersion, E2eeClaimedKey, E2eeDevice, E2eeFallbackKey, E2eeOneTimeKey,
    E2eeToDeviceMessage, File,
};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

pub use reference::E2eeReferenceDb;

/// End-to-end encryption storage: devices, keys, to-device mailbox,
/// key backup and secret storage (the server only relays opaque data)
#[async_trait]
pub trait AbstractE2ee: Sync + Send {
    // ? Devices

    /// Insert device keys, returns false if the device already has keys
    async fn insert_e2ee_device(&self, device: &E2eeDevice) -> Result<bool>;

    /// Fetch a device
    async fn fetch_e2ee_device(&self, device_id: &str) -> Result<E2eeDevice>;

    /// Fetch all devices of the given users
    async fn fetch_e2ee_devices(&self, user_ids: &[String]) -> Result<Vec<E2eeDevice>>;

    /// Delete devices of a user, either `only` one device or all devices `except` one,
    /// returns the ids of deleted devices
    ///
    /// Keys and mailboxes are left in place, see [`AbstractE2ee::delete_e2ee_device_data`].
    async fn delete_e2ee_devices(
        &self,
        user_id: &str,
        only: Option<&str>,
        except: Option<&str>,
    ) -> Result<Vec<String>>;

    /// Delete one-time keys, fallback keys and to-device mailboxes of devices
    async fn delete_e2ee_device_data(&self, device_ids: &[String]) -> Result<()>;

    // ? One-time and fallback keys

    /// Insert one-time keys, keys that already exist are ignored (repeated upload)
    async fn insert_one_time_keys(&self, keys: Vec<E2eeOneTimeKey>) -> Result<()>;

    /// Atomically take one one-time key of a device, otherwise hand out its fallback key
    /// (marking it as used, it keeps being handed out until replaced)
    async fn claim_one_time_key(
        &self,
        device_id: &str,
        algorithm: &str,
    ) -> Result<Option<E2eeClaimedKey>>;

    /// Count unclaimed one-time keys of a device by algorithm
    async fn count_one_time_keys(&self, device_id: &str) -> Result<HashMap<String, usize>>;

    /// Set the fallback key of a device, uploading the same key again keeps its `used` flag
    async fn set_fallback_key(&self, key: &E2eeFallbackKey) -> Result<()>;

    /// Algorithms of the unused fallback key of a device
    async fn fetch_unused_fallback_key_types(&self, device_id: &str) -> Result<Vec<String>>;

    // ? To-device mailbox

    /// Insert to-device messages, duplicates of `(sender_device, txn_id, recipient_device)`
    /// are ignored (repeated request)
    async fn insert_to_device(&self, messages: Vec<E2eeToDeviceMessage>) -> Result<()>;

    /// Fetch the oldest `limit` messages in the mailbox of a device
    async fn fetch_to_device(
        &self,
        device_id: &str,
        limit: usize,
    ) -> Result<Vec<E2eeToDeviceMessage>>;

    /// Delete the given messages from the mailbox of a device
    async fn ack_to_device(&self, device_id: &str, ids: &[String]) -> Result<()>;

    /// Count messages in the mailboxes of devices (devices without messages are omitted)
    async fn count_pending_to_device(&self, device_ids: &[String]) -> Result<HashMap<String, u64>>;

    // ? Key backup

    /// Fetch the active backup version of a user, or a specific one if it is not deleted
    async fn fetch_e2ee_backup_version(
        &self,
        user_id: &str,
        version: Option<&str>,
    ) -> Result<Option<E2eeBackupVersion>>;

    /// Create a new active backup version, replacing (and emptying) the previous one
    ///
    /// Fails with `BackupVersionMismatch` if another version became active concurrently.
    async fn create_e2ee_backup_version(&self, version: &E2eeBackupVersion) -> Result<()>;

    /// Replace `auth_data` of an active backup version, returns false if not found
    async fn update_e2ee_backup_version(
        &self,
        user_id: &str,
        version: &str,
        auth_data: &str,
    ) -> Result<bool>;

    /// Mark a backup version as deleted and delete its keys, returns false if not found
    async fn delete_e2ee_backup_version(&self, user_id: &str, version: &str) -> Result<bool>;

    /// Store backed up sessions, an existing session is only replaced by a better one
    /// (lower `first_message_index`, then verified, then lower `forwarded_count`)
    ///
    /// Increments the etag of the version if anything changed.
    async fn upsert_e2ee_backup_keys(
        &self,
        user_id: &str,
        version: &str,
        keys: Vec<E2eeBackupKey>,
    ) -> Result<()>;

    /// Fetch backed up sessions, optionally of one room or one session
    async fn fetch_e2ee_backup_keys(
        &self,
        user_id: &str,
        version: &str,
        room: Option<&str>,
        session: Option<&str>,
    ) -> Result<Vec<E2eeBackupKey>>;

    /// Delete backed up sessions, optionally of one room or one session
    ///
    /// Increments the etag of the version.
    async fn delete_e2ee_backup_keys(
        &self,
        user_id: &str,
        version: &str,
        room: Option<&str>,
        session: Option<&str>,
    ) -> Result<()>;

    /// Count backed up sessions of a version
    async fn count_e2ee_backup_keys(&self, user_id: &str, version: &str) -> Result<u64>;

    // ? Secret storage

    /// Fetch a secret (JSON)
    async fn fetch_e2ee_secret(&self, user_id: &str, secret_type: &str) -> Result<Option<String>>;

    /// Create or replace a secret (JSON)
    async fn set_e2ee_secret(&self, user_id: &str, secret_type: &str, content: &str) -> Result<()>;

    /// Types of all secrets of a user
    async fn fetch_e2ee_secret_types(&self, user_id: &str) -> Result<Vec<String>>;

    // ? Account deletion

    /// Delete all E2EE data of a user: devices with their keys and mailboxes,
    /// key backup (all versions) and secret storage
    async fn delete_e2ee_user_data(&self, user_id: &str) -> Result<()>;

    // ? Channels

    /// Enable encryption of a direct message or group, only if not yet enabled
    ///
    /// Returns false if the channel is not a direct message or group, or is already encrypted.
    async fn set_channel_encryption(
        &self,
        channel_id: &str,
        encryption: &ChannelEncryption,
    ) -> Result<bool>;

    // ? Attachments

    /// Atomically mark an unused message attachment as used by `message_id`
    ///
    /// Only files whose `encrypted` flag matches are found: encrypted channels take only
    /// encrypted blobs, plain channels never take them. Fails with `NotFound` otherwise.
    async fn use_message_attachment(
        &self,
        id: &str,
        encrypted: bool,
        message_id: &str,
        uploader_id: &str,
    ) -> Result<File>;
}
