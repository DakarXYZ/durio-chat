use std::sync::{LazyLock, Mutex};

use iso8601_timestamp::Timestamp;

// Signed key objects and to-device contents are stored as JSON strings:
// Matrix-shaped keys (`@<ulid>:stoat.invalid`, `ed25519:<device>`, `org.matrix.msgid`)
// contain dots, which break BSON field paths, and the server must not normalise them.

auto_derived!(
    /// E2EE device, one per session
    pub struct E2eeDevice {
        /// Device id (same as the session id)
        #[serde(rename = "_id")]
        pub id: String,
        /// Owner of the device
        pub user_id: String,
        /// Signed device keys as uploaded (JSON)
        pub keys: String,
        /// Display name of the device
        #[serde(skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        /// When the device keys were uploaded
        pub created_at: Timestamp,
    }

    /// Unclaimed one-time key of a device
    pub struct E2eeOneTimeKey {
        /// `<device>:<algorithm>:<key id>`
        #[serde(rename = "_id")]
        pub id: String,
        /// Owner of the device
        pub user_id: String,
        /// Device id
        pub device_id: String,
        /// Key algorithm (`signed_curve25519`)
        pub algorithm: String,
        /// Key id
        pub key_id: String,
        /// Signed key (JSON)
        pub key: String,
    }

    /// Fallback key of a device, handed out when no one-time keys are left
    pub struct E2eeFallbackKey {
        /// Device id
        #[serde(rename = "_id")]
        pub id: String,
        /// Owner of the device
        pub user_id: String,
        /// Key algorithm (`signed_curve25519`)
        pub algorithm: String,
        /// Key id
        pub key_id: String,
        /// Signed key (JSON)
        pub key: String,
        /// Whether the key was claimed at least once (it is still handed out)
        pub used: bool,
    }

    /// Key handed out by a claim
    pub struct E2eeClaimedKey {
        /// Key algorithm
        pub algorithm: String,
        /// Key id
        pub key_id: String,
        /// Signed key (JSON)
        pub key: String,
        /// Whether this is the fallback key
        pub fallback: bool,
    }

    /// Message in the to-device mailbox of a device
    pub struct E2eeToDeviceMessage {
        /// Unique Id (ULID), the mailbox is served oldest first
        #[serde(rename = "_id")]
        pub id: String,
        /// Recipient user
        pub recipient_user: String,
        /// Recipient device
        pub recipient_device: String,
        /// Sending user
        pub sender_user: String,
        /// Sending device
        pub sender_device: String,
        /// Transaction id of the sending request, for idempotency
        pub txn_id: String,
        /// Event type
        #[serde(rename = "type")]
        pub event_type: String,
        /// Message content (JSON)
        pub content: String,
        /// When the message is dropped if not delivered (BSON date, TTL index)
        pub expires_at: Timestamp,
    }

    /// Key backup version of a user
    pub struct E2eeBackupVersion {
        /// Version id (ULID)
        #[serde(rename = "_id")]
        pub id: String,
        /// Owner of the backup
        pub user_id: String,
        /// Backup algorithm
        pub algorithm: String,
        /// Algorithm-specific data (JSON)
        pub auth_data: String,
        /// Incremented whenever keys in this version change
        pub etag: u64,
        /// Whether this version was replaced or deleted
        pub deleted: bool,
    }

    /// Composite primary key of a backed up session
    #[derive(Hash)]
    pub struct E2eeBackupKeyId {
        /// User id
        pub user: String,
        /// Backup version
        pub version: String,
        /// Matrix-shaped room id, as sent by the client
        pub room: String,
        /// Megolm session id
        pub session: String,
    }

    /// Backed up Megolm session
    pub struct E2eeBackupKey {
        #[serde(rename = "_id")]
        pub id: E2eeBackupKeyId,
        /// Index of the first message that can be decrypted
        pub first_message_index: u64,
        /// Number of times this key was forwarded
        pub forwarded_count: u64,
        /// Whether the sending device was verified
        pub is_verified: bool,
        /// Encrypted session data (JSON)
        pub session_data: String,
    }

    /// Composite primary key of a secret storage entry
    #[derive(Hash)]
    pub struct E2eeSecretId {
        /// User id
        pub user: String,
        /// Secret type
        #[serde(rename = "type")]
        pub secret_type: String,
    }

    /// Secret storage entry (opaque to the server)
    pub struct E2eeSecret {
        #[serde(rename = "_id")]
        pub id: E2eeSecretId,
        /// Content (JSON)
        pub content: String,
    }
);

/// Monotonic within the process, so messages queued in the same millisecond keep their order
static TO_DEVICE_IDS: LazyLock<Mutex<ulid::Generator>> =
    LazyLock::new(|| Mutex::new(ulid::Generator::new()));

impl E2eeToDeviceMessage {
    /// Id for a new mailbox message
    pub fn generate_id() -> String {
        let id = TO_DEVICE_IDS
            .lock()
            .ok()
            .and_then(|mut generator| generator.generate().ok());

        match id {
            Some(id) => id.to_string(),
            // Clock went backwards or the generator overflowed
            None => ulid::Ulid::new().to_string(),
        }
    }
}

impl E2eeOneTimeKey {
    /// Primary key of a one-time key
    pub fn make_id(device_id: &str, algorithm: &str, key_id: &str) -> String {
        format!("{device_id}:{algorithm}:{key_id}")
    }
}

impl E2eeBackupKey {
    /// Backup metadata in API form
    pub fn data(&self) -> revolt_models::v0::E2eeKeyBackupData {
        revolt_models::v0::E2eeKeyBackupData {
            first_message_index: self.first_message_index,
            forwarded_count: self.forwarded_count,
            is_verified: self.is_verified,
            session_data: serde_json::from_str(&self.session_data)
                .unwrap_or(serde_json::Value::Null),
        }
    }

    /// Whether this key should replace `existing` in the backup
    pub fn is_better_than(&self, existing: &E2eeBackupKey) -> bool {
        let meta = |key: &E2eeBackupKey| revolt_models::v0::E2eeKeyBackupData {
            first_message_index: key.first_message_index,
            forwarded_count: key.forwarded_count,
            is_verified: key.is_verified,
            session_data: serde_json::Value::Null,
        };

        meta(self).is_better_than(&meta(existing))
    }
}
