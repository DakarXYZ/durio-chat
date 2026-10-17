//! End-to-end encryption (dur.io fork)
//!
//! Bodies of `/e2ee/*` follow the Matrix client-server API v1.x one-to-one (field names
//! and nesting), only the paths are ours. The server never inspects signed key objects,
//! these are kept as raw JSON so clients can verify signatures over canonical JSON.
//!
//! Contract v1: `stoat-crypto/fixtures/` (copied to `tests/fixtures/e2ee/`).
use std::collections::HashMap;

use iso8601_timestamp::Timestamp;
use serde_json::Value;

#[cfg(feature = "validator")]
use validator::{Validate, ValidationError};

#[cfg(feature = "rocket")]
use rocket::FromForm;

/// Current version of [`EncryptedEnvelope`]
pub const E2EE_ENVELOPE_VERSION: u32 = 1;

/// Megolm, used for message content in encrypted channels
pub const E2EE_ALGORITHM_MEGOLM: &str = "m.megolm.v1.aes-sha2";

/// Olm, used for to-device messages
pub const E2EE_ALGORITHM_OLM: &str = "m.olm.v1.curve25519-aes-sha2";

/// One-time and fallback key algorithm
pub const E2EE_KEY_ALGORITHM_SIGNED_CURVE25519: &str = "signed_curve25519";

/// Supported key backup algorithms
pub const E2EE_BACKUP_ALGORITHMS: [&str; 1] = ["m.megolm_backup.v1.curve25519-aes-sha2"];

/// Server name used in Matrix-shaped identifiers
pub const E2EE_SERVER_NAME: &str = "stoat.invalid";

/// Push text of an encrypted message, the server never knows the content
pub fn e2ee_push_body(author: &str) -> String {
    format!("New message from {author}")
}

/// Matrix-shaped user id: `@<lowercase ulid>:stoat.invalid`
pub fn e2ee_user_id(user_id: &str) -> String {
    format!("@{}:{E2EE_SERVER_NAME}", user_id.to_lowercase())
}

/// Matrix-shaped room id of a channel: `!<lowercase ulid>:stoat.invalid`
pub fn e2ee_room_id(channel_id: &str) -> String {
    format!("!{}:{E2EE_SERVER_NAME}", channel_id.to_lowercase())
}

/// User id (ULID) from a Matrix-shaped user id
pub fn user_id_from_e2ee(id: &str) -> Option<String> {
    parse_e2ee_id(id, '@')
}

/// Channel id (ULID) from a Matrix-shaped room id
pub fn channel_id_from_e2ee(id: &str) -> Option<String> {
    parse_e2ee_id(id, '!')
}

fn parse_e2ee_id(id: &str, sigil: char) -> Option<String> {
    let local = id
        .strip_prefix(sigil)?
        .strip_suffix(E2EE_SERVER_NAME)?
        .strip_suffix(':')?;

    // Only the canonical (lowercase) form is accepted
    if local.len() == 26
        && local
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
    {
        Some(local.to_uppercase())
    } else {
        None
    }
}

#[cfg(feature = "validator")]
fn validate_envelope_algorithm(algorithm: &str) -> Result<(), ValidationError> {
    if algorithm == E2EE_ALGORITHM_MEGOLM {
        Ok(())
    } else {
        Err(ValidationError::new("algorithm"))
    }
}

auto_derived!(
    /// Encrypted message envelope (version 1)
    ///
    /// Unknown fields are rejected, the format only changes with a new version.
    #[serde(deny_unknown_fields)]
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct EncryptedEnvelope {
        /// Envelope version
        #[cfg_attr(feature = "validator", validate(range(min = 1, max = 1)))]
        pub v: u32,
        /// Encryption algorithm
        #[cfg_attr(
            feature = "validator",
            validate(custom = "validate_envelope_algorithm")
        )]
        pub algorithm: String,
        /// Megolm session id
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
        pub session_id: String,
        /// Sending device (session) id, only a hint
        #[cfg_attr(feature = "validator", validate(length(equal = 26)))]
        pub device_id: String,
        /// Megolm ciphertext (upper bound is `max_envelope_bytes`)
        #[cfg_attr(feature = "validator", validate(length(min = 1)))]
        pub ciphertext: String,
    }

    /// Encryption settings of a direct message or group
    ///
    /// Once enabled, encryption cannot be disabled.
    pub struct ChannelEncryption {
        /// Encryption algorithm
        pub algorithm: String,
        /// When encryption was enabled
        pub enabled_at: Timestamp,
        /// Id of the user who enabled encryption
        pub enabled_by: String,
        /// Rotate the outbound session after this many milliseconds
        #[serde(skip_serializing_if = "Option::is_none")]
        pub rotation_period_ms: Option<u64>,
        /// Rotate the outbound session after this many messages
        #[serde(skip_serializing_if = "Option::is_none")]
        pub rotation_period_msgs: Option<u32>,
    }

    /// Enable encryption in a channel
    pub struct DataChannelEncryption {
        /// Encryption algorithm
        pub algorithm: String,
    }

    /// Upload keys of the current device
    pub struct DataE2eeKeysUpload {
        /// Signed device keys (only once per device)
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "utoipa", schema(value_type = Option<Object>))]
        pub device_keys: Option<Value>,
        /// Signed one-time keys, `signed_curve25519:<key id>` → key
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "utoipa", schema(value_type = Option<HashMap<String, Object>>))]
        pub one_time_keys: Option<HashMap<String, Value>>,
        /// Signed fallback keys, `signed_curve25519:<key id>` → key
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "utoipa", schema(value_type = Option<HashMap<String, Object>>))]
        pub fallback_keys: Option<HashMap<String, Value>>,
    }

    /// Key upload response
    pub struct E2eeKeysUploadResponse {
        /// Number of unclaimed one-time keys per algorithm
        pub one_time_key_counts: HashMap<String, usize>,
        /// Algorithms of unused fallback keys
        ///
        /// Not part of the Matrix response, ignored by Matrix clients.
        #[serde(default)]
        pub device_unused_fallback_key_types: Vec<String>,
    }

    /// Query device keys of users
    pub struct DataE2eeKeysQuery {
        /// User id → device ids (empty for all devices)
        pub device_keys: HashMap<String, Vec<String>>,
    }

    /// Key query response
    pub struct E2eeKeysQueryResponse {
        /// User id → device id → signed device keys
        #[cfg_attr(feature = "utoipa", schema(value_type = HashMap<String, HashMap<String, Object>>))]
        pub device_keys: HashMap<String, HashMap<String, Value>>,
        /// Servers that could not be reached (always empty)
        #[cfg_attr(feature = "utoipa", schema(value_type = HashMap<String, Object>))]
        pub failures: HashMap<String, Value>,
        /// Cross-signing master keys (empty until cross-signing is supported)
        #[cfg_attr(feature = "utoipa", schema(value_type = HashMap<String, Object>))]
        pub master_keys: HashMap<String, Value>,
        /// Cross-signing self-signing keys (empty until cross-signing is supported)
        #[cfg_attr(feature = "utoipa", schema(value_type = HashMap<String, Object>))]
        pub self_signing_keys: HashMap<String, Value>,
        /// Cross-signing user-signing keys (empty until cross-signing is supported)
        #[cfg_attr(feature = "utoipa", schema(value_type = HashMap<String, Object>))]
        pub user_signing_keys: HashMap<String, Value>,
    }

    /// Claim one-time keys of devices
    pub struct DataE2eeKeysClaim {
        /// User id → device id → key algorithm
        pub one_time_keys: HashMap<String, HashMap<String, String>>,
    }

    /// Key claim response
    pub struct E2eeKeysClaimResponse {
        /// Servers that could not be reached (always empty)
        #[cfg_attr(feature = "utoipa", schema(value_type = HashMap<String, Object>))]
        pub failures: HashMap<String, Value>,
        /// User id → device id → `<algorithm>:<key id>` → signed key
        #[cfg_attr(
            feature = "utoipa",
            schema(value_type = HashMap<String, HashMap<String, HashMap<String, Object>>>)
        )]
        pub one_time_keys: HashMap<String, HashMap<String, HashMap<String, Value>>>,
    }

    /// Key count response
    pub struct E2eeKeysCountResponse {
        /// Number of unclaimed one-time keys per algorithm
        pub one_time_key_counts: HashMap<String, usize>,
        /// Algorithms of unused fallback keys
        ///
        /// Always present: without it clients never upload a fallback key.
        pub device_unused_fallback_key_types: Vec<String>,
    }

    /// Send to-device messages
    pub struct DataE2eeToDeviceSend {
        /// Event type
        #[serde(rename = "type")]
        pub event_type: String,
        /// User id → device id (or `*` for all devices) → content
        #[cfg_attr(feature = "utoipa", schema(value_type = HashMap<String, HashMap<String, Object>>))]
        pub messages: HashMap<String, HashMap<String, Value>>,
    }

    /// To-device send response
    #[derive(Default)]
    pub struct E2eeToDeviceSendResponse {
        /// User id → device ids whose mailbox is full, messages for these were not stored
        #[serde(skip_serializing_if = "HashMap::is_empty", default)]
        pub failed: HashMap<String, Vec<String>>,
    }

    /// Options for fetching to-device messages
    #[cfg_attr(feature = "validator", derive(Validate))]
    #[cfg_attr(feature = "rocket", derive(FromForm))]
    pub struct OptionsE2eeToDeviceFetch {
        /// Maximum number of messages to fetch
        #[cfg_attr(feature = "validator", validate(range(min = 1, max = 100)))]
        pub limit: Option<i64>,
    }

    /// To-device message delivered to the current device
    pub struct E2eeToDeviceMessage {
        /// Unique Id
        pub id: String,
        /// Matrix-shaped id of the sending user
        pub sender: String,
        /// Id of the sending device
        pub sender_device: String,
        /// Event type
        #[serde(rename = "type")]
        pub event_type: String,
        /// Message content
        #[cfg_attr(feature = "utoipa", schema(value_type = Object))]
        pub content: Value,
    }

    /// To-device fetch response, oldest messages first
    pub struct E2eeToDeviceFetchResponse {
        /// Messages
        pub messages: Vec<E2eeToDeviceMessage>,
    }

    /// Acknowledge (delete) processed to-device messages
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataE2eeToDeviceAck {
        /// Message ids
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 100)))]
        pub ids: Vec<String>,
    }

    /// Create or update a key backup version
    pub struct DataE2eeBackupVersion {
        /// Backup algorithm
        pub algorithm: String,
        /// Algorithm-specific data (public key and signatures)
        #[cfg_attr(feature = "utoipa", schema(value_type = Object))]
        pub auth_data: Value,
        /// Version being updated (only when updating)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
    }

    /// Key backup version creation response
    pub struct E2eeBackupVersionCreateResponse {
        /// Version id
        pub version: String,
    }

    /// Key backup version
    pub struct E2eeBackupVersion {
        /// Backup algorithm
        pub algorithm: String,
        /// Algorithm-specific data (public key and signatures)
        #[cfg_attr(feature = "utoipa", schema(value_type = Object))]
        pub auth_data: Value,
        /// Number of keys in the backup
        pub count: u64,
        /// Changes whenever keys in the backup change
        pub etag: String,
        /// Version id
        pub version: String,
    }

    /// Options selecting a key backup version
    #[cfg_attr(feature = "validator", derive(Validate))]
    #[cfg_attr(feature = "rocket", derive(FromForm))]
    pub struct OptionsE2eeBackupKeys {
        /// Version id
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub version: String,
    }

    /// Encrypted Megolm session in the key backup
    pub struct E2eeKeyBackupData {
        /// Index of the first message that can be decrypted
        pub first_message_index: u64,
        /// Number of times this key was forwarded
        pub forwarded_count: u64,
        /// Whether the sending device was verified
        pub is_verified: bool,
        /// Encrypted session data
        #[cfg_attr(feature = "utoipa", schema(value_type = Object))]
        pub session_data: Value,
    }

    /// Backed up sessions of a single room
    pub struct E2eeRoomKeyBackup {
        /// Session id → session
        pub sessions: HashMap<String, E2eeKeyBackupData>,
    }

    /// Backed up sessions
    pub struct E2eeKeysBackup {
        /// Matrix-shaped room id → sessions
        pub rooms: HashMap<String, E2eeRoomKeyBackup>,
    }

    /// Key backup update response
    pub struct E2eeKeysBackupUpdateResponse {
        /// Number of keys in the backup
        pub count: u64,
        /// New etag of the backup
        pub etag: String,
    }
);

impl E2eeKeyBackupData {
    /// Whether this key should replace `existing` in the backup
    ///
    /// Same rule as Matrix: lower `first_message_index` wins, then verified,
    /// then lower `forwarded_count`.
    pub fn is_better_than(&self, existing: &E2eeKeyBackupData) -> bool {
        if self.first_message_index != existing.first_message_index {
            return self.first_message_index < existing.first_message_index;
        }

        if self.is_verified != existing.is_verified {
            return self.is_verified;
        }

        self.forwarded_count < existing.forwarded_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_ids() {
        let user = "01KAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(
            e2ee_user_id(user),
            "@01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid"
        );
        assert_eq!(
            user_id_from_e2ee(&e2ee_user_id(user)).as_deref(),
            Some(user)
        );
        assert_eq!(
            channel_id_from_e2ee(&e2ee_room_id(user)).as_deref(),
            Some(user)
        );

        for bad in [
            "@01KAAAAAAAAAAAAAAAAAAAAAAA:stoat.invalid",
            "@01kaaaaaaaaaaaaaaaaaaaaaaa:example.com",
            "@01kaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid",
            "!01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid",
            "@01kaaaaaaaaaaaaaaaaaaaaaaastoat.invalid",
            "",
        ] {
            assert_eq!(user_id_from_e2ee(bad), None, "{bad}");
        }
    }

    #[test]
    fn better_backup_key() {
        let key = |first_message_index, is_verified, forwarded_count| E2eeKeyBackupData {
            first_message_index,
            forwarded_count,
            is_verified,
            session_data: Value::Null,
        };

        assert!(key(0, false, 5).is_better_than(&key(1, true, 0)));
        assert!(key(1, true, 5).is_better_than(&key(1, false, 0)));
        assert!(key(1, true, 0).is_better_than(&key(1, true, 1)));
        assert!(!key(1, true, 1).is_better_than(&key(1, true, 1)));
        assert!(!key(2, true, 0).is_better_than(&key(1, false, 9)));
    }
}
