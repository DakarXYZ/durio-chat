//! Storage tests, run against both `TEST_DB=REFERENCE` and `TEST_DB=MONGODB`
use iso8601_timestamp::Timestamp;
use revolt_models::v0::{self, ChannelEncryption};

use crate::{
    Channel, Database, DatabaseInfo, E2eeBackupKey, E2eeBackupKeyId, E2eeBackupVersion, E2eeDevice,
    E2eeFallbackKey, E2eeOneTimeKey, E2eeToDeviceMessage,
};

/// Fresh database with collections and indexes
async fn test_db(name: &str) -> Database {
    let db = DatabaseInfo::Test(format!("revolt_test_e2ee_{name}"))
        .connect()
        .await
        .expect("Database connection failed.");

    db.drop_database().await;
    db.migrate_database().await.unwrap();
    db
}

fn device(id: &str, user: &str) -> E2eeDevice {
    E2eeDevice {
        id: id.to_string(),
        user_id: user.to_string(),
        keys: format!(r#"{{"device_id":"{id}"}}"#),
        display_name: None,
        created_at: Timestamp::now_utc(),
    }
}

fn otk(device: &str, key_id: &str) -> E2eeOneTimeKey {
    E2eeOneTimeKey {
        id: E2eeOneTimeKey::make_id(device, "signed_curve25519", key_id),
        user_id: "user".to_string(),
        device_id: device.to_string(),
        algorithm: "signed_curve25519".to_string(),
        key_id: key_id.to_string(),
        key: format!(r#"{{"key":"{key_id}"}}"#),
    }
}

fn fallback(device: &str, key_id: &str) -> E2eeFallbackKey {
    E2eeFallbackKey {
        id: device.to_string(),
        user_id: "user".to_string(),
        algorithm: "signed_curve25519".to_string(),
        key_id: key_id.to_string(),
        key: format!(r#"{{"key":"{key_id}","fallback":true}}"#),
        used: false,
    }
}

fn to_device(recipient: &str, sender: &str, txn_id: &str) -> E2eeToDeviceMessage {
    E2eeToDeviceMessage {
        id: E2eeToDeviceMessage::generate_id(),
        recipient_user: "recipient".to_string(),
        recipient_device: recipient.to_string(),
        sender_user: "sender".to_string(),
        sender_device: sender.to_string(),
        txn_id: txn_id.to_string(),
        event_type: "m.room.encrypted".to_string(),
        content: r#"{"org.matrix.msgid":"x"}"#.to_string(),
        expires_at: Timestamp::now_utc()
            .checked_add(iso8601_timestamp::Duration::days(1))
            .unwrap(),
    }
}

fn backup_version(id: &str, user: &str) -> E2eeBackupVersion {
    E2eeBackupVersion {
        id: id.to_string(),
        user_id: user.to_string(),
        algorithm: v0::E2EE_BACKUP_ALGORITHMS[0].to_string(),
        auth_data: r#"{"public_key":"a","signatures":{}}"#.to_string(),
        etag: 0,
        deleted: false,
    }
}

fn backup_key(
    version: &str,
    session: &str,
    first_message_index: u64,
    is_verified: bool,
    forwarded_count: u64,
) -> E2eeBackupKey {
    E2eeBackupKey {
        id: E2eeBackupKeyId {
            user: "user".to_string(),
            version: version.to_string(),
            room: "!01kccccccccccccccccccccccc:stoat.invalid".to_string(),
            session: session.to_string(),
        },
        first_message_index,
        forwarded_count,
        is_verified,
        session_data: format!(r#"{{"ciphertext":"{first_message_index}"}}"#),
    }
}

#[tokio::test]
async fn devices() {
    let db = test_db("devices").await;

    assert!(db.insert_e2ee_device(&device("A1", "A")).await.unwrap());
    assert!(db.insert_e2ee_device(&device("A2", "A")).await.unwrap());
    assert!(db.insert_e2ee_device(&device("A3", "A")).await.unwrap());
    assert!(db.insert_e2ee_device(&device("B1", "B")).await.unwrap());

    // Keys are immutable, the second upload does not replace them
    let mut other = device("A1", "A");
    other.keys = "{}".to_string();
    assert!(!db.insert_e2ee_device(&other).await.unwrap());
    assert_eq!(
        db.fetch_e2ee_device("A1").await.unwrap().keys,
        device("A1", "A").keys
    );
    assert!(db.fetch_e2ee_device("missing").await.is_err());

    let mut ids: Vec<String> = db
        .fetch_e2ee_devices(&["A".to_string(), "B".to_string()])
        .await
        .unwrap()
        .into_iter()
        .map(|device| device.id)
        .collect();
    ids.sort();
    assert_eq!(ids, ["A1", "A2", "A3", "B1"]);

    // Someone else's device cannot be deleted
    assert!(
        db.delete_e2ee_devices("B", Some("A1"), None)
            .await
            .unwrap()
            .is_empty()
    );

    assert_eq!(
        db.delete_e2ee_devices("A", Some("A1"), None).await.unwrap(),
        ["A1"]
    );
    assert_eq!(
        db.delete_e2ee_devices("A", None, Some("A3")).await.unwrap(),
        ["A2"]
    );
    let remaining: Vec<String> = db
        .fetch_e2ee_devices(&["A".to_string()])
        .await
        .unwrap()
        .into_iter()
        .map(|device| device.id)
        .collect();
    assert_eq!(remaining, ["A3"]);
}

#[tokio::test]
async fn device_data_cascade() {
    let db = test_db("device_data_cascade").await;

    db.insert_one_time_keys(vec![otk("D1", "k1"), otk("D2", "k1")])
        .await
        .unwrap();
    db.set_fallback_key(&fallback("D1", "f1")).await.unwrap();
    db.set_fallback_key(&fallback("D2", "f1")).await.unwrap();
    db.insert_to_device(vec![to_device("D1", "S", "t1"), to_device("D2", "S", "t1")])
        .await
        .unwrap();

    db.delete_e2ee_device_data(&["D1".to_string()])
        .await
        .unwrap();

    assert!(db.count_one_time_keys("D1").await.unwrap().is_empty());
    assert!(
        db.fetch_unused_fallback_key_types("D1")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(db.fetch_to_device("D1", 10).await.unwrap().is_empty());

    assert_eq!(
        db.count_one_time_keys("D2").await.unwrap()["signed_curve25519"],
        1
    );
    assert_eq!(
        db.fetch_unused_fallback_key_types("D2").await.unwrap(),
        ["signed_curve25519"]
    );
    assert_eq!(db.fetch_to_device("D2", 10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn one_time_keys_then_fallback() {
    let db = test_db("one_time_keys_then_fallback").await;

    db.insert_one_time_keys(vec![otk("D", "k1"), otk("D", "k2")])
        .await
        .unwrap();
    // Repeated upload is ignored
    db.insert_one_time_keys(vec![otk("D", "k2"), otk("D", "k3")])
        .await
        .unwrap();
    assert_eq!(
        db.count_one_time_keys("D").await.unwrap()["signed_curve25519"],
        3
    );

    // No fallback yet: the list is present but empty
    assert!(
        db.fetch_unused_fallback_key_types("D")
            .await
            .unwrap()
            .is_empty()
    );
    db.set_fallback_key(&fallback("D", "f1")).await.unwrap();
    assert_eq!(
        db.fetch_unused_fallback_key_types("D").await.unwrap(),
        ["signed_curve25519"]
    );

    // Oldest first, each key handed out once
    for key_id in ["k1", "k2", "k3"] {
        let claimed = db
            .claim_one_time_key("D", "signed_curve25519")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.key_id, key_id);
        assert!(!claimed.fallback);
    }
    assert!(db.count_one_time_keys("D").await.unwrap().is_empty());

    // Exhausted: the fallback key is handed out again and again
    for _ in 0..2 {
        let claimed = db
            .claim_one_time_key("D", "signed_curve25519")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.key_id, "f1");
        assert!(claimed.fallback);
    }
    assert!(
        db.fetch_unused_fallback_key_types("D")
            .await
            .unwrap()
            .is_empty()
    );

    // Same key uploaded again stays used, a new key replaces it
    db.set_fallback_key(&fallback("D", "f1")).await.unwrap();
    assert!(
        db.fetch_unused_fallback_key_types("D")
            .await
            .unwrap()
            .is_empty()
    );
    db.set_fallback_key(&fallback("D", "f2")).await.unwrap();
    assert_eq!(
        db.fetch_unused_fallback_key_types("D").await.unwrap(),
        ["signed_curve25519"]
    );
    assert_eq!(
        db.claim_one_time_key("D", "signed_curve25519")
            .await
            .unwrap()
            .unwrap()
            .key_id,
        "f2"
    );

    // Unknown algorithm or device
    assert!(
        db.claim_one_time_key("D", "curve25519")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.claim_one_time_key("X", "signed_curve25519")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn claim_race() {
    let db = test_db("claim_race").await;

    // Two keys: two concurrent claims get different keys
    db.insert_one_time_keys(vec![otk("D", "k1"), otk("D", "k2")])
        .await
        .unwrap();
    db.set_fallback_key(&fallback("D", "f1")).await.unwrap();

    let (a, b) = futures::join!(
        db.claim_one_time_key("D", "signed_curve25519"),
        db.claim_one_time_key("D", "signed_curve25519")
    );
    let (a, b) = (a.unwrap().unwrap(), b.unwrap().unwrap());
    assert_ne!(a.key_id, b.key_id);
    assert!(!a.fallback && !b.fallback);

    // One key left: one claim gets it, the other the fallback key
    db.insert_one_time_keys(vec![otk("D", "k3")]).await.unwrap();
    let (a, b) = futures::join!(
        db.claim_one_time_key("D", "signed_curve25519"),
        db.claim_one_time_key("D", "signed_curve25519")
    );
    let mut ids = [a.unwrap().unwrap().key_id, b.unwrap().unwrap().key_id];
    ids.sort();
    assert_eq!(ids, ["f1", "k3"]);
}

#[tokio::test]
async fn to_device_mailbox() {
    let db = test_db("to_device_mailbox").await;

    let first = to_device("R", "S", "t1");
    let second = to_device("R", "S", "t2");
    let other = to_device("O", "S", "t1");
    db.insert_to_device(vec![first.clone(), second.clone(), other.clone()])
        .await
        .unwrap();

    // Oldest first, limited
    let fetched = db.fetch_to_device("R", 1).await.unwrap();
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].id, first.id);
    assert_eq!(fetched[0].content, first.content);
    assert_eq!(fetched[0].event_type, first.event_type);

    let counts = db
        .count_pending_to_device(&["R".to_string(), "O".to_string(), "X".to_string()])
        .await
        .unwrap();
    assert_eq!(counts["R"], 2);
    assert_eq!(counts["O"], 1);
    assert!(!counts.contains_key("X"));

    // Ack only removes listed messages of the own mailbox
    db.ack_to_device("R", &[first.id.clone(), other.id.clone()])
        .await
        .unwrap();
    let ids: Vec<String> = db
        .fetch_to_device("R", 10)
        .await
        .unwrap()
        .into_iter()
        .map(|message| message.id)
        .collect();
    assert_eq!(ids, [second.id]);
    assert_eq!(db.fetch_to_device("O", 10).await.unwrap().len(), 1);
}

async fn backup_etag(db: &Database, version: &str) -> u64 {
    db.fetch_e2ee_backup_version("user", Some(version))
        .await
        .unwrap()
        .unwrap()
        .etag
}

#[tokio::test]
async fn backup() {
    let db = test_db("backup").await;
    let room = "!01kccccccccccccccccccccccc:stoat.invalid";

    assert!(
        db.fetch_e2ee_backup_version("user", None)
            .await
            .unwrap()
            .is_none()
    );

    db.create_e2ee_backup_version(&backup_version("V1", "user"))
        .await
        .unwrap();
    let active = db
        .fetch_e2ee_backup_version("user", None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.id, "V1");
    assert_eq!(active.etag, 0);

    db.upsert_e2ee_backup_keys(
        "user",
        "V1",
        vec![
            backup_key("V1", "s1", 5, false, 0),
            backup_key("V1", "s2", 0, false, 0),
        ],
    )
    .await
    .unwrap();
    assert_eq!(db.count_e2ee_backup_keys("user", "V1").await.unwrap(), 2);
    assert_eq!(backup_etag(&db, "V1").await, 1);

    // Worse keys do not replace better ones and do not change the etag
    db.upsert_e2ee_backup_keys("user", "V1", vec![backup_key("V1", "s1", 6, true, 0)])
        .await
        .unwrap();
    assert_eq!(backup_etag(&db, "V1").await, 1);

    // Better keys do: lower index, then verified, then fewer forwards
    for key in [
        backup_key("V1", "s1", 2, false, 3),
        backup_key("V1", "s1", 2, true, 9),
        backup_key("V1", "s1", 2, true, 1),
    ] {
        db.upsert_e2ee_backup_keys("user", "V1", vec![key])
            .await
            .unwrap();
    }
    assert_eq!(
        db.fetch_e2ee_backup_keys("user", "V1", None, Some("s1"))
            .await
            .unwrap(),
        [backup_key("V1", "s1", 2, true, 1)]
    );
    assert_eq!(backup_etag(&db, "V1").await, 4);

    assert_eq!(
        db.fetch_e2ee_backup_keys("user", "V1", Some(room), None)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(
        db.fetch_e2ee_backup_keys("user", "V1", Some("!other:stoat.invalid"), None)
            .await
            .unwrap()
            .is_empty()
    );

    db.delete_e2ee_backup_keys("user", "V1", Some(room), Some("s2"))
        .await
        .unwrap();
    assert_eq!(db.count_e2ee_backup_keys("user", "V1").await.unwrap(), 1);
    assert_eq!(backup_etag(&db, "V1").await, 5);

    assert!(
        db.update_e2ee_backup_version("user", "V1", r#"{"public_key":"b"}"#)
            .await
            .unwrap()
    );
    assert!(
        !db.update_e2ee_backup_version("other", "V1", "{}")
            .await
            .unwrap()
    );

    // A new version replaces the old one and drops its keys
    db.create_e2ee_backup_version(&backup_version("V2", "user"))
        .await
        .unwrap();
    assert_eq!(
        db.fetch_e2ee_backup_version("user", None)
            .await
            .unwrap()
            .unwrap()
            .id,
        "V2"
    );
    assert!(
        db.fetch_e2ee_backup_version("user", Some("V1"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(db.count_e2ee_backup_keys("user", "V1").await.unwrap(), 0);

    db.upsert_e2ee_backup_keys("user", "V2", vec![backup_key("V2", "s1", 0, false, 0)])
        .await
        .unwrap();
    assert!(!db.delete_e2ee_backup_version("user", "V1").await.unwrap());
    assert!(db.delete_e2ee_backup_version("user", "V2").await.unwrap());
    assert!(
        db.fetch_e2ee_backup_version("user", None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(db.count_e2ee_backup_keys("user", "V2").await.unwrap(), 0);
}

#[tokio::test]
async fn secrets() {
    let db = test_db("secrets").await;

    assert!(
        db.fetch_e2ee_secret("user", "m.megolm_backup.v1")
            .await
            .unwrap()
            .is_none()
    );

    db.set_e2ee_secret("user", "m.megolm_backup.v1", r#"{"a":1}"#)
        .await
        .unwrap();
    db.set_e2ee_secret("user", "m.megolm_backup.v1", r#"{"a":2}"#)
        .await
        .unwrap();
    db.set_e2ee_secret("user", "m.secret_storage.key.ABC", "{}")
        .await
        .unwrap();
    db.set_e2ee_secret("other", "m.megolm_backup.v1", "{}")
        .await
        .unwrap();

    assert_eq!(
        db.fetch_e2ee_secret("user", "m.megolm_backup.v1")
            .await
            .unwrap()
            .as_deref(),
        Some(r#"{"a":2}"#)
    );

    let mut types = db.fetch_e2ee_secret_types("user").await.unwrap();
    types.sort();
    assert_eq!(types, ["m.megolm_backup.v1", "m.secret_storage.key.ABC"]);
}

#[tokio::test]
async fn channel_encryption() {
    let db = test_db("channel_encryption").await;

    let dm = Channel::DirectMessage {
        id: "DM".to_string(),
        active: true,
        recipients: vec!["A".to_string(), "B".to_string()],
        last_message_id: None,
        encryption: None,
    };
    let saved = Channel::SavedMessages {
        id: "SAVED".to_string(),
        user: "A".to_string(),
    };

    #[allow(clippy::disallowed_methods)]
    {
        db.insert_channel(&dm).await.unwrap();
        db.insert_channel(&saved).await.unwrap();
    }

    let encryption = ChannelEncryption {
        algorithm: v0::E2EE_ALGORITHM_MEGOLM.to_string(),
        enabled_at: Timestamp::now_utc(),
        enabled_by: "A".to_string(),
        rotation_period_ms: None,
        rotation_period_msgs: None,
    };

    // Concurrent attempts: exactly one wins, encryption cannot be changed afterwards
    let (a, b) = futures::join!(
        db.set_channel_encryption("DM", &encryption),
        db.set_channel_encryption("DM", &encryption)
    );
    assert!(a.unwrap() ^ b.unwrap());
    assert!(!db.set_channel_encryption("DM", &encryption).await.unwrap());
    assert!(
        !db.set_channel_encryption("SAVED", &encryption)
            .await
            .unwrap()
    );
    assert!(
        !db.set_channel_encryption("missing", &encryption)
            .await
            .unwrap()
    );

    match db.fetch_channel("DM").await.unwrap() {
        Channel::DirectMessage {
            encryption: Some(stored),
            ..
        } => {
            assert_eq!(stored.algorithm, encryption.algorithm);
            assert_eq!(stored.enabled_by, encryption.enabled_by);
        }
        channel => panic!("not encrypted: {channel:?}"),
    }
}

#[tokio::test]
async fn to_device_idempotency() {
    let db = test_db("to_device_idempotency").await;

    let first = to_device("R", "S", "t1");
    db.insert_to_device(vec![first.clone(), to_device("R2", "S", "t1")])
        .await
        .unwrap();

    // Retried request: new ids, same (sender_device, txn_id, recipient_device)
    db.insert_to_device(vec![
        to_device("R", "S", "t1"),
        to_device("R2", "S", "t1"),
        to_device("R3", "S", "t1"),
    ])
    .await
    .unwrap();

    let mailbox = db.fetch_to_device("R", 10).await.unwrap();
    assert_eq!(mailbox.len(), 1);
    assert_eq!(mailbox[0].id, first.id);
    assert_eq!(db.fetch_to_device("R2", 10).await.unwrap().len(), 1);
    // The part that failed the first time is delivered by the retry
    assert_eq!(db.fetch_to_device("R3", 10).await.unwrap().len(), 1);

    // expires_at must be a BSON date, TTL indexes ignore anything else
    #[cfg(feature = "mongodb")]
    if let Database::MongoDb(mongo) = &db {
        let dates = mongo
            .col::<bson::Document>("e2ee_to_device")
            .count_documents(doc! { "expires_at": { "$type": "date" } })
            .await
            .unwrap();
        assert_eq!(dates, 3);
    }
}
