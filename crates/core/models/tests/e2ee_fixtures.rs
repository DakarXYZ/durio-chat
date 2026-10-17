//! Contract v1 of `/e2ee/*`: the API models must (de)serialize exactly what
//! matrix-sdk-crypto 0.19.1 sends and accepts.
//!
//! `fixtures/e2ee/` is a copy of `stoat-crypto/fixtures/{api,envelope}` (CR-01 spike,
//! stoat-crypto a9aa860). Update both together, the contract only changes with a new version.
use std::path::PathBuf;

use revolt_models::v0::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

fn read(rel: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/e2ee")
        .join(rel);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    serde_json::from_str(&text).unwrap()
}

/// Parse into `T` and serialize back, the JSON must not change
fn round_trip<T: DeserializeOwned + Serialize>(value: &Value) -> T {
    let parsed: T = serde_json::from_value(value.clone()).expect("fixture parses");
    assert_eq!(&serde_json::to_value(&parsed).unwrap(), value);
    parsed
}

/// Request and response of an API fixture
fn api(rel: &str) -> (Value, Value) {
    let fixture = read(&format!("api/{rel}.json"));
    (fixture["request"].clone(), fixture["response"].clone())
}

#[test]
fn keys_upload_initial() {
    let (request, response) = api("keys/upload.initial");
    let body: DataE2eeKeysUpload = round_trip(&request);

    let device_keys = body.device_keys.unwrap();
    assert_eq!(
        user_id_from_e2ee(device_keys["user_id"].as_str().unwrap()).as_deref(),
        Some("01KAAAAAAAAAAAAAAAAAAAAAAA")
    );
    assert_eq!(body.one_time_keys.unwrap().len(), 50);
    assert!(body.fallback_keys.is_none());

    // Extra `device_unused_fallback_key_types` is ignored by the library
    let parsed: E2eeKeysUploadResponse = serde_json::from_value(response.clone()).unwrap();
    assert_eq!(parsed.one_time_key_counts["signed_curve25519"], 50);
    let mut expected = response;
    expected["device_unused_fallback_key_types"] = json!([]);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), expected);
}

#[test]
fn keys_upload_fallback_only() {
    let (request, _) = api("keys/upload.otk_only");
    let body: DataE2eeKeysUpload = round_trip(&request);

    assert!(body.device_keys.is_none());
    assert!(body.one_time_keys.is_none());
    let fallback = body.fallback_keys.unwrap();
    assert_eq!(fallback.len(), 1);
    let (key_id, key) = fallback.into_iter().next().unwrap();
    assert!(key_id.starts_with("signed_curve25519:"));
    assert_eq!(key["fallback"], json!(true));
}

#[test]
fn keys_query() {
    let (request, response) = api("keys/query");
    let body: DataE2eeKeysQuery = round_trip(&request);
    assert_eq!(body.device_keys.len(), 1);

    let parsed: E2eeKeysQueryResponse = round_trip(&response);
    assert!(parsed.failures.is_empty());
    assert!(parsed.master_keys.is_empty());
}

#[test]
fn keys_claim() {
    let (request, response) = api("keys/claim");
    let body: DataE2eeKeysClaim = round_trip(&request);
    let devices = &body.one_time_keys["@01kbbbbbbbbbbbbbbbbbbbbbbb:stoat.invalid"];
    assert!(
        devices
            .values()
            .all(|algorithm| algorithm == E2EE_KEY_ALGORITHM_SIGNED_CURVE25519)
    );

    round_trip::<E2eeKeysClaimResponse>(&response);
}

#[test]
fn keys_count() {
    let (request, response) = api("keys/count");
    assert_eq!(request, Value::Null);
    let parsed: E2eeKeysCountResponse = round_trip(&response);
    assert!(parsed.device_unused_fallback_key_types.is_empty());

    // The field is required, without it clients never upload a fallback key
    let mut missing = response;
    missing
        .as_object_mut()
        .unwrap()
        .remove("device_unused_fallback_key_types");
    assert!(serde_json::from_value::<E2eeKeysCountResponse>(missing).is_err());
}

#[test]
fn to_device_send() {
    for (name, all_devices) in [
        ("m.room.encrypted", false),
        ("m.room_key_request", true),
        ("m.key.verification.request", false),
        ("m.key.verification.ready", false),
    ] {
        let (request, response) = api(&format!("to_device/put.{name}"));
        let body: DataE2eeToDeviceSend = round_trip(&request);
        assert_eq!(body.event_type, name);
        assert_eq!(
            body.messages
                .values()
                .flat_map(|devices| devices.keys())
                .any(|device| device == "*"),
            all_devices,
            "{name}"
        );

        assert_eq!(
            round_trip::<E2eeToDeviceSendResponse>(&response),
            E2eeToDeviceSendResponse::default()
        );
    }

    // Full mailboxes are reported back (ignored by the library)
    let response = E2eeToDeviceSendResponse {
        failed: [(
            "@01kbbbbbbbbbbbbbbbbbbbbbbb:stoat.invalid".to_string(),
            vec!["01KDB1B1B1B1B1B1B1B1B1B1B1".to_string()],
        )]
        .into(),
    };
    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        json!({ "failed": { "@01kbbbbbbbbbbbbbbbbbbbbbbb:stoat.invalid": ["01KDB1B1B1B1B1B1B1B1B1B1B1"] } })
    );
}

#[test]
fn to_device_fetch_and_ack() {
    let (request, response) = api("to_device/get");
    assert_eq!(request, Value::Null);
    let parsed: E2eeToDeviceFetchResponse = round_trip(&response);
    let message = &parsed.messages[0];
    assert_eq!(message.event_type, "m.room.encrypted");
    assert_eq!(
        user_id_from_e2ee(&message.sender).as_deref(),
        Some("01KAAAAAAAAAAAAAAAAAAAAAAA")
    );

    let (request, response) = api("to_device/ack");
    let body: DataE2eeToDeviceAck = round_trip(&request);
    assert_eq!(body.ids.len(), 1);
    assert_eq!(response, Value::Null);
}

#[test]
fn backup_version() {
    let (request, response) = api("backup/version.create");
    let body: DataE2eeBackupVersion = round_trip(&request);
    assert!(E2EE_BACKUP_ALGORITHMS.contains(&body.algorithm.as_str()));
    assert!(body.version.is_none());
    round_trip::<E2eeBackupVersionCreateResponse>(&response);

    let (_, response) = api("backup/version.get");
    let version: E2eeBackupVersion = round_trip(&response);
    assert_eq!(version.etag, "2");
    assert_eq!(version.count, 2);
}

#[test]
fn backup_keys() {
    let (request, response) = api("backup/keys.put");
    let body: E2eeKeysBackup = round_trip(&request);
    for room in body.rooms.keys() {
        assert!(channel_id_from_e2ee(room).is_some(), "{room}");
    }
    let parsed: E2eeKeysBackupUpdateResponse = round_trip(&response);
    assert_eq!(parsed.etag, "1");

    let (_, response) = api("backup/keys.get");
    let parsed: E2eeKeysBackup = round_trip(&response);
    assert_eq!(
        parsed
            .rooms
            .values()
            .map(|r| r.sessions.len())
            .sum::<usize>(),
        2
    );
}

#[test]
fn envelope() {
    let valid: EncryptedEnvelope = round_trip(&read("envelope/valid.json"));
    assert_eq!(valid.v, E2EE_ENVELOPE_VERSION);

    // Strict: unknown fields (e.g. `sender_key`) and missing fields are rejected
    for bad in ["unknown_field", "missing_ciphertext"] {
        assert!(
            serde_json::from_value::<EncryptedEnvelope>(read(&format!(
                "envelope/invalid.{bad}.json"
            )))
            .is_err(),
            "{bad}"
        );
    }

    #[cfg(feature = "validator")]
    {
        use validator::Validate;

        assert!(valid.validate().is_ok());
        for bad in ["version", "algorithm"] {
            let envelope: EncryptedEnvelope =
                serde_json::from_value(read(&format!("envelope/invalid.{bad}.json"))).unwrap();
            assert!(envelope.validate().is_err(), "{bad}");
        }

        // Nested validation in message bodies
        let send: DataMessageSend = serde_json::from_value(json!({
            "encrypted": read("envelope/invalid.version.json")
        }))
        .unwrap();
        assert!(send.validate().is_err());
        let edit: DataEditMessage = serde_json::from_value(json!({
            "encrypted": read("envelope/valid.json")
        }))
        .unwrap();
        assert!(edit.validate().is_ok());
    }
}

#[test]
fn message_and_channel_fields_are_optional() {
    // Old documents and old clients: no new fields, nothing new serialized
    let message = json!({ "_id": "01M", "channel": "01C", "author": "01A", "content": "hi" });
    let parsed: Message = round_trip(&message);
    assert!(parsed.encrypted.is_none());

    let dm = json!({
        "channel_type": "DirectMessage",
        "_id": "01C",
        "active": true,
        "recipients": ["01A", "01B"]
    });
    let parsed: Channel = round_trip(&dm);
    assert!(matches!(
        parsed,
        Channel::DirectMessage {
            encryption: None,
            ..
        }
    ));

    // Encrypted message: no content, envelope as is
    let envelope = read("envelope/valid.json");
    let message = json!({
        "_id": "01M",
        "channel": "01C",
        "author": "01A",
        "encrypted": envelope
    });
    let parsed: Message = round_trip(&message);
    assert!(parsed.content.is_none());

    let group = json!({
        "channel_type": "Group",
        "_id": "01C",
        "name": "group",
        "owner": "01A",
        "recipients": ["01A", "01B"],
        "encryption": {
            "algorithm": E2EE_ALGORITHM_MEGOLM,
            "enabled_at": "2026-10-18T00:00:00.000Z",
            "enabled_by": "01A"
        }
    });
    round_trip::<Channel>(&group);
}
