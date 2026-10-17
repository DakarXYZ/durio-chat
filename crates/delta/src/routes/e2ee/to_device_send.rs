//! Send to-device messages
//! PUT /e2ee/to_device/<txn_id>
use std::collections::{HashMap, HashSet};

use iso8601_timestamp::{Duration, Timestamp};
use revolt_config::config;
use revolt_database::{Database, E2eeToDeviceMessage, e2ee_visible_users, events::client::EventV1};
use revolt_models::v0::{self, e2ee_user_id, user_id_from_e2ee};
use revolt_result::{Result, create_error};
use rocket::{State, serde::json::Json};
use serde_json::Value;

use super::{E2eeSession, invalid, json_size};

/// Upper bound of a transaction id
const MAX_TXN_ID_LENGTH: usize = 64;

/// Upper bound of an event type
const MAX_EVENT_TYPE_LENGTH: usize = 255;

/// All devices of the user except the sending one
const ALL_DEVICES: &str = "*";

/// # Send To-Device Messages
///
/// Put messages into the mailboxes of devices (`*` for all devices of a user except the
/// sending one). Repeating a request with the same transaction id stores nothing twice.
/// Devices of invisible users are skipped; devices whose mailbox is full are listed
/// in `failed`, the rest of the batch is still delivered.
#[openapi(tag = "E2EE")]
#[put("/to_device/<txn_id>", data = "<data>")]
pub async fn send(
    db: &State<Database>,
    e2ee: E2eeSession,
    txn_id: String,
    data: Json<v0::DataE2eeToDeviceSend>,
) -> Result<Json<v0::E2eeToDeviceSendResponse>> {
    let data = data.into_inner();
    let config = config().await;
    let limits = &config.features.e2ee;

    if txn_id.is_empty()
        || txn_id.len() > MAX_TXN_ID_LENGTH
        || !txn_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(invalid("txn_id"));
    }

    if data.event_type.is_empty() || data.event_type.len() > MAX_EVENT_TYPE_LENGTH {
        return Err(invalid("type"));
    }

    if data.messages.values().map(HashMap::len).sum::<usize>() > limits.max_to_device_batch {
        return Err(create_error!(PayloadTooLarge));
    }

    for content in data.messages.values().flat_map(HashMap::values) {
        if !content.is_object() {
            return Err(invalid("messages"));
        }

        if json_size(content) > limits.max_to_device_bytes {
            return Err(create_error!(PayloadTooLarge));
        }
    }

    let visible = e2ee_visible_users(db, &e2ee.user).await?;
    let user_ids: Vec<String> = data
        .messages
        .keys()
        .filter_map(|id| user_id_from_e2ee(id))
        .filter(|id| visible.contains(id))
        .collect();

    // User id → device ids
    let mut devices: HashMap<String, HashSet<String>> = HashMap::new();
    if !user_ids.is_empty() {
        for device in db.fetch_e2ee_devices(&user_ids).await? {
            devices.entry(device.user_id).or_default().insert(device.id);
        }
    }

    // (recipient user, Matrix-shaped recipient, recipient device, content)
    let mut deliveries: Vec<(String, String, String, Value)> = vec![];
    for (matrix_id, messages) in data.messages {
        let Some(user_id) = user_id_from_e2ee(&matrix_id) else {
            continue;
        };

        let Some(user_devices) = devices.get(&user_id) else {
            continue;
        };

        // Explicitly addressed devices take precedence over `*`
        let mut wildcard = None;
        let mut addressed = HashSet::new();
        for (device_id, content) in messages {
            if device_id == ALL_DEVICES {
                wildcard = Some(content);
            } else if user_devices.contains(&device_id) {
                addressed.insert(device_id.clone());
                deliveries.push((user_id.clone(), matrix_id.clone(), device_id, content));
            }
        }

        if let Some(content) = wildcard {
            for device_id in user_devices {
                if device_id != e2ee.device_id() && !addressed.contains(device_id) {
                    deliveries.push((
                        user_id.clone(),
                        matrix_id.clone(),
                        device_id.clone(),
                        content.clone(),
                    ));
                }
            }
        }
    }

    let recipients: Vec<String> = deliveries
        .iter()
        .map(|(_, _, device_id, _)| device_id.clone())
        .collect();

    let pending = if recipients.is_empty() {
        HashMap::new()
    } else {
        db.count_pending_to_device(&recipients).await?
    };

    let expires_at = Timestamp::now_utc()
        .checked_add(Duration::days(limits.to_device_ttl_days as i64))
        .unwrap_or_else(Timestamp::now_utc);

    let mut response = v0::E2eeToDeviceSendResponse::default();
    let mut stored = vec![];
    for (user_id, matrix_id, device_id, content) in deliveries {
        // A full mailbox does not block the rest of the batch
        if pending.get(&device_id).copied().unwrap_or_default()
            >= limits.max_pending_to_device as u64
        {
            response
                .failed
                .entry(matrix_id)
                .or_default()
                .push(device_id);
            continue;
        }

        stored.push(E2eeToDeviceMessage {
            id: E2eeToDeviceMessage::generate_id(),
            recipient_user: user_id,
            recipient_device: device_id,
            sender_user: e2ee.user.id.clone(),
            sender_device: e2ee.device_id().to_string(),
            txn_id: txn_id.clone(),
            event_type: data.event_type.clone(),
            content: content.to_string(),
            expires_at,
        });
    }

    if !stored.is_empty() {
        db.insert_to_device(stored.clone()).await?;
    }

    // Doorbells only, clients fetch the mailbox
    let sender = e2ee_user_id(&e2ee.user.id);
    for message in stored {
        EventV1::E2eeToDevice {
            id: message.id,
            recipient_device: message.recipient_device,
            sender: sender.clone(),
            sender_device: message.sender_device,
            event_type: message.event_type,
        }
        .p_redis_only(message.recipient_user)
        .await;
    }

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use revolt_database::events::client::EventV1;
    use revolt_models::v0::e2ee_user_id;
    use rocket::http::{Method, Status};
    use serde_json::{Value, json};

    use crate::routes::e2ee::tests::{direct_message, get, new_device, new_device_user, request};
    use crate::util::test::{PubSubTestHelper, TestHarness};

    async fn put(
        harness: &TestHarness,
        session: &revolt_database::Session,
        txn_id: &str,
        body: Value,
    ) -> (Status, Value) {
        request(
            harness,
            Method::Put,
            session,
            &format!("/e2ee/to_device/{txn_id}"),
            Some(body),
        )
        .await
    }

    #[rocket::async_test]
    async fn deliver_to_device_and_all() {
        let harness = TestHarness::new().await;
        let (account, session, user) = new_device_user(&harness).await;
        let second = new_device(&harness, &account).await;
        let (peer_account, peer_session, peer) = new_device_user(&harness).await;
        let peer_second = new_device(&harness, &peer_account).await;
        direct_message(&harness, &user, &peer).await;

        let mut events = PubSubTestHelper::new(&format!("{}!", peer.id)).await;

        // The m.room.encrypted fixture, addressed to the peer's devices
        let (status, body) = put(
            &harness,
            &session,
            "txn1",
            json!({
                "type": "m.room.encrypted",
                "messages": {
                    e2ee_user_id(&peer.id): {
                        peer_session.id.clone(): { "ciphertext": "for first" },
                        peer_second.id.clone(): { "ciphertext": "for second" }
                    }
                }
            }),
        )
        .await;
        assert_eq!(status, Status::Ok);
        assert_eq!(body, json!({}));

        let event = tokio::time::timeout(
            Duration::from_secs(5),
            events.wait_for_event(|event| {
                matches!(event, EventV1::E2eeToDevice { recipient_device, .. } if *recipient_device == peer_second.id)
            }),
        )
        .await
        .expect("doorbell");

        let EventV1::E2eeToDevice {
            id,
            sender,
            sender_device,
            event_type,
            ..
        } = event
        else {
            unreachable!()
        };
        assert_eq!(sender, e2ee_user_id(&user.id));
        assert_eq!(sender_device, session.id);
        assert_eq!(event_type, "m.room.encrypted");

        let (status, body) = get(&harness, &peer_second, "/e2ee/to_device").await;
        assert_eq!(status, Status::Ok);
        assert_eq!(
            body,
            json!({
                "messages": [{
                    "id": id,
                    "sender": e2ee_user_id(&user.id),
                    "sender_device": session.id.clone(),
                    "type": "m.room.encrypted",
                    "content": { "ciphertext": "for second" }
                }]
            })
        );

        // `*` (plaintext m.room_key_request) reaches all own devices but the sending one
        let (status, _) = put(
            &harness,
            &session,
            "txn2",
            json!({
                "type": "m.room_key_request",
                "messages": { e2ee_user_id(&user.id): { "*": { "action": "request" } } }
            }),
        )
        .await;
        assert_eq!(status, Status::Ok);

        let (_, body) = get(&harness, &second, "/e2ee/to_device").await;
        assert_eq!(body["messages"][0]["type"], "m.room_key_request");
        assert_eq!(
            body["messages"][0]["content"],
            json!({ "action": "request" })
        );

        let (_, body) = get(&harness, &session, "/e2ee/to_device").await;
        assert_eq!(body, json!({ "messages": [] }));
    }

    #[rocket::async_test]
    async fn repeated_txn_id() {
        let harness = TestHarness::new().await;
        let (_, session, user) = new_device_user(&harness).await;
        let (_, peer_session, peer) = new_device_user(&harness).await;
        direct_message(&harness, &user, &peer).await;

        let body = json!({
            "type": "m.room.encrypted",
            "messages": { e2ee_user_id(&peer.id): { peer_session.id.clone(): { "n": 1 } } }
        });

        for _ in 0..2 {
            let (status, _) = put(&harness, &session, "same", body.clone()).await;
            assert_eq!(status, Status::Ok);
        }

        // Another transaction is another message
        let (status, _) = put(&harness, &session, "other", body).await;
        assert_eq!(status, Status::Ok);

        let (_, messages) = get(&harness, &peer_session, "/e2ee/to_device").await;
        assert_eq!(messages["messages"].as_array().unwrap().len(), 2);
    }

    #[rocket::async_test]
    async fn invisible_recipients() {
        let harness = TestHarness::new().await;
        let (_, session, _) = new_device_user(&harness).await;
        let (_, stranger_session, stranger) = new_device_user(&harness).await;
        let (_, other_session, _) = new_device_user(&harness).await;

        let (status, body) = put(
            &harness,
            &session,
            "txn",
            json!({
                "type": "m.room.encrypted",
                "messages": {
                    e2ee_user_id(&stranger.id): {
                        stranger_session.id.clone(): { "n": 1 },
                        // Device of someone else under the stranger
                        other_session.id.clone(): { "n": 1 },
                        "*": { "n": 2 }
                    }
                }
            }),
        )
        .await;
        assert_eq!(status, Status::Ok);
        assert_eq!(body, json!({}));

        for session in [&stranger_session, &other_session] {
            let (_, body) = get(&harness, session, "/e2ee/to_device").await;
            assert_eq!(body, json!({ "messages": [] }));
        }
    }

    #[rocket::async_test]
    async fn full_mailbox() {
        revolt_config::overwrite_config(|config| config.features.e2ee.max_pending_to_device = 2)
            .await;

        let harness = TestHarness::new().await;
        let (account, session, user) = new_device_user(&harness).await;
        let second = new_device(&harness, &account).await;
        let third = new_device(&harness, &account).await;

        // Fill the mailbox of the second device
        for txn_id in ["a", "b"] {
            let (status, _) = put(
                &harness,
                &session,
                txn_id,
                json!({
                    "type": "m.dummy",
                    "messages": { e2ee_user_id(&user.id): { second.id.clone(): {} } }
                }),
            )
            .await;
            assert_eq!(status, Status::Ok);
        }

        let (status, body) = put(
            &harness,
            &session,
            "c",
            json!({
                "type": "m.dummy",
                "messages": { e2ee_user_id(&user.id): { "*": {} } }
            }),
        )
        .await;
        assert_eq!(status, Status::Ok);
        assert_eq!(
            body,
            json!({ "failed": { e2ee_user_id(&user.id): [second.id.clone()] } })
        );

        let (_, body) = get(&harness, &third, "/e2ee/to_device").await;
        assert_eq!(body["messages"].as_array().unwrap().len(), 1);
        let (_, body) = get(&harness, &second, "/e2ee/to_device").await;
        assert_eq!(body["messages"].as_array().unwrap().len(), 2);
    }

    /// The JSON limit is raised to `max_request_bytes` (4 MiB) for large batches (BE-29)
    #[rocket::async_test]
    async fn large_batch() {
        let harness = TestHarness::new().await;
        let (account, session, user) = new_device_user(&harness).await;
        let second = new_device(&harness, &account).await;

        // Over 3 MiB: 50 contents of 64 000 bytes, one of them for a real device
        let content = json!({ "data": "x".repeat(64_000) });
        let mut devices: serde_json::Map<String, Value> = (0..49)
            .map(|n| (format!("UNKNOWN{n}"), content.clone()))
            .collect();
        devices.insert(second.id.clone(), content.clone());

        let body = json!({
            "type": "m.dummy",
            "messages": { e2ee_user_id(&user.id): devices }
        });
        assert!(body.to_string().len() > 3 * 1024 * 1024);

        let (status, _) = put(&harness, &session, "large", body).await;
        assert_eq!(status, Status::Ok);

        let (_, body) = get(&harness, &second, "/e2ee/to_device").await;
        assert_eq!(body["messages"][0]["content"], content);

        // Above the limit the body is rejected before the route
        let devices: serde_json::Map<String, Value> = (0..70)
            .map(|n| (format!("UNKNOWN{n}"), content.clone()))
            .collect();
        let (status, _) = put(
            &harness,
            &session,
            "too-large",
            json!({ "type": "m.dummy", "messages": { e2ee_user_id(&user.id): devices } }),
        )
        .await;
        assert_eq!(status, Status::PayloadTooLarge);
    }

    #[rocket::async_test]
    async fn invalid_requests() {
        let harness = TestHarness::new().await;
        let (_, session, user) = new_device_user(&harness).await;
        let me = e2ee_user_id(&user.id);
        let long_txn_id = "x".repeat(65);

        for (txn_id, body, status) in [
            (
                "bad%20txn",
                json!({ "type": "m.dummy", "messages": {} }),
                Status::BadRequest,
            ),
            (
                long_txn_id.as_str(),
                json!({ "type": "m.dummy", "messages": {} }),
                Status::BadRequest,
            ),
            (
                "txn",
                json!({ "type": "", "messages": {} }),
                Status::BadRequest,
            ),
            (
                "txn",
                json!({ "type": "m.dummy", "messages": { me.clone(): { "*": "text" } } }),
                Status::BadRequest,
            ),
            (
                "txn",
                // 64 KiB in the default config
                json!({
                    "type": "m.dummy",
                    "messages": { me.clone(): { "*": { "data": "x".repeat(65_536) } } }
                }),
                Status::UnprocessableEntity,
            ),
            (
                "txn",
                // 1000 in the default config
                json!({
                    "type": "m.dummy",
                    "messages": {
                        me.clone(): (0..1001)
                            .map(|n| (format!("DEVICE{n}"), json!({})))
                            .collect::<serde_json::Map<String, Value>>()
                    }
                }),
                Status::UnprocessableEntity,
            ),
        ] {
            let (actual, _) = put(&harness, &session, txn_id, body).await;
            assert_eq!(actual, status, "{txn_id}");
        }
    }
}
