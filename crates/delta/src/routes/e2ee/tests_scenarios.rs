//! Scenarios of the test matrix (00-architecture §8) at the server level (BE-22)
//!
//! Key material and ciphertext are fake strings: the server relays them without looking
//! inside. Real cryptography is tested end to end by the stoat-crypto testkit (CR-15).
use std::time::Duration;

use revolt_database::{MFATicket, Session, events::client::EventV1};
use revolt_models::v0::{e2ee_room_id, e2ee_user_id};
use rocket::http::{Header, Method, Status};
use serde_json::{Value, json};

use super::tests::{
    fallback_keys, get, new_device, new_device_user, one_time_keys, post, request, request_with,
};
use super::tests_channels::{encrypt, friendly_dm, group};
use super::tests_messages::{envelope, send};
use crate::util::test::{PubSubTestHelper, TestHarness};

/// Device ids of `user_id` as seen by `viewer`
async fn visible_devices(harness: &TestHarness, viewer: &Session, user_id: &str) -> Vec<String> {
    let (status, body) = post(
        harness,
        viewer,
        "/e2ee/keys/query",
        json!({ "device_keys": { e2ee_user_id(user_id): [] } }),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let mut ids: Vec<String> = body["device_keys"][e2ee_user_id(user_id)]
        .as_object()
        .map(|devices| devices.keys().cloned().collect())
        .unwrap_or_default();
    ids.sort();
    ids
}

/// Claim one key of each device of `user_id`, returns the claimed key ids per device
async fn claim(
    harness: &TestHarness,
    session: &Session,
    user_id: &str,
    device_ids: &[&str],
) -> Value {
    let devices: serde_json::Map<String, Value> = device_ids
        .iter()
        .map(|id| (id.to_string(), json!("signed_curve25519")))
        .collect();

    let (status, body) = post(
        harness,
        session,
        "/e2ee/keys/claim",
        json!({ "one_time_keys": { e2ee_user_id(user_id): devices } }),
    )
    .await;
    assert_eq!(status, Status::Ok);
    body["one_time_keys"][e2ee_user_id(user_id)].clone()
}

/// `PUT /e2ee/to_device/<txn>` with one `content` per (user, device)
async fn to_device(
    harness: &TestHarness,
    session: &Session,
    txn_id: &str,
    event_type: &str,
    messages: Value,
) {
    let (status, body) = request(
        harness,
        Method::Put,
        session,
        &format!("/e2ee/to_device/{txn_id}"),
        Some(json!({ "type": event_type, "messages": messages })),
    )
    .await;
    assert_eq!(status, Status::Ok, "{body}");
}

/// Mailbox of the device of `session`
async fn mailbox(harness: &TestHarness, session: &Session) -> Vec<Value> {
    let (status, body) = get(harness, session, "/e2ee/to_device").await;
    assert_eq!(status, Status::Ok);
    body["messages"].as_array().unwrap().clone()
}

async fn ack(harness: &TestHarness, session: &Session, messages: &[Value]) {
    let ids: Vec<&Value> = messages.iter().map(|message| &message["id"]).collect();
    let (status, _) = post(
        harness,
        session,
        "/e2ee/to_device/ack",
        json!({ "ids": ids }),
    )
    .await;
    assert_eq!(status, Status::NoContent);
}

/// Messages of a channel as `session` sees them
async fn messages(harness: &TestHarness, session: &Session, channel_id: &str) -> (Status, Value) {
    get(
        harness,
        session,
        &format!("/channels/{channel_id}/messages"),
    )
    .await
}

/// Wait for a device list update of `user_id` on its topic
async fn device_list_update(events: &mut PubSubTestHelper, user_id: &str) {
    tokio::time::timeout(
        Duration::from_secs(5),
        events.wait_for_event(
            |event| matches!(event, EventV1::E2eeDeviceListUpdate { user } if user == user_id),
        ),
    )
    .await
    .expect("`E2eeDeviceListUpdate`");
}

/// T1: A and B with one device each in a direct message
///
/// A starts an Olm session with B's device, shares the Megolm key through the mailbox and
/// sends a message. B reads both; the database keeps nothing but the ciphertext.
#[rocket::async_test]
async fn t1_direct_message() {
    let harness = TestHarness::new().await;
    let (_, a, mut user_a) = new_device_user(&harness).await;
    let (_, b, mut user_b) = new_device_user(&harness).await;
    let channel = friendly_dm(&harness, &mut user_a, &mut user_b).await;

    let (status, _) = post(
        &harness,
        &b,
        "/e2ee/keys/upload",
        json!({ "one_time_keys": one_time_keys(&user_b.id, &b.id, "B", 1) }),
    )
    .await;
    assert_eq!(status, Status::Ok);

    assert_eq!(
        visible_devices(&harness, &a, &user_b.id).await,
        vec![b.id.clone()]
    );
    let claimed = claim(&harness, &a, &user_b.id, &[&b.id]).await;
    assert!(claimed[&b.id]["signed_curve25519:B0"].is_object());

    let (status, _) = encrypt(&harness, &a, channel.id()).await;
    assert_eq!(status, Status::Ok);

    to_device(
        &harness,
        &a,
        "room-key",
        "m.room.encrypted",
        json!({ e2ee_user_id(&user_b.id): { b.id.clone(): { "ciphertext": "olm(room key)" } } }),
    )
    .await;

    let sent = envelope(&a.id, "megolm(hello)");
    let (status, message) = send(&harness, &a, channel.id(), json!({ "encrypted": sent })).await;
    assert_eq!(status, Status::Ok, "{message}");
    let id = message["_id"].as_str().unwrap().to_string();

    // B gets the key, then the message
    let keys = mailbox(&harness, &b).await;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["sender_device"], a.id.as_str());
    assert_eq!(keys[0]["content"], json!({ "ciphertext": "olm(room key)" }));
    ack(&harness, &b, &keys).await;
    assert!(mailbox(&harness, &b).await.is_empty());

    for session in [&a, &b] {
        let (status, body) = messages(&harness, session, channel.id()).await;
        assert_eq!(status, Status::Ok);
        let fetched = body
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["_id"] == id.as_str())
            .expect("message")
            .clone();
        assert_eq!(fetched["encrypted"], sent);
    }

    let stored = harness.db.fetch_message(&id).await.unwrap();
    assert!(stored.content.is_none());
    assert_eq!(stored.encrypted.unwrap().ciphertext, "megolm(hello)");
}

/// T2: A logs in on a new device after the conversation
///
/// Contacts are told to re-query the device list and see the new device. The new device
/// asks A's other devices for old keys (`*`), gets a forwarded key and can still fetch the
/// old ciphertext.
#[rocket::async_test]
async fn t2_new_device() {
    let harness = TestHarness::new().await;
    let (account, a1, mut user_a) = new_device_user(&harness).await;
    let (_, b, mut user_b) = new_device_user(&harness).await;
    let channel = friendly_dm(&harness, &mut user_a, &mut user_b).await;
    let (status, _) = encrypt(&harness, &a1, channel.id()).await;
    assert_eq!(status, Status::Ok);

    let (status, old) = send(
        &harness,
        &b,
        channel.id(),
        json!({ "encrypted": envelope(&b.id, "before the new device") }),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let mut events = PubSubTestHelper::new(&user_a.id).await;
    let a2 = new_device(&harness, &account).await;
    device_list_update(&mut events, &user_a.id).await;

    let mut expected = vec![a1.id.clone(), a2.id.clone()];
    expected.sort();
    assert_eq!(visible_devices(&harness, &b, &user_a.id).await, expected);

    // Key request to all own devices but the asking one
    to_device(
        &harness,
        &a2,
        "request",
        "m.room_key_request",
        json!({ e2ee_user_id(&user_a.id): { "*": { "action": "request", "body": {} } } }),
    )
    .await;
    assert!(mailbox(&harness, &a2).await.is_empty());
    let requests = mailbox(&harness, &a1).await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["type"], "m.room_key_request");
    assert_eq!(requests[0]["sender_device"], a2.id.as_str());
    ack(&harness, &a1, &requests).await;

    to_device(
        &harness,
        &a1,
        "forward",
        "m.room.encrypted",
        json!({ e2ee_user_id(&user_a.id): { a2.id.clone(): { "ciphertext": "olm(forwarded key)" } } }),
    )
    .await;
    let forwarded = mailbox(&harness, &a2).await;
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0]["sender_device"], a1.id.as_str());

    let (status, body) = messages(&harness, &a2, channel.id()).await;
    assert_eq!(status, Status::Ok);
    assert!(
        body.as_array()
            .unwrap()
            .iter()
            .any(|message| message["_id"] == old["_id"]
                && message["encrypted"]["ciphertext"] == "before the new device")
    );
}

/// T3: every device is lost, a new device restores keys from the backup
#[rocket::async_test]
async fn t3_restore_from_backup() {
    let harness = TestHarness::new().await;
    let (account, a1, mut user_a) = new_device_user(&harness).await;
    let (_, _, mut user_b) = new_device_user(&harness).await;
    let channel = friendly_dm(&harness, &mut user_a, &mut user_b).await;

    let auth_data = json!({ "public_key": "backup-public-key", "signatures": {} });
    let (status, body) = post(
        &harness,
        &a1,
        "/e2ee/backup/version",
        json!({
            "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
            "auth_data": auth_data
        }),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let version = body["version"].as_str().unwrap().to_string();

    let room = e2ee_room_id(channel.id());
    let key = json!({
        "first_message_index": 0,
        "forwarded_count": 0,
        "is_verified": true,
        "session_data": { "ephemeral": "e", "ciphertext": "aes(session)", "mac": "m" }
    });
    let (status, body) = request(
        &harness,
        Method::Put,
        &a1,
        &format!("/e2ee/backup/keys?version={version}"),
        Some(json!({ "rooms": { room.clone(): { "sessions": { "megolm-session": key } } } })),
    )
    .await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["count"], 1);

    // The recovery key itself lives in secret storage, encrypted by the client
    let secret = json!({ "encrypted": { "key": { "iv": "i", "ciphertext": "c", "mac": "m" } } });
    let (status, _) = request(
        &harness,
        Method::Put,
        &a1,
        "/e2ee/secrets/m.megolm_backup.v1",
        Some(secret.clone()),
    )
    .await;
    assert_eq!(status, Status::NoContent);

    // The only device is lost: logged out everywhere
    account
        .delete_all_sessions(&harness.db, None)
        .await
        .unwrap();
    assert!(harness.db.fetch_e2ee_device(&a1.id).await.is_err());

    let a2 = new_device(&harness, &account).await;
    let (status, current) = get(&harness, &a2, "/e2ee/backup/version").await;
    assert_eq!(status, Status::Ok);
    assert_eq!(current["version"], version.as_str());
    assert_eq!(current["auth_data"], auth_data);
    assert_eq!(current["count"], 1);

    let (status, keys) = get(
        &harness,
        &a2,
        &format!("/e2ee/backup/keys?version={version}"),
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert_eq!(
        keys,
        json!({ "rooms": { room: { "sessions": { "megolm-session": key } } } })
    );

    let (status, restored) = get(&harness, &a2, "/e2ee/secrets/m.megolm_backup.v1").await;
    assert_eq!(status, Status::Ok);
    assert_eq!(restored, secret);
}

/// T4: A loses a device and revokes it from another one
///
/// B is told to re-query, no longer sees or reaches the device, and the device's token
/// is useless.
#[rocket::async_test]
async fn t4_lost_device() {
    let harness = TestHarness::new().await;
    let (account, a1, mut user_a) = new_device_user(&harness).await;
    let lost = new_device(&harness, &account).await;
    let (_, b, mut user_b) = new_device_user(&harness).await;
    friendly_dm(&harness, &mut user_a, &mut user_b).await;

    let (status, _) = post(
        &harness,
        &lost,
        "/e2ee/keys/upload",
        json!({ "one_time_keys": one_time_keys(&user_a.id, &lost.id, "L", 2) }),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let ticket = MFATicket::new(account.id.clone(), true);
    ticket.save(&harness.db).await.unwrap();

    let mut events = PubSubTestHelper::new(&user_a.id).await;
    let (status, _) = request_with(
        &harness,
        Method::Delete,
        &a1,
        &format!("/auth/session/{}", lost.id),
        None,
        vec![Header::new("x-mfa-ticket", ticket.token)],
    )
    .await;
    assert_eq!(status, Status::NoContent);
    device_list_update(&mut events, &user_a.id).await;

    assert_eq!(
        visible_devices(&harness, &b, &user_a.id).await,
        vec![a1.id.clone()]
    );
    assert_eq!(
        claim(&harness, &b, &user_a.id, &[&lost.id]).await,
        Value::Null
    );

    // A new Megolm session goes to the remaining device only, the lost one gets nothing
    to_device(
        &harness,
        &b,
        "rotate",
        "m.room.encrypted",
        json!({ e2ee_user_id(&user_a.id): {
            "*": { "ciphertext": "olm(new room key)" },
            lost.id.clone(): { "ciphertext": "olm(new room key)" }
        } }),
    )
    .await;
    assert_eq!(mailbox(&harness, &a1).await.len(), 1);
    assert!(
        harness
            .db
            .fetch_to_device(&lost.id, 10)
            .await
            .unwrap()
            .is_empty()
    );

    let (status, _) = get(&harness, &lost, "/e2ee/to_device").await;
    assert_eq!(status, Status::Unauthorized);
}

/// T5: C is removed from a group of four
///
/// Members learn about it from `ChannelGroupLeave` and rotate the group session; C no longer
/// sees the members' devices, gets no new keys and cannot read new messages.
#[rocket::async_test]
async fn t5_group_member_removed() {
    let harness = TestHarness::new().await;
    let (_, a, user_a) = new_device_user(&harness).await;
    let (_, b, user_b) = new_device_user(&harness).await;
    let (_, c, user_c) = new_device_user(&harness).await;
    let (_, d, user_d) = new_device_user(&harness).await;
    let channel = group(&harness, &user_a, &[&user_b, &user_c, &user_d]).await;
    let (status, _) = encrypt(&harness, &a, channel.id()).await;
    assert_eq!(status, Status::Ok);

    assert_eq!(
        visible_devices(&harness, &c, &user_a.id).await,
        vec![a.id.clone()]
    );

    let mut events = PubSubTestHelper::new(channel.id()).await;
    let (status, _) = request(
        &harness,
        Method::Delete,
        &a,
        &format!("/channels/{}/recipients/{}", channel.id(), user_c.id),
        None,
    )
    .await;
    assert_eq!(status, Status::NoContent);

    let event = tokio::time::timeout(
        Duration::from_secs(5),
        events.wait_for_event(|event| matches!(event, EventV1::ChannelGroupLeave { .. })),
    )
    .await
    .expect("`ChannelGroupLeave`");
    assert!(matches!(event, EventV1::ChannelGroupLeave { user, .. } if user == user_c.id));

    // Nothing else connects A and C
    assert!(visible_devices(&harness, &a, &user_c.id).await.is_empty());
    assert!(visible_devices(&harness, &c, &user_a.id).await.is_empty());

    // Rotation: the new key reaches B and D, a stale device list does not leak it to C
    let rotated = json!({ "ciphertext": "olm(rotated key)" });
    to_device(
        &harness,
        &a,
        "rotate",
        "m.room.encrypted",
        json!({
            e2ee_user_id(&user_b.id): { b.id.clone(): rotated },
            e2ee_user_id(&user_c.id): { c.id.clone(): rotated },
            e2ee_user_id(&user_d.id): { d.id.clone(): rotated }
        }),
    )
    .await;
    assert_eq!(mailbox(&harness, &b).await.len(), 1);
    assert_eq!(mailbox(&harness, &d).await.len(), 1);
    assert!(mailbox(&harness, &c).await.is_empty());

    let (status, sent) = send(
        &harness,
        &a,
        channel.id(),
        json!({ "encrypted": envelope(&a.id, "megolm(after rotation)") }),
    )
    .await;
    assert_eq!(status, Status::Ok, "{sent}");

    let (status, body) = messages(&harness, &b, channel.id()).await;
    assert_eq!(status, Status::Ok);
    assert!(
        body.as_array()
            .unwrap()
            .iter()
            .any(|message| message["_id"] == sent["_id"])
    );

    let (status, _) = messages(&harness, &c, channel.id()).await;
    assert_ne!(status, Status::Ok);
    let (status, _) = send(
        &harness,
        &c,
        channel.id(),
        json!({ "encrypted": envelope(&c.id, "megolm(stale)") }),
    )
    .await;
    assert_ne!(status, Status::Ok);
}

/// T7: the room key did not get through
///
/// Mailbox messages survive until acknowledged (lost doorbell, crash before ack). If the key
/// is lost anyway, the device asks its other devices and gets it forwarded.
#[rocket::async_test]
async fn t7_undelivered_key() {
    let harness = TestHarness::new().await;
    let (_, a, mut user_a) = new_device_user(&harness).await;
    let (account_b, b1, mut user_b) = new_device_user(&harness).await;
    let b2 = new_device(&harness, &account_b).await;
    let channel = friendly_dm(&harness, &mut user_a, &mut user_b).await;
    let (status, _) = encrypt(&harness, &a, channel.id()).await;
    assert_eq!(status, Status::Ok);

    // Only B2 gets the key (B1 was missing from A's device list)
    to_device(
        &harness,
        &a,
        "key",
        "m.room.encrypted",
        json!({ e2ee_user_id(&user_b.id): { b2.id.clone(): { "ciphertext": "olm(room key)" } } }),
    )
    .await;

    // Not acknowledged: fetched again and again
    let first = mailbox(&harness, &b2).await;
    let again = mailbox(&harness, &b2).await;
    assert_eq!(first.len(), 1);
    assert_eq!(first, again);
    ack(&harness, &b2, &first).await;
    assert!(mailbox(&harness, &b2).await.is_empty());

    // B1 asks its own devices
    to_device(
        &harness,
        &b1,
        "request",
        "m.room_key_request",
        json!({ e2ee_user_id(&user_b.id): { "*": { "action": "request" } } }),
    )
    .await;
    let requests = mailbox(&harness, &b2).await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["sender_device"], b1.id.as_str());
    ack(&harness, &b2, &requests).await;

    to_device(
        &harness,
        &b2,
        "forward",
        "m.room.encrypted",
        json!({ e2ee_user_id(&user_b.id): { b1.id.clone(): { "ciphertext": "olm(forwarded key)" } } }),
    )
    .await;
    let forwarded = mailbox(&harness, &b1).await;
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0]["content"]["ciphertext"], "olm(forwarded key)");

    // Acknowledging someone else's message does nothing
    ack(&harness, &a, &forwarded).await;
    assert_eq!(mailbox(&harness, &b1).await, forwarded);
}

/// T13: one-time keys run out
///
/// Claims fall back to the fallback key, `keys/count` tells the owner to upload more,
/// and new one-time keys are handed out again.
#[rocket::async_test]
async fn t13_one_time_keys_exhausted() {
    let harness = TestHarness::new().await;
    let (_, a, mut user_a) = new_device_user(&harness).await;
    let (_, b, mut user_b) = new_device_user(&harness).await;
    let (_, c, mut user_c) = new_device_user(&harness).await;
    friendly_dm(&harness, &mut user_a, &mut user_b).await;
    friendly_dm(&harness, &mut user_a, &mut user_c).await;

    let (status, _) = post(
        &harness,
        &a,
        "/e2ee/keys/upload",
        json!({
            "one_time_keys": one_time_keys(&user_a.id, &a.id, "A", 1),
            "fallback_keys": fallback_keys(&user_a.id, &a.id, "F")
        }),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let key_ids = |claimed: Value| -> Vec<String> {
        claimed[&a.id]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    };

    assert_eq!(
        key_ids(claim(&harness, &b, &user_a.id, &[&a.id]).await),
        vec!["signed_curve25519:A0"]
    );
    // Exhausted: both contacts can still start a session through the fallback key
    for session in [&b, &c] {
        assert_eq!(
            key_ids(claim(&harness, session, &user_a.id, &[&a.id]).await),
            vec!["signed_curve25519:F"]
        );
    }

    let (_, counts) = get(&harness, &a, "/e2ee/keys/count").await;
    assert_eq!(counts["one_time_key_counts"]["signed_curve25519"], 0);
    // The used fallback key is reported as used, the client rotates it
    assert_eq!(counts["device_unused_fallback_key_types"], json!([]));

    let (status, body) = post(
        &harness,
        &a,
        "/e2ee/keys/upload",
        json!({ "one_time_keys": one_time_keys(&user_a.id, &a.id, "R", 1) }),
    )
    .await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body["one_time_key_counts"]["signed_curve25519"], 1);

    assert_eq!(
        key_ids(claim(&harness, &c, &user_a.id, &[&a.id]).await),
        vec!["signed_curve25519:R0"]
    );
}

/// Logging out removes the device with everything addressed to it, other devices keep theirs
#[rocket::async_test]
async fn logout_cascade() {
    let harness = TestHarness::new().await;
    let (account, a1, mut user_a) = new_device_user(&harness).await;
    let a2 = new_device(&harness, &account).await;
    let (_, b, mut user_b) = new_device_user(&harness).await;
    friendly_dm(&harness, &mut user_a, &mut user_b).await;

    for session in [&a1, &a2] {
        let (status, _) = post(
            &harness,
            session,
            "/e2ee/keys/upload",
            json!({ "one_time_keys": one_time_keys(&user_a.id, &session.id, "K", 2) }),
        )
        .await;
        assert_eq!(status, Status::Ok);
    }
    to_device(
        &harness,
        &b,
        "both",
        "m.room.encrypted",
        json!({ e2ee_user_id(&user_a.id): { "*": { "ciphertext": "olm" } } }),
    )
    .await;

    let mut events = PubSubTestHelper::new(&user_a.id).await;
    let (status, _) = request(&harness, Method::Post, &a1, "/auth/session/logout", None).await;
    assert_eq!(status, Status::NoContent);
    device_list_update(&mut events, &user_a.id).await;

    assert!(harness.db.fetch_e2ee_device(&a1.id).await.is_err());
    assert!(
        harness
            .db
            .count_one_time_keys(&a1.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        harness
            .db
            .fetch_to_device(&a1.id, 10)
            .await
            .unwrap()
            .is_empty()
    );

    assert_eq!(
        visible_devices(&harness, &b, &user_a.id).await,
        vec![a2.id.clone()]
    );
    assert_eq!(mailbox(&harness, &a2).await.len(), 1);
    let (_, counts) = get(&harness, &a2, "/e2ee/keys/count").await;
    assert_eq!(counts["one_time_key_counts"]["signed_curve25519"], 2);
}

/// Deleting the account removes devices, keys, mailboxes, backup and secrets;
/// contacts no longer see or reach any device
#[rocket::async_test]
async fn account_delete() {
    let harness = TestHarness::new().await;
    let (_, a, mut user_a) = new_device_user(&harness).await;
    let (_, b, mut user_b) = new_device_user(&harness).await;
    friendly_dm(&harness, &mut user_a, &mut user_b).await;

    let (status, _) = post(
        &harness,
        &a,
        "/e2ee/keys/upload",
        json!({ "one_time_keys": one_time_keys(&user_a.id, &a.id, "A", 2) }),
    )
    .await;
    assert_eq!(status, Status::Ok);
    to_device(
        &harness,
        &b,
        "waiting",
        "m.room.encrypted",
        json!({ e2ee_user_id(&user_a.id): { a.id.clone(): { "ciphertext": "olm" } } }),
    )
    .await;
    let (status, body) = post(
        &harness,
        &a,
        "/e2ee/backup/version",
        json!({
            "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
            "auth_data": { "public_key": "key", "signatures": {} }
        }),
    )
    .await;
    assert_eq!(status, Status::Ok);
    let version = body["version"].as_str().unwrap().to_string();
    let (status, _) = request(
        &harness,
        Method::Put,
        &a,
        "/e2ee/secrets/m.megolm_backup.v1",
        Some(json!({ "encrypted": {} })),
    )
    .await;
    assert_eq!(status, Status::NoContent);

    user_a.delete(&harness.db).await.unwrap();

    assert!(visible_devices(&harness, &b, &user_a.id).await.is_empty());
    assert_eq!(claim(&harness, &b, &user_a.id, &[&a.id]).await, Value::Null);
    assert!(
        harness
            .db
            .count_one_time_keys(&a.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        harness
            .db
            .fetch_to_device(&a.id, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        harness
            .db
            .fetch_e2ee_backup_version(&user_a.id, Some(version.as_str()))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        harness
            .db
            .fetch_e2ee_secret_types(&user_a.id)
            .await
            .unwrap()
            .is_empty()
    );
}
