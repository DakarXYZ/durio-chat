//! E2EE devices follow their sessions (BE-10)
use std::time::Duration;

use iso8601_timestamp::Timestamp;
use revolt_database::{E2eeDevice, MFATicket, Session, events::client::EventV1};
use revolt_models::v0::e2ee_user_id;
use rocket::http::{Header, Method, Status};
use serde_json::json;

use super::tests::{
    direct_message, get, new_device, new_device_user, one_time_keys, post, request, request_with,
};
use crate::util::test::{PubSubTestHelper, TestHarness};

/// Wait for a device list update of `user_id`, `None` after `seconds`
async fn device_list_update(
    events: &mut PubSubTestHelper,
    user_id: &str,
    seconds: u64,
) -> Option<EventV1> {
    tokio::time::timeout(
        Duration::from_secs(seconds),
        events.wait_for_event(
            |event| matches!(event, EventV1::E2eeDeviceListUpdate { user } if user == user_id),
        ),
    )
    .await
    .ok()
}

/// Give a device one-time keys and a waiting to-device message
async fn fill_device(harness: &TestHarness, session: &Session, sender: &Session) {
    let (status, _) = post(
        harness,
        session,
        "/e2ee/keys/upload",
        json!({ "one_time_keys": one_time_keys(&session.user_id, &session.id, "A", 2) }),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let (status, _) = request(
        harness,
        Method::Put,
        sender,
        &format!("/e2ee/to_device/fill{}", session.id),
        Some(json!({
            "type": "m.dummy",
            "messages": { e2ee_user_id(&session.user_id): { session.id.clone(): {} } }
        })),
    )
    .await;
    assert_eq!(status, Status::Ok);
}

/// The device, its keys and its mailbox are gone
async fn assert_device_gone(harness: &TestHarness, device_id: &str) {
    assert!(harness.db.fetch_e2ee_device(device_id).await.is_err());
    assert!(
        harness
            .db
            .count_one_time_keys(device_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        harness
            .db
            .fetch_to_device(device_id, 100)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Device ids of `user_id` as seen by `viewer`
async fn queried_devices(harness: &TestHarness, viewer: &Session, user_id: &str) -> Vec<String> {
    let (_, body) = post(
        harness,
        viewer,
        "/e2ee/keys/query",
        json!({ "device_keys": { e2ee_user_id(user_id): [] } }),
    )
    .await;

    let mut ids: Vec<String> = body["device_keys"][e2ee_user_id(user_id)]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    ids.sort();
    ids
}

#[rocket::async_test]
async fn logout() {
    let harness = TestHarness::new().await;
    let (account, session, user) = new_device_user(&harness).await;
    let second = new_device(&harness, &account).await;
    let (_, peer_session, peer) = new_device_user(&harness).await;
    direct_message(&harness, &user, &peer).await;
    fill_device(&harness, &session, &peer_session).await;

    let mut events = PubSubTestHelper::new(&user.id).await;
    let (status, _) = request(
        &harness,
        Method::Post,
        &session,
        "/auth/session/logout",
        None,
    )
    .await;
    assert_eq!(status, Status::NoContent);

    assert_device_gone(&harness, &session.id).await;
    assert!(device_list_update(&mut events, &user.id, 5).await.is_some());
    assert_eq!(
        queried_devices(&harness, &peer_session, &user.id).await,
        vec![second.id.clone()]
    );
}

#[rocket::async_test]
async fn revoke_other_session() {
    let harness = TestHarness::new().await;
    let (account, session, user) = new_device_user(&harness).await;
    let second = new_device(&harness, &account).await;
    fill_device(&harness, &second, &session).await;

    let ticket = MFATicket::new(account.id.clone(), true);
    ticket.save(&harness.db).await.unwrap();

    let mut events = PubSubTestHelper::new(&user.id).await;
    let (status, _) = request_with(
        &harness,
        Method::Delete,
        &session,
        &format!("/auth/session/{}", second.id),
        None,
        vec![Header::new("x-mfa-ticket", ticket.token)],
    )
    .await;
    assert_eq!(status, Status::NoContent);

    assert_device_gone(&harness, &second.id).await;
    assert!(device_list_update(&mut events, &user.id, 5).await.is_some());
    assert_eq!(
        queried_devices(&harness, &session, &user.id).await,
        vec![session.id.clone()]
    );
}

#[rocket::async_test]
async fn revoke_all_but_self() {
    let harness = TestHarness::new().await;
    let (account, session, user) = new_device_user(&harness).await;
    let second = new_device(&harness, &account).await;
    let third = new_device(&harness, &account).await;
    fill_device(&harness, &second, &session).await;
    fill_device(&harness, &session, &third).await;

    let ticket = MFATicket::new(account.id.clone(), true);
    ticket.save(&harness.db).await.unwrap();

    let mut events = PubSubTestHelper::new(&user.id).await;
    let (status, _) = request_with(
        &harness,
        Method::Delete,
        &session,
        "/auth/session/all?revoke_self=false",
        None,
        vec![Header::new("x-mfa-ticket", ticket.token)],
    )
    .await;
    assert_eq!(status, Status::NoContent);

    assert_device_gone(&harness, &second.id).await;
    assert_device_gone(&harness, &third.id).await;
    assert!(device_list_update(&mut events, &user.id, 5).await.is_some());

    // The remaining device keeps its keys and mailbox
    assert_eq!(
        queried_devices(&harness, &session, &user.id).await,
        vec![session.id.clone()]
    );
    let (_, counts) = get(&harness, &session, "/e2ee/keys/count").await;
    assert_eq!(counts["one_time_key_counts"]["signed_curve25519"], 2);
    let (_, mailbox) = get(&harness, &session, "/e2ee/to_device").await;
    assert_eq!(mailbox["messages"].as_array().unwrap().len(), 1);
}

/// Password reset, account disable and suspension go through `delete_all_sessions`
#[rocket::async_test]
async fn delete_all_sessions() {
    let harness = TestHarness::new().await;
    let (account, session, user) = new_device_user(&harness).await;
    let second = new_device(&harness, &account).await;

    let mut events = PubSubTestHelper::new(&user.id).await;
    account
        .delete_all_sessions(&harness.db, None)
        .await
        .unwrap();

    assert_device_gone(&harness, &session.id).await;
    assert_device_gone(&harness, &second.id).await;
    assert!(device_list_update(&mut events, &user.id, 5).await.is_some());

    // Nothing left: no second event (suspension deletes sessions twice)
    let mut events = PubSubTestHelper::new(&user.id).await;
    account
        .delete_all_sessions(&harness.db, None)
        .await
        .unwrap();
    assert!(device_list_update(&mut events, &user.id, 1).await.is_none());
}

#[rocket::async_test]
async fn no_devices_no_event() {
    let harness = TestHarness::new().await;
    let (_, session, user) = harness.new_user().await;

    let mut events = PubSubTestHelper::new(&user.id).await;
    let (status, _) = request(
        &harness,
        Method::Post,
        &session,
        "/auth/session/logout",
        None,
    )
    .await;
    assert_eq!(status, Status::NoContent);
    assert!(device_list_update(&mut events, &user.id, 1).await.is_none());
}

/// With E2EE disabled devices are still removed, but no event is published
#[rocket::async_test]
async fn disabled_no_event() {
    revolt_config::overwrite_config(|config| config.features.e2ee.enabled = false).await;

    let harness = TestHarness::new().await;
    let (_, session, user) = harness.new_user().await;
    harness
        .db
        .insert_e2ee_device(&E2eeDevice {
            id: session.id.clone(),
            user_id: user.id.clone(),
            keys: "{}".to_string(),
            display_name: None,
            created_at: Timestamp::now_utc(),
        })
        .await
        .unwrap();

    let mut events = PubSubTestHelper::new(&user.id).await;
    let (status, _) = request(
        &harness,
        Method::Post,
        &session,
        "/auth/session/logout",
        None,
    )
    .await;
    assert_eq!(status, Status::NoContent);

    assert_device_gone(&harness, &session.id).await;
    assert!(device_list_update(&mut events, &user.id, 1).await.is_none());
}

/// Deleting an account removes backup and secrets too, they belong to the user (BE-27)
#[rocket::async_test]
async fn user_delete() {
    let harness = TestHarness::new().await;
    let (_, session, mut user) = new_device_user(&harness).await;

    let (status, body) = post(
        &harness,
        &session,
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
        &session,
        &format!("/e2ee/backup/keys/!01kccccccccccccccccccccccc:stoat.invalid/S?version={version}"),
        Some(json!({
            "first_message_index": 0,
            "forwarded_count": 0,
            "is_verified": false,
            "session_data": {}
        })),
    )
    .await;
    assert_eq!(status, Status::Ok);

    let (status, _) = request(
        &harness,
        Method::Put,
        &session,
        "/e2ee/secrets/m.megolm_backup.v1",
        Some(json!({ "encrypted": {} })),
    )
    .await;
    assert_eq!(status, Status::NoContent);

    user.delete(&harness.db).await.unwrap();

    assert!(harness.db.fetch_e2ee_device(&session.id).await.is_err());
    assert!(
        harness
            .db
            .fetch_e2ee_backup_version(&user.id, None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        harness
            .db
            .count_e2ee_backup_keys(&user.id, &version)
            .await
            .unwrap(),
        0
    );
    assert!(
        harness
            .db
            .fetch_e2ee_secret_types(&user.id)
            .await
            .unwrap()
            .is_empty()
    );
}
