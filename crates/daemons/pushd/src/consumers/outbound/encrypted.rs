//! Push for end-to-end encrypted messages (plan BE-15).
//!
//! The text is fixed ("New message from X"), the envelope rides along only while the
//! payload stays under the provider limit (4 KiB); otherwise the client fetches the
//! message by id.

use std::{borrow::Cow, collections::HashMap};

use revolt_models::v0::{EncryptedEnvelope, PushNotification};
use serde_json::Value;

/// Payload budget, leaves headroom below the 4 KiB limit of FCM and APNs
pub const MAX_PAYLOAD_BYTES: usize = 3584;

/// Serialized size of an FCM data payload (keys and values)
pub fn payload_size(data: &HashMap<String, Value>) -> usize {
    serde_json::to_vec(data).map_or(usize::MAX, |bytes| bytes.len())
}

/// Add the envelope (a JSON string, FCM values are strings) if it still fits
pub fn with_envelope(
    mut data: HashMap<String, Value>,
    envelope: Option<&EncryptedEnvelope>,
) -> HashMap<String, Value> {
    if let Some(envelope) = envelope.and_then(|envelope| serde_json::to_string(envelope).ok()) {
        data.insert("envelope".to_string(), Value::String(envelope));
        if payload_size(&data) > MAX_PAYLOAD_BYTES {
            data.remove("envelope");
        }
    }

    data
}

/// APNs carries the whole message: drop the envelope if the notification is too large
pub fn fit_apn_notification(notification: &PushNotification) -> Cow<'_, PushNotification> {
    let too_large = notification.message.encrypted.is_some()
        && serde_json::to_vec(notification).map_or(true, |bytes| bytes.len() > MAX_PAYLOAD_BYTES);

    if too_large {
        let mut notification = notification.clone();
        notification.message.encrypted = None;
        Cow::Owned(notification)
    } else {
        Cow::Borrowed(notification)
    }
}

#[cfg(test)]
mod tests {
    use revolt_models::v0::{Channel, Message};

    use super::super::{fcm::NotificationData, routing::with_routing};
    use super::*;

    fn envelope(ciphertext_len: usize) -> EncryptedEnvelope {
        EncryptedEnvelope {
            v: 1,
            algorithm: "m.megolm.v1.aes-sha2".to_string(),
            session_id: "session".to_string(),
            device_id: "01HZXAMPLEDEVICE0000000000".to_string(),
            ciphertext: "c".repeat(ciphertext_len),
        }
    }

    fn data(encrypted: bool) -> HashMap<String, Value> {
        with_routing(
            NotificationData::Message {
                message: "01HZXAMPLEMESSAGE000000000".to_string(),
                body: "New message from alice".to_string(),
                image: "https://duri0.duckdns.org/api/users/x/default_avatar".to_string(),
                channel: "01HZXAMPLECHANNEL000000000".to_string(),
                author: "01HZXAMPLEUSER000000000000".to_string(),
                author_name: "alice".to_string(),
                encrypted,
            }
            .into_payload(),
            "https://duri0.duckdns.org/api",
            "01HZXAMPLERECIPIENT0000000",
        )
    }

    fn all_strings(data: &HashMap<String, Value>) -> bool {
        data.values().all(Value::is_string)
    }

    #[test]
    fn small_envelope_included() {
        let sent = envelope(512);
        let data = with_envelope(data(true), Some(&sent));

        assert_eq!(data["encrypted"], Value::String("1".to_string()));
        assert_eq!(
            serde_json::from_str::<EncryptedEnvelope>(data["envelope"].as_str().unwrap()).unwrap(),
            sent
        );
        assert_eq!(
            data["body"],
            Value::String("New message from alice".to_string())
        );
        assert!(data.contains_key("instance") && data.contains_key("recipient"));
        assert!(all_strings(&data));
        assert!(payload_size(&data) <= MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn large_envelope_dropped() {
        let data = with_envelope(data(true), Some(&envelope(16_384)));

        assert!(!data.contains_key("envelope"));
        assert_eq!(data["encrypted"], Value::String("1".to_string()));
        assert_eq!(
            data["recipient"],
            Value::String("01HZXAMPLERECIPIENT0000000".to_string())
        );
        assert!(all_strings(&data));
    }

    #[test]
    fn plain_message_unchanged() {
        let data = with_envelope(data(false), None);

        assert!(!data.contains_key("encrypted") && !data.contains_key("envelope"));
        assert!(all_strings(&data));
    }

    fn notification(encrypted: Option<EncryptedEnvelope>) -> PushNotification {
        let message: Message = serde_json::from_value(serde_json::json!({
            "_id": "01HZXAMPLEMESSAGE000000000",
            "channel": "01HZXAMPLECHANNEL000000000",
            "author": "01HZXAMPLEUSER000000000000",
            "content": "🔒 placeholder",
        }))
        .unwrap();
        let channel: Channel = serde_json::from_value(serde_json::json!({
            "channel_type": "DirectMessage",
            "_id": "01HZXAMPLECHANNEL000000000",
            "active": true,
            "recipients": []
        }))
        .unwrap();

        PushNotification {
            author: "alice".to_string(),
            icon: String::new(),
            image: None,
            body: "New message from alice".to_string(),
            raw_body: None,
            tag: channel.id().to_string(),
            timestamp: 0,
            url: String::new(),
            message: Message {
                encrypted,
                ..message
            },
            channel,
        }
    }

    #[test]
    fn apn_envelope() {
        let small = notification(Some(envelope(512)));
        assert!(matches!(fit_apn_notification(&small), Cow::Borrowed(_)));

        let large = notification(Some(envelope(16_384)));
        let fitted = fit_apn_notification(&large);
        assert!(fitted.message.encrypted.is_none());
        assert!(serde_json::to_vec(fitted.as_ref()).unwrap().len() <= MAX_PAYLOAD_BYTES);
    }
}
