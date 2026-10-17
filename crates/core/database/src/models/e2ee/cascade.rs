use revolt_config::config;

use crate::{Database, events::client::EventV1};

/// Delete the E2EE devices of deleted sessions with their keys and mailboxes,
/// either `only` one session or all sessions of the user `except` one
///
/// Never fails: logging out must work, a failed cascade leaves orphans behind
/// for the cleanup task. Contacts are told to re-query the device list.
pub async fn e2ee_on_sessions_deleted(
    db: &Database,
    user_id: &str,
    only: Option<&str>,
    except: Option<&str>,
) {
    let ids = match db.delete_e2ee_devices(user_id, only, except).await {
        Ok(ids) => ids,
        Err(error) => {
            log::error!("Failed to delete E2EE devices of {user_id}: {error:?}");
            return;
        }
    };

    // Sessions without E2EE do not wake up contacts
    if ids.is_empty() {
        return;
    }

    if let Err(error) = db.delete_e2ee_device_data(&ids).await {
        log::error!("Failed to delete keys and mailboxes of E2EE devices: {error:?}");
    }

    // New events are only published with E2EE enabled (rollout rule)
    if config().await.features.e2ee.enabled {
        EventV1::E2eeDeviceListUpdate {
            user: user_id.to_string(),
        }
        .p(user_id.to_string())
        .await;
    }
}
