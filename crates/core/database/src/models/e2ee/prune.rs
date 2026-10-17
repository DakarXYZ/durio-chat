use revolt_result::Result;

use crate::{Database, e2ee_on_sessions_deleted};

/// What an orphan cleanup run removed
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct E2eePruneReport {
    /// Devices whose session no longer existed
    pub devices: usize,
    /// Devices whose keys or mailbox outlived them
    pub device_data: usize,
    /// Backed up sessions of replaced or deleted backup versions
    pub backup_keys: u64,
    /// Deleted backup versions
    pub backup_versions: u64,
}

/// Remove E2EE data left behind by failed cascades and races (crond)
///
/// - devices without a session (sessions deleted directly in the database, failed cascade),
///   contacts are told to re-query the device list;
/// - one-time keys, fallback keys and mailboxes of devices that no longer exist;
/// - backed up sessions of versions replaced while they were being written, and the
///   deleted versions themselves.
///
/// Expired mailbox messages are dropped by the TTL index on `expires_at`.
pub async fn prune_e2ee_orphans(db: &Database) -> Result<E2eePruneReport> {
    let devices = db.fetch_e2ee_devices_without_session().await?;
    for (user_id, device_id) in &devices {
        e2ee_on_sessions_deleted(db, user_id, Some(device_id), None).await;
    }

    let device_data = db.delete_e2ee_orphan_device_data().await?.len();
    let (backup_keys, backup_versions) = db.delete_e2ee_orphan_backups().await?;

    Ok(E2eePruneReport {
        devices: devices.len(),
        device_data,
        backup_keys,
        backup_versions,
    })
}
