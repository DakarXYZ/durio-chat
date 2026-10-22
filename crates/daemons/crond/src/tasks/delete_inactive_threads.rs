//! Threads nobody wrote in for longer than their channel keeps them (dur.io fork)
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use revolt_database::{Channel, Database, AMQP};
use revolt_result::Result;
use tokio::time::sleep;

pub async fn task(db: Database, _: AMQP) -> Result<()> {
    loop {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.as_millis() as u64)
            .unwrap_or_default();

        let count = Channel::delete_inactive_threads(&db, now_ms).await?;
        if count > 0 {
            log::info!("Deleted {count} inactive threads.");
        }

        sleep(Duration::from_hours(1)).await
    }
}
