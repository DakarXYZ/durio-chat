//! E2EE data left behind by failed cascades and races (dur.io fork)
use std::time::Duration;

use log::info;
use revolt_database::{AMQP, Database, E2eePruneReport, prune_e2ee_orphans};
use revolt_result::Result;
use tokio::time::sleep;

pub async fn task(db: Database, _: AMQP) -> Result<()> {
    loop {
        let report = prune_e2ee_orphans(&db).await?;
        if report != E2eePruneReport::default() {
            info!("Pruned E2EE orphans: {report:?}");
        }

        sleep(Duration::from_secs(24 * 60 * 60)).await;
    }
}
