//! Concurrent writes to unreads (dur.io fork)
use futures::future::join_all;

use crate::DatabaseInfo;

/// Upserts racing on a new unread all succeed (B4)
#[tokio::test]
async fn concurrent_upserts_of_new_unread() {
    let db = DatabaseInfo::Test("revolt_test_channel_unreads_race".to_string())
        .connect()
        .await
        .expect("Database connection failed.");
    db.drop_database().await;

    for round in 0..20 {
        let channel = format!("channel{round}");
        let mentions = ["m2", "m4", "m6", "m8"].map(|id| vec![id.to_string()]);

        let (added, acked) = futures::join!(
            join_all(
                mentions
                    .iter()
                    .map(|ids| db.add_mention_to_unread(&channel, "user", ids))
            ),
            join_all((0..4).map(|_| db.acknowledge_message(&channel, "user", "m1")))
        );
        for result in added {
            result.expect("add mention");
        }
        for result in acked {
            result.expect("acknowledge");
        }

        let unread = db.fetch_unread("user", &channel).await.unwrap().unwrap();
        assert_eq!(unread.last_id.as_deref(), Some("m1"));
    }

    db.drop_database().await;
}
