//! Collections and indexes of end-to-end encryption (dur.io fork), shared by
//! `init` (new databases) and `scripts` (revision 55 → 56)
use crate::mongodb::bson::{Document, doc};

/// E2EE collections
pub const E2EE_COLLECTIONS: [&str; 7] = [
    "e2ee_devices",
    "e2ee_one_time_keys",
    "e2ee_fallback_keys",
    "e2ee_to_device",
    "e2ee_backup_versions",
    "e2ee_backup_keys",
    "e2ee_secrets",
];

/// `createIndexes` commands for E2EE collections
pub fn e2ee_indexes() -> Vec<Document> {
    vec![
        doc! {
            "createIndexes": "e2ee_devices",
            "indexes": [
                {
                    "key": { "user_id": 1_i32 },
                    "name": "user_id"
                }
            ]
        },
        doc! {
            "createIndexes": "e2ee_one_time_keys",
            "indexes": [
                {
                    // Atomic claim: find_one_and_delete by device and algorithm
                    "key": { "device_id": 1_i32, "algorithm": 1_i32 },
                    "name": "device_algorithm"
                }
            ]
        },
        doc! {
            "createIndexes": "e2ee_to_device",
            "indexes": [
                {
                    // Mailbox, oldest first
                    "key": { "recipient_device": 1_i32, "_id": 1_i32 },
                    "name": "mailbox"
                },
                {
                    // Idempotency of PUT /e2ee/to_device/<txn_id>
                    "key": { "sender_device": 1_i32, "txn_id": 1_i32, "recipient_device": 1_i32 },
                    "name": "transaction",
                    "unique": true
                },
                {
                    // expires_at holds the expiry time (BSON date), see audit_logs
                    "key": { "expires_at": 1_i32 },
                    "name": "expires_at_ttl",
                    "expireAfterSeconds": 0_i32
                }
            ]
        },
        doc! {
            "createIndexes": "e2ee_backup_versions",
            "indexes": [
                {
                    "key": { "user_id": 1_i32, "deleted": 1_i32 },
                    "name": "user_deleted"
                },
                {
                    // One active version per user
                    "key": { "user_id": 1_i32 },
                    "name": "active_version",
                    "unique": true,
                    "partialFilterExpression": { "deleted": false }
                }
            ]
        },
        doc! {
            "createIndexes": "e2ee_backup_keys",
            "indexes": [
                {
                    "key": { "_id.user": 1_i32, "_id.version": 1_i32 },
                    "name": "user_version"
                }
            ]
        },
        doc! {
            "createIndexes": "e2ee_secrets",
            "indexes": [
                {
                    "key": { "_id.user": 1_i32 },
                    "name": "user"
                }
            ]
        },
    ]
}

/// Create E2EE collections and indexes, safe to run again after a partial failure
pub async fn create_e2ee_collections(db: &crate::mongodb::Database) {
    for collection in E2EE_COLLECTIONS {
        // Fails with NamespaceExists if it is already there
        db.create_collection(collection).await.ok();
    }

    for command in e2ee_indexes() {
        db.run_command(command)
            .await
            .expect("Failed to create E2EE indexes.");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use futures::StreamExt;

    use super::E2EE_COLLECTIONS;
    use crate::{
        AbstractMigrations, Database, DatabaseInfo, MongoDb,
        mongodb::bson::{Document, doc},
    };

    async fn mongo(name: &str) -> Option<MongoDb> {
        let db = DatabaseInfo::Test(format!("revolt_test_e2ee_migration_{name}"))
            .connect()
            .await
            .expect("Database connection failed.");

        match db {
            Database::MongoDb(mongo) => {
                mongo.drop_database().await;
                Some(mongo)
            }
            // Only meaningful with TEST_DB=MONGODB
            Database::Reference(_) => None,
        }
    }

    /// (collection, index name, key, options) of all E2EE indexes
    async fn schema(db: &MongoDb) -> BTreeSet<String> {
        let mut schema = BTreeSet::new();
        for collection in E2EE_COLLECTIONS {
            let mut cursor = db.col::<Document>(collection).list_indexes().await.unwrap();

            while let Some(index) = cursor.next().await {
                let index = index.unwrap();
                let options = index.options.unwrap_or_default();
                schema.insert(format!(
                    "{collection} {} {} unique={:?} ttl={:?} partial={:?}",
                    options.name.unwrap_or_default(),
                    index.keys,
                    options.unique,
                    options.expire_after,
                    options.partial_filter_expression,
                ));
            }
        }

        schema
    }

    #[tokio::test]
    async fn fresh_and_migrated_schema_match() {
        let (Some(fresh), Some(migrated)) = (mongo("fresh").await, mongo("migrated").await) else {
            return;
        };

        fresh.migrate_database().await.unwrap();

        // Database at revision 55: everything but the E2EE collections
        migrated.migrate_database().await.unwrap();
        for collection in E2EE_COLLECTIONS {
            migrated.col::<Document>(collection).drop().await.unwrap();
        }
        migrated
            .col::<Document>("migrations")
            .update_one(
                doc! { "_id": 0_i32 },
                doc! { "$set": { "revision": 55_i32 } },
            )
            .await
            .unwrap();

        migrated.migrate_database().await.unwrap();
        // Running again is a no-op
        migrated.migrate_database().await.unwrap();

        let schema = schema(&fresh).await;
        assert_eq!(schema, self::schema(&migrated).await);
        assert!(
            schema
                .iter()
                .any(|index| index.contains("transaction") && index.contains("unique=Some(true)"))
        );
        assert!(
            schema
                .iter()
                .any(|index| index.contains("expires_at_ttl") && index.contains("ttl=Some(0ns)"))
        );
        assert!(schema.iter().any(|index| index.contains("active_version")
            && index.contains("unique=Some(true)")
            && index.contains("deleted")));

        let revision = migrated
            .col::<Document>("migrations")
            .find_one(doc! { "_id": 0_i32 })
            .await
            .unwrap()
            .unwrap()
            .get_i32("revision")
            .unwrap();
        assert_eq!(revision, super::super::scripts::LATEST_REVISION);

        fresh.drop_database().await;
        migrated.drop_database().await;
    }
}
