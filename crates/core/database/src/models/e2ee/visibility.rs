use std::collections::HashSet;

use revolt_result::Result;

use crate::{Channel, Database, RelationshipStatus, User};

/// Users whose devices `user` may see and send keys to: themselves, friends and
/// pending friend requests (both directions), and participants of shared direct
/// messages and groups
///
/// Built once per request, prevents enumerating devices of arbitrary users.
pub async fn e2ee_visible_users(db: &Database, user: &User) -> Result<HashSet<String>> {
    let mut visible = HashSet::from([user.id.clone()]);

    if let Some(relations) = &user.relations {
        visible.extend(
            relations
                .iter()
                .filter(|relation| {
                    matches!(
                        relation.status,
                        RelationshipStatus::Friend
                            | RelationshipStatus::Incoming
                            | RelationshipStatus::Outgoing
                    )
                })
                .map(|relation| relation.id.clone()),
        );
    }

    for channel in db.find_direct_messages(&user.id).await? {
        if let Channel::DirectMessage { recipients, .. } | Channel::Group { recipients, .. } =
            channel
        {
            visible.extend(recipients);
        }
    }

    Ok(visible)
}

#[cfg(test)]
mod tests {
    use crate::{
        Channel, Database, DatabaseInfo, Relationship, RelationshipStatus, User, e2ee_visible_users,
    };

    fn user(id: &str, relations: Vec<(&str, RelationshipStatus)>) -> User {
        User {
            id: id.to_string(),
            username: id.to_string(),
            relations: Some(
                relations
                    .into_iter()
                    .map(|(id, status)| Relationship {
                        id: id.to_string(),
                        status,
                    })
                    .collect(),
            ),
            ..Default::default()
        }
    }

    #[allow(clippy::disallowed_methods)]
    async fn insert(db: &Database, channel: Channel) {
        db.insert_channel(&channel).await.unwrap();
    }

    #[tokio::test]
    async fn visible_users() {
        let db = DatabaseInfo::Test("revolt_test_e2ee_visibility".to_string())
            .connect()
            .await
            .expect("Database connection failed.");
        db.drop_database().await;

        insert(
            &db,
            Channel::DirectMessage {
                id: "DM".to_string(),
                active: true,
                recipients: vec!["ME".to_string(), "DM_PEER".to_string()],
                last_message_id: None,
                encryption: None,
            },
        )
        .await;
        insert(
            &db,
            Channel::Group {
                id: "GROUP".to_string(),
                name: "group".to_string(),
                owner: "GROUP_OWNER".to_string(),
                description: None,
                recipients: vec![
                    "GROUP_OWNER".to_string(),
                    "ME".to_string(),
                    "GROUP_PEER".to_string(),
                ],
                icon: None,
                last_message_id: None,
                permissions: None,
                nsfw: false,
                encryption: None,
            },
        )
        .await;
        insert(
            &db,
            Channel::Group {
                id: "OTHER_GROUP".to_string(),
                name: "group".to_string(),
                owner: "STRANGER".to_string(),
                description: None,
                recipients: vec!["STRANGER".to_string()],
                icon: None,
                last_message_id: None,
                permissions: None,
                nsfw: false,
                encryption: None,
            },
        )
        .await;

        let me = user(
            "ME",
            vec![
                ("FRIEND", RelationshipStatus::Friend),
                ("INCOMING", RelationshipStatus::Incoming),
                ("OUTGOING", RelationshipStatus::Outgoing),
                ("BLOCKED", RelationshipStatus::Blocked),
                ("BLOCKED_BY", RelationshipStatus::BlockedOther),
            ],
        );

        let mut visible: Vec<String> = e2ee_visible_users(&db, &me)
            .await
            .unwrap()
            .into_iter()
            .collect();
        visible.sort();

        assert_eq!(
            visible,
            [
                "DM_PEER",
                "FRIEND",
                "GROUP_OWNER",
                "GROUP_PEER",
                "INCOMING",
                "ME",
                "OUTGOING"
            ]
        );

        db.drop_database().await;
    }
}
