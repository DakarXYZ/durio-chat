//! E2EE event delivery rules (dur.io fork)
use revolt_database::{Channel, Relationship, RelationshipStatus, events::client::EventV1};
use revolt_models::v0;

use super::state::Cache;

/// Whether a private E2EE event is meant for the socket of this session
///
/// To-device doorbells go only to the socket of the recipient device (= session).
/// Bots have no session (`session_id` is empty), so they never get them.
pub fn private_e2ee_filter(session_id: &str, event: &EventV1) -> bool {
    match event {
        EventV1::E2eeToDevice {
            recipient_device, ..
        } => !session_id.is_empty() && session_id == recipient_device,
        _ => true,
    }
}

impl Cache {
    /// Whether the current user can see the E2EE devices of another user
    ///
    /// Same set as `e2ee_visible_users` in the database crate: self, friends,
    /// pending requests either way and members of shared DMs and groups.
    pub fn can_see_e2ee_devices(&self, user_id: &str) -> bool {
        if self.is_bot {
            return false;
        }

        if user_id == self.user_id {
            return true;
        }

        let Some(user) = self.users.get(&self.user_id) else {
            return false;
        };

        if matches!(
            user.relationship_with(user_id),
            RelationshipStatus::Friend
                | RelationshipStatus::Incoming
                | RelationshipStatus::Outgoing
        ) {
            return true;
        }

        self.channels.values().any(|channel| match channel {
            Channel::DirectMessage { recipients, .. } | Channel::Group { recipients, .. } => {
                recipients.iter().any(|id| id == user_id)
            }
            _ => false,
        })
    }

    /// Keep the relationship of the current user with another user up to date
    pub fn apply_relationship(&mut self, other: &v0::User) {
        let status = match other.relationship {
            v0::RelationshipStatus::None => RelationshipStatus::None,
            v0::RelationshipStatus::User => RelationshipStatus::User,
            v0::RelationshipStatus::Friend => RelationshipStatus::Friend,
            v0::RelationshipStatus::Outgoing => RelationshipStatus::Outgoing,
            v0::RelationshipStatus::Incoming => RelationshipStatus::Incoming,
            v0::RelationshipStatus::Blocked => RelationshipStatus::Blocked,
            v0::RelationshipStatus::BlockedOther => RelationshipStatus::BlockedOther,
        };

        if let Some(user) = self.users.get_mut(&self.user_id) {
            let relations = user.relations.get_or_insert_with(Vec::new);
            relations.retain(|relation| relation.id != other.id);

            if status != RelationshipStatus::None {
                relations.push(Relationship {
                    id: other.id.clone(),
                    status,
                });
            }
        }
    }

    /// Keep the cached recipients of a group up to date
    pub fn apply_group_membership(&mut self, channel_id: &str, user_id: &str, joined: bool) {
        if let Some(Channel::Group { recipients, .. }) = self.channels.get_mut(channel_id) {
            recipients.retain(|id| id != user_id);
            if joined {
                recipients.push(user_id.to_string());
            }
        }
    }
}

/// Other participants of a DM or group whose topics a new channel brings
pub fn channel_peers<'a>(channel: &'a v0::Channel, user_id: &str) -> Vec<&'a String> {
    match channel {
        v0::Channel::DirectMessage { recipients, .. } | v0::Channel::Group { recipients, .. } => {
            recipients.iter().filter(|id| *id != user_id).collect()
        }
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use revolt_database::{
        Channel, Database, DatabaseInfo, Relationship, RelationshipStatus, User,
        events::client::EventV1,
    };
    use revolt_models::v0;

    use super::private_e2ee_filter;
    use crate::events::state::{State, SubscriptionStateChange};

    fn to_device(recipient_device: &str) -> EventV1 {
        EventV1::E2eeToDevice {
            id: "MESSAGE".to_string(),
            recipient_device: recipient_device.to_string(),
            sender: "@SENDER:example.com".to_string(),
            sender_device: "SENDER_DEVICE".to_string(),
            event_type: "m.room.encrypted".to_string(),
        }
    }

    fn device_list(user: &str) -> EventV1 {
        EventV1::E2eeDeviceListUpdate {
            user: user.to_string(),
        }
    }

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

    fn v0_user(id: &str, relationship: v0::RelationshipStatus) -> v0::User {
        v0::User {
            id: id.to_string(),
            username: id.to_string(),
            discriminator: "0001".to_string(),
            display_name: None,
            pronouns: None,
            avatar: None,
            relations: vec![],
            badges: 0,
            status: None,
            flags: 0,
            privileged: false,
            bot: None,
            relationship,
            online: false,
        }
    }

    fn dm(id: &str, recipients: &[&str]) -> Channel {
        Channel::DirectMessage {
            id: id.to_string(),
            active: true,
            recipients: recipients.iter().map(|id| id.to_string()).collect(),
            last_message_id: None,
            encryption: None,
        }
    }

    fn group(id: &str, recipients: &[&str]) -> Channel {
        Channel::Group {
            id: id.to_string(),
            name: id.to_string(),
            owner: recipients[0].to_string(),
            description: None,
            recipients: recipients.iter().map(|id| id.to_string()).collect(),
            icon: None,
            last_message_id: None,
            permissions: None,
            nsfw: false,
            encryption: None,
        }
    }

    /// State of a socket after Ready (subscriptions flushed)
    async fn state(me: User, session_id: &str) -> State {
        let mut state = State::from(me, session_id.to_string(), NonZeroUsize::new(16).unwrap());
        state.apply_state().await;
        state
    }

    async fn db() -> Database {
        DatabaseInfo::Reference.connect().await.unwrap()
    }

    async fn delivered(state: &mut State, db: &Database, event: EventV1) -> bool {
        let mut event = event;
        state.handle_incoming_event_v1(db, &mut event).await
    }

    #[test]
    fn to_device_only_for_recipient_session() {
        assert!(private_e2ee_filter("DEVICE", &to_device("DEVICE")));
        assert!(!private_e2ee_filter("OTHER_DEVICE", &to_device("DEVICE")));
        assert!(!private_e2ee_filter("", &to_device("")));
        assert!(private_e2ee_filter("DEVICE", &device_list("USER")));
        assert!(private_e2ee_filter("", &EventV1::Logout));
    }

    #[tokio::test]
    async fn to_device_doorbell_reaches_one_socket() {
        let db = db().await;
        let mut first = state(user("ME", vec![]), "FIRST").await;
        let mut second = state(user("ME", vec![]), "SECOND").await;

        assert!(delivered(&mut first, &db, to_device("FIRST")).await);
        assert!(!delivered(&mut second, &db, to_device("FIRST")).await);
    }

    #[tokio::test]
    async fn device_list_reaches_visible_users_only() {
        let db = db().await;
        let mut me = state(
            user(
                "ME",
                vec![
                    ("FRIEND", RelationshipStatus::Friend),
                    ("INCOMING", RelationshipStatus::Incoming),
                    ("OUTGOING", RelationshipStatus::Outgoing),
                    ("BLOCKED", RelationshipStatus::Blocked),
                    ("BLOCKED_DM", RelationshipStatus::Blocked),
                ],
            ),
            "SESSION",
        )
        .await;
        me.cache
            .channels
            .insert("DM".to_string(), dm("DM", &["ME", "BLOCKED_DM"]));
        me.cache.channels.insert(
            "GROUP".to_string(),
            group("GROUP", &["OWNER", "ME", "GROUP_PEER"]),
        );

        for visible in [
            "ME",
            "FRIEND",
            "INCOMING",
            "OUTGOING",
            "BLOCKED_DM",
            "OWNER",
            "GROUP_PEER",
        ] {
            assert!(
                delivered(&mut me, &db, device_list(visible)).await,
                "{visible} should be visible"
            );
        }

        for hidden in ["BLOCKED", "STRANGER"] {
            assert!(
                !delivered(&mut me, &db, device_list(hidden)).await,
                "{hidden} should be hidden"
            );
        }
    }

    #[tokio::test]
    async fn device_list_never_reaches_bots() {
        let db = db().await;
        let mut bot = state(user("BOT", vec![]), "").await;
        bot.cache.is_bot = true;
        bot.cache
            .channels
            .insert("GROUP".to_string(), group("GROUP", &["OWNER", "BOT"]));

        assert!(!delivered(&mut bot, &db, device_list("OWNER")).await);
        assert!(!delivered(&mut bot, &db, device_list("BOT")).await);
    }

    #[tokio::test]
    async fn device_list_follows_relationship_changes() {
        let db = db().await;
        let mut me = state(user("ME", vec![]), "SESSION").await;
        assert!(!delivered(&mut me, &db, device_list("PEER")).await);

        let event = EventV1::UserRelationship {
            id: "ME".to_string(),
            user: v0_user("PEER", v0::RelationshipStatus::Incoming),
        };
        assert!(delivered(&mut me, &db, event).await);
        assert_eq!(me.clone_user().id, "ME");
        assert!(me.subscribed.read().await.contains("PEER"));
        assert!(delivered(&mut me, &db, device_list("PEER")).await);

        let event = EventV1::UserRelationship {
            id: "ME".to_string(),
            user: v0_user("PEER", v0::RelationshipStatus::None),
        };
        assert!(delivered(&mut me, &db, event).await);
        assert!(!me.subscribed.read().await.contains("PEER"));
        assert!(!delivered(&mut me, &db, device_list("PEER")).await);
    }

    #[tokio::test]
    async fn device_list_follows_group_membership() {
        let db = db().await;
        let mut me = state(user("ME", vec![]), "SESSION").await;
        me.cache
            .channels
            .insert("GROUP".to_string(), group("GROUP", &["ME", "PEER"]));

        let join = EventV1::ChannelGroupJoin {
            id: "GROUP".to_string(),
            user: "NEWCOMER".to_string(),
        };
        assert!(delivered(&mut me, &db, join).await);
        assert!(me.subscribed.read().await.contains("NEWCOMER"));
        assert!(delivered(&mut me, &db, device_list("NEWCOMER")).await);

        let leave = EventV1::ChannelGroupLeave {
            id: "GROUP".to_string(),
            user: "NEWCOMER".to_string(),
        };
        assert!(delivered(&mut me, &db, leave).await);
        assert!(!me.subscribed.read().await.contains("NEWCOMER"));
        assert!(!delivered(&mut me, &db, device_list("NEWCOMER")).await);

        let leave = EventV1::ChannelGroupLeave {
            id: "GROUP".to_string(),
            user: "ME".to_string(),
        };
        assert!(delivered(&mut me, &db, leave).await);
        assert!(!delivered(&mut me, &db, device_list("PEER")).await);
    }

    #[tokio::test]
    async fn new_dm_and_group_subscribe_to_peers() {
        let db = db().await;
        let mut me = state(user("ME", vec![]), "SESSION").await;

        let event = EventV1::ChannelCreate(dm("DM", &["PEER", "ME"]).into());
        assert!(delivered(&mut me, &db, event).await);

        let event = EventV1::ChannelCreate(group("GROUP", &["OWNER", "ME", "MEMBER"]).into());
        assert!(delivered(&mut me, &db, event).await);

        let subscribed = me.subscribed.read().await.clone();
        for topic in ["DM", "PEER", "GROUP", "OWNER", "MEMBER"] {
            assert!(subscribed.contains(topic), "{topic} should be subscribed");
        }

        for peer in ["PEER", "OWNER", "MEMBER"] {
            assert!(delivered(&mut me, &db, device_list(peer)).await);
        }

        // Flushed as an incremental change, so the socket subscribes without reconnecting.
        let SubscriptionStateChange::Change { add, remove } = me.apply_state().await else {
            panic!("expected a subscription change");
        };
        assert!(add.contains(&"PEER".to_string()) && add.contains(&"MEMBER".to_string()));
        assert!(remove.is_empty());
    }
}
