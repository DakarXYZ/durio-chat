//! End-to-end encryption of direct messages and groups (dur.io fork)
use iso8601_timestamp::Timestamp;
use revolt_config::config;
use revolt_models::v0::{self, ChannelEncryption, E2EE_ALGORITHM_MEGOLM, MessageAuthor};
use revolt_result::Result;

use crate::{AMQP, Channel, Database, SystemMessage, User, events::client::EventV1};

impl Channel {
    /// Encryption settings, if this channel is encrypted
    pub fn encryption(&self) -> Option<&ChannelEncryption> {
        match self {
            Channel::DirectMessage { encryption, .. } | Channel::Group { encryption, .. } => {
                encryption.as_ref()
            }
            _ => None,
        }
    }

    /// Whether this channel is end-to-end encrypted
    pub fn is_encrypted(&self) -> bool {
        self.encryption().is_some()
    }

    /// Encryption settings for a channel encrypted now by `user_id`
    pub fn new_encryption(user_id: &str) -> ChannelEncryption {
        ChannelEncryption {
            algorithm: E2EE_ALGORITHM_MEGOLM.to_string(),
            enabled_at: Timestamp::now_utc(),
            enabled_by: user_id.to_string(),
            rotation_period_ms: None,
            rotation_period_msgs: None,
        }
    }

    /// Encryption of a new direct message, if `features.e2ee.default_for_new_dms` is on
    ///
    /// Direct messages with bots stay unencrypted.
    pub async fn default_dm_encryption(creator: &User, other: &User) -> Option<ChannelEncryption> {
        let config = config().await;
        (config.features.e2ee.enabled
            && config.features.e2ee.default_for_new_dms
            && creator.bot.is_none()
            && other.bot.is_none())
        .then(|| Channel::new_encryption(&creator.id))
    }

    /// Enable end-to-end encryption, cannot be undone
    ///
    /// Only direct messages and groups without bots and webhooks can be encrypted.
    /// Permissions are checked by the caller. Announced with a `ChannelUpdate`
    /// and an `encryption_enabled` system message.
    pub async fn enable_encryption(
        &mut self,
        db: &Database,
        amqp: Option<&AMQP>,
        by: &User,
    ) -> Result<()> {
        let recipients = match self {
            Channel::DirectMessage {
                recipients,
                encryption,
                ..
            }
            | Channel::Group {
                recipients,
                encryption,
                ..
            } => {
                if encryption.is_some() {
                    return Err(create_error!(AlreadyEncrypted));
                }

                recipients.clone()
            }
            _ => return Err(create_error!(NotEncryptable)),
        };

        // Bots have no devices, webhooks post plain text
        if db
            .fetch_users(&recipients)
            .await?
            .iter()
            .any(|user| user.bot.is_some())
            || !db.fetch_webhooks_for_channel(self.id()).await?.is_empty()
        {
            return Err(create_error!(NotEncryptable));
        }

        // Conditional write: of two concurrent requests only one succeeds
        let settings = Channel::new_encryption(&by.id);
        if !db.set_channel_encryption(self.id(), &settings).await? {
            return Err(create_error!(AlreadyEncrypted));
        }

        if let Channel::DirectMessage { encryption, .. } | Channel::Group { encryption, .. } = self
        {
            encryption.replace(settings.clone());
        }

        let id = self.id().to_string();
        EventV1::ChannelUpdate {
            id: id.clone(),
            data: v0::PartialChannel {
                encryption: Some(settings),
                ..Default::default()
            },
            clear: vec![],
        }
        .p(id.clone())
        .await;

        // Sent after the write: the channel already counts as encrypted
        SystemMessage::EncryptionEnabled {
            by: by.id.to_string(),
        }
        .into_message(id)
        .send(
            db,
            amqp,
            MessageAuthor::System {
                username: &by.username,
                avatar: by.avatar.as_ref().map(|file| file.id.as_ref()),
            },
            None,
            None,
            self,
            false,
        )
        .await
        .ok();

        Ok(())
    }
}
