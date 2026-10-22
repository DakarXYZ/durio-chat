//! Threads of server channels (dur.io fork)
//!
//! A thread is a `TextChannel` with `thread` set: it is not in the server's
//! channel list, takes the permissions of its parent channel and hangs off a
//! message in the parent (`Message.thread`), a `thread_created` system message
//! when it was not started from one.
use std::collections::HashMap;

use revolt_models::v0::{self, MessageAuthor};
use revolt_result::Result;
use ulid::Ulid;

use crate::{
    AMQP, Channel, Database, FieldsMessage, PartialMessage, SystemMessage, User,
    events::client::EventV1,
};

#[allow(clippy::disallowed_methods)]
impl Channel {
    /// Start a thread in this channel
    ///
    /// Permissions are checked by the caller.
    pub async fn create_thread(
        &self,
        db: &Database,
        amqp: Option<&AMQP>,
        by: &User,
        data: v0::DataCreateThread,
    ) -> Result<Channel> {
        let (parent_id, server, nsfw, slowmode) = match self {
            Channel::TextChannel {
                id,
                server,
                nsfw,
                slowmode,
                thread: None,
                ..
            } => (id, server, *nsfw, *slowmode),
            _ => return Err(create_error!(InvalidOperation)),
        };

        let id = Ulid::new().to_string();

        // The message the thread hangs off: one of the channel's or a new system message
        let (mut anchor, existing) = match &data.message {
            Some(message_id) => {
                let message = db.fetch_message(message_id).await?;
                if &message.channel != parent_id {
                    return Err(create_error!(NotFound));
                }

                if message.thread.is_some() {
                    return Err(create_error!(InvalidOperation));
                }

                (message, true)
            }
            None => {
                let mut message = SystemMessage::ThreadCreated {
                    by: by.id.clone(),
                    name: data.name.clone(),
                }
                .into_message(parent_id.clone());
                message.thread = Some(id.clone());
                (message, false)
            }
        };

        let channel = Channel::TextChannel {
            id: id.clone(),
            server: server.clone(),
            name: data.name,
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: HashMap::new(),
            nsfw,
            voice: None,
            slowmode,
            thread: Some(v0::ThreadInfo {
                parent: parent_id.clone(),
                message: anchor.id.clone(),
                owner: by.id.clone(),
                archived: false,
                message_count: 0,
            }),
        };

        db.insert_channel(&channel).await?;

        EventV1::ChannelCreate(channel.clone().into())
            .p(server.clone())
            .await;

        if existing {
            anchor
                .update(
                    db,
                    PartialMessage {
                        thread: Some(id),
                        ..Default::default()
                    },
                    vec![],
                )
                .await?;
        } else {
            anchor
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
                .await?;
        }

        Ok(channel)
    }

    /// Count `by` more (or fewer) messages in a thread; a new message brings it
    /// back from the archive. Does nothing for other channels.
    pub async fn count_thread_messages(db: &Database, id: &str, by: i64) {
        if by == 0 {
            return;
        }

        if let Ok(Some(thread)) = db.bump_thread(id, by, by > 0).await {
            EventV1::ChannelUpdate {
                id: id.to_string(),
                data: v0::PartialChannel {
                    thread: Some(thread),
                    ..Default::default()
                },
                clear: vec![],
            }
            .p(id.to_string())
            .await;
        }
    }

    /// Clean up around a channel about to be deleted: a channel takes its threads
    /// with it, a thread lets go of its message (and drops a `thread_created` one)
    pub(crate) async fn delete_threads(&self, db: &Database) -> Result<()> {
        if let Some(thread) = self.thread() {
            if let Ok(mut message) = db.fetch_message(&thread.message).await
                && message.thread.as_deref() == Some(self.id())
            {
                if matches!(message.system, Some(SystemMessage::ThreadCreated { .. })) {
                    message.delete(db).await?;
                } else {
                    message
                        .update(db, PartialMessage::default(), vec![FieldsMessage::Thread])
                        .await?;
                }
            }
        } else if let Channel::TextChannel { id, .. } = self {
            for thread in db.fetch_channel_threads(id).await? {
                let thread_id = thread.id().to_string();
                EventV1::ChannelDelete {
                    id: thread_id.clone(),
                }
                .p(thread_id)
                .await;
                db.delete_channel(&thread).await?;
            }
        }

        Ok(())
    }
}
