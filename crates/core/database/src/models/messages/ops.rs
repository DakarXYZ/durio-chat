use std::collections::HashMap;
use std::time::SystemTime;
use revolt_models::v0::Poll;
use revolt_result::Result;

use crate::{AppendMessage, FieldsMessage, Message, MessageQuery, PartialMessage};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractMessages: Sync + Send {
    /// Insert a new message into the database
    async fn insert_message(&self, message: &Message) -> Result<()>;

    /// Fetch a message by its id
    async fn fetch_message(&self, id: &str) -> Result<Message>;

    /// Fetch multiple messages by given query
    async fn fetch_messages(&self, query: MessageQuery) -> Result<Vec<Message>>;

    /// Fetch multiple messages by given IDs
    async fn fetch_messages_by_id(&self, ids: &[String]) -> Result<Vec<Message>>;

    /// Fetch the message an author sent to a channel with a nonce, newer than `after` (dur.io fork)
    async fn fetch_message_by_nonce(
        &self,
        channel: &str,
        author: &str,
        nonce: &str,
        after: &str,
    ) -> Result<Option<Message>>;

    /// Update a given message with new information
    async fn update_message(&self, id: &str, message: &PartialMessage, remove: Vec<FieldsMessage>) -> Result<()>;

    /// Append information to a given message
    async fn append_message(&self, id: &str, append: &AppendMessage) -> Result<()>;

    /// Add a new reaction to a message
    async fn add_reaction(&self, id: &str, emoji: &str, user: &str) -> Result<()>;

    /// Remove a reaction from a message
    async fn remove_reaction(&self, id: &str, emoji: &str, user: &str) -> Result<()>;

    /// Remove reaction from a message
    async fn clear_reaction(&self, id: &str, emoji: &str) -> Result<()>;

    /// Make `answers` the votes of `user` in the open poll of a message (dur.io fork), in one
    /// step; the poll afterwards, `None` when the message has no open poll
    async fn vote_poll(&self, id: &str, user: &str, answers: &[String]) -> Result<Option<Poll>>;

    /// Close the poll of a message (dur.io fork); the poll afterwards, `None` without a poll
    async fn close_poll(&self, id: &str) -> Result<Option<Poll>>;

    /// Delete a message from the database by its id
    async fn delete_message(&self, id: &str) -> Result<()>;

    /// Delete messages from a channel by their ids and corresponding channel id
    async fn delete_messages(&self, channel: &str, ids: &[String]) -> Result<()>;

    /// Delete all messages from a specific author in a server from a certain ULID onwards
    async fn delete_messages_by_author_since(
        &self,
        channels: &[String],
        author: &str,
        since: SystemTime
    ) -> Result<HashMap<String, Vec<String>>>;

    async fn delete_messages_by_user(&self, user_id: &str) -> Result<()>;
}
