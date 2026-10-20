//! Polls on messages (dur.io fork)
//!
//! A poll is part of its message: the question, the answers and who picked which. Voting
//! replaces a user's picks in one database step and goes out to clients as a `MessageUpdate`
//! carrying the whole poll. Encrypted channels take no polls (the server would see the text).
use indexmap::IndexSet;
use revolt_models::v0::{DataPoll, Poll, PollAnswer};
use revolt_result::Result;

use crate::{events::client::EventV1, Database, Message, PartialMessage, User};

/// Longest answer, in characters
const MAX_ANSWER_LENGTH: usize = 100;

impl Message {
    /// A new poll from what the client sent: trimmed, answers numbered from 0
    pub fn new_poll(data: &DataPoll) -> Result<Poll> {
        let question = data.question.trim();
        let answers: Vec<&str> = data.answers.iter().map(|answer| answer.trim()).collect();

        if question.is_empty()
            || question.chars().count() > 300
            || !(2..=10).contains(&answers.len())
            || answers
                .iter()
                .any(|answer| answer.is_empty() || answer.chars().count() > MAX_ANSWER_LENGTH)
        {
            return Err(create_error!(InvalidProperty));
        }

        Ok(Poll {
            question: question.to_string(),
            answers: answers
                .into_iter()
                .enumerate()
                .map(|(index, text)| PollAnswer {
                    id: index.to_string(),
                    text: text.to_string(),
                    votes: IndexSet::new(),
                })
                .collect(),
            multiple: data.multiple,
            closed: false,
        })
    }

    /// Make `answers` the picks of `user` (empty: take the vote back)
    pub async fn vote_poll(&self, db: &Database, user: &User, answers: Vec<String>) -> Result<()> {
        let poll = self
            .poll
            .as_ref()
            .ok_or_else(|| create_error!(InvalidOperation))?;

        if poll.closed {
            return Err(create_error!(InvalidOperation));
        }

        let mut picked: Vec<String> = Vec::new();
        for answer in answers {
            if !poll.answers.iter().any(|known| known.id == answer) {
                return Err(create_error!(InvalidProperty));
            }
            if !picked.contains(&answer) {
                picked.push(answer);
            }
        }

        if !poll.multiple && picked.len() > 1 {
            return Err(create_error!(InvalidProperty));
        }

        // closed meanwhile, or the message is gone
        let poll = db
            .vote_poll(&self.id, &user.id, &picked)
            .await?
            .ok_or_else(|| create_error!(InvalidOperation))?;

        self.publish_poll(poll).await;
        Ok(())
    }

    /// Stop taking votes; the votes stay visible
    pub async fn close_poll(&self, db: &Database) -> Result<()> {
        if self.poll.as_ref().is_none_or(|poll| poll.closed) {
            return Err(create_error!(InvalidOperation));
        }

        let poll = db
            .close_poll(&self.id)
            .await?
            .ok_or_else(|| create_error!(InvalidOperation))?;

        self.publish_poll(poll).await;
        Ok(())
    }

    /// The whole poll to the clients of the channel
    async fn publish_poll(&self, poll: Poll) {
        EventV1::MessageUpdate {
            id: self.id.clone(),
            channel: self.channel.clone(),
            data: PartialMessage {
                poll: Some(poll),
                ..Default::default()
            }
            .into(),
            clear: vec![],
        }
        .p(self.channel.clone())
        .await;
    }
}
