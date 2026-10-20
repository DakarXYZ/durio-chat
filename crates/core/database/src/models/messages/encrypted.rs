//! Messages in end-to-end encrypted channels (dur.io fork)
//!
//! The server never sees the text: an encrypted message only carries the envelope,
//! no content, embeds or masquerade, and the server parses nothing out of it.
use iso8601_timestamp::Timestamp;
use revolt_config::{FeaturesE2ee, FeaturesLimits, config};
use revolt_models::v0::{DataEditMessage, DataMessageSend, EncryptedEnvelope, MessageAuthor};
use revolt_result::Result;

use crate::{Channel, Database, Message, PartialMessage};

/// Maximum number of attachments of a message
///
/// Encrypted messages also list their encrypted thumbnails, so they get twice as many.
pub fn attachment_limit(limits: &FeaturesLimits, encrypted: bool) -> usize {
    if encrypted {
        limits.message_attachments * 2
    } else {
        limits.message_attachments
    }
}

/// The envelope must name the sending device
///
/// Only a cheap sanity check: `device_id` is a hint, clients verify the sender themselves.
pub fn check_envelope_device(
    envelope: Option<&EncryptedEnvelope>,
    session_id: Option<&str>,
) -> Result<()> {
    match envelope {
        Some(envelope) if Some(envelope.device_id.as_str()) != session_id => {
            Err(create_error!(EncryptedChannelViolation))
        }
        _ => Ok(()),
    }
}

/// Envelope of a message in an encrypted channel
fn require_envelope<'a>(
    envelope: Option<&'a EncryptedEnvelope>,
    e2ee: &FeaturesE2ee,
) -> Result<&'a EncryptedEnvelope> {
    // With the feature off encrypted channels are read-only
    let envelope = envelope
        .filter(|_| e2ee.enabled)
        .ok_or_else(|| create_error!(EncryptedChannelViolation))?;

    if envelope.ciphertext.len() > e2ee.max_envelope_bytes {
        return Err(create_error!(PayloadTooLarge));
    }

    Ok(envelope)
}

impl Message {
    /// Check a new message against the encryption of its channel
    ///
    /// Encrypted channels take only an envelope from users, plain channels never take one.
    pub fn check_encrypted_send(
        channel: &Channel,
        data: &DataMessageSend,
        author: &MessageAuthor<'_>,
        e2ee: &FeaturesE2ee,
    ) -> Result<()> {
        if !channel.is_encrypted() {
            return match data.encrypted {
                Some(_) => Err(create_error!(EncryptedChannelViolation)),
                None => Ok(()),
            };
        }

        if !matches!(author, MessageAuthor::User(_))
            || data.content.is_some()
            || data
                .embeds
                .as_ref()
                .is_some_and(|embeds| !embeds.is_empty())
            || data.masquerade.is_some()
            // dur.io fork: a poll is plain text on the server
            || data.poll.is_some()
        {
            return Err(create_error!(EncryptedChannelViolation));
        }

        require_envelope(data.encrypted.as_ref(), e2ee).map(|_| ())
    }

    /// Last line of defence before a message is stored: in an encrypted channel
    /// only system messages and envelopes, elsewhere never an envelope
    pub fn check_channel_encryption(&self, channel: &Channel) -> Result<()> {
        let allowed = if channel.is_encrypted() {
            self.system.is_some() || (self.encrypted.is_some() && self.content.is_none())
        } else {
            self.encrypted.is_none()
        };

        if allowed {
            Ok(())
        } else {
            Err(create_error!(EncryptedChannelViolation))
        }
    }

    /// Edit an encrypted message: only the envelope is replaced
    ///
    /// Messages sent before encryption was enabled can no longer be edited.
    pub async fn edit_encrypted(
        &mut self,
        db: &Database,
        channel: &Channel,
        edit: DataEditMessage,
        session_id: Option<&str>,
    ) -> Result<()> {
        if !channel.is_encrypted()
            || self.encrypted.is_none()
            || edit.content.is_some()
            || edit
                .embeds
                .as_ref()
                .is_some_and(|embeds| !embeds.is_empty())
        {
            return Err(create_error!(EncryptedChannelViolation));
        }

        let config = config().await;
        let envelope = require_envelope(edit.encrypted.as_ref(), &config.features.e2ee)?;
        check_envelope_device(Some(envelope), session_id)?;

        self.edited = Some(Timestamp::now_utc());
        let partial = PartialMessage {
            edited: self.edited,
            encrypted: Some(envelope.clone()),
            ..Default::default()
        };

        self.update(db, partial, vec![]).await
    }

    /// Webhooks never touch encrypted channels or envelopes
    pub fn check_webhook_edit(&self, channel: &Channel, edit: &DataEditMessage) -> Result<()> {
        if channel.is_encrypted() || self.encrypted.is_some() || edit.encrypted.is_some() {
            Err(create_error!(EncryptedChannelViolation))
        } else {
            Ok(())
        }
    }
}
