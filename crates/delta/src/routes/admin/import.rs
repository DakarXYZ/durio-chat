//! Import of message history from another chat, e.g. a Discord export (dur.io fork)
//!
//! An elevated instance admin sends the messages of one source channel into a server text
//! channel, oldest first, in batches. Each message keeps its original time: its id is a
//! ULID with that time, its randomness taken from a hash of the source and the original
//! id, so sending a batch again finds the messages already there and skips them. The
//! original author becomes a phantom webhook (an id derived from the source and the
//! author's original id, the name and avatar on the message): no user, no profile, no
//! interaction. Imported messages carry `imported`; no events, pushes, mentions or
//! unreads are made, clients see them when they load the channel.
use std::collections::{HashMap, HashSet};

use iso8601_timestamp::Timestamp;
use revolt_database::{
    util::reference::Reference, Channel, Database, File, Message, PartialChannel, Session, User,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use sha2::{Digest, Sha256};
use ulid::Ulid;
use validator::Validate;

use super::require_elevated_admin;

/// Longest text of an imported message (Discord allows 4000)
const MAX_CONTENT: usize = 10_000;
/// Most files on an imported message (Discord allows 10)
const MAX_ATTACHMENTS: usize = 10;
/// Most replies of an imported message
const MAX_REPLIES: usize = 5;
/// Longest source id of a message or author
const MAX_ORIGINAL_ID: usize = 64;

/// Id with the time `timestamp_ms` whose randomness comes from a hash of `key`
fn derived_id(timestamp_ms: u64, key: &str) -> String {
    let hash = Sha256::digest(key.as_bytes());
    let mut random = [0u8; 16];
    random[6..].copy_from_slice(&hash[..10]);
    Ulid::from_parts(timestamp_ms, u128::from_be_bytes(random)).to_string()
}

/// Milliseconds since 1970 of an import timestamp, which must lie between 2000 and now
fn timestamp_ms(timestamp: &Timestamp) -> Result<u64> {
    let ms = timestamp
        .duration_since(Timestamp::UNIX_EPOCH)
        .whole_milliseconds();
    let now = Timestamp::now_utc()
        .duration_since(Timestamp::UNIX_EPOCH)
        .whole_milliseconds();

    if (946_684_800_000..=now).contains(&ms) {
        Ok(ms as u64)
    } else {
        Err(invalid("timestamp before 2000 or in the future"))
    }
}

/// Id of an imported message
fn message_id(source: &str, original_id: &str, timestamp: &Timestamp) -> Result<String> {
    Ok(derived_id(
        timestamp_ms(timestamp)?,
        &format!("{source}:message:{original_id}"),
    ))
}

/// Id of the phantom webhook standing for an original author
fn author_id(source: &str, original_id: &str) -> String {
    derived_id(0, &format!("{source}:author:{original_id}"))
}

fn invalid(error: &str) -> revolt_result::Error {
    create_error!(FailedValidation {
        error: error.to_owned()
    })
}

/// An original id: 1 to 64 printable characters
fn check_original_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_ORIGINAL_ID || id.chars().any(char::is_control) {
        Err(invalid("original_id must be 1 to 64 printable characters"))
    } else {
        Ok(())
    }
}

/// A source: 1 to 32 lowercase letters, digits or `-`
fn check_source(source: &str) -> Result<()> {
    if !source.is_empty()
        && source.len() <= 32
        && source
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        Ok(())
    } else {
        Err(invalid("source must be 1 to 32 of a-z, 0-9 and -"))
    }
}

/// Display name of a phantom author: trimmed, without control characters, 1 to 32 characters
fn author_name(name: &str) -> Result<String> {
    let name: String = name
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(32)
        .collect();

    if name.is_empty() {
        Err(invalid("author name is empty"))
    } else {
        Ok(name)
    }
}

/// # Import Messages
///
/// Import messages from another chat into a server text channel, oldest first, up to 100 at
/// a time (dur.io fork, elevated instance admins only). Messages already imported are
/// skipped. Files must be uploaded to autumn first (`attachments`, author avatars `avatars`).
#[openapi(tag = "Admin")]
#[post("/import/channels/<target>/messages", data = "<data>")]
// history goes straight to the database: `Message::send` would fan out events, pushes,
// mentions and unreads for messages that are years old
#[allow(clippy::disallowed_methods)]
pub async fn import_messages(
    db: &State<Database>,
    user: User,
    session: Session,
    target: Reference<'_>,
    data: Json<v0::DataImportMessages>,
) -> Result<Json<v0::ImportMessagesResult>> {
    require_elevated_admin(&user, &session).await?;

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;
    check_source(&data.source)?;

    let channel = target.as_channel(db).await?;
    if !matches!(channel, Channel::TextChannel { .. }) {
        return Err(create_error!(InvalidOperation));
    }
    if channel.is_encrypted() {
        return Err(create_error!(EncryptedChannelViolation));
    }

    // Everything is checked before anything is written
    let mut planned = Vec::with_capacity(data.messages.len());
    for message in &data.messages {
        check_original_id(&message.original_id)?;
        check_original_id(&message.author.original_id)?;
        if message.content.chars().count() > MAX_CONTENT {
            return Err(invalid("content longer than 10000 characters"));
        }
        if message.attachments.len() > MAX_ATTACHMENTS {
            return Err(invalid("more than 10 attachments"));
        }
        if message.reply_to.len() > MAX_REPLIES {
            return Err(invalid("more than 5 replies"));
        }
        if message.content.trim().is_empty() && message.attachments.is_empty() {
            return Err(invalid("message without content and attachments"));
        }

        let id = message_id(&data.source, &message.original_id, &message.timestamp)?;
        let replies = message
            .reply_to
            .iter()
            .map(|reply| {
                check_original_id(&reply.original_id)?;
                message_id(&data.source, &reply.original_id, &reply.timestamp)
            })
            .collect::<Result<Vec<_>>>()?;
        if let Some(edited) = &message.edited {
            timestamp_ms(edited)?;
        }

        planned.push((id, author_name(&message.author.name)?, replies, message));
    }

    let ids: Vec<String> = planned.iter().map(|(id, ..)| id.clone()).collect();
    let existing: HashSet<String> = db
        .fetch_messages_by_id(&ids)
        .await?
        .into_iter()
        .map(|message| message.id)
        .collect();

    let mut avatars: HashMap<String, Option<String>> = HashMap::new();
    let mut imported = 0;
    let mut newest: Option<String> = None;

    for (id, name, replies, message) in planned {
        if existing.contains(&id) {
            continue;
        }

        let author = author_id(&data.source, &message.author.original_id);
        let avatar = match avatars.get(&author) {
            Some(avatar) => avatar.clone(),
            None => {
                let avatar = match &message.author.avatar {
                    Some(file) => phantom_avatar(db, file, &author, &user.id).await,
                    None => None,
                };
                avatars.insert(author.clone(), avatar.clone());
                avatar
            }
        };

        let mut attachments = Vec::with_capacity(message.attachments.len());
        for file in &message.attachments {
            attachments.push(File::use_attachment(db, file, &id, &user.id).await?);
        }

        let content = message.content.trim_end().to_owned();
        db.insert_message(&Message {
            id: id.clone(),
            channel: channel.id().to_owned(),
            author,
            webhook: Some(v0::MessageWebhook { name, avatar }),
            content: (!content.is_empty()).then_some(content),
            imported: Some(v0::MessageImport {
                source: data.source.clone(),
            }),
            attachments: (!attachments.is_empty()).then_some(attachments),
            edited: message.edited,
            replies: (!replies.is_empty()).then_some(replies),
            pinned: message.pinned.then_some(true),
            ..Default::default()
        })
        .await?;

        imported += 1;
        if newest.as_ref().is_none_or(|newest| &id > newest) {
            newest = Some(id);
        }
    }

    // The channel's last message moves only forward: history is older than what is there
    if let Some(newest) = newest {
        let last = match &channel {
            Channel::TextChannel {
                last_message_id, ..
            } => last_message_id.clone(),
            _ => None,
        };
        if last.as_ref().is_none_or(|last| &newest > last) {
            db.update_channel(
                channel.id(),
                &PartialChannel {
                    last_message_id: Some(newest),
                    ..Default::default()
                },
                vec![],
            )
            .await?;
        }
    }

    log::info!(
        "Admin {} imported {} messages from {} into channel {}",
        user.id,
        imported,
        data.source,
        channel.id()
    );

    Ok(Json(v0::ImportMessagesResult {
        imported,
        skipped: ids.len() - imported,
    }))
}

/// The avatar of a phantom author: the uploaded file, claimed for it the first time; later
/// batches find it already used for the same author. Anything else: no avatar
async fn phantom_avatar(db: &Database, file: &str, author: &str, uploader: &str) -> Option<String> {
    if File::use_webhook_avatar(db, file, author, uploader)
        .await
        .is_ok()
    {
        return Some(file.to_owned());
    }

    db.fetch_attachment("avatars", file)
        .await
        .ok()
        .filter(|found| {
            found
                .used_for
                .as_ref()
                .is_some_and(|used| used.id == author)
        })
        .map(|found| found.id)
}

#[cfg(test)]
mod unit {
    use iso8601_timestamp::Timestamp;

    use super::{author_id, author_name, check_source, derived_id, message_id};

    #[test]
    fn ids_are_stable_and_keep_the_time() {
        let at = Timestamp::parse("2023-02-13T16:19:45.369+04:00").unwrap();
        let a = message_id("discord", "1074666187235008585", &at).unwrap();
        let b = message_id("discord", "1074666187235008585", &at).unwrap();
        assert_eq!(a, b);
        assert_ne!(
            a,
            message_id("discord", "1074666187235008586", &at).unwrap()
        );
        assert_ne!(
            a,
            message_id("telegram", "1074666187235008585", &at).unwrap()
        );

        let ulid = ulid::Ulid::from_string(&a).unwrap();
        assert_eq!(ulid.timestamp_ms(), 1_676_290_785_369);
    }

    #[test]
    fn later_messages_sort_later() {
        let first = derived_id(1_676_290_785_369, "z");
        let second = derived_id(1_676_290_785_370, "a");
        assert!(first < second);
    }

    #[test]
    fn authors_are_per_source() {
        assert_eq!(author_id("discord", "1"), author_id("discord", "1"));
        assert_ne!(author_id("discord", "1"), author_id("discord", "2"));
        assert_ne!(author_id("discord", "1"), author_id("other", "1"));
    }

    #[test]
    fn names_and_sources() {
        assert_eq!(author_name("  Cat\u{0007}Power  ").unwrap(), "CatPower");
        assert_eq!(author_name(&"я".repeat(40)).unwrap().chars().count(), 32);
        assert!(author_name(" \n ").is_err());
        assert!(check_source("discord").is_ok());
        assert!(check_source("Discord").is_err());
        assert!(check_source("").is_err());
        assert!(timestamp_out_of_range());
    }

    fn timestamp_out_of_range() -> bool {
        let old = Timestamp::parse("1999-12-31T23:59:59Z").unwrap();
        message_id("discord", "1", &old).is_err()
    }
}
