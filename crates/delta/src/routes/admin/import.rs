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
//!
//! Link previews come separately and may come later (a debugging aid without a UI): the
//! source's own previews, which outlive the dead links, set on messages imported before.
use std::collections::{HashMap, HashSet};

use iso8601_timestamp::Timestamp;
use revolt_config::config;
use revolt_database::{
    util::reference::Reference, Channel, Database, File, Message, Metadata, PartialChannel,
    PartialMessage, Session, User,
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
/// Most previews of an imported message (Discord allows 10)
const MAX_EMBEDS: usize = 10;
/// Longest preview title, description, site name and address
const MAX_EMBED_TITLE: usize = 256;
const MAX_EMBED_DESCRIPTION: usize = 2000;
const MAX_EMBED_SITE_NAME: usize = 100;
const MAX_EMBED_URL: usize = 2000;

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

/// # Import Link Previews
///
/// Set the link previews of messages imported before, up to 100 messages at a time
/// (dur.io fork, elevated instance admins only, no UI). The previews of a message are
/// replaced; files of previews must be uploaded to autumn first (`attachments`).
#[openapi(tag = "Admin")]
#[post("/import/channels/<target>/embeds", data = "<data>")]
pub async fn import_embeds(
    db: &State<Database>,
    user: User,
    session: Session,
    target: Reference<'_>,
    data: Json<v0::DataImportEmbeds>,
) -> Result<Json<v0::ImportEmbedsResult>> {
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

    let mut planned = Vec::with_capacity(data.messages.len());
    for message in &data.messages {
        check_original_id(&message.original_id)?;
        if message.embeds.len() > MAX_EMBEDS {
            return Err(invalid("more than 10 embeds"));
        }
        for embed in &message.embeds {
            check_embed(embed)?;
        }
        let id = message_id(&data.source, &message.original_id, &message.timestamp)?;
        planned.push((id, message));
    }

    let ids: Vec<String> = planned.iter().map(|(id, _)| id.clone()).collect();
    let found: HashMap<String, Message> = db
        .fetch_messages_by_id(&ids)
        .await?
        .into_iter()
        .filter(|message| message.channel == channel.id() && message.imported.is_some())
        .map(|message| (message.id.clone(), message))
        .collect();

    let autumn = config().await.hosts.autumn;
    let mut updated = 0;
    for (id, message) in planned {
        if !found.contains_key(&id) {
            continue;
        }

        let mut embeds = Vec::with_capacity(message.embeds.len());
        for embed in &message.embeds {
            embeds.push(build_embed(db, embed, &id, &user.id, &autumn).await?);
        }

        db.update_message(
            &id,
            &PartialMessage {
                embeds: Some(embeds),
                ..Default::default()
            },
            vec![],
        )
        .await?;
        updated += 1;
    }

    log::info!(
        "Admin {} set previews of {} imported messages in channel {}",
        user.id,
        updated,
        channel.id()
    );

    Ok(Json(v0::ImportEmbedsResult {
        updated,
        missing: ids.len() - updated,
    }))
}

/// Limits of an imported preview: something to show, short texts, web addresses
fn check_embed(embed: &v0::ImportEmbed) -> Result<()> {
    let too_long = |text: &Option<String>, max: usize| {
        text.as_ref().is_some_and(|text| text.chars().count() > max)
    };
    if too_long(&embed.title, MAX_EMBED_TITLE)
        || too_long(&embed.description, MAX_EMBED_DESCRIPTION)
        || too_long(&embed.site_name, MAX_EMBED_SITE_NAME)
        || too_long(&embed.colour, 32)
    {
        return Err(invalid("embed text too long"));
    }
    if let Some(url) = &embed.url {
        check_web_url(url)?;
    }
    for media in [&embed.image, &embed.video].into_iter().flatten() {
        match (&media.file, &media.url) {
            (Some(file), None) => check_original_id(file)?,
            (None, Some(url)) => check_web_url(url)?,
            _ => return Err(invalid("embed media needs either a file or a url")),
        }
    }

    let blank = |text: &Option<String>| text.as_ref().is_none_or(|text| text.trim().is_empty());
    if blank(&embed.title)
        && blank(&embed.description)
        && embed.image.is_none()
        && embed.video.is_none()
    {
        return Err(invalid("embed shows nothing"));
    }
    Ok(())
}

/// An http(s) address of reasonable length
fn check_web_url(url: &str) -> Result<()> {
    if url.len() <= MAX_EMBED_URL
        && (url.starts_with("https://") || url.starts_with("http://"))
        && !url.chars().any(char::is_whitespace)
    {
        Ok(())
    } else {
        Err(invalid("embed url must be an http(s) address"))
    }
}

/// An imported preview as clients show it. Without any text it is just its video or
/// picture; with text a website card. Uploaded files are claimed for the message (a file
/// already claimed for it, from an earlier run, is fine) and linked on this server's autumn
async fn build_embed(
    db: &Database,
    embed: &v0::ImportEmbed,
    message: &str,
    uploader: &str,
    autumn: &str,
) -> Result<v0::Embed> {
    let mut image = None;
    if let Some(media) = &embed.image {
        let (url, size) = media_url(db, media, message, uploader, autumn).await?;
        let (width, height) = size.unwrap_or((media.width, media.height));
        image = Some(v0::Image {
            url,
            width,
            height,
            size: if media.small {
                v0::ImageSize::Preview
            } else {
                v0::ImageSize::Large
            },
        });
    }
    let mut video = None;
    if let Some(media) = &embed.video {
        let (url, size) = media_url(db, media, message, uploader, autumn).await?;
        let (width, height) = size.unwrap_or((media.width, media.height));
        video = Some(v0::Video { url, width, height });
    }

    let text = |text: &Option<String>| {
        text.as_ref()
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    };
    let (title, description, site_name) = (
        text(&embed.title),
        text(&embed.description),
        text(&embed.site_name),
    );

    if title.is_none() && description.is_none() && site_name.is_none() {
        if let Some(video) = video {
            return Ok(v0::Embed::Video(video));
        }
        if let Some(mut image) = image {
            image.size = v0::ImageSize::Large;
            return Ok(v0::Embed::Image(image));
        }
    }

    Ok(v0::Embed::Website(v0::WebsiteMetadata {
        url: embed.url.clone(),
        original_url: embed.url.clone(),
        special: None,
        title,
        description,
        image,
        video,
        site_name,
        icon_url: None,
        colour: text(&embed.colour),
    }))
}

/// Address and, for an uploaded file, the dimensions autumn found
async fn media_url(
    db: &Database,
    media: &v0::ImportEmbedMedia,
    message: &str,
    uploader: &str,
    autumn: &str,
) -> Result<(String, Option<(usize, usize)>)> {
    let Some(file) = &media.file else {
        return Ok((media.url.clone().unwrap_or_default(), None));
    };

    let file = match File::use_attachment(db, file, message, uploader).await {
        Ok(file) => file,
        Err(error) => db
            .fetch_attachment("attachments", file)
            .await
            .ok()
            .filter(|found| {
                found
                    .used_for
                    .as_ref()
                    .is_some_and(|used| used.id == message)
            })
            .ok_or(error)?,
    };

    let size = match file.metadata {
        Metadata::Image { width, height, .. } | Metadata::Video { width, height } => {
            Some((width as usize, height as usize))
        }
        _ => None,
    };
    Ok((format!("{autumn}/attachments/{}", file.id), size))
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
