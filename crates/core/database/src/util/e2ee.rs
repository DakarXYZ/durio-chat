//! Content of encrypted messages for clients without E2EE support (dur.io fork)
//!
//! The placeholder is only added when a message leaves the server (`into_model`),
//! the database never stores it.
use std::sync::OnceLock;

use revolt_config::FeaturesE2ee;

static LEGACY_PLACEHOLDER: OnceLock<String> = OnceLock::new();

/// Use `features.e2ee.legacy_placeholder`, call once at startup before any message is sent
pub fn set_legacy_placeholder(text: String) {
    LEGACY_PLACEHOLDER.set(text).ok();
}

/// Text old clients show in place of an encrypted message
pub fn legacy_placeholder() -> &'static str {
    LEGACY_PLACEHOLDER.get_or_init(|| FeaturesE2ee::default().legacy_placeholder)
}

/// Content of a message as sent to clients
pub fn legacy_content(content: Option<String>, encrypted: bool) -> Option<String> {
    match content {
        None if encrypted => Some(legacy_placeholder().to_owned()),
        content => content,
    }
}
