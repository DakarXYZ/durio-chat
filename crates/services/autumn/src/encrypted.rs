//! End-to-end encrypted attachments (dur.io fork)
//!
//! An encrypted upload is an opaque blob: no MIME sniffing, metadata, EXIF stripping
//! or virus scanning, and the original filename never reaches the server.
use revolt_database::File;
use revolt_result::{Result, create_error};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::api::Tag;

/// Content type of every encrypted blob
pub const ENCRYPTED_CONTENT_TYPE: &str = "application/octet-stream";

/// Filename of every encrypted blob
pub const ENCRYPTED_FILENAME: &str = "file.bin";

/// Upload options
#[derive(Deserialize, IntoParams, Default, Debug)]
#[into_params(parameter_in = Query)]
pub struct UploadOptions {
    /// Upload an end-to-end encrypted blob (only for `attachments`)
    #[serde(default)]
    pub encrypted: bool,
}

/// Encrypted blobs are only message attachments, and only with E2EE enabled
pub fn check_upload_options(tag: &Tag, options: &UploadOptions, e2ee_enabled: bool) -> Result<()> {
    if !options.encrypted {
        Ok(())
    } else if !e2ee_enabled {
        Err(create_error!(E2eeDisabled))
    } else if !matches!(tag, Tag::attachments) {
        Err(create_error!(InvalidOperation))
    } else {
        Ok(())
    }
}

/// Mark a file as an encrypted blob
pub fn mark_encrypted(mut file: File, options: &UploadOptions) -> File {
    if options.encrypted {
        file.encrypted = Some(true);
    }

    file
}

#[cfg(test)]
mod tests {
    use axum::{extract::Query, http::Uri};
    use revolt_database::{FileHash, Metadata, iso8601_timestamp::Timestamp};
    use revolt_result::ErrorType;

    use super::*;

    fn options(query: &str) -> UploadOptions {
        let uri: Uri = format!("http://localhost/attachments{query}")
            .parse()
            .unwrap();
        Query::<UploadOptions>::try_from_uri(&uri).unwrap().0
    }

    #[test]
    fn query() {
        assert!(!options("").encrypted);
        assert!(!options("?encrypted=false").encrypted);
        assert!(options("?encrypted=true").encrypted);
    }

    #[test]
    fn only_attachments() {
        let encrypted = UploadOptions { encrypted: true };

        assert!(check_upload_options(&Tag::attachments, &encrypted, true).is_ok());
        assert!(check_upload_options(&Tag::avatars, &UploadOptions::default(), true).is_ok());
        assert!(check_upload_options(&Tag::avatars, &UploadOptions::default(), false).is_ok());

        for tag in [
            Tag::avatars,
            Tag::backgrounds,
            Tag::icons,
            Tag::banners,
            Tag::emojis,
        ] {
            assert!(matches!(
                check_upload_options(&tag, &encrypted, true)
                    .unwrap_err()
                    .error_type,
                ErrorType::InvalidOperation
            ));
        }

        assert!(matches!(
            check_upload_options(&Tag::attachments, &encrypted, false)
                .unwrap_err()
                .error_type,
            ErrorType::E2eeDisabled
        ));
    }

    #[test]
    fn marked() {
        let hash = FileHash {
            id: "hash".to_string(),
            processed_hash: "hash".to_string(),
            created_at: Timestamp::now_utc(),
            bucket_id: "bucket".to_string(),
            path: "hash".to_string(),
            iv: String::new(),
            metadata: Metadata::File,
            content_type: ENCRYPTED_CONTENT_TYPE.to_string(),
            size: 1,
        };
        let file = || {
            hash.into_file(
                "id".to_string(),
                "attachments".to_string(),
                ENCRYPTED_FILENAME.to_string(),
                "user".to_string(),
            )
        };

        assert_eq!(
            mark_encrypted(file(), &UploadOptions { encrypted: true }).encrypted,
            Some(true)
        );
        assert_eq!(
            mark_encrypted(file(), &UploadOptions::default()).encrypted,
            None
        );
    }
}
