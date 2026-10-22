mod implementation;
mod repositories;

pub use implementation::*;
pub use repositories::*;

use std::io::{BufRead, Read, Seek};

use image::DynamicImage;
use revolt_config::{report_internal_error, Files, FilesLimit, FilesS3};
use revolt_result::Result;

use tempfile::NamedTempFile;

pub const AUTHENTICATION_TAG_SIZE_BYTES: usize = 16;

/// Fetch a file from S3 (and decrypt it)
pub async fn fetch_from_s3(bucket_id: &str, path: &str, iv: &str) -> Result<Vec<u8>> {
    let encryption = implementation::EncryptionKey::from_config().await;
    let storage = implementation::S3Storage::from_config(encryption).await;
    report_internal_error!(storage.fetch_and_decrypt_file(bucket_id, path, iv).await)
}

/// Encrypt and upload a file to S3 (returning its nonce/IV)
pub async fn upload_to_s3(bucket_id: &str, path: &str, buf: &[u8]) -> Result<String> {
    let encryption = implementation::EncryptionKey::from_config().await;
    let storage = implementation::S3Storage::from_config(encryption).await;
    report_internal_error!(storage.encrypt_and_upload_file(bucket_id, path, buf).await)
}

/// Delete a file from S3 by path
pub async fn delete_from_s3(bucket_id: &str, path: &str) -> Result<()> {
    let encryption = implementation::EncryptionKey::from_config().await;
    let storage = implementation::S3Storage::from_config(encryption).await;
    report_internal_error!(storage.delete_file(bucket_id, path).await)
}

/// Determine size of image at temp file
pub fn image_size(f: &NamedTempFile) -> Option<(usize, usize)> {
    let media = MediaImpl::new(Files {
        blocked_mime_types: Default::default(),
        clamd_host: Default::default(),
        encryption_key: Default::default(),
        limit: FilesLimit {
            max_mega_pixels: 0,
            max_pixel_side: 0,
            min_file_size: 0,
            min_resolution: [0, 0],
        },
        preview: Default::default(),
        s3: FilesS3 {
            access_key_id: Default::default(),
            default_bucket: Default::default(),
            endpoint: Default::default(),
            path_style_buckets: Default::default(),
            region: Default::default(),
            secret_access_key: Default::default(),
        },
        scan_mime_types: Default::default(),
        webp_quality: Default::default(),
    });

    media.image_size(f)
}

/// Determine size of image with buffer
pub fn image_size_vec(v: &[u8], mime: &str) -> Option<(usize, usize)> {
    let media = MediaImpl::new(Files {
        blocked_mime_types: Default::default(),
        clamd_host: Default::default(),
        encryption_key: Default::default(),
        limit: FilesLimit {
            max_mega_pixels: 0,
            max_pixel_side: 0,
            min_file_size: 0,
            min_resolution: [0, 0],
        },
        preview: Default::default(),
        s3: FilesS3 {
            access_key_id: Default::default(),
            default_bucket: Default::default(),
            endpoint: Default::default(),
            path_style_buckets: Default::default(),
            region: Default::default(),
            secret_access_key: Default::default(),
        },
        scan_mime_types: Default::default(),
        webp_quality: Default::default(),
    });

    media.image_size_vec(v, mime)
}

/// Check whether an image file contains animation data
pub fn is_animated(f: &NamedTempFile, mime: &str) -> Option<bool> {
    let media = MediaImpl::new(Files {
        blocked_mime_types: Default::default(),
        clamd_host: Default::default(),
        encryption_key: Default::default(),
        limit: FilesLimit {
            max_mega_pixels: 0,
            max_pixel_side: 0,
            min_file_size: 0,
            min_resolution: [0, 0],
        },
        preview: Default::default(),
        s3: FilesS3 {
            access_key_id: Default::default(),
            default_bucket: Default::default(),
            endpoint: Default::default(),
            path_style_buckets: Default::default(),
            region: Default::default(),
            secret_access_key: Default::default(),
        },
        scan_mime_types: Default::default(),
        webp_quality: Default::default(),
    });

    media.is_animated(f, mime)
}

/// Determine size of video at temp file
pub fn video_size(f: &NamedTempFile) -> Option<(i64, i64)> {
    let media = MediaImpl::new(Files {
        blocked_mime_types: Default::default(),
        clamd_host: Default::default(),
        encryption_key: Default::default(),
        limit: FilesLimit {
            max_mega_pixels: 0,
            max_pixel_side: 0,
            min_file_size: 0,
            min_resolution: [0, 0],
        },
        preview: Default::default(),
        s3: FilesS3 {
            access_key_id: Default::default(),
            default_bucket: Default::default(),
            endpoint: Default::default(),
            path_style_buckets: Default::default(),
            region: Default::default(),
            secret_access_key: Default::default(),
        },
        scan_mime_types: Default::default(),
        webp_quality: Default::default(),
    });

    media.video_size(f)
}

/// Decode image from reader
pub fn decode_image<R: Read + BufRead + Seek>(reader: &mut R, mime: &str) -> Result<DynamicImage> {
    let media = MediaImpl::new(Files {
        blocked_mime_types: Default::default(),
        clamd_host: Default::default(),
        encryption_key: Default::default(),
        limit: FilesLimit {
            max_mega_pixels: 0,
            max_pixel_side: 0,
            min_file_size: 0,
            min_resolution: [0, 0],
        },
        preview: Default::default(),
        s3: FilesS3 {
            access_key_id: Default::default(),
            default_bucket: Default::default(),
            endpoint: Default::default(),
            path_style_buckets: Default::default(),
            region: Default::default(),
            secret_access_key: Default::default(),
        },
        scan_mime_types: Default::default(),
        webp_quality: Default::default(),
    });

    report_internal_error!(media.decode_image(reader, mime))
}

/// Check whether given reader has a valid image
pub fn is_valid_image<R: Read + BufRead + Seek>(reader: &mut R, mime: &str) -> bool {
    let media = MediaImpl::new(Files {
        blocked_mime_types: Default::default(),
        clamd_host: Default::default(),
        encryption_key: Default::default(),
        limit: FilesLimit {
            max_mega_pixels: 0,
            max_pixel_side: 0,
            min_file_size: 0,
            min_resolution: [0, 0],
        },
        preview: Default::default(),
        s3: FilesS3 {
            access_key_id: Default::default(),
            default_bucket: Default::default(),
            endpoint: Default::default(),
            path_style_buckets: Default::default(),
            region: Default::default(),
            secret_access_key: Default::default(),
        },
        scan_mime_types: Default::default(),
        webp_quality: Default::default(),
    });

    media.is_valid_image(reader, mime)
}

/// Create thumbnail from given image
pub async fn create_thumbnail(image: DynamicImage, tag: &str) -> Vec<u8> {
    let media = MediaImpl::from_config().await;
    media.create_thumbnail(image, tag)
}

/// The bytes a `Range: bytes=…` header asks for, as an inclusive range; `Err` if it
/// cannot be served, `None` if the whole file is to be sent (no header, several ranges,
/// another unit) (dur.io fork)
pub fn requested_range(value: &str, len: usize) -> Option<std::result::Result<(usize, usize), ()>> {
    let spec = value.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }

    let (from, to) = spec.split_once('-')?;
    let (from, to) = (from.trim(), to.trim());
    let range = if from.is_empty() {
        // the last `to` bytes
        let suffix: usize = to.parse().ok()?;
        if suffix == 0 || len == 0 {
            return Some(Err(()));
        }

        (len.saturating_sub(suffix), len - 1)
    } else {
        let start: usize = from.parse().ok()?;
        if start >= len {
            return Some(Err(()));
        }

        let end = if to.is_empty() {
            len - 1
        } else {
            to.parse::<usize>().ok()?.min(len - 1)
        };

        if start > end {
            return Some(Err(()));
        }

        (start, end)
    };

    Some(Ok(range))
}

#[cfg(test)]
mod range_tests {
    use super::requested_range;

    #[test]
    fn ranges() {
        assert_eq!(requested_range("bytes=0-99", 1000), Some(Ok((0, 99))));
        assert_eq!(requested_range("bytes=500-", 1000), Some(Ok((500, 999))));
        assert_eq!(requested_range("bytes=900-5000", 1000), Some(Ok((900, 999))));
        assert_eq!(requested_range("bytes=-100", 1000), Some(Ok((900, 999))));
        assert_eq!(requested_range("bytes=-5000", 1000), Some(Ok((0, 999))));
        assert_eq!(requested_range("bytes=1000-", 1000), Some(Err(())));
        assert_eq!(requested_range("bytes=5-1", 1000), Some(Err(())));
        assert_eq!(requested_range("bytes=0-1,5-9", 1000), None);
        assert_eq!(requested_range("items=0-1", 1000), None);
        assert_eq!(requested_range("bytes=x-1", 1000), None);
    }
}
