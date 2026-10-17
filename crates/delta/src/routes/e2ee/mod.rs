//! End-to-end encryption: device keys, to-device mailbox, key backup (dur.io fork)
//!
//! Bodies follow the Matrix client-server API v1.x (contract v1, `stoat-crypto/fixtures/`).
//! The server only relays opaque data: it checks structure and limits, never signatures.
use std::collections::HashMap;

use revolt_database::Database;
use revolt_models::v0::E2EE_KEY_ALGORITHM_SIGNED_CURVE25519;
use revolt_result::{Error, Result, create_error};
use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;
use serde_json::Value;

mod guard;
mod keys_claim;
mod keys_count;
mod keys_query;
mod keys_upload;
mod to_device_ack;
mod to_device_fetch;
mod to_device_send;

#[cfg(test)]
mod tests;

pub use guard::E2eeSession;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        keys_upload::upload,
        keys_query::query,
        keys_claim::claim,
        keys_count::count,
        to_device_send::send,
        to_device_fetch::fetch,
        to_device_ack::ack,
    ]
}

/// Malformed part of a request body
fn invalid(field: &str) -> Error {
    create_error!(FailedValidation {
        error: format!("invalid {field}")
    })
}

/// Serialized size of a JSON value in bytes
fn json_size(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// Unclaimed one-time keys and unused fallback key algorithms of a device
///
/// `signed_curve25519` is always counted and the fallback list is always present:
/// without it clients never upload a fallback key.
async fn key_counts(
    db: &Database,
    device_id: &str,
) -> Result<(HashMap<String, usize>, Vec<String>)> {
    let mut counts = db.count_one_time_keys(device_id).await?;
    counts
        .entry(E2EE_KEY_ALGORITHM_SIGNED_CURVE25519.to_string())
        .or_insert(0);

    let fallback = db.fetch_unused_fallback_key_types(device_id).await?;
    Ok((counts, fallback))
}
