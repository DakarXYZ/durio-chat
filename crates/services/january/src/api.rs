use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use reqwest::header;
use revolt_files::requested_range;
use revolt_models::v0::Embed;
use revolt_result::{create_error, Result};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::requests::Request;

pub static CACHE_CONTROL: &str = "public, max-age=600, immutable";

pub async fn router() -> Router {
    Router::new()
        .route("/", get(root))
        .route("/proxy", get(proxy))
        .route("/embed", get(embed))
}

/// Successful root response
#[derive(Serialize, Debug, ToSchema)]
pub struct RootResponse {
    january: &'static str,
    version: &'static str,
}

/// Capture crate version from Cargo
static CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Root response from service
#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = 200, description = "Echo response", body = RootResponse)
    )
)]
async fn root() -> Json<RootResponse> {
    Json(RootResponse {
        january: "Hello, I am a media proxy server!",
        version: CRATE_VERSION,
    })
}

#[derive(Deserialize)]
struct UrlQuery {
    url: String,
}

/// Proxy a given URL and load media
#[utoipa::path(
    get,
    path = "/proxy",
    responses(
        (status = 200, description = "Requested media file", body = Vec<u8>)
    ),
    params(
        ("url" = String, Query, description = "URL to fetch")
    ),
)]
async fn proxy(
    headers: HeaderMap,
    Query(UrlQuery { url }): Query<UrlQuery>,
) -> Result<Response> {
    Request::proxy_file(&url).await.map(|(content_type, data)| {
        let len = data.len();
        // dur.io fork: a part of the file, so that players can seek
        match headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| requested_range(value, len))
        {
            Some(Ok((start, end))) => (
                StatusCode::PARTIAL_CONTENT,
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CONTENT_DISPOSITION, "inline".to_owned()),
                    (header::CACHE_CONTROL, CACHE_CONTROL.to_owned()),
                    (header::ACCEPT_RANGES, "bytes".to_owned()),
                    (header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}")),
                ],
                data[start..=end].to_vec(),
            )
                .into_response(),
            Some(Err(())) => (
                StatusCode::RANGE_NOT_SATISFIABLE,
                [(header::CONTENT_RANGE, format!("bytes */{len}"))],
            )
                .into_response(),
            None => (
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CONTENT_DISPOSITION, "inline".to_owned()),
                    (header::CACHE_CONTROL, CACHE_CONTROL.to_owned()),
                    (header::ACCEPT_RANGES, "bytes".to_owned()),
                ],
                data,
            )
                .into_response(),
        }
    })
}

/// Generate embed for a given URL
#[utoipa::path(
    get,
    path = "/embed",
    responses(
        (status = 200, description = "Generated embed information", body = Embed)
    ),
    params(
        ("url" = String, Query, description = "URL to fetch")
    ),
    security(
        ("api_key" = [])
    )
)]
async fn embed(
    Query(UrlQuery { url }): Query<UrlQuery>,
    // TypedHeader(Authorization(_bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse> {
    match Request::generate_embed(url).await {
        Ok(Embed::None) => Err(create_error!(NoEmbedData)),
        result => result,
    }
    .map(Json)
}
