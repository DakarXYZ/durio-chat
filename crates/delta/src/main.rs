#[macro_use]
extern crate rocket;
#[macro_use]
extern crate revolt_rocket_okapi;
#[macro_use]
extern crate serde_json;

pub mod routes;
pub mod util;

use revolt_config::config;
use revolt_database::AMQP;
use revolt_ratelimits::rocket as ratelimiter;
use rocket::{Build, Rocket};
use rocket_cors::{AllowedOrigins, CorsOptions};
use rocket_prometheus::PrometheusMetrics;
use std::net::Ipv4Addr;
use std::str::FromStr;

use revolt_database::voice::VoiceClient;
use rocket::data::ToByteUnit;

pub async fn web() -> Rocket<Build> {
    // Get settings
    let config = config().await;

    // Ensure environment variables are present
    config.preflight_checks();

    // dur.io fork: text old clients show in place of encrypted messages
    revolt_database::util::e2ee::set_legacy_placeholder(
        config.features.e2ee.legacy_placeholder.clone(),
    );

    // Setup database
    let db = revolt_database::DatabaseInfo::Auto.connect().await.unwrap();
    db.migrate_database().await.unwrap();

    // Configure CORS
    let cors = CorsOptions {
        allowed_origins: AllowedOrigins::All,
        allowed_methods: [
            "Get", "Put", "Post", "Delete", "Options", "Head", "Trace", "Connect", "Patch",
        ]
        .iter()
        .map(|s| FromStr::from_str(s).unwrap())
        .collect(),
        expose_headers: [
            "X-Ratelimit-Limit",
            "X-Ratelimit-Bucket",
            "X-Ratelimit-Remaining",
            "X-Ratelimit-Reset-After",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        ..Default::default()
    }
    .to_cors()
    .expect("Failed to create CORS.");

    // Configure Swagger
    let swagger = revolt_rocket_okapi::swagger_ui::make_swagger_ui(
        &revolt_rocket_okapi::swagger_ui::SwaggerUIConfig {
            url: "/openapi.json".to_owned(),
            ..Default::default()
        },
    )
    .into();

    // Voice handler
    let voice_client = VoiceClient::new(config.api.livekit.nodes.clone());
    // Configure Rabbit

    let amqp = AMQP::new_auto().await;

    // Launch background task workers
    revolt_database::tasks::start_workers(db.clone(), amqp.clone());

    // Configure Rocket
    let rocket = rocket::build();
    let prometheus = PrometheusMetrics::new();

    // Ratelimits
    let ratelimits = ratelimiter::RatelimitStorage::new(util::ratelimits::DeltaRatelimits);

    // dur.io fork: /e2ee batches (to-device, key backup) exceed Rocket's 1 MiB JSON default
    let json_limit = config.features.e2ee.max_request_bytes;

    routes::mount(config, rocket)
        .attach(prometheus.clone())
        .mount("/metrics", prometheus)
        .mount("/", rocket_cors::catch_all_options_routes())
        .mount("/", ratelimiter::routes())
        .mount("/swagger/", swagger)
        .manage(db)
        .manage(amqp)
        .manage(cors.clone())
        .manage(voice_client)
        .manage(ratelimits)
        .attach(ratelimiter::RatelimitFairing)
        .attach(cors)
        .configure(rocket::Config {
            limits: rocket::data::Limits::default()
                .limit("string", 5.megabytes())
                .limit("json", json_limit.bytes()),
            address: Ipv4Addr::new(0, 0, 0, 0).into(),
            port: 14702,
            ip_header: Some("X-Forwarded-For".into()),
            ..Default::default()
        })
}

#[launch]
async fn rocket() -> _ {
    // Configure logging and environment
    revolt_config::configure!(api);

    // Start web server
    web().await
}
