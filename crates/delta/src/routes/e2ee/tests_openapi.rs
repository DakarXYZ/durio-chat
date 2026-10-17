//! The E2EE API is documented in `/openapi.json` (BE-23)
//!
//! Clients generate their types from it (`stoat-api` for the JS SDK), so a route or field
//! missing from the spec is missing in the clients.
use rocket::http::Status;
use serde_json::Value;

use crate::util::test::TestHarness;

async fn spec() -> Value {
    let harness = TestHarness::new().await;
    let response = harness.client.get("/openapi.json").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}

/// Properties of a schema, of one variant (`channel_type`) of a `oneOf` schema if given
fn properties<'a>(spec: &'a Value, schema: &str, variant: Option<&str>) -> &'a Value {
    let schema = &spec["components"]["schemas"][schema];
    match variant {
        None => &schema["properties"],
        Some(variant) => &schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant_schema| {
                variant_schema["properties"]["channel_type"]["enum"][0] == variant
            })
            .unwrap_or_else(|| panic!("variant {variant}"))["properties"],
    }
}

fn reference(property: &Value) -> &str {
    property["allOf"][0]["$ref"].as_str().unwrap_or_default()
}

#[rocket::async_test]
async fn e2ee_routes() {
    let spec = spec().await;
    let paths = &spec["paths"];

    let routes = [
        ("post", "/e2ee/keys/upload"),
        ("post", "/e2ee/keys/query"),
        ("post", "/e2ee/keys/claim"),
        ("get", "/e2ee/keys/count"),
        ("put", "/e2ee/to_device/{txn_id}"),
        ("get", "/e2ee/to_device"),
        ("post", "/e2ee/to_device/ack"),
        ("get", "/e2ee/backup/version"),
        ("post", "/e2ee/backup/version"),
        ("get", "/e2ee/backup/version/{version}"),
        ("put", "/e2ee/backup/version/{version}"),
        ("delete", "/e2ee/backup/version/{version}"),
        ("get", "/e2ee/backup/keys"),
        ("put", "/e2ee/backup/keys"),
        ("delete", "/e2ee/backup/keys"),
        ("get", "/e2ee/backup/keys/{room}"),
        ("put", "/e2ee/backup/keys/{room}"),
        ("delete", "/e2ee/backup/keys/{room}"),
        ("get", "/e2ee/backup/keys/{room}/{session}"),
        ("put", "/e2ee/backup/keys/{room}/{session}"),
        ("delete", "/e2ee/backup/keys/{room}/{session}"),
        ("get", "/e2ee/secrets/{secret_type}"),
        ("put", "/e2ee/secrets/{secret_type}"),
    ];

    for (method, path) in routes {
        let operation = &paths[path][method];
        assert_eq!(operation["tags"][0], "E2EE", "{method} {path}");
        // Some routes also take an MFA ticket
        assert!(
            operation["security"]
                .as_array()
                .unwrap()
                .iter()
                .any(|security| security.get("Session Token").is_some()),
            "{method} {path}"
        );
    }

    let documented = paths
        .as_object()
        .unwrap()
        .keys()
        .filter(|path| path.starts_with("/e2ee"))
        .count();
    assert_eq!(documented, 13, "a new /e2ee route needs to be listed here");

    let encryption = &paths["/channels/{target}/encryption"]["put"];
    assert_eq!(encryption["tags"][0], "Channel Information");
    assert_eq!(
        encryption["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/DataChannelEncryption"
    );

    // Grouped in the sidebar of the docs
    assert!(
        spec["x-tagGroups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| group["tags"].as_array().unwrap().contains(&"E2EE".into()))
    );
}

#[rocket::async_test]
async fn encrypted_fields() {
    let spec = spec().await;
    let envelope = "#/components/schemas/EncryptedEnvelope";

    for schema in ["Message", "DataMessageSend", "DataEditMessage"] {
        assert_eq!(
            reference(&properties(&spec, schema, None)["encrypted"]),
            envelope,
            "{schema}"
        );
    }

    assert_eq!(
        properties(&spec, "File", None)["encrypted"]["type"],
        "boolean"
    );

    for variant in ["DirectMessage", "Group"] {
        assert_eq!(
            reference(&properties(&spec, "Channel", Some(variant))["encryption"]),
            "#/components/schemas/ChannelEncryption"
        );
    }
    for variant in ["SavedMessages", "TextChannel"] {
        assert!(properties(&spec, "Channel", Some(variant))["encryption"].is_null());
    }

    assert_eq!(
        reference(&properties(&spec, "RevoltFeatures", None)["e2ee"]),
        "#/components/schemas/E2eeFeature"
    );

    // Unknown envelope fields are rejected, the schema says so
    let schemas = &spec["components"]["schemas"];
    assert_eq!(
        schemas["EncryptedEnvelope"]["additionalProperties"],
        Value::Bool(false)
    );

    assert!(
        schemas["SystemMessage"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |variant| variant["properties"]["type"]["enum"][0] == "encryption_enabled"
                    && variant["properties"]["by"]["type"] == "string"
            )
    );
}

#[rocket::async_test]
async fn e2ee_errors() {
    let spec = spec().await;
    let errors = spec["components"]["schemas"]["Error"].to_string();

    for error in [
        "E2eeDisabled",
        "EncryptedChannelViolation",
        "NotEncryptable",
        "AlreadyEncrypted",
        "SearchUnavailableInEncryptedChannel",
        "DeviceNotFound",
        "TooManyPendingToDevice",
        "DeviceKeysMismatch",
        "BackupVersionMismatch",
    ] {
        assert!(errors.contains(&format!("\"{error}\"")), "{error}");
    }
}
