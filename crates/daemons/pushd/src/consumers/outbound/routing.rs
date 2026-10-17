//! Push routing fields for clients that hold several accounts (plan BE-30).
//!
//! Every FCM data payload carries `instance` (the canonical API URL of this server) and
//! `recipient` (the user the push is for), so a client can pick the right account even when
//! several accounts on several servers share one FCM token.

use std::collections::HashMap;

use serde_json::Value;

/// Canonical form of an API URL, shared with the clients' `canonicalApiUrl`:
/// lowercase scheme and host, default port dropped, no trailing slash, path kept as is.
pub fn canonical_api_url(url: &str) -> String {
    let url = url.trim();
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => ("https".to_string(), url),
    };

    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, ""),
    };

    let mut authority = authority.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => Some(":443"),
        "http" => Some(":80"),
        _ => None,
    };
    if let Some(stripped) = default_port.and_then(|port| authority.strip_suffix(port)) {
        authority = stripped.to_string();
    }

    format!("{scheme}://{authority}{}", path.trim_end_matches('/'))
}

/// Add the routing fields to an FCM data payload.
pub fn with_routing(
    mut data: HashMap<String, Value>,
    instance: &str,
    recipient: &str,
) -> HashMap<String, Value> {
    data.insert("instance".to_string(), Value::String(instance.to_string()));
    data.insert("recipient".to_string(), Value::String(recipient.to_string()));
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_api_url_vectors() {
        let vectors = [
            ("https://duri0.duckdns.org/api", "https://duri0.duckdns.org/api"),
            ("https://duri0.duckdns.org/api/", "https://duri0.duckdns.org/api"),
            ("HTTPS://Duri0.DuckDNS.org/api", "https://duri0.duckdns.org/api"),
            ("https://duri0.duckdns.org:443/api", "https://duri0.duckdns.org/api"),
            ("http://localhost:80/", "http://localhost"),
            ("http://10.0.2.2:14702", "http://10.0.2.2:14702"),
            ("https://example.com:8443/api", "https://example.com:8443/api"),
            ("https://api.stoat.chat", "https://api.stoat.chat"),
            ("duri0.duckdns.org/api", "https://duri0.duckdns.org/api"),
            ("  https://duri0.duckdns.org/API/  ", "https://duri0.duckdns.org/API"),
        ];

        for (input, expected) in vectors {
            assert_eq!(canonical_api_url(input), expected, "input: {input:?}");
        }
    }

    #[test]
    fn routing_fields_are_strings() {
        let mut data = HashMap::new();
        data.insert("type".to_string(), Value::String("push.message".into()));

        let data = with_routing(data, "https://duri0.duckdns.org/api", "01HZXAMPLEUSER");

        assert_eq!(
            data.get("instance"),
            Some(&Value::String("https://duri0.duckdns.org/api".into()))
        );
        assert_eq!(
            data.get("recipient"),
            Some(&Value::String("01HZXAMPLEUSER".into()))
        );
        assert_eq!(data.get("type"), Some(&Value::String("push.message".into())));
    }
}
