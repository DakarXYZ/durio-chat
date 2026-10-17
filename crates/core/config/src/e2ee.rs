use serde::Deserialize;

/// End-to-end encryption in direct messages and groups (dur.io fork)
///
/// Read once at startup: changing any value (especially `enabled`) requires
/// restarting every backend service. Do not disable after enabling in production,
/// encrypted conversations become read-only.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct FeaturesE2ee {
    /// Whether the `/e2ee` routes, encrypted messages and E2EE events are available
    pub enabled: bool,
    /// Whether new direct messages are encrypted from the start
    pub default_for_new_dms: bool,
    /// Maximum size of an encrypted message envelope ciphertext (bytes)
    pub max_envelope_bytes: usize,
    /// Maximum size of a single to-device message content (bytes)
    pub max_to_device_bytes: usize,
    /// Maximum number of to-device messages in a single request
    pub max_to_device_batch: usize,
    /// Maximum number of one-time keys stored per device
    pub max_otk_per_device: usize,
    /// Maximum number of undelivered to-device messages per device
    pub max_pending_to_device: usize,
    /// Number of days after which undelivered to-device messages are dropped
    pub to_device_ttl_days: u32,
    /// Text shown by clients without E2EE support in place of an encrypted message
    pub legacy_placeholder: String,
    /// Maximum size of a single key in the key backup (bytes)
    pub max_backup_key_bytes: usize,
    /// Maximum size of a single secret storage entry (bytes)
    pub max_secret_bytes: usize,
    /// Maximum number of users or devices in a single key query or claim
    pub max_devices_per_request: usize,
    /// Notify the device when its one-time key count drops below this
    pub otk_low_threshold: usize,
    /// Maximum JSON request body size accepted by the API (bytes)
    pub max_request_bytes: usize,
}

impl Default for FeaturesE2ee {
    fn default() -> Self {
        Self {
            enabled: false,
            default_for_new_dms: false,
            max_envelope_bytes: 16_384,
            max_to_device_bytes: 65_536,
            max_to_device_batch: 1_000,
            max_otk_per_device: 100,
            max_pending_to_device: 10_000,
            to_device_ttl_days: 30,
            legacy_placeholder: "🔒 Зашифрованное сообщение. Обновите приложение.".to_string(),
            max_backup_key_bytes: 4_096,
            max_secret_bytes: 16_384,
            max_devices_per_request: 256,
            otk_low_threshold: 10,
            max_request_bytes: 4_194_304,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FeaturesE2ee;

    #[derive(serde::Deserialize)]
    struct Root {
        features: Features,
    }

    #[derive(serde::Deserialize)]
    struct Features {
        e2ee: FeaturesE2ee,
    }

    fn parse(toml: &str) -> FeaturesE2ee {
        config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize::<Root>()
            .unwrap()
            .features
            .e2ee
    }

    #[test]
    fn defaults_match_revolt_toml() {
        assert_eq!(
            parse(include_str!("../Revolt.toml")),
            FeaturesE2ee::default()
        );
    }

    #[test]
    fn partial_section_uses_defaults() {
        let e2ee = parse("[features.e2ee]\nenabled = true\n");
        assert!(e2ee.enabled);
        assert_eq!(
            e2ee,
            FeaturesE2ee {
                enabled: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn disabled_by_default() {
        assert!(!FeaturesE2ee::default().enabled);
    }
}
