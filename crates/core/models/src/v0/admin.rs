//! Instance administration from the client (dur.io fork)

use iso8601_timestamp::Timestamp;

auto_derived!(
    /// # Instance Admin Status
    pub struct AdminStatus {
        /// Whether the current user may use the `/admin` routes of this instance
        pub admin: bool,
        /// Until when admin actions are allowed from this session (after `POST /admin/elevate`)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub elevated_until: Option<Timestamp>,
    }

    /// # Admin Elevation
    pub struct AdminElevation {
        /// When admin actions from this session need a new elevation
        pub expires_at: Timestamp,
    }

    /// # User Found by an Admin
    pub struct AdminUser {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Username
        pub username: String,
        /// Discriminator
        pub discriminator: String,
        /// Display name
        #[serde(skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        /// Whether the user is a bot (bots have no sessions)
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub bot: bool,
    }

    /// # Account Invite Made by an Admin
    ///
    /// Share it as the link `https://<domain>/invite/<code>`.
    pub struct AdminInvite {
        /// Invite code
        #[serde(rename = "_id")]
        pub id: String,
        /// When the invite stops working
        pub expires_at: Timestamp,
        /// Whether the invite works for any number of accounts until it expires
        pub multi_use: bool,
        /// Number of accounts created with the invite
        pub uses: i64,
        /// Id of the admin who made the invite
        pub created_by: String,
        /// When the invite was made
        pub created_at: Timestamp,
    }

    /// # Account Invite Data
    pub struct DataCreateAdminInvite {
        /// How long the invite works: 1, 4, 12 or 24 hours
        pub ttl_hours: u32,
        /// Whether the invite works for any number of accounts until it expires,
        /// otherwise it works once
        #[serde(default)]
        pub multi_use: bool,
    }

    /// # Find User Options
    #[cfg_attr(feature = "rocket", derive(rocket::FromForm))]
    pub struct OptionsAdminFindUser {
        /// User id or `username#discriminator`
        pub query: String,
    }
);
