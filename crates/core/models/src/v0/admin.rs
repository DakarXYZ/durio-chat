//! Instance administration from the client (dur.io fork)

auto_derived!(
    /// # Instance Admin Status
    pub struct AdminStatus {
        /// Whether the current user may use the `/admin` routes of this instance
        pub admin: bool,
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

    /// # Find User Options
    #[cfg_attr(feature = "rocket", derive(rocket::FromForm))]
    pub struct OptionsAdminFindUser {
        /// User id or `username#discriminator`
        pub query: String,
    }
);
