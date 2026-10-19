use iso8601_timestamp::Timestamp;

use crate::{if_false, Database};
use revolt_result::Result;

auto_derived_partial!(
    /// Account invite ticket
    pub struct AccountInvite {
        /// Invite code
        #[serde(rename = "_id")]
        pub id: String,
        /// Whether this invite ticket has been used
        #[serde(skip_serializing_if = "if_false", default)]
        pub used: bool,
        /// User ID that this invite was claimed by
        #[serde(skip_serializing_if = "Option::is_none")]
        pub claimed_by: Option<String>,

        /// When this invite stops working (dur.io fork), manual invites never expire
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub expires_at: Option<Timestamp>,
        /// Whether this invite works for any number of accounts until it expires (dur.io fork)
        #[serde(skip_serializing_if = "if_false", default)]
        pub multi_use: bool,
        /// Number of accounts created with this multi-use invite (dur.io fork)
        #[serde(skip_serializing_if = "if_zero", default)]
        pub uses: i64,
        /// Admin who generated this invite in the app (dur.io fork)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub created_by: Option<String>,
        /// When the invite was generated in the app (dur.io fork)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub created_at: Option<Timestamp>,
    },
    "PartialAccountInvite"
);

fn if_zero(n: &i64) -> bool {
    *n == 0
}

#[allow(clippy::derivable_impls)]
impl Default for AccountInvite {
    fn default() -> Self {
        Self {
            id: String::new(),
            used: false,
            claimed_by: None,
            expires_at: None,
            multi_use: false,
            uses: 0,
            created_by: None,
            created_at: None,
        }
    }
}

impl AccountInvite {
    /// Save model
    pub async fn save(&self, db: &Database) -> Result<()> {
        db.save_account_invite(self).await
    }

    /// Whether this invite has expired at `now`
    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }

    /// Whether this invite can still be used to create an account at `now`
    pub fn is_active(&self, now: Timestamp) -> bool {
        !self.is_expired(now) && (self.multi_use || !self.used)
    }
}
