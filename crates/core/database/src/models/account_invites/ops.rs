use revolt_result::Result;

use crate::AccountInvite;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractAccountInvites: Sync + Send {
    /// Find invite by id
    async fn fetch_account_invite(&self, id: &str) -> Result<AccountInvite>;

    /// Save invite
    async fn save_account_invite(&self, invite: &AccountInvite) -> Result<()>;

    /// Mark an unused invite as used, atomically: of concurrent claims only one succeeds
    /// (dur.io fork). `InvalidInvite` if it does not exist or is used already.
    async fn claim_account_invite(&self, id: &str) -> Result<()>;

    /// Make a claimed invite usable again, e.g. when creating the account failed (dur.io fork)
    async fn release_account_invite(&self, id: &str) -> Result<()>;
}
