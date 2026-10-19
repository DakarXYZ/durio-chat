use crate::{AbstractAccountInvites, AccountInvite, ReferenceDb};
use revolt_result::Result;

#[async_trait]
impl AbstractAccountInvites for ReferenceDb {
    /// Find invite by id
    async fn fetch_account_invite(&self, id: &str) -> Result<AccountInvite> {
        let invites = self.account_invites.lock().await;
        invites
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(InvalidInvite))
    }

    /// Save invite
    async fn save_account_invite(&self, invite: &AccountInvite) -> Result<()> {
        let mut invites = self.account_invites.lock().await;
        invites.insert(invite.id.to_string(), invite.clone());
        Ok(())
    }

    /// Mark an unused invite as used
    async fn claim_account_invite(&self, id: &str) -> Result<()> {
        let mut invites = self.account_invites.lock().await;
        match invites.get_mut(id) {
            Some(invite) if !invite.used => {
                invite.used = true;
                Ok(())
            }
            _ => Err(create_error!(InvalidInvite)),
        }
    }

    /// Make a claimed invite usable again
    async fn release_account_invite(&self, id: &str) -> Result<()> {
        let mut invites = self.account_invites.lock().await;
        if let Some(invite) = invites.get_mut(id) {
            invite.used = false;
            invite.claimed_by = None;
        }

        Ok(())
    }
}
