use revolt_result::Result;

use crate::{Channel, FieldsUser, MemberCompositeKey, PartialUser, RelationshipStatus, User};
use crate::{ReferenceDb, Relationship};

use super::AbstractUsers;

#[async_trait]
impl AbstractUsers for ReferenceDb {
    /// Insert a new user into the database
    async fn insert_user(&self, user: &User) -> Result<()> {
        let mut users = self.users.lock().await;
        if users.contains_key(&user.id) {
            Err(create_database_error!("insert", "user"))
        } else {
            users.insert(user.id.to_string(), user.clone());
            Ok(())
        }
    }

    /// Fetch a user from the database
    async fn fetch_user(&self, id: &str) -> Result<User> {
        let users = self.users.lock().await;
        users
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch a user from the database by their username
    async fn fetch_user_by_username(&self, username: &str, discriminator: &str) -> Result<User> {
        let users = self.users.lock().await;
        let lowercase = username.to_lowercase();
        users
            .values()
            .find(|user| {
                user.username.to_lowercase() == lowercase && user.discriminator == discriminator
            })
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch multiple users by their ids
    ///
    /// Unknown ids are skipped like in MongoDB (`$in`), e.g. the system author.
    async fn fetch_users<'a>(&self, ids: &'a [String]) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        Ok(ids.iter().filter_map(|id| users.get(id).cloned()).collect())
    }

    /// Fetch all discriminators in use for a username
    async fn fetch_discriminators_in_use(&self, username: &str) -> Result<Vec<String>> {
        let users = self.users.lock().await;
        let lowercase = username.to_lowercase();
        Ok(users
            .values()
            .filter(|user| user.username.to_lowercase() == lowercase)
            .map(|user| &user.discriminator)
            .cloned()
            .collect())
    }

    /// Fetch ids of users that both users are friends with
    async fn fetch_mutual_user_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>> {
        let is_friend = |user: &User, id: &str| {
            user.relations.as_ref().is_some_and(|relations| {
                relations.iter().any(|relationship| {
                    relationship.id == id && relationship.status == RelationshipStatus::Friend
                })
            })
        };

        let users = self.users.lock().await;
        Ok(users
            .values()
            .filter(|user| is_friend(user, user_a) && is_friend(user, user_b))
            .map(|user| user.id.clone())
            .collect())
    }

    /// Fetch ids of channels that both users are in
    async fn fetch_mutual_channel_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>> {
        let channels = self.channels.lock().await;
        Ok(channels
            .values()
            .filter(|channel| match channel {
                Channel::DirectMessage { recipients, .. } | Channel::Group { recipients, .. } => {
                    recipients.iter().any(|id| id == user_a)
                        && recipients.iter().any(|id| id == user_b)
                }
                _ => false,
            })
            .map(|channel| channel.id().to_string())
            .collect())
    }

    /// Fetch ids of servers that both users share
    async fn fetch_mutual_server_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>> {
        let members = self.server_members.lock().await;
        Ok(members
            .keys()
            .filter(|key| {
                key.user == user_a
                    && members.contains_key(&MemberCompositeKey {
                        server: key.server.clone(),
                        user: user_b.to_string(),
                    })
            })
            .map(|key| key.server.clone())
            .collect())
    }

    /// Update a user by their id given some data
    async fn update_user(
        &self,
        id: &str,
        partial: &PartialUser,
        remove: Vec<FieldsUser>,
    ) -> Result<()> {
        let mut users = self.users.lock().await;
        if let Some(user) = users.get_mut(id) {
            for field in remove {
                #[allow(clippy::disallowed_methods)]
                user.remove_field(&field);
            }

            user.apply_options(partial.clone());
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Set relationship with another user
    ///
    /// This should use pull_relationship if relationship is None or User.
    async fn set_relationship(
        &self,
        user_id: &str,
        target_id: &str,
        relationship: &RelationshipStatus,
    ) -> Result<()> {
        if let RelationshipStatus::User | RelationshipStatus::None = &relationship {
            self.pull_relationship(user_id, target_id).await
        } else {
            let mut users = self.users.lock().await;
            let user = users
                .get_mut(user_id)
                .ok_or_else(|| create_error!(NotFound))?;

            let relation = Relationship {
                id: target_id.to_string(),
                status: relationship.clone(),
            };

            if let Some(relations) = &mut user.relations {
                relations.retain(|relation| relation.id != target_id);
                relations.push(relation);
            } else {
                user.relations = Some(vec![relation]);
            }

            Ok(())
        }
    }

    /// Remove relationship with another user
    async fn pull_relationship(&self, user_id: &str, target_id: &str) -> Result<()> {
        let mut users = self.users.lock().await;
        let user = users
            .get_mut(user_id)
            .ok_or_else(|| create_error!(NotFound))?;

        if let Some(relations) = &mut user.relations {
            relations.retain(|relation| relation.id != target_id);
        }

        Ok(())
    }

    /// Delete a user by their id
    async fn delete_user(&self, id: &str) -> Result<()> {
        let mut users = self.users.lock().await;
        if users.remove(id).is_some() {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Removes all relationships with the user from the list of users
    async fn clear_user_relationships(
        &self,
        target_id: &str,
        user_ids: Vec<String>,
    ) -> Result<()> {
        let mut users = self.users.lock().await;

        for user_id in user_ids {
            if let Some(user) = users.get_mut(&user_id) {
                if let Some(relations) = &mut user.relations {
                    relations.retain(|relation| relation.id != target_id);
                }
            }
        }

        Ok(())
    }
}
