//! Publishing E2EE events (dur.io fork)
use super::client::EventV1;

impl EventV1 {
    /// Publish to Redis (bonfire) only, without the RabbitMQ copy
    ///
    /// For to-device doorbells: one event per stored message, nobody consumes them from RabbitMQ.
    pub async fn p_redis_only(self, channel: String) {
        let redis_channel = self.redis_suffix(channel);
        if let Err(error) = redis_kiss::publish(redis_channel, &self).await {
            log::error!("Failed to publish E2EE event: {error:?}");
        }
    }
}
