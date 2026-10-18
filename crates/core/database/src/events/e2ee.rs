//! Publishing E2EE events (dur.io fork)
use super::client::EventV1;

impl EventV1 {
    /// Publish to Redis (bonfire) only, without the RabbitMQ copy
    ///
    /// For to-device doorbells: one event per stored message, nobody consumes them from RabbitMQ.
    pub async fn p_redis_only(self, channel: String) {
        let redis_channel = self.redis_suffix(channel);
        self.publish_redis(redis_channel).await;
    }
}
