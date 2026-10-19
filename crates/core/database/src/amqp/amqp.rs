use std::{
    collections::HashSet,
    sync::{Arc, OnceLock, RwLock},
    time::{Duration, Instant},
};

use crate::User;
use crate::events::{client::EventV1, rabbit::*};
use lapin::{
    BasicProperties, Channel, Connection, ConnectionProperties, Error as AMQPError,
    options::BasicPublishOptions,
    protocol::basic::AMQPProperties,
    types::{AMQPValue, FieldTable},
};
use revolt_config::config;
use revolt_models::v0::PushNotification;
use revolt_presence::filter_online;
use revolt_result::Result;

use serde_json::to_string;
use tokio::{sync::Mutex, time::timeout};

static AMQP_INSTANCE: OnceLock<AMQP> = OnceLock::new();

pub fn get_amqp() -> &'static AMQP {
    AMQP_INSTANCE.get().expect("No AMQP instance set.")
}

/// Channels of one broker connection, replaced as a whole on reconnect
struct Channels {
    /// Bumped on every reconnect, so racing publishers reconnect only once
    generation: u64,
    friend_request_accepted: Channel,
    friend_request_received: Channel,
    generic_message: Channel,
    message_sent: Channel,
    mass_mention_message_sent: Channel,
    ack_notification_message: Channel,
    dm_call_updated: Channel,
    process_ack: Channel,
    publish_event: Channel,
    connection: Arc<Connection>,
}

impl Channels {
    async fn open(connection: Arc<Connection>, generation: u64) -> Result<Self, AMQPError> {
        Ok(Self {
            generation,
            friend_request_accepted: connection.create_channel().await?,
            friend_request_received: connection.create_channel().await?,
            generic_message: connection.create_channel().await?,
            message_sent: connection.create_channel().await?,
            mass_mention_message_sent: connection.create_channel().await?,
            ack_notification_message: connection.create_channel().await?,
            dm_call_updated: connection.create_channel().await?,
            process_ack: connection.create_channel().await?,
            publish_event: connection.create_channel().await?,
            connection,
        })
    }
}

/// Pause between reconnect attempts, so requests during an outage fail fast
/// instead of each one dialling the broker
#[derive(Default, Debug)]
struct Backoff {
    failures: u32,
    next_attempt: Option<Instant>,
}

impl Backoff {
    const MIN: Duration = Duration::from_millis(500);
    const MAX: Duration = Duration::from_secs(30);

    fn ready(&self, now: Instant) -> bool {
        self.next_attempt.is_none_or(|next| now >= next)
    }

    fn failed(&mut self, now: Instant) {
        let delay = Self::MIN
            .saturating_mul(1 << self.failures.min(16))
            .min(Self::MAX);
        self.failures = self.failures.saturating_add(1);
        self.next_attempt = Some(now + delay);
    }

    fn succeeded(&mut self) {
        *self = Self::default();
    }
}

/// Upper bound for one reconnect attempt made on a request path
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

// dur.io fork: the connection and its channels are replaced after a broker
// restart, upstream kept the first ones forever (B1)
#[derive(Clone)]
pub struct AMQP {
    channels: Arc<RwLock<Arc<Channels>>>,
    reconnect: Arc<Mutex<Backoff>>,
}

impl AMQP {
    pub async fn new(connection: Arc<Connection>) -> Self {
        let channels = Channels::open(connection, 0)
            .await
            .expect("Failed to create channel");

        let this = Self {
            channels: Arc::new(RwLock::new(Arc::new(channels))),
            reconnect: Arc::new(Mutex::new(Backoff::default())),
        };

        let _ = AMQP_INSTANCE.set(this.clone());

        this
    }

    pub async fn new_auto() -> Self {
        let connection = Arc::new(
            Self::connect()
                .await
                .expect("Failed to connect to RabbitMQ"),
        );

        Self::new(connection).await
    }

    async fn connect() -> Result<Connection, AMQPError> {
        let config = revolt_config::config().await;

        Connection::connect(
            &format!(
                "amqp://{}:{}@{}:{}",
                &config.rabbit.username,
                &config.rabbit.password,
                &config.rabbit.host,
                &config.rabbit.port,
            ),
            ConnectionProperties::default(),
        )
        .await
    }

    pub fn connection(&self) -> Arc<Connection> {
        self.current().connection.clone()
    }

    fn current(&self) -> Arc<Channels> {
        self.channels
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Replace the connection after a failed publish on generation `failed`;
    /// `None` while the broker is unreachable or the backoff has not passed
    async fn reconnect(&self, failed: u64) -> Option<Arc<Channels>> {
        let mut backoff = self.reconnect.lock().await;

        // Someone else already reconnected
        let current = self.current();
        if current.generation != failed {
            return Some(current);
        }

        if !backoff.ready(Instant::now()) {
            return None;
        }

        let opened = timeout(CONNECT_TIMEOUT, async {
            let connection = Arc::new(Self::connect().await?);
            Channels::open(connection, failed + 1).await
        })
        .await;

        match opened {
            Ok(Ok(channels)) => {
                backoff.succeeded();
                let channels = Arc::new(channels);
                *self
                    .channels
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = channels.clone();
                info!(
                    "Reconnected to RabbitMQ (generation {})",
                    channels.generation
                );

                // The old connection may still be half alive (a channel error)
                let old = current.connection.clone();
                tokio::spawn(async move {
                    let _ = old.close(200, "reconnecting".into()).await;
                });

                Some(channels)
            }
            Ok(Err(error)) => {
                backoff.failed(Instant::now());
                warn!("Failed to reconnect to RabbitMQ: {error:?}");
                None
            }
            Err(_) => {
                backoff.failed(Instant::now());
                warn!("Timed out reconnecting to RabbitMQ");
                None
            }
        }
    }

    /// Publish on one of the channels, reconnecting once if it is dead
    async fn publish(
        &self,
        channel: fn(&Channels) -> &Channel,
        exchange: &str,
        routing_key: &str,
        payload: &[u8],
        properties: BasicProperties,
    ) -> Result<(), AMQPError> {
        let current = self.current();
        let error = match channel(&current)
            .basic_publish(
                exchange.into(),
                routing_key.into(),
                BasicPublishOptions::default(),
                payload,
                properties.clone(),
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };

        warn!("Publish to {routing_key} failed, reconnecting to RabbitMQ: {error:?}");
        let Some(fresh) = self.reconnect(current.generation).await else {
            return Err(error);
        };

        channel(&fresh)
            .basic_publish(
                exchange.into(),
                routing_key.into(),
                BasicPublishOptions::default(),
                payload,
                properties,
            )
            .await
            .map(|_| ())
    }

    pub async fn friend_request_accepted(
        &self,
        accepted_request_user: &User,
        sent_request_user: &User,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;
        let payload = FRAcceptedPayload {
            accepted_user: accepted_request_user.to_owned(),
            user: sent_request_user.id.clone(),
        };
        let payload = to_string(&payload).unwrap();

        debug!(
            "Sending friend request accept payload on channel {}: {}",
            config.pushd.get_fr_accepted_routing_key(),
            payload
        );

        self.publish(
            |channels| &channels.friend_request_accepted,
            &config.pushd.exchange,
            &config.pushd.get_fr_accepted_routing_key(),
            payload.as_bytes(),
            AMQPProperties::default()
                .with_content_type("application/json".into())
                .with_delivery_mode(2),
        )
        .await?;

        Ok(())
    }

    pub async fn friend_request_received(
        &self,
        received_request_user: &User,
        sent_request_user: &User,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;
        let payload = FRReceivedPayload {
            from_user: sent_request_user.to_owned(),
            user: received_request_user.id.clone(),
        };
        let payload = to_string(&payload).unwrap();

        debug!(
            "Sending friend request received payload on channel {}: {}",
            config.pushd.get_fr_received_routing_key(),
            payload
        );

        self.publish(
            |channels| &channels.friend_request_received,
            &config.pushd.exchange,
            &config.pushd.get_fr_received_routing_key(),
            payload.as_bytes(),
            AMQPProperties::default()
                .with_content_type("application/json".into())
                .with_delivery_mode(2),
        )
        .await?;

        Ok(())
    }

    pub async fn generic_message(
        &self,
        user: &User,
        title: String,
        body: String,
        icon: Option<String>,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;
        let payload = GenericPayload {
            title,
            body,
            icon,
            user: user.to_owned(),
        };
        let payload = to_string(&payload).unwrap();

        debug!(
            "Sending generic payload on channel {}: {}",
            config.pushd.get_generic_routing_key(),
            payload
        );

        self.publish(
            |channels| &channels.generic_message,
            &config.pushd.exchange,
            &config.pushd.get_generic_routing_key(),
            payload.as_bytes(),
            AMQPProperties::default()
                .with_content_type("application/json".into())
                .with_delivery_mode(2),
        )
        .await?;

        Ok(())
    }

    pub async fn message_sent(
        &self,
        recipients: Vec<String>,
        payload: PushNotification,
    ) -> Result<(), AMQPError> {
        if recipients.is_empty() {
            return Ok(());
        }

        let config = revolt_config::config().await;

        let online_ids = filter_online(&recipients).await;
        let recipients = (&recipients.into_iter().collect::<HashSet<String>>() - &online_ids)
            .into_iter()
            .collect::<Vec<String>>();

        let payload = MessageSentPayload {
            notification: payload,
            users: recipients,
        };
        let payload = to_string(&payload).unwrap();

        debug!(
            "Sending message payload on channel {}: {}",
            config.pushd.get_message_routing_key(),
            payload
        );

        self.publish(
            |channels| &channels.message_sent,
            &config.pushd.exchange,
            &config.pushd.get_message_routing_key(),
            payload.as_bytes(),
            AMQPProperties::default()
                .with_content_type("application/json".into())
                .with_delivery_mode(2),
        )
        .await?;

        Ok(())
    }

    pub async fn mass_mention_message_sent(
        &self,
        server_id: String,
        payload: Vec<PushNotification>,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;

        let payload = MassMessageSentPayload {
            notifications: payload,
            server_id,
        };
        let payload = to_string(&payload).unwrap();

        let routing_key = config.pushd.get_mass_mention_routing_key();

        debug!(
            "Sending mass mention payload on channel {}: {}",
            routing_key, payload
        );

        self.publish(
            |channels| &channels.mass_mention_message_sent,
            &config.pushd.exchange,
            &routing_key,
            payload.as_bytes(),
            AMQPProperties::default()
                .with_content_type("application/json".into())
                .with_delivery_mode(2),
        )
        .await?;

        Ok(())
    }

    /// # Sends an ack to pushd to update badges on iPhones.
    /// Not to be confused with the process_ack function, which handles sending all acks to crond for processing.
    pub async fn ack_notification_message(
        &self,
        user_id: String,
        channel_id: String,
        message_id: String,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;

        let payload = AckPayload {
            user_id: user_id.clone(),
            channel_id: channel_id.clone(),
            message_id,
        };
        let payload = to_string(&payload).unwrap();

        info!(
            "Sending ack payload on channel {}: {}",
            config.pushd.ack_queue, payload
        );

        let mut headers = FieldTable::default();
        headers.insert(
            "x-deduplication-header".into(),
            AMQPValue::LongString(format!("{}-{}", &user_id, &channel_id).into()),
        );

        self.publish(
            |channels| &channels.ack_notification_message,
            &config.pushd.exchange,
            &config.pushd.ack_queue,
            payload.as_bytes(),
            AMQPProperties::default()
                .with_content_type("application/json".into())
                .with_delivery_mode(2),
        )
        .await?;

        Ok(())
    }

    /// # DM Call Update
    /// Used to send an update about a DM call, eg. start or end of a call.
    /// Recipients can be used to narrow the scope of recipients, otherwise all recipients will be notified.
    /// `ended` refers to the ringing period, not necessarily the call itself.
    pub async fn dm_call_updated(
        &self,
        initiator_id: &str,
        channel_id: &str,
        started_at: Option<&str>,
        ended: bool,
        recipients: Option<Vec<String>>,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;

        let payload = InternalDmCallPayload {
            payload: DmCallPayload {
                initiator_id: initiator_id.to_string(),
                channel_id: channel_id.to_string(),
                started_at: started_at.map(|f| f.to_string()),
                ended,
            },
            recipients,
        };
        let payload = to_string(&payload).unwrap();

        debug!(
            "Sending dm call update payload on channel {}: {}",
            config.pushd.get_dm_call_routing_key(),
            payload
        );

        self.publish(
            |channels| &channels.dm_call_updated,
            &config.pushd.exchange,
            &config.pushd.get_dm_call_routing_key(),
            payload.as_bytes(),
            AMQPProperties::default()
                .with_content_type("application/json".into())
                .with_delivery_mode(2),
        )
        .await?;

        Ok(())
    }

    /// # Send an ack to crond for processing
    pub async fn process_ack(
        &self,
        user_id: &str,
        channel_id: Option<&str>,
        server_id: Option<&str>,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;

        let payload = AckEventPayload {
            user_id: user_id.to_string(),
            channel_id: channel_id.map(|value| value.to_string()),
            server_id: server_id.map(|value| value.to_string()),
        };
        let payload = to_string(&payload).unwrap();

        info!(
            "Sending ack processor event on exchange {}, channel {}: {}",
            config.rabbit.default_exchange, config.rabbit.queues.acks, payload
        );

        self.publish(
            |channels| &channels.process_ack,
            &config.rabbit.default_exchange,
            &config.rabbit.queues.acks,
            payload.as_bytes(),
            AMQPProperties::default()
                .with_content_type("application/json".into())
                .with_delivery_mode(2),
        )
        .await?;

        Ok(())
    }

    pub async fn publish_event(&self, channel: String, event: &EventV1) -> Result<(), AMQPError> {
        let mut headers = FieldTable::default();
        headers.insert("c".into(), AMQPValue::LongString(channel.into()));

        let config = config().await;

        self.publish(
            |channels| &channels.publish_event,
            &config.rabbit.default_exchange,
            &config.rabbit.queues.events,
            &erltf_serde::to_bytes(event).unwrap(),
            BasicProperties::default().with_headers(headers),
        )
        .await?;

        Ok(())
    }

    pub async fn publish_event_broadcast(
        &self,
        channels: Vec<String>,
        event: &EventV1,
    ) -> Result<(), AMQPError> {
        let mut headers = FieldTable::default();
        headers.insert(
            "c".into(),
            AMQPValue::FieldArray(
                channels
                    .into_iter()
                    .map(|c| AMQPValue::LongString(c.into()))
                    .collect::<Vec<_>>()
                    .into(),
            ),
        );

        let config = config().await;

        self.publish(
            |channels| &channels.publish_event,
            &config.rabbit.default_exchange,
            &config.rabbit.queues.events,
            &erltf_serde::to_bytes(event).unwrap(),
            BasicProperties::default().with_headers(headers),
        )
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use lapin::{ExchangeKind, options::ExchangeDeclareOptions, types::FieldTable};

    use super::{AMQP, Backoff};

    #[test]
    fn backoff_grows_and_resets() {
        let now = Instant::now();
        let mut backoff = Backoff::default();
        assert!(backoff.ready(now));

        backoff.failed(now);
        assert!(!backoff.ready(now));
        assert!(backoff.ready(now + Backoff::MIN));

        for _ in 0..40 {
            backoff.failed(now);
        }
        assert!(!backoff.ready(now + Backoff::MAX - Duration::from_millis(1)));
        assert!(backoff.ready(now + Backoff::MAX));

        backoff.succeeded();
        assert!(backoff.ready(now));
    }

    /// A dead connection is replaced on the next publish (B1)
    #[tokio::test]
    async fn publish_reconnects_after_connection_loss() {
        let config = revolt_config::config().await;
        let amqp = AMQP::new_auto().await;
        // closed explicitly below: a dropped lapin channel closes in the background, and a
        // connection close racing it fails with InvalidChannelState(Closing, "channel.close")
        let declare = amqp.connection().create_channel().await.unwrap();
        declare
            .exchange_declare(
                config.rabbit.default_exchange.clone().into(),
                ExchangeKind::Topic,
                ExchangeDeclareOptions {
                    durable: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await
            .unwrap();
        declare.close(200, "declared".into()).await.unwrap();

        amqp.process_ack("user", Some("channel"), None)
            .await
            .unwrap();
        assert_eq!(amqp.current().generation, 0);

        // What a broker restart leaves behind: every channel is closed
        amqp.connection()
            .close(320, "broker restart".into())
            .await
            .unwrap();

        amqp.process_ack("user", Some("channel"), None)
            .await
            .expect("publish after reconnect");
        assert_eq!(amqp.current().generation, 1);
        assert!(amqp.connection().status().connected());

        // Clones share the new connection
        amqp.clone()
            .process_ack("user", Some("channel"), None)
            .await
            .unwrap();
        assert_eq!(amqp.current().generation, 1);
    }
}
