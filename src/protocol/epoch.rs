//! Epoch Event Listener for Silica Protocol
//!
//! Listens for epoch finalization events via WebSocket and triggers
//! reward finalization in TigerBeetle.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use super::types::*;

#[derive(Debug, Clone)]
pub struct EpochConfig {
    pub ws_url: String,
    pub reconnect_delay_secs: u64,
    pub ping_interval_secs: u64,
    pub subscribe_to_events: Vec<String>,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            ws_url: "ws://127.0.0.1:26657/websocket".to_string(),
            reconnect_delay_secs: 5,
            ping_interval_secs: 30,
            subscribe_to_events: vec![
                "epoch_started".to_string(),
                "epoch_finalized".to_string(),
                "rewards_calculated".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochEvent {
    pub event_type: EpochEventType,
    pub epoch: u64,
    pub timestamp: DateTime<Utc>,
    pub details: EpochDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochDetails {
    pub block_height: u64,
    pub proofs_accepted: usize,
    pub total_rewards: u64,
    pub validators: Vec<String>,
    pub slashes: Vec<SlashRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochEventType {
    Started,
    Finalized,
    RewardsCalculated,
}

pub struct EpochListener {
    config: EpochConfig,
    event_sender: broadcast::Sender<EpochEvent>,
    state: Arc<RwLock<ListenerState>>,
    shutdown: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone, Default)]
struct ListenerState {
    connected: bool,
    current_epoch: u64,
    last_event_time: Option<DateTime<Utc>>,
    events_received: u64,
}

impl EpochListener {
    pub fn new(config: EpochConfig) -> Self {
        let (event_sender, _) = broadcast::channel(256);
        
        Self {
            config,
            event_sender,
            state: Arc::new(RwLock::new(ListenerState::default())),
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EpochEvent> {
        self.event_sender.subscribe()
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting epoch listener: {}", self.config.ws_url);

        loop {
            if *self.shutdown.read().await {
                info!("Shutdown signal received, stopping epoch listener");
                break;
            }

            match self.connect_and_listen().await {
                Ok(()) => {
                    info!("WebSocket connection closed normally");
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                }
            }

            let delay = self.config.reconnect_delay_secs;
            info!("Reconnecting in {} seconds...", delay);
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }

        Ok(())
    }

    pub async fn stop(&self) {
        let mut shutdown = self.shutdown.write().await;
        *shutdown = true;
        info!("Epoch listener stop requested");
    }

    async fn connect_and_listen(&self) -> Result<()> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(&self.config.ws_url)
            .await
            .context("Failed to connect to WebSocket")?;

        info!("Connected to epoch WebSocket");
        
        let mut state = self.state.write().await;
        state.connected = true;
        drop(state);

        let (mut write, mut read) = ws_stream.split();

        let subscribe_msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "subscribe",
            "params": {
                "query": "tm.event='Tx' AND action='epoch'"
            },
            "id": 1
        });

        write
            .send(tokio_tungstenite::tungstenite::Message::Text(
                subscribe_msg.to_string().into(),
            ))
            .await
            .context("Failed to send subscription")?;

        while let Some(msg) = read.next().await {
            if *self.shutdown.read().await {
                break;
            }

            match msg {
                Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                    if let Err(e) = self.handle_message(&text).await {
                        error!("Error handling message: {}", e);
                    }
                }
                Ok(tokio_tungstenite::tungstenite::Message::Ping(data)) => {
                    let _ = write
                        .send(tokio_tungstenite::tungstenite::Message::Pong(data))
                        .await;
                }
                Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => {
                    info!("WebSocket close frame received");
                    break;
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }

        let mut state = self.state.write().await;
        state.connected = false;

        Ok(())
    }

    async fn handle_message(&self, text: &str) -> Result<()> {
        debug!("Received WebSocket message: {}", text);

        let response: serde_json::Value = serde_json::from_str(text)
            .context("Failed to parse WebSocket message")?;

        if let Some(result) = response.get("result") {
            if let Some(event) = self.parse_epoch_event(result)? {
                let mut state = self.state.write().await;
                state.current_epoch = event.epoch;
                state.last_event_time = Some(Utc::now());
                state.events_received += 1;
                drop(state);

                info!(
                    "Epoch event: {:?} - epoch {} - {} proofs - {} CHERT",
                    event.event_type,
                    event.epoch,
                    event.details.proofs_accepted,
                    event.details.total_rewards
                );

                let _ = self.event_sender.send(event);
            }
        }

        Ok(())
    }

    fn parse_epoch_event(&self, result: &serde_json::Value) -> Result<Option<EpochEvent>> {
        let events = result
            .get("data")
            .and_then(|d| d.get("value"))
            .and_then(|v| v.get("TxResult"))
            .and_then(|t| t.get("result"))
            .and_then(|r| r.get("events"));

        let events = match events {
            Some(e) => e,
            None => return Ok(None),
        };

        let event_type_str = events
            .get("epoch.event")
            .and_then(|e| e.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let event_type = match event_type_str {
            "started" => EpochEventType::Started,
            "finalized" => EpochEventType::Finalized,
            "rewards_calculated" => EpochEventType::RewardsCalculated,
            _ => return Ok(None),
        };

        let epoch = events
            .get("epoch.number")
            .and_then(|e| e.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let block_height = events
            .get("epoch.height")
            .and_then(|e| e.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let proofs_accepted = events
            .get("epoch.proofs")
            .and_then(|e| e.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let total_rewards = events
            .get("epoch.rewards")
            .and_then(|e| e.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let validators = events
            .get("epoch.validators")
            .and_then(|e| e.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Some(EpochEvent {
            event_type,
            epoch,
            timestamp: Utc::now(),
            details: EpochDetails {
                block_height,
                proofs_accepted,
                total_rewards,
                validators,
                slashes: vec![],
            },
        }))
    }

    pub async fn is_connected(&self) -> bool {
        self.state.read().await.connected
    }

    pub async fn current_epoch(&self) -> u64 {
        self.state.read().await.current_epoch
    }

    pub async fn events_received(&self) -> u64 {
        self.state.read().await.events_received
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = EpochConfig::default();
        assert_eq!(config.reconnect_delay_secs, 5);
        assert!(config.subscribe_to_events.contains(&"epoch_finalized".to_string()));
    }

    #[test]
    fn test_listener_creation() {
        let config = EpochConfig::default();
        let listener = EpochListener::new(config);
        let _receiver = listener.subscribe();
    }
}
