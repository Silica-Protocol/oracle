//! RPC Client for Silica Protocol Communication
//!
//! Handles bidirectional communication between the Oracle and Silica consensus:
//! - Receives NUW tasks from the protocol
//! - Submits proofs back to consensus
//! - Claims rewards for miners

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use super::types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConfig {
    pub rpc_url: String,
    pub ws_url: String,
    pub api_key: String,
    pub timeout_secs: u64,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://127.0.0.1:26657".to_string(),
            ws_url: "ws://127.0.0.1:26657/websocket".to_string(),
            api_key: String::new(),
            timeout_secs: 30,
            max_retries: 3,
            retry_delay_ms: 100,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolClient {
    config: ProtocolConfig,
    http_client: Client,
    state: Arc<RwLock<ClientState>>,
}

#[derive(Debug, Clone, Default)]
struct ClientState {
    connected: bool,
    last_height: u64,
    pending_tasks: usize,
}

impl ProtocolClient {
    pub fn new(config: ProtocolConfig) -> Result<Self> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent("Chert-Oracle/1.0")
            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                if !config.api_key.is_empty() {
                    if let Ok(val) = reqwest::header::HeaderValue::from_str(&config.api_key) {
                        headers.insert("X-Api-Key", val);
                    }
                }
                headers
            })
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            config,
            http_client,
            state: Arc::new(RwLock::new(ClientState::default())),
        })
    }

    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/health", self.config.rpc_url);
        
        match self.http_client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let mut state = self.state.write().await;
                state.connected = true;
                Ok(true)
            }
            Ok(resp) => {
                warn!("Health check failed with status: {}", resp.status());
                Ok(false)
            }
            Err(e) => {
                error!("Health check failed: {}", e);
                Ok(false)
            }
        }
    }

    pub async fn get_status(&self) -> Result<ProtocolStatus> {
        let url = format!("{}/status", self.config.rpc_url);
        
        let resp = self.http_client
            .get(&url)
            .send()
            .await
            .context("Failed to get protocol status")?;

        let status: ProtocolStatus = resp.json().await
            .context("Failed to parse status response")?;

        let mut state = self.state.write().await;
        state.connected = true;
        state.last_height = status.latest_block_height;

        Ok(status)
    }

    pub async fn get_pending_tasks(&self) -> Result<Vec<ProtocolTask>> {
        let url = format!("{}/oracle/v1/tasks/pending", self.config.rpc_url);
        
        let resp = self.retry_get(&url).await?;

        let tasks: TasksResponse = resp.json().await
            .context("Failed to parse tasks response")?;

        let mut state = self.state.write().await;
        state.pending_tasks = tasks.tasks.len();

        Ok(tasks.tasks)
    }

    pub async fn get_task(&self, task_id: &str) -> Result<Option<ProtocolTask>> {
        let url = format!("{}/oracle/v1/task/{}", self.config.rpc_url, task_id);
        
        let resp = self.http_client
            .get(&url)
            .send()
            .await
            .context("Failed to get task")?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let task: ProtocolTask = resp.json().await
            .context("Failed to parse task response")?;

        Ok(Some(task))
    }

    pub async fn submit_proof(&self, proof: &ProofSubmission) -> Result<ProofResponse> {
        let url = format!("{}/oracle/v1/proof", self.config.rpc_url);
        
        info!("Submitting proof for task: {}", proof.task_id);

        let resp = self.retry_post(&url, proof).await?;

        let response: ProofResponse = resp.json().await
            .context("Failed to parse proof response")?;

        if response.success {
            info!("Proof accepted for task {}: tx={:?}", proof.task_id, response.tx_hash);
        } else {
            warn!("Proof rejected for task {}: {:?}", proof.task_id, response.error);
        }

        Ok(response)
    }

    pub async fn claim_rewards(&self, claim: &ClaimRequest) -> Result<ClaimResponse> {
        let url = format!("{}/oracle/v1/claim", self.config.rpc_url);
        
        info!("Processing claim for miner: {}", claim.miner_id);

        let resp = self.http_client
            .post(&url)
            .json(claim)
            .send()
            .await
            .context("Failed to submit claim")?;

        let response: ClaimResponse = resp.json().await
            .context("Failed to parse claim response")?;

        if response.success {
            info!("Claim successful for {}: {} CHERT", claim.miner_id, response.amount);
        } else {
            warn!("Claim failed for {}: {:?}", claim.miner_id, response.error);
        }

        Ok(response)
    }

    pub async fn get_miner_balance(&self, miner_id: &str) -> Result<MinerBalance> {
        let url = format!("{}/oracle/v1/miner/{}/balance", self.config.rpc_url, miner_id);
        
        let resp = self.http_client
            .get(&url)
            .send()
            .await
            .context("Failed to get miner balance")?;

        let balance: MinerBalance = resp.json().await
            .context("Failed to parse balance response")?;

        Ok(balance)
    }

    pub async fn subscribe_tasks(&self) -> Result<()> {
        let url = format!("{}/oracle/v1/tasks/subscribe", self.config.rpc_url);
        
        let resp = self.http_client
            .post(&url)
            .send()
            .await
            .context("Failed to subscribe to tasks")?;

        if resp.status().is_success() {
            info!("Subscribed to task notifications");
        }

        Ok(())
    }

    pub async fn report_slash(&self, slash: &SlashReport) -> Result<SlashResponse> {
        let url = format!("{}/oracle/v1/slash", self.config.rpc_url);
        
        info!("Reporting slash for account: {}", slash.account);

        let resp = self.http_client
            .post(&url)
            .json(slash)
            .send()
            .await
            .context("Failed to report slash")?;

        let response: SlashResponse = resp.json().await
            .context("Failed to parse slash response")?;

        Ok(response)
    }

    async fn retry_get(&self, url: &str) -> Result<reqwest::Response> {
        let mut attempts = 0;
        let max_retries = self.config.max_retries;
        let delay = Duration::from_millis(self.config.retry_delay_ms);

        loop {
            attempts += 1;
            
            match self.http_client.get(url).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(resp),
                Ok(resp) if attempts < max_retries => {
                    debug!("Request failed with status {}, retrying ({}/{})", 
                           resp.status(), attempts, max_retries);
                    tokio::time::sleep(delay).await;
                }
                Ok(resp) => {
                    return Err(anyhow::anyhow!(
                        "Request failed after {} attempts with status: {}",
                        max_retries, resp.status()
                    ));
                }
                Err(e) if attempts < max_retries => {
                    debug!("Request error: {}, retrying ({}/{})", e, attempts, max_retries);
                    tokio::time::sleep(delay).await;
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Request failed after {} attempts: {}",
                        max_retries, e
                    ));
                }
            }
        }
    }

    async fn retry_post<T: Serialize>(&self, url: &str, body: &T) -> Result<reqwest::Response> {
        let mut attempts = 0;
        let max_retries = self.config.max_retries;
        let delay = Duration::from_millis(self.config.retry_delay_ms);

        loop {
            attempts += 1;
            
            match self.http_client.post(url).json(body).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(resp),
                Ok(resp) if attempts < max_retries => {
                    debug!("Request failed with status {}, retrying ({}/{})", 
                           resp.status(), attempts, max_retries);
                    tokio::time::sleep(delay).await;
                }
                Ok(resp) => {
                    return Err(anyhow::anyhow!(
                        "Request failed after {} attempts with status: {}",
                        max_retries, resp.status()
                    ));
                }
                Err(e) if attempts < max_retries => {
                    debug!("Request error: {}, retrying ({}/{})", e, attempts, max_retries);
                    tokio::time::sleep(delay).await;
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Request failed after {} attempts: {}",
                        max_retries, e
                    ));
                }
            }
        }
    }

    pub async fn is_connected(&self) -> bool {
        self.state.read().await.connected
    }

    pub async fn get_last_height(&self) -> u64 {
        self.state.read().await.last_height
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStatus {
    pub connected: bool,
    pub latest_block_height: u64,
    pub latest_block_time: DateTime<Utc>,
    pub catching_up: bool,
    pub oracle_registered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TasksResponse {
    tasks: Vec<ProtocolTask>,
    total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResponse {
    pub success: bool,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
    pub rewards_distributed: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerBalance {
    pub miner_id: String,
    pub pending_rewards: u64,
    pub finalized_rewards: u64,
    pub total_claimed: u64,
    pub locked_rewards: u64,
    pub lockup_expires: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashReport {
    pub account: String,
    pub reason: String,
    pub evidence_hash: String,
    pub severity: u8,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashResponse {
    pub success: bool,
    pub slash_id: Option<String>,
    pub amount_slashed: Option<u64>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ProtocolConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_client_creation() {
        let config = ProtocolConfig::default();
        let client = ProtocolClient::new(config);
        assert!(client.is_ok());
    }
}
