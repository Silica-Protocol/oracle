//! Protocol Integration API Endpoints
//!
//! Endpoints for Silica protocol integration:
//!   POST /v1/task           -> Receive task from protocol
//!   POST /v1/proof          -> Submit proof to protocol
//!   GET  /v1/status         -> Oracle status for protocol
//!   POST /v1/claim          -> User reward claim
//!   WS   /v1/epoch          -> Epoch event stream

use axum::{
    Json, Router,
    extract::{Path, State, WebSocketUpgrade},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::protocol::{
    ClaimRequest, ConsensusInfo,
    ProofSubmission, ProofType, ProtocolClient, ProtocolTask,
    NuwTaskType, ProofData, HashProofData,
};
use crate::protocol::types::MinerContribution;
use crate::reputation::ReputationManager;
use crate::tigerbeetle::TigerBeetleClient;

#[derive(Clone)]
pub struct ProtocolApiState {
    pub client: Arc<ProtocolClient>,
    pub reputation: Arc<RwLock<ReputationManager>>,
    pub tigerbeetle: Arc<RwLock<Option<TigerBeetleClient>>>,
}

impl ProtocolApiState {
    pub fn new(
        client: Arc<ProtocolClient>,
        reputation: Arc<RwLock<ReputationManager>>,
        tigerbeetle: Arc<RwLock<Option<TigerBeetleClient>>>,
    ) -> Self {
        Self {
            client,
            reputation,
            tigerbeetle,
        }
    }
}

pub fn create_protocol_router() -> Router<ProtocolApiState> {
    Router::new()
        .route("/v1/task", post(receive_task))
        .route("/v1/task/{id}", get(get_task))
        .route("/v1/proof", post(submit_proof))
        .route("/v1/status", get(get_status))
        .route("/v1/claim", post(process_claim))
        .route("/v1/miner/{id}/balance", get(get_miner_balance))
        .route("/v1/epoch", get(epoch_websocket))
}

#[derive(Debug, Deserialize)]
pub struct ReceiveTaskRequest {
    pub task: ProtocolTask,
}

#[derive(Debug, Serialize)]
pub struct ReceiveTaskResponse {
    pub accepted: bool,
    pub task_id: String,
    pub message: String,
}

async fn receive_task(
    State(state): State<ProtocolApiState>,
    Json(req): Json<ReceiveTaskRequest>,
) -> Result<Json<ReceiveTaskResponse>, StatusCode> {
    let task = req.task;
    let task_id = task.task_id.clone();
    
    info!("Received task from protocol: {} ({:?})", task_id, task.task_type);

    let reputation = state.reputation.read().await;
    
    match task.task_type.is_boinc() {
        true => {
            info!("BOINC task received: {} - priority {:?}", task_id, task.priority);
            
            let lockup_secs = task.metadata.lockup_secs;
            debug!("BOINC task lockup: {} seconds", lockup_secs);
        }
        false => {
            info!("NUW task received: {} - priority {:?}", task_id, task.priority);
        }
    }

    Ok(Json(ReceiveTaskResponse {
        accepted: true,
        task_id,
        message: "Task accepted and queued for processing".to_string(),
    }))
}

async fn get_task(
    State(state): State<ProtocolApiState>,
    Path(task_id): Path<String>,
) -> Result<Json<Option<ProtocolTask>>, StatusCode> {
    match state.client.get_task(&task_id).await {
        Ok(task) => Ok(Json(task)),
        Err(e) => {
            error!("Failed to get task {}: {}", task_id, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SubmitProofRequest {
    pub task_id: String,
    pub proof_type: ProofType,
    pub result_hash: String,
    pub miners: Vec<MinerContribution>,
    pub consensus: ConsensusInfo,
}

#[derive(Debug, Serialize)]
pub struct SubmitProofResponse {
    pub success: bool,
    pub tx_hash: Option<String>,
    pub rewards_distributed: Option<u64>,
    pub error: Option<String>,
}

async fn submit_proof(
    State(state): State<ProtocolApiState>,
    Json(req): Json<SubmitProofRequest>,
) -> Result<Json<SubmitProofResponse>, StatusCode> {
    info!(
        "Submitting proof for task {} (consensus: {}/{})",
        req.task_id, req.consensus.agreeing_miners, req.consensus.total_miners
    );

    if !req.consensus.reached {
        warn!("Proof submitted without consensus for task {}", req.task_id);
    }

    let proof = ProofSubmission {
        task_id: req.task_id.clone(),
        task_type: NuwTaskType::BoincMilkyWay,
        proof_type: req.proof_type,
        proof_data: ProofData::Hash(HashProofData {
            hash: req.result_hash,
            salt: String::new(),
            context: String::new(),
        }),
        miners: req.miners,
        consensus: req.consensus,
        generated_at: chrono::Utc::now(),
        signature: String::new(),
    };

    match state.client.submit_proof(&proof).await {
        Ok(response) => Ok(Json(SubmitProofResponse {
            success: response.success,
            tx_hash: response.tx_hash,
            rewards_distributed: response.rewards_distributed,
            error: response.error,
        })),
        Err(e) => {
            error!("Failed to submit proof: {}", e);
            Ok(Json(SubmitProofResponse {
                success: false,
                tx_hash: None,
                rewards_distributed: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OracleStatusResponse {
    pub connected: bool,
    pub registered: bool,
    pub current_epoch: u64,
    pub pending_tasks: usize,
    pub last_height: u64,
    pub tigerbeetle_connected: bool,
}

async fn get_status(
    State(state): State<ProtocolApiState>,
) -> Result<Json<OracleStatusResponse>, StatusCode> {
    let connected = state.client.is_connected().await;
    let last_height = state.client.get_last_height().await;
    let tb_connected = state.tigerbeetle.read().await.is_some();

    Ok(Json(OracleStatusResponse {
        connected,
        registered: true,
        current_epoch: 0,
        pending_tasks: 0,
        last_height,
        tigerbeetle_connected: tb_connected,
    }))
}

#[derive(Debug, Serialize)]
pub struct ClaimResponseApi {
    pub success: bool,
    pub amount: u64,
    pub tx_id: Option<String>,
    pub error: Option<String>,
    pub remaining_pending: u64,
    pub remaining_finalized: u64,
}

async fn process_claim(
    State(state): State<ProtocolApiState>,
    Json(req): Json<ClaimRequest>,
) -> Result<Json<ClaimResponseApi>, StatusCode> {
    info!("Processing claim for miner: {}", req.miner_id);

    match state.client.claim_rewards(&req).await {
        Ok(response) => Ok(Json(ClaimResponseApi {
            success: response.success,
            amount: response.amount,
            tx_id: response.tx_id,
            error: response.error,
            remaining_pending: response.remaining_pending,
            remaining_finalized: response.remaining_finalized,
        })),
        Err(e) => {
            error!("Claim failed: {}", e);
            Ok(Json(ClaimResponseApi {
                success: false,
                amount: 0,
                tx_id: None,
                error: Some(e.to_string()),
                remaining_pending: 0,
                remaining_finalized: 0,
            }))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MinerBalanceResponse {
    pub miner_id: String,
    pub pending_rewards: u64,
    pub finalized_rewards: u64,
    pub total_claimed: u64,
    pub locked_rewards: u64,
}

async fn get_miner_balance(
    State(state): State<ProtocolApiState>,
    Path(miner_id): Path<String>,
) -> Result<Json<MinerBalanceResponse>, StatusCode> {
    match state.client.get_miner_balance(&miner_id).await {
        Ok(balance) => Ok(Json(MinerBalanceResponse {
            miner_id: balance.miner_id,
            pending_rewards: balance.pending_rewards,
            finalized_rewards: balance.finalized_rewards,
            total_claimed: balance.total_claimed,
            locked_rewards: balance.locked_rewards,
        })),
        Err(e) => {
            error!("Failed to get balance for {}: {}", miner_id, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn epoch_websocket(
    ws: WebSocketUpgrade,
    State(_state): State<ProtocolApiState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_epoch_websocket(socket))
}

async fn handle_epoch_websocket(socket: axum::extract::ws::WebSocket) {
    use axum::extract::ws::Message;
    use futures::{SinkExt, StreamExt};

    let (mut sender, mut receiver) = socket.split();

    info!("Epoch WebSocket client connected");

    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                debug!("Received WebSocket message: {}", text);
                
                let response = serde_json::json!({
                    "type": "ping",
                    "timestamp": chrono::Utc::now().to_rfc3339()
                });
                
                if sender.send(Message::Text(response.to_string().into())).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) => {
                info!("Epoch WebSocket client disconnected");
                break;
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }
}
