//! NUW Miner API endpoints
//!
//! Endpoints for NUW (Network Utility Work) miners:
//!   POST /register -> Register miner
//!   GET /task -> Get assigned task
//!   POST /solution -> Submit solution
//!   GET /balance -> Check balance
//!   GET /rewards -> Check pending rewards

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::pouw::nuw::{
    MinerInfo, MinerTier, NuwOracle, NuwSolution, NuwTask, TaskType,
};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub miner_id: String,
    pub public_key: Vec<u8>,
    pub supported_task_types: Vec<TaskType>,
    pub region: String,
    pub endpoint: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub message: String,
    pub tier: MinerTier,
}

#[derive(Debug, Deserialize)]
pub struct GetTaskQuery {
    pub miner_id: String,
    pub task_type: Option<TaskType>,
}

#[derive(Debug, Serialize)]
pub struct GetTaskResponse {
    pub task: Option<NuwTask>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitSolutionRequest {
    pub miner_id: String,
    pub task_id: String,
    pub result: Vec<u8>,
    pub compute_time_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct SubmitSolutionResponse {
    pub success: bool,
    pub message: String,
    pub solution_hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BalanceResponse {
    pub miner_id: String,
    pub balance: u128,
    pub pending_rewards: u64,
}

#[derive(Debug, Serialize)]
pub struct RewardsResponse {
    pub miner_id: String,
    pub pending: Vec<PendingReward>,
    pub finalized: u64,
    pub claimed: u64,
}

#[derive(Debug, Serialize)]
pub struct PendingReward {
    pub task_id: String,
    pub amount: u64,
    pub locked_until: String,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub queue_depth: usize,
    pub active_tasks: usize,
    pub active_miners: usize,
    pub total_tasks_received: u64,
    pub total_tasks_completed: u64,
    pub total_rewards_finalized: u64,
    pub tigerbeetle_initialized: bool,
}

#[derive(Clone)]
pub struct NuwApiState {
    pub oracle: Arc<RwLock<NuwOracle>>,
}

impl NuwApiState {
    pub fn new(oracle: NuwOracle) -> Self {
        Self {
            oracle: Arc::new(RwLock::new(oracle)),
        }
    }
}

pub fn create_router(state: NuwApiState) -> Router {
    Router::new()
        .route("/register", post(register_miner))
        .route("/task", get(get_task))
        .route("/solution", post(submit_solution))
        .route("/balance", get(get_balance))
        .route("/rewards", get(get_rewards))
        .route("/stats", get(get_stats))
        .with_state(state)
}

async fn register_miner(
    State(state): State<NuwApiState>,
    Json(req): Json<RegisterRequest>,
) -> (StatusCode, Json<RegisterResponse>) {
    info!(miner_id = %req.miner_id, "Miner registration request");

    let miner_info = MinerInfo {
        miner_id: req.miner_id.clone(),
        public_key: req.public_key,
        supported_task_types: req.supported_task_types,
        region: req.region,
        endpoint: req.endpoint,
        reputation_score: 0.0,
        tier: MinerTier::Bronze,
    };

    let mut oracle = state.oracle.write().await;
    oracle.register_miner(miner_info);

    (
        StatusCode::OK,
        Json(RegisterResponse {
            success: true,
            message: "Miner registered successfully".to_string(),
            tier: MinerTier::Bronze,
        }),
    )
}

async fn get_task(
    State(state): State<NuwApiState>,
    Query(_query): Query<GetTaskQuery>,
) -> (StatusCode, Json<GetTaskResponse>) {
    let _oracle = state.oracle.read().await;

    // TODO: Get task from distributor based on miner_id and task_type
    // For now, return empty - this will be connected to the quad-send system

    (
        StatusCode::OK,
        Json(GetTaskResponse {
            task: None,
            message: Some("Task fetching not yet connected to quad-send".to_string()),
        }),
    )
}

async fn submit_solution(
    State(state): State<NuwApiState>,
    Json(req): Json<SubmitSolutionRequest>,
) -> (StatusCode, Json<SubmitSolutionResponse>) {
    info!(
        miner_id = %req.miner_id,
        task_id = %req.task_id,
        "Solution submission"
    );

    let _solution = NuwSolution {
        task_id: req.task_id.clone(),
        miner_id: req.miner_id.clone(),
        miner_index: 0,
        result: req.result,
        computed_at: chrono::Utc::now(),
        compute_time_ms: req.compute_time_ms,
    };

    let _oracle = state.oracle.write().await;
    
    // TODO: Connect to distributor for consensus evaluation
    // oracle.submit_solution(solution).await

    (
        StatusCode::OK,
        Json(SubmitSolutionResponse {
            success: true,
            message: "Solution submitted".to_string(),
            solution_hash: Some(format!("{:x}", md5::compute(&req.task_id))),
        }),
    )
}

async fn get_balance(
    State(state): State<NuwApiState>,
    Query(query): Query<GetTaskQuery>,
) -> (StatusCode, Json<BalanceResponse>) {
    let oracle = state.oracle.read().await;

    let balance = oracle.get_miner_balance(&query.miner_id).await.unwrap_or(0);
    let pending = oracle.get_pending_rewards(&query.miner_id).await;
    let pending_sum: u64 = pending.iter().map(|r| r.amount).sum();

    (
        StatusCode::OK,
        Json(BalanceResponse {
            miner_id: query.miner_id,
            balance,
            pending_rewards: pending_sum,
        }),
    )
}

async fn get_rewards(
    State(state): State<NuwApiState>,
    Query(query): Query<GetTaskQuery>,
) -> (StatusCode, Json<RewardsResponse>) {
    let oracle = state.oracle.read().await;

    let pending = oracle.get_pending_rewards(&query.miner_id).await;
    
    let pending_rewards: Vec<PendingReward> = pending
        .iter()
        .map(|r| PendingReward {
            task_id: r.task_id.clone(),
            amount: r.amount,
            locked_until: r.locked_until.to_rfc3339(),
        })
        .collect();

    let finalized: u64 = pending.iter().filter(|r| r.finalized).map(|r| r.amount).sum();
    let claimed: u64 = pending.iter().filter(|r| r.claimed).map(|r| r.amount).sum();

    (
        StatusCode::OK,
        Json(RewardsResponse {
            miner_id: query.miner_id,
            pending: pending_rewards,
            finalized,
            claimed,
        }),
    )
}

async fn get_stats(
    State(state): State<NuwApiState>,
) -> (StatusCode, Json<StatsResponse>) {
    let oracle = state.oracle.read().await;

    let stats = oracle.stats.read().await;

    (
        StatusCode::OK,
        Json(StatsResponse {
            queue_depth: oracle.get_queue_depth(),
            active_tasks: oracle.get_active_tasks(),
            active_miners: stats.active_miners,
            total_tasks_received: stats.total_tasks_received,
            total_tasks_completed: stats.total_tasks_completed,
            total_rewards_finalized: stats.total_rewards_finalized,
            tigerbeetle_initialized: oracle.is_tigerbeetle_initialized(),
        }),
    )
}
