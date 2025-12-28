//! Oracle API endpoints for work verification and proof generation
//!
//! Endpoints:
//!   POST /verify          -> Verify work unit
//!   POST /verify/batch    -> Verify multiple work units
//!   POST /proof/generate  -> Generate PoUW proof for verified work
//!   GET  /proof/:id       -> Get proof by work ID
//!   POST /challenge/create -> Create a new challenge
//!   POST /challenge/assign -> Assign challenge to worker
//!   POST /challenge/submit -> Submit challenge result
//!   GET  /challenge/:id    -> Get challenge status
//!   GET  /stats           -> Oracle statistics
//!   GET  /stats/user/:addr -> User statistics
//!   GET  /projects        -> List known projects
//!   GET  /health          -> Oracle health check

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::pouw::aggregator::PoUWAggregator;
use crate::pouw::boinc::ProjectManager;
use crate::pouw::challenge::{PouwChallenge, PouwResult};
use crate::pouw::models::{BoincWork, PoUWProof};
use crate::pouw::oracle::{PoUWOracle, ProviderProjectConfig, VerificationResult};

// ============================================================================
// State
// ============================================================================

/// Oracle API state
#[derive(Clone)]
pub struct OracleApiState {
    pub oracle: Arc<RwLock<PoUWOracle>>,
    pub aggregator: Arc<RwLock<PoUWAggregator>>,
    pub project_manager: Arc<RwLock<ProjectManager>>,
}

impl OracleApiState {
    pub fn new(
        oracle: Arc<RwLock<PoUWOracle>>,
        aggregator: Arc<RwLock<PoUWAggregator>>,
        project_manager: Arc<RwLock<ProjectManager>>,
    ) -> Self {
        Self {
            oracle,
            aggregator,
            project_manager,
        }
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Work verification request
#[derive(Debug, Deserialize)]
pub struct VerifyWorkRequest {
    pub work: BoincWork,
    /// Optional Chert address to associate with this work
    pub chert_address: Option<String>,
}

/// Work verification response
#[derive(Debug, Serialize)]
pub struct VerifyWorkResponse {
    pub is_valid: bool,
    pub work_id: String,
    pub checks_passed: Vec<String>,
    pub checks_failed: Vec<String>,
    pub confidence_score: f64,
    pub reward_eligible: bool,
    pub message: String,
}

impl From<VerificationResult> for VerifyWorkResponse {
    fn from(result: VerificationResult) -> Self {
        let message = if result.is_valid {
            "Work verification successful".to_string()
        } else {
            format!("Verification failed: {}", result.checks_failed.join(", "))
        };

        Self {
            is_valid: result.is_valid,
            work_id: result.work_id,
            checks_passed: result.checks_passed,
            checks_failed: result.checks_failed,
            confidence_score: result.confidence_score,
            reward_eligible: result.reward_eligible,
            message,
        }
    }
}

/// Batch verification request
#[derive(Debug, Deserialize)]
pub struct BatchVerifyRequest {
    pub works: Vec<BoincWork>,
    pub chert_address: Option<String>,
}

/// Batch verification response
#[derive(Debug, Serialize)]
pub struct BatchVerifyResponse {
    pub results: Vec<VerifyWorkResponse>,
    pub total_valid: usize,
    pub total_invalid: usize,
}

/// Proof generation request
#[derive(Debug, Deserialize)]
pub struct GenerateProofRequest {
    pub work: BoincWork,
    pub contributor_address: String,
}

/// Proof generation response
#[derive(Debug, Serialize)]
pub struct GenerateProofResponse {
    pub success: bool,
    pub proof: Option<ProofSummary>,
    pub error: Option<String>,
}

/// Proof summary for API responses
#[derive(Debug, Serialize)]
pub struct ProofSummary {
    pub work_hash: String,
    pub contributor_address: String,
    pub task_id: String,
    pub project_name: String,
    pub proof_timestamp: String,
    pub difficulty_score: f64,
    pub reward_points: u64,
}

impl From<PoUWProof> for ProofSummary {
    fn from(proof: PoUWProof) -> Self {
        Self {
            work_hash: proof.work_hash,
            contributor_address: proof.contributor_address,
            task_id: proof.boinc_work.task_id,
            project_name: proof.boinc_work.project_name,
            proof_timestamp: proof.proof_timestamp.to_rfc3339(),
            difficulty_score: proof.difficulty_score,
            reward_points: proof.reward_points,
        }
    }
}

/// Challenge creation request
#[derive(Debug, Deserialize)]
pub struct CreateChallengeRequest {
    pub work: BoincWork,
    pub reward_multiplier: u32,
}

/// Challenge creation response
#[derive(Debug, Serialize)]
pub struct CreateChallengeResponse {
    pub success: bool,
    pub challenge: Option<ChallengeSummary>,
    pub error: Option<String>,
}

/// Challenge summary for API responses
#[derive(Debug, Serialize)]
pub struct ChallengeSummary {
    pub challenge_id: String,
    pub task_name: String,
    pub project_url: String,
    pub reward_multiplier: u32,
    pub deadline: u64,
    pub oracle_address: String,
}

impl From<PouwChallenge> for ChallengeSummary {
    fn from(challenge: PouwChallenge) -> Self {
        Self {
            challenge_id: challenge.challenge_id,
            task_name: challenge.boinc_task_name,
            project_url: challenge.boinc_project_url,
            reward_multiplier: challenge.reward_multiplier,
            deadline: challenge.deadline,
            oracle_address: challenge.oracle_address,
        }
    }
}

/// Challenge assignment request
#[derive(Debug, Deserialize)]
pub struct AssignChallengeRequest {
    pub challenge_id: String,
    pub worker_address: String,
}

/// Challenge assignment response
#[derive(Debug, Serialize)]
pub struct AssignChallengeResponse {
    pub success: bool,
    pub message: String,
}

/// Challenge submission request
#[derive(Debug, Deserialize)]
pub struct SubmitChallengeRequest {
    pub result: PouwResult,
}

/// Challenge submission response
#[derive(Debug, Serialize)]
pub struct SubmitChallengeResponse {
    pub success: bool,
    pub verification: Option<VerifyWorkResponse>,
    pub error: Option<String>,
}

/// Challenge status response
#[derive(Debug, Serialize)]
pub struct ChallengeStatusResponse {
    pub found: bool,
    pub challenge_id: String,
    pub status: Option<String>,
    pub assigned_to: Option<String>,
    pub expires_at: Option<String>,
}

/// Oracle statistics response
#[derive(Debug, Serialize)]
pub struct OracleStatsResponse {
    pub verified_work_count: usize,
    pub active_challenges: usize,
    pub total_users: usize,
    pub known_projects: usize,
    pub uptime_seconds: u64,
}

/// User statistics query
#[derive(Debug, Deserialize)]
pub struct UserStatsQuery {
    pub address: String,
}

/// User statistics response
#[derive(Debug, Serialize)]
pub struct UserStatsResponse {
    pub address: String,
    pub challenges_today: usize,
    pub completed_challenges: usize,
    pub failed_challenges: usize,
    pub last_activity: Option<String>,
}

/// Project list response
#[derive(Debug, Serialize)]
pub struct ProjectListResponse {
    pub projects: Vec<ProjectSummary>,
    pub total: usize,
}

/// Project summary
#[derive(Debug, Serialize)]
pub struct ProjectSummary {
    pub name: String,
    pub api_endpoint: String,
    pub credit_multiplier: f64,
    pub min_cpu_time: f64,
    pub enabled: bool,
}

impl From<&ProviderProjectConfig> for ProjectSummary {
    fn from(config: &ProviderProjectConfig) -> Self {
        Self {
            name: config.name.clone(),
            api_endpoint: config.api_endpoint.clone(),
            credit_multiplier: config.credit_multiplier,
            min_cpu_time: config.min_cpu_time,
            enabled: config.enabled,
        }
    }
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct OracleHealthResponse {
    pub status: String,
    pub oracle_ready: bool,
    pub aggregator_ready: bool,
    pub project_manager_ready: bool,
    pub timestamp: String,
}

// ============================================================================
// API Handlers
// ============================================================================

/// Verify a single work unit
pub async fn verify_work(
    State(state): State<OracleApiState>,
    Json(request): Json<VerifyWorkRequest>,
) -> Result<Json<VerifyWorkResponse>, StatusCode> {
    info!("Verifying work: {}", request.work.task_id);

    let oracle = state.oracle.read().await;

    match oracle.verify_work(&request.work).await {
        Ok(result) => {
            // If valid and chert_address provided, cache the work
            if result.is_valid {
                if let Some(addr) = &request.chert_address {
                    let aggregator = state.aggregator.read().await;
                    if let Err(e) = aggregator
                        .add_work_to_cache(addr, vec![request.work.clone()])
                        .await
                    {
                        warn!("Failed to cache verified work: {}", e);
                    }
                }
            }

            Ok(Json(result.into()))
        }
        Err(e) => {
            error!("Work verification error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Verify multiple work units in batch
pub async fn verify_work_batch(
    State(state): State<OracleApiState>,
    Json(request): Json<BatchVerifyRequest>,
) -> Result<Json<BatchVerifyResponse>, StatusCode> {
    info!("Batch verifying {} work units", request.works.len());

    let oracle = state.oracle.read().await;

    match oracle.verify_work_batch(&request.works).await {
        Ok(results) => {
            let total_valid = results.iter().filter(|r| r.is_valid).count();
            let total_invalid = results.len() - total_valid;

            let response_results: Vec<VerifyWorkResponse> =
                results.into_iter().map(|r| r.into()).collect();

            Ok(Json(BatchVerifyResponse {
                results: response_results,
                total_valid,
                total_invalid,
            }))
        }
        Err(e) => {
            error!("Batch verification error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Generate a PoUW proof for verified work
pub async fn generate_proof(
    State(state): State<OracleApiState>,
    Json(request): Json<GenerateProofRequest>,
) -> Result<Json<GenerateProofResponse>, StatusCode> {
    info!(
        "Generating proof for work: {} (contributor: {})",
        request.work.task_id, request.contributor_address
    );

    let oracle = state.oracle.read().await;

    match oracle
        .generate_proof(&request.work, &request.contributor_address)
        .await
    {
        Ok(proof) => Ok(Json(GenerateProofResponse {
            success: true,
            proof: Some(proof.into()),
            error: None,
        })),
        Err(e) => {
            warn!("Proof generation failed: {}", e);
            Ok(Json(GenerateProofResponse {
                success: false,
                proof: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

/// Get proof by work ID (from cache)
pub async fn get_proof(
    State(_state): State<OracleApiState>,
    Path(work_id): Path<String>,
) -> Result<Json<GenerateProofResponse>, StatusCode> {
    // For now, proofs are generated on-demand
    // In a full implementation, this would query a proof database
    warn!("Proof lookup not yet implemented for: {}", work_id);

    Ok(Json(GenerateProofResponse {
        success: false,
        proof: None,
        error: Some("Proof lookup not implemented - use /proof/generate".to_string()),
    }))
}

/// Create a new challenge
pub async fn create_challenge(
    State(state): State<OracleApiState>,
    Json(request): Json<CreateChallengeRequest>,
) -> Result<Json<CreateChallengeResponse>, StatusCode> {
    info!(
        "Creating challenge for task: {} (multiplier: {}x)",
        request.work.task_id, request.reward_multiplier
    );

    let mut oracle = state.oracle.write().await;

    match oracle
        .create_challenge(&request.work, request.reward_multiplier)
        .await
    {
        Ok(challenge) => Ok(Json(CreateChallengeResponse {
            success: true,
            challenge: Some(challenge.into()),
            error: None,
        })),
        Err(e) => {
            warn!("Challenge creation failed: {}", e);
            Ok(Json(CreateChallengeResponse {
                success: false,
                challenge: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

/// Assign a challenge to a worker
pub async fn assign_challenge(
    State(state): State<OracleApiState>,
    Json(request): Json<AssignChallengeRequest>,
) -> Result<Json<AssignChallengeResponse>, StatusCode> {
    info!(
        "Assigning challenge {} to worker {}",
        request.challenge_id, request.worker_address
    );

    let oracle = state.oracle.read().await;

    match oracle
        .assign_challenge(&request.challenge_id, &request.worker_address)
        .await
    {
        Ok(true) => Ok(Json(AssignChallengeResponse {
            success: true,
            message: "Challenge assigned successfully".to_string(),
        })),
        Ok(false) => Ok(Json(AssignChallengeResponse {
            success: false,
            message: "Challenge could not be assigned (may be expired or already assigned)"
                .to_string(),
        })),
        Err(e) => {
            error!("Challenge assignment error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Submit a challenge result
pub async fn submit_challenge(
    State(state): State<OracleApiState>,
    Json(request): Json<SubmitChallengeRequest>,
) -> Result<Json<SubmitChallengeResponse>, StatusCode> {
    info!(
        "Submitting challenge result for: {}",
        request.result.challenge_id
    );

    let oracle = state.oracle.read().await;

    match oracle.submit_challenge_result(&request.result).await {
        Ok(verification) => Ok(Json(SubmitChallengeResponse {
            success: verification.is_valid,
            verification: Some(verification.into()),
            error: None,
        })),
        Err(e) => {
            warn!("Challenge submission failed: {}", e);
            Ok(Json(SubmitChallengeResponse {
                success: false,
                verification: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

/// Get challenge status
pub async fn get_challenge_status(
    State(_state): State<OracleApiState>,
    Path(challenge_id): Path<String>,
) -> Result<Json<ChallengeStatusResponse>, StatusCode> {
    // For now, return not found - challenge lookup requires oracle state access
    // In a full implementation, this would query the active_challenges map
    warn!("Challenge status lookup not yet fully implemented");

    Ok(Json(ChallengeStatusResponse {
        found: false,
        challenge_id,
        status: None,
        assigned_to: None,
        expires_at: None,
    }))
}

/// Get oracle statistics
pub async fn get_oracle_stats(
    State(state): State<OracleApiState>,
) -> Result<Json<OracleStatsResponse>, StatusCode> {
    let oracle = state.oracle.read().await;
    let stats = oracle.get_stats().await;

    Ok(Json(OracleStatsResponse {
        verified_work_count: stats.verified_work_count,
        active_challenges: stats.active_challenges,
        total_users: stats.total_users,
        known_projects: stats.known_projects,
        uptime_seconds: 0, // Would track actual uptime
    }))
}

/// Get user statistics
pub async fn get_user_stats(
    State(state): State<OracleApiState>,
    Path(address): Path<String>,
) -> Result<Json<UserStatsResponse>, StatusCode> {
    let oracle = state.oracle.read().await;

    match oracle.get_user_stats(&address).await {
        Some(stats) => Ok(Json(UserStatsResponse {
            address,
            challenges_today: stats.challenges_today,
            completed_challenges: stats.completed_challenges,
            failed_challenges: stats.failed_challenges,
            last_activity: stats.last_challenge_time.map(|t| t.to_rfc3339()),
        })),
        None => Ok(Json(UserStatsResponse {
            address,
            challenges_today: 0,
            completed_challenges: 0,
            failed_challenges: 0,
            last_activity: None,
        })),
    }
}

/// List known projects
pub async fn list_projects(
    State(state): State<OracleApiState>,
) -> Result<Json<ProjectListResponse>, StatusCode> {
    let oracle = state.oracle.read().await;
    let projects = oracle.get_known_projects();

    let summaries: Vec<ProjectSummary> = projects.values().map(|p| p.into()).collect();
    let total = summaries.len();

    Ok(Json(ProjectListResponse {
        projects: summaries,
        total,
    }))
}

/// Oracle health check
pub async fn oracle_health(
    State(state): State<OracleApiState>,
) -> Result<Json<OracleHealthResponse>, StatusCode> {
    // Check all components are accessible
    let oracle_ready = state.oracle.try_read().is_ok();
    let aggregator_ready = state.aggregator.try_read().is_ok();
    let project_manager_ready = state.project_manager.try_read().is_ok();

    let all_ready = oracle_ready && aggregator_ready && project_manager_ready;

    Ok(Json(OracleHealthResponse {
        status: if all_ready { "healthy" } else { "degraded" }.to_string(),
        oracle_ready,
        aggregator_ready,
        project_manager_ready,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

// ============================================================================
// Router
// ============================================================================

/// Create the Oracle API router
pub fn create_router(state: OracleApiState) -> Router {
    Router::new()
        // Work verification
        .route("/verify", post(verify_work))
        .route("/verify/batch", post(verify_work_batch))
        // Proof generation
        .route("/proof/generate", post(generate_proof))
        .route("/proof/{work_id}", get(get_proof))
        // Challenge management
        .route("/challenge/create", post(create_challenge))
        .route("/challenge/assign", post(assign_challenge))
        .route("/challenge/submit", post(submit_challenge))
        .route("/challenge/{challenge_id}", get(get_challenge_status))
        // Statistics
        .route("/stats", get(get_oracle_stats))
        .route("/stats/user/{address}", get(get_user_stats))
        // Projects
        .route("/projects", get(list_projects))
        // Health
        .route("/health", get(oracle_health))
        .with_state(state)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_response_from_result() {
        let result = VerificationResult {
            is_valid: true,
            work_id: "test_123".to_string(),
            verification_time: chrono::Utc::now(),
            checks_passed: vec!["check1".to_string(), "check2".to_string()],
            checks_failed: vec![],
            confidence_score: 0.95,
            reward_eligible: true,
        };

        let response: VerifyWorkResponse = result.into();

        assert!(response.is_valid);
        assert_eq!(response.work_id, "test_123");
        assert_eq!(response.checks_passed.len(), 2);
        assert!(response.checks_failed.is_empty());
        assert!(response.message.contains("successful"));
    }

    #[test]
    fn test_verification_response_failure() {
        let result = VerificationResult {
            is_valid: false,
            work_id: "test_456".to_string(),
            verification_time: chrono::Utc::now(),
            checks_passed: vec![],
            checks_failed: vec!["cpu_time_low".to_string()],
            confidence_score: 0.0,
            reward_eligible: false,
        };

        let response: VerifyWorkResponse = result.into();

        assert!(!response.is_valid);
        assert!(response.message.contains("cpu_time_low"));
    }
}
