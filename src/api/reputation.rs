//! Reputation API Endpoints
//!
//! Provides monitoring and governance endpoints for the reputation system.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
    Router,
    routing::{get, put, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::reputation::{
    EligibilityStatus, ProjectMetrics, ReputationManager, ReputationScore,
    ReputationThresholds, SlashEvent, SlashReason,
};
use crate::pouw::boinc::result_tracker::{
    ResultTracker, ResultRecord, ResultStatus, SuspiciousActivity, AdminDecision,
};

/// API state for reputation endpoints
#[derive(Clone)]
pub struct ReputationApiState {
    pub reputation_manager: Arc<RwLock<ReputationManager>>,
    pub result_tracker: Arc<RwLock<ResultTracker>>,
    pub admin_api_key: Option<String>,
}

// Response types

#[derive(Debug, Serialize)]
pub struct ReputationResponse {
    pub user_id: String,
    pub effective_score: i32,
    pub eligibility: EligibilityStatus,
    pub successful_submissions: u64,
    pub total_credits_earned: f64,
    pub project_metrics: Vec<ProjectMetrics>,
    pub pending_slashes: u32,
}

#[derive(Debug, Serialize)]
pub struct SlashHistoryResponse {
    pub user_id: String,
    pub total_slashes: usize,
    pub total_points_deducted: i32,
    pub active_slashes: usize,
    pub events: Vec<SlashEventSummary>,
}

#[derive(Debug, Serialize)]
pub struct SlashEventSummary {
    pub id: String,
    pub reason: SlashReason,
    pub points_deducted: i32,
    pub slashed_at: String,
    pub is_decayed: bool,
    pub task_id: Option<String>,
    pub project_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ThresholdsResponse {
    pub good_behavior_reward: u32,
    pub restricted_threshold: i32,
    pub temp_ban_threshold: i32,
    pub temp_ban_days: u32,
    pub perm_ban_threshold: i32,
    pub slash_decay_days: u32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateThresholdsRequest {
    pub good_behavior_reward: Option<u32>,
    pub restricted_threshold: Option<i32>,
    pub temp_ban_threshold: Option<i32>,
    pub temp_ban_days: Option<u32>,
    pub perm_ban_threshold: Option<i32>,
    pub slash_decay_days: Option<u32>,
    pub admin_api_key: String,
}

#[derive(Debug, Serialize)]
pub struct PendingReviewsResponse {
    pub total: usize,
    pub activities: Vec<SuspiciousActivitySummary>,
}

#[derive(Debug, Serialize)]
pub struct SuspiciousActivitySummary {
    pub id: String,
    pub activity_type: String,
    pub users_involved: Vec<String>,
    pub tasks_involved: Vec<String>,
    pub detected_at: String,
    pub reviewed: bool,
    pub decision: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveActivityRequest {
    pub decision: AdminDecision,
    pub admin_api_key: String,
}

#[derive(Debug, Serialize)]
pub struct ResultsResponse {
    pub user_id: String,
    pub total_results: usize,
    pub pending: usize,
    pub validated: usize,
    pub rejected: usize,
    pub results: Vec<ResultSummary>,
}

#[derive(Debug, Serialize)]
pub struct ResultSummary {
    pub obfuscated_id: String,
    pub wu_name: String,
    pub status: String,
    pub submitted_at: String,
    pub credits_granted: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_users: usize,
    pub total_results_tracked: usize,
    pub pending_validations: usize,
    pub pending_reviews: usize,
}

// Endpoints

/// GET /reputation/:user_id - Get user's reputation
pub async fn get_reputation(
    State(state): State<ReputationApiState>,
    Path(user_id): Path<String>,
) -> Result<Json<ReputationResponse>, (StatusCode, String)> {
    let rep_manager = state.reputation_manager.read().await;
    
    let score = rep_manager.get_score(&user_id).await;
    let effective_score = rep_manager.get_effective_score(&user_id).await;
    let eligibility = rep_manager.check_eligibility(&user_id).await;
    let slash_history = rep_manager.get_slash_history(&user_id).await;
    
    let pending_slashes = slash_history
        .iter()
        .filter(|e| !e.is_decayed)
        .count() as u32;
    
    let project_metrics: Vec<_> = score.project_metrics.values().cloned().collect();
    
    Ok(Json(ReputationResponse {
        user_id: user_id.clone(),
        effective_score,
        eligibility,
        successful_submissions: score.successful_submissions,
        total_credits_earned: score.total_credits_earned,
        project_metrics,
        pending_slashes,
    }))
}

/// GET /reputation/:user_id/history - Get slash history
pub async fn get_slash_history(
    State(state): State<ReputationApiState>,
    Path(user_id): Path<String>,
) -> Result<Json<SlashHistoryResponse>, (StatusCode, String)> {
    let rep_manager = state.reputation_manager.read().await;
    
    let events = rep_manager.get_slash_history(&user_id).await;
    let total_slashes = events.len();
    let active_slashes = events.iter().filter(|e| !e.is_decayed).count();
    let total_points_deducted = events
        .iter()
        .filter(|e| !e.is_decayed)
        .map(|e| e.points_deducted)
        .sum();
    
    let event_summaries: Vec<SlashEventSummary> = events
        .iter()
        .map(|e| SlashEventSummary {
            id: e.id.clone(),
            reason: e.reason,
            points_deducted: e.points_deducted,
            slashed_at: e.slashed_at.to_rfc3339(),
            is_decayed: e.is_decayed,
            task_id: e.evidence.task_id.clone(),
            project_name: e.evidence.project_name.clone(),
        })
        .collect();
    
    Ok(Json(SlashHistoryResponse {
        user_id,
        total_slashes,
        total_points_deducted,
        active_slashes,
        events: event_summaries,
    }))
}

/// GET /reputation/:user_id/results - Get user's result history
pub async fn get_user_results(
    State(state): State<ReputationApiState>,
    Path(user_id): Path<String>,
) -> Result<Json<ResultsResponse>, (StatusCode, String)> {
    let tracker = state.result_tracker.read().await;
    
    let results = tracker.get_user_results(&user_id);
    let total_results = results.len();
    let pending = results.iter().filter(|r| r.status == ResultStatus::Pending).count();
    let validated = results.iter().filter(|r| r.status == ResultStatus::Validated).count();
    let rejected = results.iter().filter(|r| r.status == ResultStatus::Rejected).count();
    
    let result_summaries: Vec<ResultSummary> = results
        .iter()
        .map(|r| ResultSummary {
            obfuscated_id: r.obfuscated_id.clone(),
            wu_name: r.wu_name.clone(),
            status: format!("{:?}", r.status),
            submitted_at: r.submitted_at.to_rfc3339(),
            credits_granted: r.credits_granted,
        })
        .collect();
    
    Ok(Json(ResultsResponse {
        user_id,
        total_results,
        pending,
        validated,
        rejected,
        results: result_summaries,
    }))
}

/// GET /reputation/thresholds - Get current thresholds
pub async fn get_thresholds(
    State(state): State<ReputationApiState>,
) -> Json<ThresholdsResponse> {
    let rep_manager = state.reputation_manager.read().await;
    let thresholds = rep_manager.get_thresholds();
    
    Json(ThresholdsResponse {
        good_behavior_reward: thresholds.good_behavior_reward,
        restricted_threshold: thresholds.restricted_threshold,
        temp_ban_threshold: thresholds.temp_ban_threshold,
        temp_ban_days: thresholds.temp_ban_days,
        perm_ban_threshold: thresholds.perm_ban_threshold,
        slash_decay_days: thresholds.slash_decay_days,
    })
}

/// PUT /reputation/thresholds - Update thresholds (governance only)
pub async fn update_thresholds(
    State(state): State<ReputationApiState>,
    Json(payload): Json<UpdateThresholdsRequest>,
) -> Result<Json<ThresholdsResponse>, (StatusCode, String)> {
    // Validate admin API key
    if let Some(ref admin_key) = state.admin_api_key {
        if &payload.admin_api_key != admin_key {
            return Err((StatusCode::FORBIDDEN, "Invalid admin API key".to_string()));
        }
    } else {
        return Err((StatusCode::FORBIDDEN, "Admin API key not configured".to_string()));
    }
    
    let mut rep_manager = state.reputation_manager.write().await;
    let current = rep_manager.get_thresholds();
    
    let new_thresholds = ReputationThresholds {
        good_behavior_reward: payload.good_behavior_reward.unwrap_or(current.good_behavior_reward),
        restricted_threshold: payload.restricted_threshold.unwrap_or(current.restricted_threshold),
        temp_ban_threshold: payload.temp_ban_threshold.unwrap_or(current.temp_ban_threshold),
        temp_ban_days: payload.temp_ban_days.unwrap_or(current.temp_ban_days),
        perm_ban_threshold: payload.perm_ban_threshold.unwrap_or(current.perm_ban_threshold),
        slash_decay_days: payload.slash_decay_days.unwrap_or(current.slash_decay_days),
    };
    
    rep_manager.update_thresholds(new_thresholds.clone());
    
    Ok(Json(ThresholdsResponse {
        good_behavior_reward: new_thresholds.good_behavior_reward,
        restricted_threshold: new_thresholds.restricted_threshold,
        temp_ban_threshold: new_thresholds.temp_ban_threshold,
        temp_ban_days: new_thresholds.temp_ban_days,
        perm_ban_threshold: new_thresholds.perm_ban_threshold,
        slash_decay_days: new_thresholds.slash_decay_days,
    }))
}

/// GET /reputation/pending-reviews - Get all pending suspicious activities
pub async fn get_pending_reviews(
    State(state): State<ReputationApiState>,
) -> Json<PendingReviewsResponse> {
    let tracker = state.result_tracker.read().await;
    
    let pending = tracker.get_pending_reviews();
    let total = pending.len();
    
    let activities: Vec<SuspiciousActivitySummary> = pending
        .iter()
        .map(|a| SuspiciousActivitySummary {
            id: a.id.clone(),
            activity_type: format!("{:?}", a.activity_type),
            users_involved: a.users_involved.clone(),
            tasks_involved: a.tasks_involved.clone(),
            detected_at: a.detected_at.to_rfc3339(),
            reviewed: a.reviewed,
            decision: a.decision.map(|d| format!("{:?}", d)),
        })
        .collect();
    
    Json(PendingReviewsResponse { total, activities })
}

/// POST /reputation/review/:activity_id - Resolve a suspicious activity
pub async fn resolve_activity(
    State(state): State<ReputationApiState>,
    Path(activity_id): Path<String>,
    Json(payload): Json<ResolveActivityRequest>,
) -> Result<Json<SuspiciousActivitySummary>, (StatusCode, String)> {
    // Validate admin API key
    if let Some(ref admin_key) = state.admin_api_key {
        if &payload.admin_api_key != admin_key {
            return Err((StatusCode::FORBIDDEN, "Invalid admin API key".to_string()));
        }
    } else {
        return Err((StatusCode::FORBIDDEN, "Admin API key not configured".to_string()));
    }
    
    let mut tracker = state.result_tracker.write().await;
    
    if !tracker.resolve_suspicious_activity(&activity_id, payload.decision) {
        return Err((StatusCode::NOT_FOUND, "Activity not found".to_string()));
    }
    
    // Find the activity to return
    let activities = tracker.get_pending_reviews();
    // Also check resolved ones - need to add a method for this
    // For now, return a basic summary
    
    Ok(Json(SuspiciousActivitySummary {
        id: activity_id,
        activity_type: "Resolved".to_string(),
        users_involved: vec![],
        tasks_involved: vec![],
        detected_at: chrono::Utc::now().to_rfc3339(),
        reviewed: true,
        decision: Some(format!("{:?}", payload.decision)),
    }))
}

/// GET /reputation/stats - Get overall stats
pub async fn get_stats(
    State(state): State<ReputationApiState>,
) -> Json<StatsResponse> {
    let tracker = state.result_tracker.read().await;
    
    let pending_results = tracker.get_pending_results();
    let pending_reviews = tracker.get_pending_reviews();
    
    Json(StatsResponse {
        total_users: 0, // Would need user index in tracker
        total_results_tracked: tracker.get_user_results("").len(), // Placeholder
        pending_validations: pending_results.len(),
        pending_reviews: pending_reviews.len(),
    })
}

/// Create the reputation API router
pub fn create_reputation_router(state: ReputationApiState) -> Router {
    Router::new()
        .route("/{user_id}", get(get_reputation))
        .route("/{user_id}/history", get(get_slash_history))
        .route("/{user_id}/results", get(get_user_results))
        .route("/thresholds", get(get_thresholds).put(update_thresholds))
        .route("/pending-reviews", get(get_pending_reviews))
        .route("/review/{activity_id}", post(resolve_activity))
        .route("/stats", get(get_stats))
        .with_state(state)
}
