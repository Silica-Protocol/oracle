//! Web API for human-readable endpoints
//!
//! Endpoints:
//!   GET /stats -> System statistics and tracking
//!   GET /users -> User account information
//!   GET /projects -> Project status and management
//!   GET /projects/{name}/stats -> Detailed project statistics
//!   GET /projects/{name}/health -> Project health monitoring
//!   GET /health -> Health check

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::pouw::aggregator::PoUWAggregator;
use crate::pouw::boinc::client::{ProjectStatus, UserProfile};
use crate::pouw::boinc::{BoincClient, ProjectManager, ProjectStats, UserStats};
use chrono::{DateTime, Utc};
use tracing::{error, warn};

#[derive(Clone)]
pub struct WebApiState {
    pub aggregator: Arc<RwLock<PoUWAggregator>>,
    pub boinc_client: Arc<RwLock<BoincClient>>,
    pub accounts: Arc<RwLock<HashMap<String, String>>>,
    pub project_manager: Arc<RwLock<ProjectManager>>,
}

#[derive(Serialize)]
pub struct SystemStats {
    pub total_users: usize,
    pub total_cached_jobs: usize,
    pub active_projects: Vec<String>,
    pub cache_stats: HashMap<String, usize>,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub user_id: String,
    pub cached_jobs: usize,
    pub last_activity: Option<String>,
}

#[derive(Serialize)]
pub struct Notice {
    pub id: u64,
    pub title: String,
    pub description: String,
    pub category: String,
    pub link: Option<String>,
    pub create_time: DateTime<Utc>,
    pub priority: u8,
}

#[derive(Serialize)]
pub struct NoticesResponse {
    pub notices: Vec<Notice>,
    pub total_count: usize,
}

pub async fn get_stats(State(state): State<WebApiState>) -> Json<SystemStats> {
    let aggregator = state.aggregator.read().await;
    let cache_stats = aggregator.get_cache_stats().await;

    let total_cached_jobs = cache_stats.values().sum::<usize>();
    let total_users = cache_stats.len();

    // Get active projects from BOINC client
    let boinc_client = state.boinc_client.read().await;
    let active_projects = boinc_client.get_configured_projects().await;

    Json(SystemStats {
        total_users,
        total_cached_jobs,
        active_projects,
        cache_stats,
    })
}

pub async fn get_users(State(state): State<WebApiState>) -> Json<Vec<UserProfile>> {
    let _boinc_client = state.boinc_client.read().await;
    // TODO: Implement user listing
    let users = vec![];

    Json(users)
}

pub async fn get_projects(State(state): State<WebApiState>) -> Json<Vec<ProjectStatus>> {
    let boinc_client = state.boinc_client.read().await;
    let projects = boinc_client.get_all_project_status().await;

    Json(projects)
}

/// Get detailed project statistics
pub async fn get_project_stats(
    State(state): State<WebApiState>,
    Path(project_name): Path<String>,
) -> Json<ProjectStats> {
    let project_manager = state.project_manager.read().await;

    match project_manager.get_project_stats(&project_name).await {
        Ok(stats) => Json(stats),
        Err(e) => {
            warn!(
                error = ?e,
                project = %project_name,
                "Falling back to default project stats"
            );
            // Return default stats if project not found
            Json(ProjectStats {
                project_name,
                total_assignments: 0,
                completed: 0,
                in_progress: 0,
                failed: 0,
                credit_multiplier: 1.0,
                enabled: false,
            })
        }
    }
}

/// Get project health information
#[derive(Serialize)]
pub struct ProjectHealth {
    pub project_name: String,
    pub status: String,
    pub last_check: DateTime<Utc>,
    pub response_time_ms: Option<u64>,
    pub error_count: u32,
    pub success_rate: f64,
    pub is_available: bool,
}

/// Get allocation statistics
#[derive(Serialize)]
pub struct AllocationStatsResponse {
    pub total_work: usize,
    pub assigned_work: usize,
    pub completed_work: usize,
    pub duplicate_work: usize,
    pub active_locks: usize,
    pub duplicate_prevention_rate: f64,
}

pub async fn get_project_health(
    State(state): State<WebApiState>,
    Path(project_name): Path<String>,
) -> Json<ProjectHealth> {
    let project_manager = state.project_manager.read().await;
    let default_response_time_ms = Some(150);

    let (status, success_rate, error_count, is_available) =
        match project_manager.get_project_stats(&project_name).await {
            Ok(stats) => {
                let total = stats.total_assignments;
                let success_rate = if total > 0 {
                    (stats.completed as f64 / total as f64) * 100.0
                } else {
                    100.0
                };
                let status = if stats.enabled {
                    "operational".to_string()
                } else {
                    "disabled".to_string()
                };
                let error_count = stats.failed as u32;
                let is_available = stats.enabled;
                (status, success_rate, error_count, is_available)
            }
            Err(e) => {
                warn!(
                    error = ?e,
                    project = %project_name,
                    "Falling back to default project health"
                );
                ("unknown".to_string(), 0.0, 0, false)
            }
        };

    Json(ProjectHealth {
        project_name,
        status,
        last_check: Utc::now(),
        response_time_ms: default_response_time_ms,
        error_count,
        success_rate,
        is_available,
    })
}

/// Get user statistics
pub async fn get_user_stats(
    State(state): State<WebApiState>,
    Path(user_id): Path<String>,
) -> Json<UserStats> {
    let project_manager = state.project_manager.read().await;

    match project_manager.get_user_stats(&user_id).await {
        Ok(stats) => Json(stats),
        Err(e) => {
            warn!(
                error = ?e,
                user = %user_id,
                "Falling back to default user stats"
            );
            // Return default stats if user not found
            Json(UserStats {
                user_id,
                total_assignments: 0,
                completed: 0,
                in_progress: 0,
                failed: 0,
                total_credits: 0.0,
                today_credits: 0.0,
            })
        }
    }
}

pub async fn health_check() -> &'static str {
    "OK"
}

pub async fn get_notices(State(_state): State<WebApiState>) -> Json<NoticesResponse> {
    // Generate sample notices for BOINC client compatibility
    let notices = vec![
        Notice {
            id: 1,
            title: "Chert Proxy Active".to_string(),
            description: "The Chert BOINC proxy is running and processing scientific work."
                .to_string(),
            category: "system".to_string(),
            link: Some("http://localhost:8765/api/stats".to_string()),
            create_time: Utc::now(),
            priority: 1,
        },
        Notice {
            id: 2,
            title: "Privacy Protection Enabled".to_string(),
            description: "Your personal data is being obfuscated for privacy protection."
                .to_string(),
            category: "privacy".to_string(),
            link: None,
            create_time: Utc::now(),
            priority: 2,
        },
    ];

    Json(NoticesResponse {
        total_count: notices.len(),
        notices,
    })
}

pub async fn get_allocation_stats(
    State(state): State<WebApiState>,
) -> Json<AllocationStatsResponse> {
    let project_manager = state.project_manager.read().await;

    match project_manager.get_allocation_stats().await {
        Ok(stats) => {
            let duplicate_prevention_rate = if stats.total_work > 0 {
                (stats.duplicate_work as f64 / stats.total_work as f64) * 100.0
            } else {
                0.0
            };

            Json(AllocationStatsResponse {
                total_work: stats.total_work,
                assigned_work: stats.assigned_work,
                completed_work: stats.completed_work,
                duplicate_work: stats.duplicate_work,
                active_locks: stats.active_locks,
                duplicate_prevention_rate,
            })
        }
        Err(e) => {
            error!("Failed to get allocation stats: {}", e);
            Json(AllocationStatsResponse {
                total_work: 0,
                assigned_work: 0,
                completed_work: 0,
                duplicate_work: 0,
                active_locks: 0,
                duplicate_prevention_rate: 0.0,
            })
        }
    }
}

pub fn create_router(state: WebApiState) -> Router {
    Router::new()
        .route("/stats", get(get_stats))
        .route("/users", get(get_users))
        .route("/projects", get(get_projects))
        .route("/projects/{project_name}/stats", get(get_project_stats))
        .route("/projects/{project_name}/health", get(get_project_health))
        .route("/users/{user_id}/stats", get(get_user_stats))
        .route("/allocation/stats", get(get_allocation_stats))
        .route("/notices", get(get_notices))
        .route("/health", get(health_check))
        .with_state(state)
}
