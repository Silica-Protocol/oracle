//! Miner API endpoints for work distribution
//!
//! Endpoints:
//!   GET /job?user=<user> -> Get next job for miner (uses smart task selection)
//!   POST /submit -> Submit completed work
//!   GET /status?user=<user> -> Get miner status
//!   GET /profile?user=<user> -> Get miner hardware profile
//!   POST /profile -> Register/update miner hardware profile
//!   GET /preferences?user=<user> -> Get miner project preferences
//!   POST /preferences -> Update miner project preferences
//!   GET /recommendations?user=<user> -> Get ranked project recommendations

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::pouw::aggregator::PoUWAggregator;
use crate::pouw::boinc::ProjectManager;
use crate::pouw::models::BoincWork;
use crate::pouw::task_selection::{
    CpuArchitecture, CpuInfo, GpuInfo, GpuVendor, MinerPreferences as TaskMinerPreferences,
    MinerProfile, OperatingSystem, ScienceArea, TaskSelector, create_default_project_requirements,
};

#[derive(Debug, Deserialize)]
pub struct GetJobQuery {
    pub user: String,
}

#[derive(Debug, Serialize)]
pub struct GetJobResponse {
    pub job: Option<BoincWork>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitWorkRequest {
    pub user: String,
    pub work: BoincWork,
}

#[derive(Debug, Serialize)]
pub struct SubmitWorkResponse {
    pub success: bool,
    pub message: String,
    pub receipt: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StatusQuery {
    pub user: String,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: String,
    pub work_count: usize,
    pub user: String,
}

#[derive(Clone)]
pub struct MinerApiState {
    pub aggregator: Arc<RwLock<PoUWAggregator>>,
    pub project_manager: Arc<RwLock<ProjectManager>>,
    pub task_selector: Arc<RwLock<TaskSelector>>,
}

impl MinerApiState {
    pub fn new(
        aggregator: Arc<RwLock<PoUWAggregator>>,
        project_manager: Arc<RwLock<ProjectManager>>,
    ) -> Self {
        // Initialize task selector with default project requirements
        let mut task_selector = TaskSelector::new();
        for req in create_default_project_requirements() {
            task_selector.register_project(req);
        }

        Self {
            aggregator,
            project_manager,
            task_selector: Arc::new(RwLock::new(task_selector)),
        }
    }

    /// Create with custom task selector
    pub fn with_task_selector(
        aggregator: Arc<RwLock<PoUWAggregator>>,
        project_manager: Arc<RwLock<ProjectManager>>,
        task_selector: TaskSelector,
    ) -> Self {
        Self {
            aggregator,
            project_manager,
            task_selector: Arc::new(RwLock::new(task_selector)),
        }
    }
}

/// Get miner project preferences
#[derive(Debug, Deserialize)]
pub struct PreferencesQuery {
    pub user: String,
}

#[derive(Debug, Serialize)]
pub struct PreferencesResponse {
    pub user: String,
    pub available_projects: Vec<String>,
    pub compatible_projects: Vec<String>,
    pub recommended_projects: Vec<String>,
    pub current_preferences: Option<MinerPreferences>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MinerPreferences {
    pub preferred_projects: Vec<String>,
    pub blocked_projects: Vec<String>,
    pub hardware_capabilities: String,
    pub auto_select_projects: bool,
    pub prefer_gpu_tasks: bool,
    pub prefer_short_tasks: bool,
    pub max_task_duration_hours: Option<u32>,
    pub project_weights: HashMap<String, f64>,
    pub preferred_science_areas: Vec<String>,
}

impl Default for MinerPreferences {
    fn default() -> Self {
        Self {
            preferred_projects: Vec::new(),
            blocked_projects: Vec::new(),
            hardware_capabilities: String::new(),
            auto_select_projects: true,
            prefer_gpu_tasks: true,
            prefer_short_tasks: false,
            max_task_duration_hours: None,
            project_weights: HashMap::new(),
            preferred_science_areas: Vec::new(),
        }
    }
}

/// Update miner project preferences
#[derive(Debug, Deserialize)]
pub struct UpdatePreferencesRequest {
    pub user: String,
    pub preferences: MinerPreferences,
}

#[derive(Debug, Serialize)]
pub struct UpdatePreferencesResponse {
    pub success: bool,
    pub message: String,
    pub updated_preferences: Option<MinerPreferences>,
}

// ============================================================================
// Hardware Profile Types
// ============================================================================

/// Query for miner profile
#[derive(Debug, Deserialize)]
pub struct ProfileQuery {
    pub user: String,
}

/// Hardware profile registration request
#[derive(Debug, Deserialize)]
pub struct RegisterProfileRequest {
    pub user: String,
    pub cpu: CpuProfileInput,
    pub gpus: Vec<GpuProfileInput>,
    pub ram_mb: u64,
    pub storage_gb: u64,
    pub os: String,
    pub network_speed_mbps: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CpuProfileInput {
    pub vendor: String,
    pub model: String,
    pub cores: u32,
    pub threads: u32,
    pub base_frequency_mhz: Option<u32>,
    pub features: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct GpuProfileInput {
    pub vendor: String,
    pub model: String,
    pub vram_mb: u32,
    pub compute_capability: Option<String>,
}

/// Profile response
#[derive(Debug, Serialize)]
pub struct ProfileResponse {
    pub user: String,
    pub profile: Option<MinerProfileOutput>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MinerProfileOutput {
    pub cpu: CpuProfileOutput,
    pub gpus: Vec<GpuProfileOutput>,
    pub ram_mb: u64,
    pub storage_gb: u64,
    pub os: String,
    pub gpu_tier: String,
    pub has_cuda: bool,
    pub total_vram_mb: u32,
}

#[derive(Debug, Serialize)]
pub struct CpuProfileOutput {
    pub vendor: String,
    pub model: String,
    pub cores: u32,
    pub threads: u32,
    pub features: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct GpuProfileOutput {
    pub vendor: String,
    pub model: String,
    pub vram_mb: u32,
    pub tier: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterProfileResponse {
    pub success: bool,
    pub message: String,
    pub compatible_projects: Vec<String>,
    pub recommended_project: Option<String>,
}

// ============================================================================
// Recommendations Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RecommendationsQuery {
    pub user: String,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct RecommendationsResponse {
    pub user: String,
    pub recommendations: Vec<ProjectRecommendation>,
    pub total_compatible: usize,
}

#[derive(Debug, Serialize)]
pub struct ProjectRecommendation {
    pub rank: usize,
    pub project_name: String,
    pub score: f64,
    pub estimated_reward: f64,
    pub estimated_duration_hours: f64,
    pub science_area: String,
    pub gpu_required: bool,
    pub compatibility_notes: Vec<String>,
}

/// Get miner project preferences
pub async fn get_preferences(
    State(state): State<MinerApiState>,
    Query(query): Query<PreferencesQuery>,
) -> Result<Json<PreferencesResponse>, StatusCode> {
    let project_manager = state.project_manager.read().await;
    let task_selector = state.task_selector.read().await;

    let project_names = project_manager.get_project_names().await;

    // Get recommendations if profile exists
    let (compatible_projects, recommended_projects, current_prefs) =
        match task_selector.get_recommendations(&query.user) {
            Ok(recommendations) => {
                let compatible: Vec<String> = recommendations
                    .iter()
                    .map(|r| r.project_name.clone())
                    .collect();
                let recommended: Vec<String> = recommendations
                    .iter()
                    .take(3)
                    .map(|r| r.project_name.clone())
                    .collect();

                // Convert stored preferences to API format
                let prefs =
                    task_selector
                        .get_miner_preferences(&query.user)
                        .map(|p| MinerPreferences {
                            preferred_projects: p.preferred_projects.clone(),
                            blocked_projects: p.blocked_projects.clone(),
                            hardware_capabilities: String::new(), // Derived from profile
                            auto_select_projects: p.auto_select_projects,
                            prefer_gpu_tasks: p.prefer_gpu_tasks,
                            prefer_short_tasks: p.prefer_short_tasks,
                            max_task_duration_hours: p.max_task_duration_hours,
                            project_weights: p.project_weights.clone(),
                            preferred_science_areas: p
                                .preferred_science_areas
                                .iter()
                                .map(|s| format!("{:?}", s))
                                .collect(),
                        });

                (compatible, recommended, prefs)
            }
            Err(_) => {
                // No profile registered, return all projects as available
                (project_names.clone(), vec![], None)
            }
        };

    let response = PreferencesResponse {
        user: query.user,
        available_projects: project_names,
        compatible_projects,
        recommended_projects,
        current_preferences: current_prefs,
    };

    Ok(Json(response))
}

/// Update miner project preferences
pub async fn update_preferences(
    State(state): State<MinerApiState>,
    Json(request): Json<UpdatePreferencesRequest>,
) -> Result<Json<UpdatePreferencesResponse>, StatusCode> {
    info!("Updating preferences for user: {}", request.user);

    let mut task_selector = state.task_selector.write().await;

    // Convert API preferences to internal format
    let science_areas: Vec<ScienceArea> = request
        .preferences
        .preferred_science_areas
        .iter()
        .map(|s| match s.to_lowercase().as_str() {
            "astronomy" => ScienceArea::Astronomy,
            "biology" => ScienceArea::Biology,
            "chemistry" => ScienceArea::Chemistry,
            "climate" => ScienceArea::Climate,
            "mathematics" => ScienceArea::Mathematics,
            "medicine" => ScienceArea::Medicine,
            "physics" => ScienceArea::Physics,
            "machinelearning" | "ml" | "ai" => ScienceArea::MachineLearning,
            _ => ScienceArea::Other,
        })
        .collect();

    let mut internal_prefs = TaskMinerPreferences::new(&request.user);
    internal_prefs.preferred_projects = request.preferences.preferred_projects.clone();
    internal_prefs.blocked_projects = request.preferences.blocked_projects.clone();
    internal_prefs.auto_select_projects = request.preferences.auto_select_projects;
    internal_prefs.prefer_gpu_tasks = request.preferences.prefer_gpu_tasks;
    internal_prefs.prefer_short_tasks = request.preferences.prefer_short_tasks;
    internal_prefs.max_task_duration_hours = request.preferences.max_task_duration_hours;
    internal_prefs.project_weights = request.preferences.project_weights.clone();
    internal_prefs.preferred_science_areas = science_areas;

    task_selector.register_miner_preferences(internal_prefs);

    let response = UpdatePreferencesResponse {
        success: true,
        message: "Preferences updated successfully".to_string(),
        updated_preferences: Some(request.preferences),
    };

    Ok(Json(response))
}

// ============================================================================
// Profile Endpoints
// ============================================================================

/// Get miner hardware profile
pub async fn get_profile(
    State(state): State<MinerApiState>,
    Query(query): Query<ProfileQuery>,
) -> Json<ProfileResponse> {
    let task_selector = state.task_selector.read().await;

    match task_selector.get_miner_profile(&query.user) {
        Some(profile) => {
            let output = MinerProfileOutput {
                cpu: CpuProfileOutput {
                    vendor: profile.cpu.vendor.clone(),
                    model: profile.cpu.model.clone(),
                    cores: profile.cpu.cores,
                    threads: profile.cpu.threads,
                    features: profile.cpu.features.clone(),
                },
                gpus: profile
                    .gpus
                    .iter()
                    .map(|g| GpuProfileOutput {
                        vendor: format!("{:?}", g.vendor),
                        model: g.model.clone(),
                        vram_mb: g.vram_mb,
                        tier: format!("{:?}", g.tier),
                    })
                    .collect(),
                ram_mb: profile.ram_mb,
                storage_gb: profile.storage_gb,
                os: format!("{:?}", profile.os),
                gpu_tier: format!("{:?}", profile.best_gpu_tier()),
                has_cuda: profile.has_cuda(),
                total_vram_mb: profile.total_vram_mb(),
            };

            Json(ProfileResponse {
                user: query.user,
                profile: Some(output),
                message: None,
            })
        }
        None => Json(ProfileResponse {
            user: query.user,
            profile: None,
            message: Some("No profile registered. POST to /miner/profile to register.".to_string()),
        }),
    }
}

/// Register or update miner hardware profile
pub async fn register_profile(
    State(state): State<MinerApiState>,
    Json(request): Json<RegisterProfileRequest>,
) -> Json<RegisterProfileResponse> {
    info!("Registering profile for miner: {}", request.user);

    let mut task_selector = state.task_selector.write().await;

    // Parse OS
    let os = match request.os.to_lowercase().as_str() {
        "linux" => OperatingSystem::Linux,
        "windows" => OperatingSystem::Windows,
        "macos" | "darwin" => OperatingSystem::MacOS,
        _ => OperatingSystem::Other,
    };

    // Parse CPU architecture (default to x86_64 for now)
    let architecture = CpuArchitecture::X86_64;

    // Create CPU info
    let cpu = CpuInfo {
        vendor: request.cpu.vendor.clone(),
        model: request.cpu.model.clone(),
        cores: request.cpu.cores,
        threads: request.cpu.threads,
        base_frequency_mhz: request.cpu.base_frequency_mhz.unwrap_or(0),
        architecture,
        features: request.cpu.features.clone().unwrap_or_default(),
    };

    // Create profile
    let mut profile = MinerProfile::new(&request.user, cpu, request.ram_mb);
    profile.storage_gb = request.storage_gb;
    profile.os = os;
    profile.network_speed_mbps = request.network_speed_mbps;

    // Add GPUs
    for gpu_input in &request.gpus {
        let vendor = match gpu_input.vendor.to_lowercase().as_str() {
            "nvidia" => GpuVendor::Nvidia,
            "amd" => GpuVendor::Amd,
            "intel" => GpuVendor::Intel,
            "apple" => GpuVendor::Apple,
            _ => GpuVendor::Unknown,
        };

        let mut gpu = GpuInfo::new(vendor, &gpu_input.model, gpu_input.vram_mb);
        gpu.compute_capability = gpu_input.compute_capability.clone();
        profile.add_gpu(gpu);
    }

    // Register profile
    task_selector.register_miner_profile(profile);

    // Get recommendations
    let recommendations = task_selector
        .get_recommendations(&request.user)
        .unwrap_or_default();

    let compatible_projects: Vec<String> = recommendations
        .iter()
        .map(|r| r.project_name.clone())
        .collect();

    let recommended_project = recommendations.first().map(|r| r.project_name.clone());

    info!(
        "Registered profile for {}: {} compatible projects",
        request.user,
        compatible_projects.len()
    );

    Json(RegisterProfileResponse {
        success: true,
        message: format!(
            "Profile registered. {} compatible projects found.",
            compatible_projects.len()
        ),
        compatible_projects,
        recommended_project,
    })
}

// ============================================================================
// Recommendations Endpoint
// ============================================================================

/// Get ranked project recommendations for a miner
pub async fn get_recommendations(
    State(state): State<MinerApiState>,
    Query(query): Query<RecommendationsQuery>,
) -> Result<Json<RecommendationsResponse>, StatusCode> {
    let task_selector = state.task_selector.read().await;

    // Check if profile exists
    if task_selector.get_miner_profile(&query.user).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    match task_selector.get_recommendations(&query.user) {
        Ok(recommendations) => {
            let limit = query.limit.unwrap_or(10);
            let total_compatible = recommendations.len();

            let project_recs: Vec<ProjectRecommendation> = recommendations
                .into_iter()
                .take(limit)
                .map(|r| {
                    // Get project requirements for additional info
                    let (science_area, gpu_required) = task_selector
                        .get_project_requirements(&r.project_name)
                        .map(|req| (format!("{:?}", req.science_area), req.gpu_required))
                        .unwrap_or(("Unknown".to_string(), false));

                    ProjectRecommendation {
                        rank: r.rank,
                        project_name: r.project_name,
                        score: r.score,
                        estimated_reward: r.estimated_reward,
                        estimated_duration_hours: r.estimated_duration_hours,
                        science_area,
                        gpu_required,
                        compatibility_notes: r.compatibility.warnings,
                    }
                })
                .collect();

            Ok(Json(RecommendationsResponse {
                user: query.user,
                recommendations: project_recs,
                total_compatible,
            }))
        }
        Err(e) => {
            error!("Failed to get recommendations for {}: {}", query.user, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Create the miner API router
pub fn create_router(state: MinerApiState) -> Router {
    Router::new()
        .route("/job", get(get_work))
        .route("/submit", post(submit_work))
        .route("/status", get(get_status))
        .route("/profile", get(get_profile))
        .route("/profile", post(register_profile))
        .route("/preferences", get(get_preferences))
        .route("/preferences", post(update_preferences))
        .route("/recommendations", get(get_recommendations))
        .with_state(state)
}

/// Get status for a specific user
pub async fn get_status(
    State(state): State<MinerApiState>,
    Query(query): Query<StatusQuery>,
) -> Json<StatusResponse> {
    let aggregator = state.aggregator.read().await;

    match aggregator.get_current_work(&query.user).await {
        Ok(work_list) => Json(StatusResponse {
            status: "active".to_string(),
            work_count: work_list.len(),
            user: query.user,
        }),
        Err(_) => Json(StatusResponse {
            status: "unknown".to_string(),
            work_count: 0,
            user: query.user,
        }),
    }
}

/// Get available work for a miner with smart task selection
pub async fn get_work(
    State(state): State<MinerApiState>,
    Query(query): Query<GetJobQuery>,
) -> Json<GetJobResponse> {
    let task_selector = state.task_selector.read().await;
    let project_manager = state.project_manager.read().await;

    // Get best project recommendation if profile exists
    let recommended_project = task_selector
        .get_best_project(&query.user)
        .ok()
        .flatten()
        .map(|r| r.project_name);

    if let Some(project_name) = &recommended_project {
        info!(
            "Smart selection recommends {} for miner {}",
            project_name, query.user
        );
    }

    // Use recommended project or fall back to any available work
    match project_manager.get_available_work(&query.user, None).await {
        Ok(Some(work)) => {
            let is_recommended = recommended_project
                .as_ref()
                .map(|p| p == &work.project_name)
                .unwrap_or(false);

            info!(
                "Providing {} work to miner {}: {} (recommended: {})",
                work.project_name, query.user, work.task_id, is_recommended
            );

            Json(GetJobResponse {
                job: Some(work),
                message: if is_recommended {
                    Some("Task from recommended project based on your hardware profile".to_string())
                } else {
                    None
                },
            })
        }
        Ok(None) => Json(GetJobResponse {
            job: None,
            message: Some(
                "No work available. Register your hardware profile for better task matching."
                    .to_string(),
            ),
        }),
        Err(e) => {
            error!("Failed to get work for {}: {}", query.user, e);
            Json(GetJobResponse {
                job: None,
                message: Some(format!("Error: {}", e)),
            })
        }
    }
}

/// Submit completed work results with duplicate prevention
pub async fn submit_work(
    State(state): State<MinerApiState>,
    Json(request): Json<SubmitWorkRequest>,
) -> Json<SubmitWorkResponse> {
    info!(
        "Received work submission from user: {} (duplicate prevention active)",
        request.user
    );

    let project_manager = state.project_manager.read().await;

    // Submit work through project manager with duplicate checking
    match project_manager
        .submit_work(&request.user, request.work, vec![])
        .await
    {
        Ok(receipt) => {
            info!(
                "Successfully processed work submission from {} with duplicate prevention",
                request.user
            );
            Json(SubmitWorkResponse {
                success: true,
                message: "Work submitted successfully".to_string(),
                receipt: Some(receipt.work_id.clone()),
            })
        }
        Err(e) => {
            error!(
                "Failed to process work submission from {}: {}",
                request.user, e
            );
            Json(SubmitWorkResponse {
                success: false,
                message: format!("Error: {}", e),
                receipt: None,
            })
        }
    }
}
