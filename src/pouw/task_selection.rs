//! Task Selection System for PoUW Oracle
//!
//! Provides intelligent task assignment based on miner hardware capabilities,
//! preferences, and project requirements.
//!
//! # Architecture
//!
//! ```text
//! MinerProfile (hardware) + MinerPreferences (user settings)
//!          ↓
//! ProjectRequirements (what each project needs)
//!          ↓
//! TaskSelector (smart matching algorithm)
//!          ↓
//! Ranked list of compatible projects/tasks
//! ```

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

// ============================================================================
// Hardware Capabilities
// ============================================================================

/// GPU vendor/architecture
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GpuVendor {
    Nvidia,
    Amd,
    Intel,
    Apple, // Apple Silicon
    Unknown,
}

/// GPU capability tier (determines compatible workloads)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum GpuTier {
    None,       // No GPU or unsupported
    Entry,      // Basic GPU, <4GB VRAM
    Mid,        // Mid-range, 4-8GB VRAM
    High,       // High-end, 8-16GB VRAM
    Enthusiast, // Top-tier, 16GB+ VRAM
    Datacenter, // Server GPUs (A100, H100, etc.)
}

/// Individual GPU information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub vendor: GpuVendor,
    pub model: String,
    pub vram_mb: u32,
    pub compute_capability: Option<String>, // CUDA compute capability for Nvidia
    pub tier: GpuTier,
    pub cuda_cores: Option<u32>,
    pub tensor_cores: Option<bool>,
}

impl GpuInfo {
    /// Create GPU info from basic parameters
    pub fn new(vendor: GpuVendor, model: &str, vram_mb: u32) -> Self {
        let tier = Self::calculate_tier(vram_mb);
        Self {
            vendor,
            model: model.to_string(),
            vram_mb,
            compute_capability: None,
            tier,
            cuda_cores: None,
            tensor_cores: None,
        }
    }

    fn calculate_tier(vram_mb: u32) -> GpuTier {
        match vram_mb {
            0 => GpuTier::None,
            1..=4095 => GpuTier::Entry,
            4096..=8191 => GpuTier::Mid,
            8192..=16383 => GpuTier::High,
            16384..=49151 => GpuTier::Enthusiast,
            _ => GpuTier::Datacenter,
        }
    }

    /// Check if GPU supports CUDA
    pub fn supports_cuda(&self) -> bool {
        matches!(self.vendor, GpuVendor::Nvidia)
    }

    /// Check if GPU supports OpenCL
    pub fn supports_opencl(&self) -> bool {
        !matches!(self.vendor, GpuVendor::Unknown)
    }
}

/// CPU information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub vendor: String,
    pub model: String,
    pub cores: u32,
    pub threads: u32,
    pub base_frequency_mhz: u32,
    pub architecture: CpuArchitecture,
    pub features: Vec<String>, // SSE4, AVX, AVX2, AVX-512, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CpuArchitecture {
    X86_64,
    Arm64,
    Other,
}

impl CpuInfo {
    pub fn new(vendor: &str, model: &str, cores: u32, threads: u32) -> Self {
        Self {
            vendor: vendor.to_string(),
            model: model.to_string(),
            cores,
            threads,
            base_frequency_mhz: 0,
            architecture: CpuArchitecture::X86_64,
            features: Vec::new(),
        }
    }

    /// Check if CPU supports AVX2 (important for many scientific workloads)
    pub fn supports_avx2(&self) -> bool {
        self.features.iter().any(|f| f.to_uppercase() == "AVX2")
    }

    /// Check if CPU supports AVX-512
    pub fn supports_avx512(&self) -> bool {
        self.features
            .iter()
            .any(|f| f.to_uppercase().starts_with("AVX512"))
    }
}

// ============================================================================
// Miner Profile
// ============================================================================

/// Complete hardware profile for a miner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerProfile {
    pub miner_id: String,
    pub cpu: CpuInfo,
    pub gpus: Vec<GpuInfo>,
    pub ram_mb: u64,
    pub storage_gb: u64,
    pub os: OperatingSystem,
    pub network_speed_mbps: Option<u32>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperatingSystem {
    Linux,
    Windows,
    MacOS,
    Other,
}

impl MinerProfile {
    pub fn new(miner_id: &str, cpu: CpuInfo, ram_mb: u64) -> Self {
        Self {
            miner_id: miner_id.to_string(),
            cpu,
            gpus: Vec::new(),
            ram_mb,
            storage_gb: 0,
            os: OperatingSystem::Linux,
            network_speed_mbps: None,
            last_updated: Utc::now(),
        }
    }

    /// Add a GPU to the profile
    pub fn add_gpu(&mut self, gpu: GpuInfo) {
        self.gpus.push(gpu);
    }

    /// Get the best GPU tier available
    pub fn best_gpu_tier(&self) -> GpuTier {
        self.gpus
            .iter()
            .map(|g| g.tier.clone())
            .max()
            .unwrap_or(GpuTier::None)
    }

    /// Check if miner has any CUDA-capable GPU
    pub fn has_cuda(&self) -> bool {
        self.gpus.iter().any(|g| g.supports_cuda())
    }

    /// Check if miner has any OpenCL-capable GPU
    pub fn has_opencl(&self) -> bool {
        self.gpus.iter().any(|g| g.supports_opencl())
    }

    /// Get total VRAM across all GPUs
    pub fn total_vram_mb(&self) -> u32 {
        self.gpus.iter().map(|g| g.vram_mb).sum()
    }

    /// Get number of GPUs
    pub fn gpu_count(&self) -> usize {
        self.gpus.len()
    }
}

// ============================================================================
// Miner Preferences
// ============================================================================

/// User preferences for task selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerPreferences {
    pub miner_id: String,

    // Project preferences
    pub preferred_projects: Vec<String>,
    pub blocked_projects: Vec<String>,
    pub project_weights: HashMap<String, f64>, // 0.0-1.0 weight for each project

    // Resource limits
    pub max_cpu_usage_percent: u8,     // 0-100
    pub max_gpu_usage_percent: u8,     // 0-100
    pub max_ram_usage_mb: Option<u64>, // Optional RAM limit
    pub max_disk_usage_gb: Option<u64>,

    // Scheduling preferences
    pub auto_select_projects: bool,
    pub prefer_short_tasks: bool, // Prefer tasks < 1 hour
    pub prefer_gpu_tasks: bool,   // Prefer GPU over CPU when possible
    pub max_task_duration_hours: Option<u32>,

    // Network preferences
    pub allow_large_downloads: bool, // Tasks requiring >100MB downloads
    pub prefer_low_bandwidth: bool,  // Prefer tasks with minimal network usage

    // Scientific preferences (for users who want specific research areas)
    pub preferred_science_areas: Vec<ScienceArea>,

    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ScienceArea {
    Astronomy,
    Biology,
    Chemistry,
    Climate,
    Mathematics,
    Medicine,
    Physics,
    MachineLearning,
    Other,
}

impl Default for MinerPreferences {
    fn default() -> Self {
        Self {
            miner_id: String::new(),
            preferred_projects: Vec::new(),
            blocked_projects: Vec::new(),
            project_weights: HashMap::new(),
            max_cpu_usage_percent: 80,
            max_gpu_usage_percent: 90,
            max_ram_usage_mb: None,
            max_disk_usage_gb: None,
            auto_select_projects: true,
            prefer_short_tasks: false,
            prefer_gpu_tasks: true,
            max_task_duration_hours: None,
            allow_large_downloads: true,
            prefer_low_bandwidth: false,
            preferred_science_areas: Vec::new(),
            last_updated: Utc::now(),
        }
    }
}

impl MinerPreferences {
    pub fn new(miner_id: &str) -> Self {
        Self {
            miner_id: miner_id.to_string(),
            ..Default::default()
        }
    }

    /// Check if a project is blocked
    pub fn is_project_blocked(&self, project_name: &str) -> bool {
        self.blocked_projects
            .iter()
            .any(|p| p.eq_ignore_ascii_case(project_name))
    }

    /// Check if a project is preferred
    pub fn is_project_preferred(&self, project_name: &str) -> bool {
        self.preferred_projects
            .iter()
            .any(|p| p.eq_ignore_ascii_case(project_name))
    }

    /// Get weight for a project (1.0 if not specified)
    pub fn get_project_weight(&self, project_name: &str) -> f64 {
        self.project_weights
            .get(project_name)
            .copied()
            .unwrap_or(1.0)
    }
}

// ============================================================================
// Project Requirements
// ============================================================================

/// Hardware and software requirements for a BOINC project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectRequirements {
    pub project_name: String,

    // CPU requirements
    pub min_cpu_cores: u32,
    pub min_cpu_threads: u32,
    pub requires_avx2: bool,
    pub requires_avx512: bool,
    pub supported_architectures: Vec<CpuArchitecture>,

    // GPU requirements
    pub gpu_required: bool,
    pub min_gpu_tier: GpuTier,
    pub min_vram_mb: u32,
    pub requires_cuda: bool,
    pub requires_opencl: bool,
    pub min_cuda_compute: Option<String>, // e.g., "6.0"

    // Memory requirements
    pub min_ram_mb: u64,
    pub typical_ram_usage_mb: u64,

    // Storage requirements
    pub min_disk_mb: u64,
    pub typical_download_mb: u64,

    // OS support
    pub supported_os: Vec<OperatingSystem>,

    // Task characteristics
    pub typical_task_duration_hours: f64,
    pub science_area: ScienceArea,

    // Priority/scoring modifiers
    pub base_priority: u32,
    pub reward_multiplier: f64,
}

impl ProjectRequirements {
    /// Create minimal CPU-only requirements
    pub fn cpu_only(project_name: &str) -> Self {
        Self {
            project_name: project_name.to_string(),
            min_cpu_cores: 1,
            min_cpu_threads: 1,
            requires_avx2: false,
            requires_avx512: false,
            supported_architectures: vec![CpuArchitecture::X86_64, CpuArchitecture::Arm64],
            gpu_required: false,
            min_gpu_tier: GpuTier::None,
            min_vram_mb: 0,
            requires_cuda: false,
            requires_opencl: false,
            min_cuda_compute: None,
            min_ram_mb: 512,
            typical_ram_usage_mb: 256,
            min_disk_mb: 100,
            typical_download_mb: 10,
            supported_os: vec![
                OperatingSystem::Linux,
                OperatingSystem::Windows,
                OperatingSystem::MacOS,
            ],
            typical_task_duration_hours: 1.0,
            science_area: ScienceArea::Other,
            base_priority: 50,
            reward_multiplier: 1.0,
        }
    }

    /// Create GPU-required requirements
    pub fn gpu_required(project_name: &str, min_vram_mb: u32) -> Self {
        Self {
            project_name: project_name.to_string(),
            min_cpu_cores: 1,
            min_cpu_threads: 2,
            requires_avx2: false,
            requires_avx512: false,
            supported_architectures: vec![CpuArchitecture::X86_64],
            gpu_required: true,
            min_gpu_tier: GpuTier::Mid,
            min_vram_mb,
            requires_cuda: true,
            requires_opencl: false,
            min_cuda_compute: Some("5.0".to_string()),
            min_ram_mb: 4096,
            typical_ram_usage_mb: 2048,
            min_disk_mb: 1000,
            typical_download_mb: 50,
            supported_os: vec![OperatingSystem::Linux, OperatingSystem::Windows],
            typical_task_duration_hours: 2.0,
            science_area: ScienceArea::Other,
            base_priority: 50,
            reward_multiplier: 1.5,
        }
    }
}

// ============================================================================
// Compatibility Checking
// ============================================================================

/// Result of checking if a miner can run a project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityResult {
    pub project_name: String,
    pub is_compatible: bool,
    pub compatibility_score: f64, // 0.0 - 1.0
    pub issues: Vec<CompatibilityIssue>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityIssue {
    pub category: IssueCategory,
    pub message: String,
    pub severity: IssueSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IssueCategory {
    Cpu,
    Gpu,
    Ram,
    Disk,
    Os,
    Network,
    Preference,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    Info,
    Warning,
    Error, // Blocks compatibility
}

/// Check compatibility between a miner profile and project requirements
pub fn check_compatibility(
    profile: &MinerProfile,
    requirements: &ProjectRequirements,
    preferences: Option<&MinerPreferences>,
) -> CompatibilityResult {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut score = 1.0;

    // Check if project is blocked by user preference
    if let Some(prefs) = preferences {
        if prefs.is_project_blocked(&requirements.project_name) {
            issues.push(CompatibilityIssue {
                category: IssueCategory::Preference,
                message: "Project is blocked by user preferences".to_string(),
                severity: IssueSeverity::Error,
            });
            return CompatibilityResult {
                project_name: requirements.project_name.clone(),
                is_compatible: false,
                compatibility_score: 0.0,
                issues,
                warnings,
            };
        }
    }

    // Check OS compatibility
    if !requirements.supported_os.contains(&profile.os) {
        issues.push(CompatibilityIssue {
            category: IssueCategory::Os,
            message: format!("OS {:?} not supported by project", profile.os),
            severity: IssueSeverity::Error,
        });
    }

    // Check CPU architecture
    if !requirements
        .supported_architectures
        .contains(&profile.cpu.architecture)
    {
        issues.push(CompatibilityIssue {
            category: IssueCategory::Cpu,
            message: format!(
                "CPU architecture {:?} not supported",
                profile.cpu.architecture
            ),
            severity: IssueSeverity::Error,
        });
    }

    // Check CPU cores
    if profile.cpu.cores < requirements.min_cpu_cores {
        issues.push(CompatibilityIssue {
            category: IssueCategory::Cpu,
            message: format!(
                "Insufficient CPU cores: {} < {}",
                profile.cpu.cores, requirements.min_cpu_cores
            ),
            severity: IssueSeverity::Error,
        });
    }

    // Check AVX2 requirement
    if requirements.requires_avx2 && !profile.cpu.supports_avx2() {
        issues.push(CompatibilityIssue {
            category: IssueCategory::Cpu,
            message: "AVX2 required but not supported".to_string(),
            severity: IssueSeverity::Error,
        });
    }

    // Check AVX-512 requirement
    if requirements.requires_avx512 && !profile.cpu.supports_avx512() {
        issues.push(CompatibilityIssue {
            category: IssueCategory::Cpu,
            message: "AVX-512 required but not supported".to_string(),
            severity: IssueSeverity::Error,
        });
    }

    // Check RAM
    if profile.ram_mb < requirements.min_ram_mb {
        issues.push(CompatibilityIssue {
            category: IssueCategory::Ram,
            message: format!(
                "Insufficient RAM: {} MB < {} MB required",
                profile.ram_mb, requirements.min_ram_mb
            ),
            severity: IssueSeverity::Error,
        });
    } else if profile.ram_mb < requirements.typical_ram_usage_mb * 2 {
        warnings.push(format!(
            "RAM may be tight: {} MB available, {} MB typical usage",
            profile.ram_mb, requirements.typical_ram_usage_mb
        ));
        score *= 0.9;
    }

    // Check GPU requirements
    if requirements.gpu_required {
        if profile.gpus.is_empty() {
            issues.push(CompatibilityIssue {
                category: IssueCategory::Gpu,
                message: "GPU required but none detected".to_string(),
                severity: IssueSeverity::Error,
            });
        } else {
            // Check GPU tier
            let best_tier = profile.best_gpu_tier();
            if best_tier < requirements.min_gpu_tier {
                issues.push(CompatibilityIssue {
                    category: IssueCategory::Gpu,
                    message: format!(
                        "GPU tier {:?} below required {:?}",
                        best_tier, requirements.min_gpu_tier
                    ),
                    severity: IssueSeverity::Error,
                });
            }

            // Check VRAM
            let total_vram = profile.total_vram_mb();
            if total_vram < requirements.min_vram_mb {
                issues.push(CompatibilityIssue {
                    category: IssueCategory::Gpu,
                    message: format!(
                        "Insufficient VRAM: {} MB < {} MB required",
                        total_vram, requirements.min_vram_mb
                    ),
                    severity: IssueSeverity::Error,
                });
            }

            // Check CUDA requirement
            if requirements.requires_cuda && !profile.has_cuda() {
                issues.push(CompatibilityIssue {
                    category: IssueCategory::Gpu,
                    message: "CUDA required but no NVIDIA GPU detected".to_string(),
                    severity: IssueSeverity::Error,
                });
            }

            // Check OpenCL requirement
            if requirements.requires_opencl && !profile.has_opencl() {
                issues.push(CompatibilityIssue {
                    category: IssueCategory::Gpu,
                    message: "OpenCL required but not supported".to_string(),
                    severity: IssueSeverity::Error,
                });
            }
        }
    }

    // Check disk space
    if profile.storage_gb * 1024 < requirements.min_disk_mb {
        issues.push(CompatibilityIssue {
            category: IssueCategory::Disk,
            message: format!(
                "Insufficient disk space: {} GB < {} MB required",
                profile.storage_gb, requirements.min_disk_mb
            ),
            severity: IssueSeverity::Error,
        });
    }

    // Check download size preference
    if let Some(prefs) = preferences {
        if !prefs.allow_large_downloads && requirements.typical_download_mb > 100 {
            issues.push(CompatibilityIssue {
                category: IssueCategory::Network,
                message: format!(
                    "Task requires ~{} MB download but large downloads are disabled",
                    requirements.typical_download_mb
                ),
                severity: IssueSeverity::Error,
            });
        }

        // Check task duration preference
        if let Some(max_hours) = prefs.max_task_duration_hours {
            if requirements.typical_task_duration_hours > max_hours as f64 {
                warnings.push(format!(
                    "Task typically takes {:.1} hours, exceeds preference of {} hours",
                    requirements.typical_task_duration_hours, max_hours
                ));
                score *= 0.7;
            }
        }
    }

    // Calculate final compatibility
    let has_errors = issues.iter().any(|i| i.severity == IssueSeverity::Error);

    // Adjust score based on preference matching
    if let Some(prefs) = preferences {
        // Boost score for preferred projects
        if prefs.is_project_preferred(&requirements.project_name) {
            score *= 1.2;
        }

        // Apply user-defined weight
        score *= prefs.get_project_weight(&requirements.project_name);

        // Boost for matching science area
        if prefs
            .preferred_science_areas
            .contains(&requirements.science_area)
        {
            score *= 1.1;
        }

        // Boost for GPU tasks if user prefers them
        if prefs.prefer_gpu_tasks && requirements.gpu_required && profile.has_cuda() {
            score *= 1.15;
        }

        // Boost for short tasks if user prefers them
        if prefs.prefer_short_tasks && requirements.typical_task_duration_hours < 1.0 {
            score *= 1.1;
        }
    }

    // Clamp score minimum to 0.0 but allow >1.0 for preference boosts
    // The score is used for ranking, not display, so higher is better
    score = score.max(0.0);

    CompatibilityResult {
        project_name: requirements.project_name.clone(),
        is_compatible: !has_errors,
        compatibility_score: if has_errors { 0.0 } else { score },
        issues,
        warnings,
    }
}

// ============================================================================
// Task Selector
// ============================================================================

/// Task selection result with ranking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecommendation {
    pub project_name: String,
    pub rank: usize,
    pub score: f64,
    pub compatibility: CompatibilityResult,
    pub estimated_reward: f64,
    pub estimated_duration_hours: f64,
}

/// Intelligent task selector
pub struct TaskSelector {
    project_requirements: HashMap<String, ProjectRequirements>,
    miner_profiles: HashMap<String, MinerProfile>,
    miner_preferences: HashMap<String, MinerPreferences>,
}

impl Default for TaskSelector {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskSelector {
    pub fn new() -> Self {
        Self {
            project_requirements: HashMap::new(),
            miner_profiles: HashMap::new(),
            miner_preferences: HashMap::new(),
        }
    }

    /// Register project requirements
    pub fn register_project(&mut self, requirements: ProjectRequirements) {
        info!(
            "Registered project requirements: {}",
            requirements.project_name
        );
        self.project_requirements
            .insert(requirements.project_name.clone(), requirements);
    }

    /// Register or update miner profile
    pub fn register_miner_profile(&mut self, profile: MinerProfile) {
        info!(
            "Registered miner profile: {} (CPUs: {}, GPUs: {})",
            profile.miner_id,
            profile.cpu.cores,
            profile.gpus.len()
        );
        self.miner_profiles
            .insert(profile.miner_id.clone(), profile);
    }

    /// Register or update miner preferences
    pub fn register_miner_preferences(&mut self, preferences: MinerPreferences) {
        info!("Registered miner preferences: {}", preferences.miner_id);
        self.miner_preferences
            .insert(preferences.miner_id.clone(), preferences);
    }

    /// Get miner profile
    pub fn get_miner_profile(&self, miner_id: &str) -> Option<&MinerProfile> {
        self.miner_profiles.get(miner_id)
    }

    /// Get miner preferences
    pub fn get_miner_preferences(&self, miner_id: &str) -> Option<&MinerPreferences> {
        self.miner_preferences.get(miner_id)
    }

    /// Get project requirements
    pub fn get_project_requirements(&self, project_name: &str) -> Option<&ProjectRequirements> {
        self.project_requirements.get(project_name)
    }

    /// Get all registered projects
    pub fn get_all_projects(&self) -> Vec<&str> {
        self.project_requirements
            .keys()
            .map(|s| s.as_str())
            .collect()
    }

    /// Get ranked list of compatible projects for a miner
    pub fn get_recommendations(&self, miner_id: &str) -> Result<Vec<TaskRecommendation>> {
        let profile = self
            .miner_profiles
            .get(miner_id)
            .context(format!("Miner profile not found: {}", miner_id))?;

        let preferences = self.miner_preferences.get(miner_id);

        let mut recommendations: Vec<TaskRecommendation> = self
            .project_requirements
            .values()
            .map(|req| {
                let compatibility = check_compatibility(profile, req, preferences);
                let estimated_reward = req.reward_multiplier * 100.0; // Base reward

                TaskRecommendation {
                    project_name: req.project_name.clone(),
                    rank: 0, // Will be set after sorting
                    score: compatibility.compatibility_score
                        * req.base_priority as f64
                        * req.reward_multiplier,
                    compatibility,
                    estimated_reward,
                    estimated_duration_hours: req.typical_task_duration_hours,
                }
            })
            .filter(|r| r.compatibility.is_compatible)
            .collect();

        // Sort by score (descending)
        recommendations.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        // Set ranks
        for (i, rec) in recommendations.iter_mut().enumerate() {
            rec.rank = i + 1;
        }

        debug!(
            "Generated {} recommendations for miner {}",
            recommendations.len(),
            miner_id
        );

        Ok(recommendations)
    }

    /// Get the best project for a miner
    pub fn get_best_project(&self, miner_id: &str) -> Result<Option<TaskRecommendation>> {
        let recommendations = self.get_recommendations(miner_id)?;
        Ok(recommendations.into_iter().next())
    }

    /// Check if a specific project is compatible with a miner
    pub fn check_project_compatibility(
        &self,
        miner_id: &str,
        project_name: &str,
    ) -> Result<CompatibilityResult> {
        let profile = self
            .miner_profiles
            .get(miner_id)
            .context(format!("Miner profile not found: {}", miner_id))?;

        let requirements = self
            .project_requirements
            .get(project_name)
            .context(format!("Project requirements not found: {}", project_name))?;

        let preferences = self.miner_preferences.get(miner_id);

        Ok(check_compatibility(profile, requirements, preferences))
    }
}

// ============================================================================
// Default Project Configurations
// ============================================================================

/// Create default requirements for known BOINC projects
pub fn create_default_project_requirements() -> Vec<ProjectRequirements> {
    vec![
        // MilkyWay@Home - CPU-based galaxy modeling
        ProjectRequirements {
            project_name: "MilkyWay@Home".to_string(),
            min_cpu_cores: 1,
            min_cpu_threads: 1,
            requires_avx2: false,
            requires_avx512: false,
            supported_architectures: vec![CpuArchitecture::X86_64, CpuArchitecture::Arm64],
            gpu_required: false,
            min_gpu_tier: GpuTier::None,
            min_vram_mb: 0,
            requires_cuda: false,
            requires_opencl: false,
            min_cuda_compute: None,
            min_ram_mb: 512,
            typical_ram_usage_mb: 256,
            min_disk_mb: 50,
            typical_download_mb: 5,
            supported_os: vec![
                OperatingSystem::Linux,
                OperatingSystem::Windows,
                OperatingSystem::MacOS,
            ],
            typical_task_duration_hours: 0.5,
            science_area: ScienceArea::Astronomy,
            base_priority: 60,
            reward_multiplier: 1.0,
        },
        // Rosetta@Home - Protein folding (CPU intensive)
        ProjectRequirements {
            project_name: "Rosetta@Home".to_string(),
            min_cpu_cores: 1,
            min_cpu_threads: 2,
            requires_avx2: true,
            requires_avx512: false,
            supported_architectures: vec![CpuArchitecture::X86_64],
            gpu_required: false,
            min_gpu_tier: GpuTier::None,
            min_vram_mb: 0,
            requires_cuda: false,
            requires_opencl: false,
            min_cuda_compute: None,
            min_ram_mb: 2048,
            typical_ram_usage_mb: 1024,
            min_disk_mb: 200,
            typical_download_mb: 20,
            supported_os: vec![OperatingSystem::Linux, OperatingSystem::Windows],
            typical_task_duration_hours: 2.0,
            science_area: ScienceArea::Biology,
            base_priority: 70,
            reward_multiplier: 1.2,
        },
        // World Community Grid - Various medical research
        ProjectRequirements {
            project_name: "World Community Grid".to_string(),
            min_cpu_cores: 1,
            min_cpu_threads: 1,
            requires_avx2: false,
            requires_avx512: false,
            supported_architectures: vec![CpuArchitecture::X86_64, CpuArchitecture::Arm64],
            gpu_required: false,
            min_gpu_tier: GpuTier::None,
            min_vram_mb: 0,
            requires_cuda: false,
            requires_opencl: false,
            min_cuda_compute: None,
            min_ram_mb: 1024,
            typical_ram_usage_mb: 512,
            min_disk_mb: 100,
            typical_download_mb: 10,
            supported_os: vec![
                OperatingSystem::Linux,
                OperatingSystem::Windows,
                OperatingSystem::MacOS,
            ],
            typical_task_duration_hours: 1.0,
            science_area: ScienceArea::Medicine,
            base_priority: 65,
            reward_multiplier: 1.1,
        },
        // GPUGRID - GPU-based molecular dynamics
        ProjectRequirements {
            project_name: "GPUGRID".to_string(),
            min_cpu_cores: 2,
            min_cpu_threads: 4,
            requires_avx2: false,
            requires_avx512: false,
            supported_architectures: vec![CpuArchitecture::X86_64],
            gpu_required: true,
            min_gpu_tier: GpuTier::Mid,
            min_vram_mb: 4096,
            requires_cuda: true,
            requires_opencl: false,
            min_cuda_compute: Some("5.0".to_string()),
            min_ram_mb: 8192,
            typical_ram_usage_mb: 4096,
            min_disk_mb: 2000,
            typical_download_mb: 100,
            supported_os: vec![OperatingSystem::Linux, OperatingSystem::Windows],
            typical_task_duration_hours: 4.0,
            science_area: ScienceArea::Biology,
            base_priority: 80,
            reward_multiplier: 2.0,
        },
        // Einstein@Home - Gravitational wave search
        ProjectRequirements {
            project_name: "Einstein@Home".to_string(),
            min_cpu_cores: 1,
            min_cpu_threads: 2,
            requires_avx2: true,
            requires_avx512: false,
            supported_architectures: vec![CpuArchitecture::X86_64],
            gpu_required: false, // Has GPU version but not required
            min_gpu_tier: GpuTier::None,
            min_vram_mb: 0,
            requires_cuda: false,
            requires_opencl: false,
            min_cuda_compute: None,
            min_ram_mb: 2048,
            typical_ram_usage_mb: 1024,
            min_disk_mb: 500,
            typical_download_mb: 50,
            supported_os: vec![OperatingSystem::Linux, OperatingSystem::Windows],
            typical_task_duration_hours: 3.0,
            science_area: ScienceArea::Physics,
            base_priority: 75,
            reward_multiplier: 1.3,
        },
    ]
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_profile() -> MinerProfile {
        let cpu = CpuInfo {
            vendor: "Intel".to_string(),
            model: "Core i7-12700K".to_string(),
            cores: 12,
            threads: 20,
            base_frequency_mhz: 3600,
            architecture: CpuArchitecture::X86_64,
            features: vec!["AVX2".to_string(), "AVX512F".to_string()],
        };

        let mut profile = MinerProfile::new("test_miner", cpu, 32768);
        profile.storage_gb = 500;
        profile.os = OperatingSystem::Linux;

        // Add a mid-range GPU
        profile.add_gpu(GpuInfo::new(GpuVendor::Nvidia, "RTX 3070", 8192));

        profile
    }

    #[test]
    fn test_gpu_tier_calculation() {
        assert_eq!(GpuInfo::calculate_tier(0), GpuTier::None);
        assert_eq!(GpuInfo::calculate_tier(2048), GpuTier::Entry);
        assert_eq!(GpuInfo::calculate_tier(6144), GpuTier::Mid);
        assert_eq!(GpuInfo::calculate_tier(12288), GpuTier::High);
        assert_eq!(GpuInfo::calculate_tier(24576), GpuTier::Enthusiast);
        assert_eq!(GpuInfo::calculate_tier(81920), GpuTier::Datacenter);
    }

    #[test]
    fn test_miner_profile() {
        let profile = create_test_profile();

        assert_eq!(profile.gpu_count(), 1);
        assert_eq!(profile.best_gpu_tier(), GpuTier::High);
        assert!(profile.has_cuda());
        assert_eq!(profile.total_vram_mb(), 8192);
    }

    #[test]
    fn test_compatibility_cpu_only() {
        let profile = create_test_profile();
        let requirements = ProjectRequirements::cpu_only("TestProject");

        let result = check_compatibility(&profile, &requirements, None);

        assert!(result.is_compatible);
        assert!(result.compatibility_score > 0.0);
        assert!(result.issues.is_empty());
    }

    #[test]
    fn test_compatibility_gpu_required() {
        let profile = create_test_profile();
        let requirements = ProjectRequirements::gpu_required("GPUProject", 4096);

        let result = check_compatibility(&profile, &requirements, None);

        assert!(result.is_compatible);
        assert!(result.compatibility_score > 0.0);
    }

    #[test]
    fn test_compatibility_insufficient_vram() {
        let mut profile = create_test_profile();
        profile.gpus.clear();
        profile.add_gpu(GpuInfo::new(GpuVendor::Nvidia, "GTX 1050", 2048));

        let requirements = ProjectRequirements::gpu_required("GPUProject", 8192);

        let result = check_compatibility(&profile, &requirements, None);

        assert!(!result.is_compatible);
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.category == IssueCategory::Gpu)
        );
    }

    #[test]
    fn test_blocked_project() {
        let profile = create_test_profile();
        let requirements = ProjectRequirements::cpu_only("BlockedProject");

        let mut prefs = MinerPreferences::new("test_miner");
        prefs.blocked_projects.push("BlockedProject".to_string());

        let result = check_compatibility(&profile, &requirements, Some(&prefs));

        assert!(!result.is_compatible);
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.category == IssueCategory::Preference)
        );
    }

    #[test]
    fn test_task_selector() {
        let mut selector = TaskSelector::new();

        // Register project requirements
        for req in create_default_project_requirements() {
            selector.register_project(req);
        }

        // Register miner
        selector.register_miner_profile(create_test_profile());

        // Get recommendations
        let recommendations = selector.get_recommendations("test_miner").unwrap();

        assert!(!recommendations.is_empty());
        assert_eq!(recommendations[0].rank, 1);

        // Check that GPUGRID is recommended (since we have a good GPU)
        let gpugrid_rec = recommendations.iter().find(|r| r.project_name == "GPUGRID");
        assert!(gpugrid_rec.is_some());
    }

    #[test]
    fn test_preferences_boost_score() {
        let mut selector = TaskSelector::new();

        // Register projects
        for req in create_default_project_requirements() {
            selector.register_project(req);
        }

        // Register miner with preferences
        selector.register_miner_profile(create_test_profile());

        let mut prefs = MinerPreferences::new("test_miner");
        prefs.preferred_projects.push("MilkyWay@Home".to_string());
        prefs.preferred_science_areas.push(ScienceArea::Astronomy);
        selector.register_miner_preferences(prefs);

        let recommendations = selector.get_recommendations("test_miner").unwrap();

        // MilkyWay should have boosted score due to preferences
        let milkyway = recommendations
            .iter()
            .find(|r| r.project_name == "MilkyWay@Home")
            .unwrap();

        assert!(milkyway.score > 50.0); // Base would be 60 * 1.0 * 1.0 = 60
    }
}
