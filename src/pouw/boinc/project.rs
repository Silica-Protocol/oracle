//! Project Manager for PoUW Oracle
//!
//! Manages multiple BOINC projects and coordinates work distribution.

use crate::crypto::{CryptoEngine, WorkReceipt};
use crate::pouw::boinc::compat::BoincCompatClient;
use crate::pouw::models::BoincWork;
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Custom Project Manager for Chert PoI Oracle
/// Manages multiple BOINC projects and coordinates work distribution

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    pub project_url: String,
    pub api_endpoint: String,
    pub user_id: String,
    pub authenticator: String,
    pub credit_multiplier: f64,
    pub min_cpu_time: f64,
    pub max_daily_credits: f64,
    pub priority: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkAssignment {
    pub work_id: String,
    pub project_name: String,
    pub assigned_to: String,
    pub assigned_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
    pub status: WorkStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkStatus {
    Assigned,
    InProgress,
    Completed,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalWorkAssignment {
    pub work_id: String,
    pub project_name: String,
    pub assigned_to: Option<String>, // None if not yet assigned
    pub assigned_at: Option<DateTime<Utc>>,
    pub deadline: DateTime<Utc>,
    pub status: GlobalWorkStatus,
    pub location_hints: Vec<String>, // GPOD location hints for geographic diversity
    pub assignment_lock: Option<String>, // UUID of current assignment lock
    pub lock_expires: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GlobalWorkStatus {
    Available,
    Assigned,
    InProgress,
    Completed,
    Failed,
    Expired,
    DuplicateDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkAllocationLock {
    pub lock_id: String,
    pub work_id: String,
    pub miner_id: String,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub location: Option<String>, // GPOD location for diversity tracking
}

pub struct ProjectManager {
    boinc_client: tokio::sync::RwLock<BoincCompatClient>,
    crypto: CryptoEngine,
    projects: RwLock<HashMap<String, ProjectConfig>>,
    work_assignments: RwLock<HashMap<String, WorkAssignment>>,
    global_work_registry: RwLock<HashMap<String, GlobalWorkAssignment>>, // work_id -> global assignment
    allocation_locks: RwLock<HashMap<String, WorkAllocationLock>>,       // lock_id -> lock details
    active_locks: RwLock<HashMap<String, HashSet<String>>>, // work_id -> set of active lock_ids
    daily_credits: RwLock<HashMap<String, f64>>,            // user -> credits used today
    last_reset: RwLock<DateTime<Utc>>,
}

impl ProjectManager {
    pub fn new() -> Self {
        Self {
            boinc_client: tokio::sync::RwLock::new(BoincCompatClient::new(true)), // Use client mode
            crypto: CryptoEngine::new(),
            projects: RwLock::new(HashMap::new()),
            work_assignments: RwLock::new(HashMap::new()),
            global_work_registry: RwLock::new(HashMap::new()),
            allocation_locks: RwLock::new(HashMap::new()),
            active_locks: RwLock::new(HashMap::new()),
            daily_credits: RwLock::new(HashMap::new()),
            last_reset: RwLock::new(Utc::now()),
        }
    }

    /// Register a new BOINC project
    pub async fn register_project(&self, config: ProjectConfig) -> Result<()> {
        info!("Registering project: {}", config.name);

        // Determine which base URL to use for client RPC calls: use project_url for RPC
        let rpc_base = config.project_url.clone();

        // Determine which base URL to use for API calls: prefer api_endpoint when provided
        let api_base = if !config.api_endpoint.trim().is_empty() {
            config.api_endpoint.clone()
        } else {
            config.project_url.clone()
        };

        // Add to BOINC client
        let project = crate::pouw::boinc::client::BoincProject {
            name: config.name.clone(),
            url: rpc_base.clone(),
            user_id: config.user_id.clone(),
            authenticator: config.authenticator.clone(),
        };
        tracing::info!(
            "Registering project '{}' with RPC base: {}, API base: {}",
            config.name,
            rpc_base,
            api_base
        );
        // Add the project into the internal BoincCompatClient so client-driven fetches work
        {
            let mut client_guard = self.boinc_client.write().await;
            client_guard.add_project(project);
        }

        // Store project config
        let project_name = config.name.clone();
        let mut projects = self.projects.write().await;
        projects.insert(project_name.clone(), config);

        info!("Successfully registered project: {}", project_name);
        Ok(())
    }

    /// Get project authenticator by project name
    pub fn get_project_authenticator(&self, project_name: &str) -> Option<String> {
        // We need to get the projects synchronously for the main.rs initialization
        // This is safe during startup before any async operations begin
        if let Ok(projects) = self.projects.try_read() {
            projects
                .get(project_name)
                .map(|config| config.authenticator.clone())
        } else {
            None
        }
    }

    /// Get available work for a user with duplicate prevention
    pub async fn get_available_work(
        &self,
        user_id: &str,
        miner_location: Option<&str>,
    ) -> Result<Option<BoincWork>> {
        debug!(
            "Getting available work for user: {} (location: {:?})",
            user_id, miner_location
        );

        // Check daily credit limit
        if !self.check_daily_limit(user_id).await? {
            warn!("User {} has exceeded daily credit limit", user_id);
            return Ok(None);
        }

        // Get all enabled projects
        let projects = self.projects.read().await;
        let enabled_projects: Vec<_> = projects.values().filter(|p| p.enabled).collect();

        if enabled_projects.is_empty() {
            debug!("No enabled projects available");
            return Ok(None);
        }

        // Try to get work from projects (prioritize by priority)
        let mut sorted_projects: Vec<_> = enabled_projects.iter().collect();
        sorted_projects.sort_by(|a, b| b.priority.cmp(&a.priority));

        for project in sorted_projects {
            // Acquire a read lock on the boinc client and call fetch_work
            let client_guard = self.boinc_client.read().await;
            match client_guard.fetch_work(&project.name).await {
                Ok(work_units) => {
                    for work in work_units {
                        // Check if work meets minimum requirements
                        if work.cpu_time >= project.min_cpu_time {
                            // Check for duplicate assignment using global registry
                            if self
                                .try_assign_work_exclusively(
                                    &work.task_id,
                                    &project.name,
                                    user_id,
                                    miner_location,
                                )
                                .await?
                            {
                                // Create work assignment
                                let assignment = WorkAssignment {
                                    work_id: work.task_id.clone(),
                                    project_name: project.name.clone(),
                                    assigned_to: user_id.to_string(),
                                    assigned_at: Utc::now(),
                                    deadline: Utc::now() + Duration::hours(24), // 24 hour deadline
                                    status: WorkStatus::Assigned,
                                };

                                let mut assignments = self.work_assignments.write().await;
                                assignments.insert(work.task_id.clone(), assignment);

                                info!(
                                    "Assigned work {} from {} to {} (location: {:?})",
                                    work.task_id, project.name, user_id, miner_location
                                );
                                return Ok(Some(work));
                            } else {
                                debug!(
                                    "Work {} already assigned or locked, skipping",
                                    work.task_id
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to fetch work from {}: {}", project.name, e);
                    continue;
                }
            }
        }

        debug!("No suitable work found for user: {}", user_id);
        Ok(None)
    }

    /// Try to assign work exclusively using global registry and locks
    async fn try_assign_work_exclusively(
        &self,
        work_id: &str,
        project_name: &str,
        user_id: &str,
        miner_location: Option<&str>,
    ) -> Result<bool> {
        let mut global_registry = self.global_work_registry.write().await;

        // Check if work is already in global registry
        if let Some(existing) = global_registry.get(work_id) {
            match existing.status {
                GlobalWorkStatus::Available => {
                    // Work is available, try to assign it
                }
                GlobalWorkStatus::Assigned | GlobalWorkStatus::InProgress => {
                    // Work already assigned, cannot assign again
                    return Ok(false);
                }
                GlobalWorkStatus::Completed
                | GlobalWorkStatus::Failed
                | GlobalWorkStatus::Expired => {
                    // Work finished, should not be reassigned
                    return Ok(false);
                }
                GlobalWorkStatus::DuplicateDetected => {
                    // Duplicate detected, do not assign
                    return Ok(false);
                }
            }
        }

        // Create or update global work assignment
        let location_hints = if let Some(loc) = miner_location {
            vec![loc.to_string()]
        } else {
            vec![]
        };

        let global_assignment = GlobalWorkAssignment {
            work_id: work_id.to_string(),
            project_name: project_name.to_string(),
            assigned_to: Some(user_id.to_string()),
            assigned_at: Some(Utc::now()),
            deadline: Utc::now() + Duration::hours(24),
            status: GlobalWorkStatus::Assigned,
            location_hints,
            assignment_lock: None,
            lock_expires: None,
        };

        global_registry.insert(work_id.to_string(), global_assignment);

        // Create allocation lock for this assignment
        let lock_id = format!("lock_{}_{}", work_id, user_id);
        let allocation_lock = WorkAllocationLock {
            lock_id: lock_id.clone(),
            work_id: work_id.to_string(),
            miner_id: user_id.to_string(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1), // 1 hour lock
            location: miner_location.map(|s| s.to_string()),
        };

        let mut allocation_locks = self.allocation_locks.write().await;
        allocation_locks.insert(lock_id.clone(), allocation_lock);

        // Track active locks for this work
        let mut active_locks = self.active_locks.write().await;
        active_locks
            .entry(work_id.to_string())
            .or_insert_with(HashSet::new)
            .insert(lock_id.clone());

        info!(
            "Created exclusive assignment for work {} to user {} with lock {}",
            work_id, user_id, lock_id
        );
        Ok(true)
    }

    /// Submit completed work with duplicate prevention
    pub async fn submit_work(
        &self,
        user_id: &str,
        work: BoincWork,
        _result_data: Vec<u8>,
    ) -> Result<WorkReceipt> {
        debug!("Submitting work {} for user {}", work.task_id, user_id);

        // Verify work assignment and check for duplicates
        {
            let assignments = self.work_assignments.read().await;
            let assignment = assignments.get(&work.task_id).ok_or_else(|| {
                anyhow::anyhow!("Work {} not assigned to {}", work.task_id, user_id)
            })?;

            if assignment.assigned_to != user_id {
                return Err(anyhow::anyhow!(
                    "Work {} not assigned to user {}",
                    work.task_id,
                    user_id
                ));
            }

            if matches!(assignment.status, WorkStatus::Completed) {
                return Err(anyhow::anyhow!("Work {} already completed", work.task_id));
            }

            // Check deadline
            if Utc::now() > assignment.deadline {
                // Acquire write to set expired
                let mut assignments = self.work_assignments.write().await;
                if let Some(assignment) = assignments.get_mut(&work.task_id) {
                    assignment.status = WorkStatus::Expired;
                }
                // Update global registry
                self.update_global_work_status(&work.task_id, GlobalWorkStatus::Expired)
                    .await?;
                return Err(anyhow::anyhow!("Work {} deadline exceeded", work.task_id));
            }

            // Check for duplicate submission using global registry
            if let Some(global_assignment) =
                self.global_work_registry.read().await.get(&work.task_id)
            {
                match global_assignment.status {
                    GlobalWorkStatus::Completed => {
                        warn!(
                            "Duplicate submission detected for work {} - already completed",
                            work.task_id
                        );
                        return Err(anyhow::anyhow!(
                            "Work {} already completed by another miner",
                            work.task_id
                        ));
                    }
                    GlobalWorkStatus::DuplicateDetected => {
                        warn!("Duplicate submission blocked for work {}", work.task_id);
                        return Err(anyhow::anyhow!("Duplicate work submission detected"));
                    }
                    _ => {} // Continue with submission
                }
            }
        }

        // Create work receipt
        let mut receipt = WorkReceipt::new(
            work.task_id.clone(),
            user_id.to_string(),
            work.project_name.clone(),
            work.cpu_time,
            work.credit_granted,
        );

        // Sign receipt
        receipt.sign(&self.crypto, "oracle")?;

        // Update assignment status
        let mut assignments = self.work_assignments.write().await;
        if let Some(assignment) = assignments.get_mut(&work.task_id) {
            assignment.status = WorkStatus::Completed;
        }

        // Update global registry to mark as completed
        self.update_global_work_status(&work.task_id, GlobalWorkStatus::Completed)
            .await?;

        // Release allocation locks for this work
        self.release_work_allocation_locks(&work.task_id).await?;

        // Update daily credits
        let mut daily_credits = self.daily_credits.write().await;
        let current_credits = daily_credits.entry(user_id.to_string()).or_insert(0.0);
        *current_credits += work.credit_granted;

        info!(
            "Successfully submitted work {} for user {} (duplicate prevention active)",
            work.task_id, user_id
        );
        Ok(receipt)
    }

    /// Update global work status
    async fn update_global_work_status(
        &self,
        work_id: &str,
        status: GlobalWorkStatus,
    ) -> Result<()> {
        let mut global_registry = self.global_work_registry.write().await;
        if let Some(assignment) = global_registry.get_mut(work_id) {
            assignment.status = status.clone();
            debug!("Updated global status for work {} to {:?}", work_id, status);
        }
        Ok(())
    }

    /// Release allocation locks for completed work
    async fn release_work_allocation_locks(&self, work_id: &str) -> Result<()> {
        let mut active_locks = self.active_locks.write().await;
        if let Some(lock_ids) = active_locks.remove(work_id) {
            let mut allocation_locks = self.allocation_locks.write().await;
            for lock_id in lock_ids {
                allocation_locks.remove(&lock_id);
                debug!("Released allocation lock {} for work {}", lock_id, work_id);
            }
        }
        Ok(())
    }

    /// Get project statistics
    pub async fn get_project_stats(&self, project_name: &str) -> Result<ProjectStats> {
        let projects = self.projects.read().await;
        let project: &ProjectConfig = projects
            .get(project_name)
            .ok_or_else(|| anyhow::anyhow!("Project {} not found", project_name))?;

        let assignments = self.work_assignments.read().await;
        let project_assignments: Vec<_> = assignments
            .values()
            .filter(|a| a.project_name == project_name)
            .collect();

        let completed = project_assignments
            .iter()
            .filter(|a| matches!(a.status, WorkStatus::Completed))
            .count();

        let in_progress = project_assignments
            .iter()
            .filter(|a| matches!(a.status, WorkStatus::InProgress))
            .count();

        let failed = project_assignments
            .iter()
            .filter(|a| matches!(a.status, WorkStatus::Failed))
            .count();

        Ok(ProjectStats {
            project_name: project_name.to_string(),
            total_assignments: project_assignments.len(),
            completed,
            in_progress,
            failed,
            credit_multiplier: project.credit_multiplier,
            enabled: project.enabled,
        })
    }

    /// Get user statistics
    pub async fn get_user_stats(&self, user_id: &str) -> Result<UserStats> {
        let assignments = self.work_assignments.read().await;
        let user_assignments: Vec<_> = assignments
            .values()
            .filter(|a| a.assigned_to == user_id)
            .collect();

        let completed = user_assignments
            .iter()
            .filter(|a| matches!(a.status, WorkStatus::Completed))
            .count();

        let in_progress = user_assignments
            .iter()
            .filter(|a| matches!(a.status, WorkStatus::InProgress))
            .count();

        let failed = user_assignments
            .iter()
            .filter(|a| matches!(a.status, WorkStatus::Failed))
            .count();

        let total_credits = user_assignments
            .iter()
            .filter_map(|a| {
                if matches!(a.status, WorkStatus::Completed) {
                    // We'd need to look up the actual work to get credits
                    // For now, return a placeholder
                    Some(100.0)
                } else {
                    None
                }
            })
            .sum();

        let daily_credits = self.daily_credits.read().await;
        let today_credits = daily_credits.get(user_id).copied().unwrap_or(0.0);

        Ok(UserStats {
            user_id: user_id.to_string(),
            total_assignments: user_assignments.len(),
            completed,
            in_progress,
            failed,
            total_credits,
            today_credits,
        })
    }

    /// Check if user is within daily credit limit
    async fn check_daily_limit(&self, user_id: &str) -> Result<bool> {
        // Reset daily credits if it's a new day
        let now = Utc::now();
        let mut last_reset = self.last_reset.write().await;

        if now.date_naive() != last_reset.date_naive() {
            let mut daily_credits = self.daily_credits.write().await;
            daily_credits.clear();
            *last_reset = now;
        }

        let daily_credits = self.daily_credits.read().await;
        let current_credits = daily_credits.get(user_id).copied().unwrap_or(0.0);

        // Check against project limits (simplified - use first enabled project)
        let projects = self.projects.read().await;
        let max_daily = projects
            .values()
            .filter(|p| p.enabled)
            .map(|p| p.max_daily_credits)
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(1000.0); // Default limit

        Ok(current_credits < max_daily)
    }

    /// Get all registered project names
    pub async fn get_project_names(&self) -> Vec<String> {
        let projects = self.projects.read().await;
        projects.keys().cloned().collect()
    }

    /// Check for duplicate work assignments across the network
    pub async fn check_duplicate_assignments(&self, work_id: &str) -> Result<bool> {
        let global_registry = self.global_work_registry.read().await;
        if let Some(assignment) = global_registry.get(work_id) {
            match assignment.status {
                GlobalWorkStatus::Assigned | GlobalWorkStatus::InProgress => {
                    // Work is actively assigned, check if it's a duplicate
                    Ok(true)
                }
                GlobalWorkStatus::DuplicateDetected => {
                    // Explicitly marked as duplicate
                    Ok(true)
                }
                _ => Ok(false),
            }
        } else {
            Ok(false)
        }
    }

    /// Mark work as duplicate detected
    pub async fn mark_work_duplicate(&self, work_id: &str) -> Result<()> {
        let mut global_registry = self.global_work_registry.write().await;
        if let Some(assignment) = global_registry.get_mut(work_id) {
            assignment.status = GlobalWorkStatus::DuplicateDetected;
            warn!("Marked work {} as duplicate detected", work_id);
        }
        Ok(())
    }

    /// Get work allocation statistics for monitoring
    pub async fn get_allocation_stats(&self) -> Result<AllocationStats> {
        let global_registry = self.global_work_registry.read().await;
        let allocation_locks = self.allocation_locks.read().await;

        let total_work = global_registry.len();
        let assigned_work = global_registry
            .values()
            .filter(|a| {
                matches!(
                    a.status,
                    GlobalWorkStatus::Assigned | GlobalWorkStatus::InProgress
                )
            })
            .count();
        let completed_work = global_registry
            .values()
            .filter(|a| matches!(a.status, GlobalWorkStatus::Completed))
            .count();
        let duplicate_work = global_registry
            .values()
            .filter(|a| matches!(a.status, GlobalWorkStatus::DuplicateDetected))
            .count();
        let active_locks = allocation_locks.len();

        Ok(AllocationStats {
            total_work,
            assigned_work,
            completed_work,
            duplicate_work,
            active_locks,
        })
    }

    /// Clean up expired locks and assignments
    pub async fn cleanup_expired_allocations(&self) -> Result<()> {
        let now = Utc::now();
        let mut global_registry = self.global_work_registry.write().await;
        let mut allocation_locks = self.allocation_locks.write().await;
        let mut active_locks = self.active_locks.write().await;

        // Clean up expired locks
        let expired_locks: Vec<String> = allocation_locks
            .iter()
            .filter(|(_, lock)| lock.expires_at < now)
            .map(|(id, _)| id.clone())
            .collect();

        for lock_id in &expired_locks {
            if let Some(lock) = allocation_locks.remove(lock_id) {
                // Remove from active locks set
                if let Some(work_locks) = active_locks.get_mut(&lock.work_id) {
                    work_locks.remove(lock_id);
                    if work_locks.is_empty() {
                        active_locks.remove(&lock.work_id);
                    }
                }
                debug!(
                    "Cleaned up expired lock {} for work {}",
                    lock_id, lock.work_id
                );
            }
        }

        // Clean up expired assignments (older than 7 days)
        let expired_assignments: Vec<String> = global_registry
            .iter()
            .filter(|(_, assignment)| {
                assignment.deadline < now - Duration::days(7)
                    && matches!(
                        assignment.status,
                        GlobalWorkStatus::Expired | GlobalWorkStatus::Failed
                    )
            })
            .map(|(id, _)| id.clone())
            .collect();

        for work_id in &expired_assignments {
            global_registry.remove(work_id);
            debug!("Cleaned up expired assignment for work {}", work_id);
        }

        if !expired_locks.is_empty() || !expired_assignments.is_empty() {
            info!(
                "Cleaned up {} expired locks and {} expired assignments",
                expired_locks.len(),
                expired_assignments.len()
            );
        }

        Ok(())
    }

    /// Generate a key pair for an entity
    pub fn generate_keypair(&mut self, entity_id: &str) -> Result<VerifyingKey> {
        self.crypto.generate_keypair(entity_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectStats {
    pub project_name: String,
    pub total_assignments: usize,
    pub completed: usize,
    pub in_progress: usize,
    pub failed: usize,
    pub credit_multiplier: f64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStats {
    pub user_id: String,
    pub total_assignments: usize,
    pub completed: usize,
    pub in_progress: usize,
    pub failed: usize,
    pub total_credits: f64,
    pub today_credits: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationStats {
    pub total_work: usize,
    pub assigned_work: usize,
    pub completed_work: usize,
    pub duplicate_work: usize,
    pub active_locks: usize,
}

impl Default for ProjectManager {
    fn default() -> Self {
        Self::new()
    }
}
