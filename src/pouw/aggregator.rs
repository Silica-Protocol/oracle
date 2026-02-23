//! PoUW Aggregator - Aggregates work from multiple PoUW providers
//!
//! Collects and validates computational work from BOINC, Folding@Home, and other
//! distributed computing platforms.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::pouw::boinc::{BoincClient, BoincProject};
use crate::pouw::models::{BoincWork, PoUWProof, PoUWServiceConfig, ProjectInfo};
use crate::pouw::oracle::PoUWOracle;

/// Aggregates PoUW from multiple providers
pub struct PoUWAggregator {
    oracle: Arc<RwLock<PoUWOracle>>,
    boinc_client: Arc<RwLock<BoincClient>>,
    services: HashMap<String, PoUWServiceConfig>,
    work_cache: Arc<RwLock<HashMap<String, Vec<BoincWork>>>>,
    /// Track registered Chert addresses for work fetching
    registered_addresses: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl Default for PoUWAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl PoUWAggregator {
    // Get cache statistics for monitoring
    pub async fn get_cache_stats(&self) -> HashMap<String, usize> {
        let cache = self.work_cache.read().await;
        let mut stats = HashMap::new();
        for (user, work_list) in cache.iter() {
            stats.insert(user.clone(), work_list.len());
        }
        stats
    }
    pub fn new() -> Self {
        let oracle = Arc::new(RwLock::new(PoUWOracle::new()));

        let mut boinc_client = BoincClient::new();

        // Load BOINC configuration if available (optional for tests)
        if let Ok(config_str) = std::fs::read_to_string("config.json") {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str) {
                // Load providers from config and add them to BoincClient
                if let Some(providers) = config.get("providers").and_then(|p| p.as_array()) {
                    for provider in providers {
                        if let (Some(name), Some(project_url), Some(user_id), Some(auth_key)) = (
                            provider.get("name").and_then(|n| n.as_str()),
                            provider.get("project_url").and_then(|u| u.as_str()),
                            provider.get("user_id").and_then(|i| i.as_str()),
                            provider.get("auth_key").and_then(|a| a.as_str()),
                        ) {
                            let project = BoincProject {
                                name: name.to_string(),
                                url: project_url.to_string(),
                                user_id: user_id.to_string(),
                                authenticator: auth_key.to_string(),
                            };
                            boinc_client.add_project(project);
                        }
                    }
                }
            }
        }

        let services = HashMap::new(); // Optionally, load from config as well
        Self {
            oracle,
            boinc_client: Arc::new(RwLock::new(boinc_client)),
            services,
            work_cache: Arc::new(RwLock::new(HashMap::new())),
            registered_addresses: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    // Add work to cache from external source (e.g., BOINC proxy)
    pub async fn add_work_to_cache(&self, chert_address: &str, work: Vec<BoincWork>) -> Result<()> {
        let mut cache = self.work_cache.write().await;
        let existing_work = cache
            .entry(chert_address.to_string())
            .or_insert_with(Vec::new);
        existing_work.extend(work.clone());

        info!(
            "Added {} work units to cache for user {} (total cached: {})",
            work.len(),
            chert_address,
            existing_work.len()
        );
        Ok(())
    }

    // Fetch work from all configured providers for a user (config-driven, generic)
    pub async fn fetch_all_user_work(&self, chert_address: &str) -> Result<Vec<BoincWork>> {
        // This method should be called by external services that have already fetched work
        // For now, return empty vec - work should be provided by the calling service
        info!(
            "fetch_all_user_work called for {} - work should be provided by caller",
            chert_address
        );
        Ok(Vec::new())
    }

    // Get available projects (for GUI/CLI selection)
    pub async fn get_available_projects(&self) -> Result<Vec<ProjectInfo>> {
        let _boinc_client = self.boinc_client.read().await;
        // For now, return first configured provider as a ProjectInfo
        // Later: implement proper project discovery in API client
        let projects = vec![ProjectInfo {
            name: "MilkyWay@Home".to_string(),
            description: "Galaxy structure and evolution modeling".to_string(),
            cpu_supported: true,
            gpu_supported: true,
            estimated_runtime: Duration::hours(1),
            priority: 1,
            reward_multiplier: 1.0,
        }];

        info!("Available projects: {}", projects.len());
        Ok(projects)
    }

    // Get current in-flight work for CHERT address
    pub async fn get_current_work(&self, chert_address: &str) -> Result<Vec<BoincWork>> {
        let cache = self.work_cache.read().await;
        let work = cache.get(chert_address).cloned().unwrap_or_default();
        info!("Current work for {}: {} units", chert_address, work.len());
        Ok(work)
    }

    /// Generate PoUW proofs for all cached work
    pub async fn generate_pouw_proofs(&self, chert_address: &str) -> Result<Vec<PoUWProof>> {
        // Get work from cache
        let work_list = {
            let cache = self.work_cache.read().await;
            cache.get(chert_address).cloned().unwrap_or_default()
        };

        let mut proofs = Vec::new();

        for work in work_list {
            // Need to drop oracle lock between iterations for async
            let result = {
                let oracle = self.oracle.read().await;
                oracle.generate_proof(&work, chert_address).await
            };

            match result {
                Ok(proof) => {
                    info!(
                        "Generated PoUW proof for task: {} ({})",
                        work.task_id, work.project_name
                    );
                    proofs.push(proof);
                }
                Err(e) => {
                    error!("Failed to generate proof for {}: {}", work.task_id, e);
                }
            }
        }

        Ok(proofs)
    }

    /// Validate multiple PoUW proofs
    pub async fn validate_pouw_proofs(&self, proofs: &[PoUWProof]) -> Result<Vec<bool>> {
        let oracle = self.oracle.read().await;
        let mut results = Vec::new();

        for proof in proofs {
            match oracle.validate_proof(proof) {
                Ok(valid) => results.push(valid),
                Err(e) => {
                    error!("Proof validation error: {}", e);
                    results.push(false);
                }
            }
        }

        Ok(results)
    }

    /// Get supported services
    pub fn get_supported_services(&self) -> Vec<&PoUWServiceConfig> {
        self.services.values().collect()
    }

    /// Get user statistics
    pub async fn get_user_stats(&self, chert_address: &str) -> Result<UserPoUWStats> {
        let cache = self.work_cache.read().await;
        let empty_vec = Vec::new();
        let work_list = cache.get(chert_address).unwrap_or(&empty_vec);

        let total_work_units = work_list.len();
        let total_cpu_time: f64 = work_list.iter().map(|w| w.cpu_time).sum();
        let total_credits: f64 = work_list.iter().map(|w| w.credit_granted).sum();

        let mut project_stats = HashMap::new();
        for work in work_list {
            let stats = project_stats
                .entry(work.project_name.clone())
                .or_insert(ProjectStats {
                    work_units: 0,
                    cpu_time: 0.0,
                    credits: 0.0,
                });
            stats.work_units += 1;
            stats.cpu_time += work.cpu_time;
            stats.credits += work.credit_granted;
        }

        Ok(UserPoUWStats {
            chert_address: chert_address.to_string(),
            total_work_units,
            total_cpu_time,
            total_credits,
            project_stats,
            last_activity: Utc::now(),
        })
    }

    /// Continuous work fetching (for background daemon)
    pub async fn start_continuous_fetching(&self, interval_minutes: u64) {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(interval_minutes * 60));

        loop {
            interval.tick().await;

            info!("Starting periodic PoUW work fetch...");

            let users: Vec<String> = {
                let addresses_lock = self.registered_addresses.read().await;
                addresses_lock.iter().cloned().collect()
            };

            for chert_address in users {
                match self.fetch_all_user_work(&chert_address).await {
                    Ok(work_count) => {
                        debug!(
                            "Fetched {} work units for {}",
                            work_count.len(),
                            chert_address
                        );
                    }
                    Err(e) => {
                        error!("Failed to fetch work for {}: {}", chert_address, e);
                    }
                }
            }
        }
    }

    /// Verify work and add to cache if valid
    pub async fn verify_and_cache_work(
        &self,
        chert_address: &str,
        work: BoincWork,
    ) -> Result<crate::pouw::oracle::VerificationResult> {
        let oracle = self.oracle.read().await;
        let result = oracle.verify_work(&work).await?;

        if result.is_valid {
            // Add verified work to cache
            let mut cache = self.work_cache.write().await;
            let work_list = cache
                .entry(chert_address.to_string())
                .or_insert_with(Vec::new);
            work_list.push(work);

            info!(
                "Verified and cached work for {}: {} (confidence: {:.2})",
                chert_address, result.work_id, result.confidence_score
            );
        }

        Ok(result)
    }

    /// Get oracle statistics
    pub async fn get_oracle_stats(&self) -> crate::pouw::oracle::OracleStats {
        let oracle = self.oracle.read().await;
        oracle.get_stats().await
    }

    /// Register an address for continuous work fetching
    pub async fn register_address(&self, chert_address: &str) {
        let mut addresses = self.registered_addresses.write().await;
        addresses.insert(chert_address.to_string());
        info!(
            "Registered address for continuous fetching: {}",
            chert_address
        );
    }

    /// Unregister an address from continuous work fetching
    pub async fn unregister_address(&self, chert_address: &str) {
        let mut addresses = self.registered_addresses.write().await;
        addresses.remove(chert_address);
        info!(
            "Unregistered address from continuous fetching: {}",
            chert_address
        );
    }

    /// Get number of registered addresses
    pub async fn get_registered_count(&self) -> usize {
        self.registered_addresses.read().await.len()
    }
}

/// User statistics for PoUW contributions
#[derive(Debug, Clone)]
pub struct UserPoUWStats {
    pub chert_address: String,
    pub total_work_units: usize,
    pub total_cpu_time: f64,
    pub total_credits: f64,
    pub project_stats: HashMap<String, ProjectStats>,
    pub last_activity: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ProjectStats {
    pub work_units: usize,
    pub cpu_time: f64,
    pub credits: f64,
}
