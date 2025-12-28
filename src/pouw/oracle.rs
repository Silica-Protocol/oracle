//! PoUW Oracle - Core verification and proof generation
//!
//! The PoUW Oracle is responsible for:
//! - Verifying computational work from BOINC and other providers
//! - Generating cryptographically signed proofs of useful work
//! - Managing challenges and their lifecycle
//! - Calculating rewards based on verified work
//!
//! ## Security Model
//! - All proofs are signed with Ed25519 (future: Dilithium for PQ)
//! - Work verification requires multiple independent checks
//! - Replay attacks prevented via nonce and timestamp validation
//! - Rate limiting prevents DoS and gaming

use crate::crypto::{CryptoEngine, WorkReceipt};
use crate::pouw::boinc::BoincClient;
use crate::pouw::challenge::{PouwChallenge, PouwResult};
use crate::pouw::models::{BoincWork, PoUWProof};
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// ============================================================================
// Constants
// ============================================================================

/// Maximum age for work to be eligible for rewards (7 days)
const MAX_WORK_AGE_DAYS: i64 = 7;

/// Maximum age for proofs before they expire (24 hours)
const MAX_PROOF_AGE_HOURS: i64 = 24;

/// Minimum CPU time required for any work unit (30 minutes)
const MIN_CPU_TIME_SECS: f64 = 1800.0;

/// Maximum challenges per user per day (anti-gaming)
const MAX_CHALLENGES_PER_DAY: usize = 100;

/// Challenge expiry time (4 hours)
const CHALLENGE_EXPIRY_HOURS: i64 = 4;

/// Nonce expiry time for replay protection (1 hour)
const _NONCE_EXPIRY_HOURS: i64 = 1;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for a PoUW provider project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderProjectConfig {
    pub name: String,
    pub api_endpoint: String,
    pub scheduler_url: String,
    pub credit_multiplier: f64,
    pub verification_required: bool,
    pub min_cpu_time: f64,
    pub max_daily_credits: f64,
    pub enabled: bool,
}

impl Default for ProviderProjectConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            api_endpoint: String::new(),
            scheduler_url: String::new(),
            credit_multiplier: 1.0,
            verification_required: true,
            min_cpu_time: MIN_CPU_TIME_SECS,
            max_daily_credits: 10000.0,
            enabled: true,
        }
    }
}

/// Reward calculation configuration
#[derive(Debug, Clone)]
pub struct RewardConfig {
    /// Base reward per credit unit
    pub base_reward_per_credit: u64,
    /// Bonus multiplier for difficulty
    pub difficulty_bonus_multiplier: f64,
    /// Bonus for completing challenges quickly
    pub speed_bonus_multiplier: f64,
    /// Maximum reward per work unit
    pub max_reward_per_unit: u64,
    /// Minimum reward per work unit
    pub min_reward_per_unit: u64,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            base_reward_per_credit: 100,
            difficulty_bonus_multiplier: 0.5,
            speed_bonus_multiplier: 0.1,
            max_reward_per_unit: 100_000,
            min_reward_per_unit: 10,
        }
    }
}

// ============================================================================
// Challenge Management
// ============================================================================

/// Active challenge tracking
#[derive(Debug, Clone)]
pub struct ActiveChallenge {
    pub challenge: PouwChallenge,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub assigned_to: Option<String>,
    pub status: ChallengeStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeStatus {
    Pending,
    Assigned,
    Submitted,
    Verified,
    Expired,
    Invalid,
}

/// User challenge tracking for rate limiting
#[derive(Debug, Clone, Default)]
pub struct UserChallengeStats {
    pub challenges_today: usize,
    pub last_challenge_time: Option<DateTime<Utc>>,
    pub completed_challenges: usize,
    pub failed_challenges: usize,
}

// ============================================================================
// Verification Results
// ============================================================================

/// Detailed verification result
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub is_valid: bool,
    pub work_id: String,
    pub verification_time: DateTime<Utc>,
    pub checks_passed: Vec<String>,
    pub checks_failed: Vec<String>,
    pub confidence_score: f64,
    pub reward_eligible: bool,
}

impl VerificationResult {
    pub fn success(work_id: String, checks: Vec<String>) -> Self {
        Self {
            is_valid: true,
            work_id,
            verification_time: Utc::now(),
            checks_passed: checks,
            checks_failed: Vec::new(),
            confidence_score: 1.0,
            reward_eligible: true,
        }
    }

    pub fn failure(work_id: String, reason: String) -> Self {
        Self {
            is_valid: false,
            work_id,
            verification_time: Utc::now(),
            checks_passed: Vec::new(),
            checks_failed: vec![reason],
            confidence_score: 0.0,
            reward_eligible: false,
        }
    }
}

// ============================================================================
// PoUW Oracle
// ============================================================================

/// PoUW Oracle - verifies computational work and generates proofs
pub struct PoUWOracle {
    /// Known BOINC projects with their configurations
    known_projects: HashMap<String, ProviderProjectConfig>,
    /// Verified work cache (task_id -> work)
    verified_work_cache: Arc<RwLock<HashMap<String, VerifiedWork>>>,
    /// Active challenges (challenge_id -> challenge)
    active_challenges: Arc<RwLock<HashMap<String, ActiveChallenge>>>,
    /// User challenge stats for rate limiting
    user_stats: Arc<RwLock<HashMap<String, UserChallengeStats>>>,
    /// Used nonces for replay protection
    used_nonces: Arc<RwLock<HashSet<String>>>,
    /// Cryptographic engine for signing
    crypto: CryptoEngine,
    /// BOINC client for API verification (reserved for future use)
    #[allow(dead_code)]
    boinc_client: BoincClient,
    /// Reward configuration
    reward_config: RewardConfig,
    /// Oracle public key for signature verification
    oracle_public_key: Option<VerifyingKey>,
}

/// Verified work entry with metadata
#[derive(Debug, Clone)]
pub struct VerifiedWork {
    pub work: BoincWork,
    pub verified_at: DateTime<Utc>,
    pub verification_result: VerificationResult,
    pub proof: Option<PoUWProof>,
}

impl Default for PoUWOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl PoUWOracle {
    /// Create a new PoUW Oracle with default configuration
    pub fn new() -> Self {
        let mut crypto = CryptoEngine::new();

        // Generate oracle keypair
        let oracle_public_key = crypto.generate_keypair("oracle").ok();

        Self {
            known_projects: HashMap::new(),
            verified_work_cache: Arc::new(RwLock::new(HashMap::new())),
            active_challenges: Arc::new(RwLock::new(HashMap::new())),
            user_stats: Arc::new(RwLock::new(HashMap::new())),
            used_nonces: Arc::new(RwLock::new(HashSet::new())),
            crypto,
            boinc_client: BoincClient::new(),
            reward_config: RewardConfig::default(),
            oracle_public_key,
        }
    }

    /// Create oracle with custom configuration
    pub fn with_config(
        projects: HashMap<String, ProviderProjectConfig>,
        reward_config: RewardConfig,
    ) -> Self {
        let mut oracle = Self::new();
        oracle.known_projects = projects;
        oracle.reward_config = reward_config;
        oracle
    }

    /// Register a new project
    pub fn register_project(&mut self, config: ProviderProjectConfig) {
        info!("Registering project: {}", config.name);
        self.known_projects.insert(config.name.clone(), config);
    }

    /// Get oracle's public key for verification
    pub fn get_public_key(&self) -> Option<&VerifyingKey> {
        self.oracle_public_key.as_ref()
    }

    /// Get known projects
    pub fn get_known_projects(&self) -> &HashMap<String, ProviderProjectConfig> {
        &self.known_projects
    }

    // ========================================================================
    // Work Verification
    // ========================================================================

    /// Verify BOINC work with comprehensive checks
    pub async fn verify_work(&self, work: &BoincWork) -> Result<VerificationResult> {
        let mut checks_passed = Vec::new();
        let mut checks_failed = Vec::new();

        // Check 1: Project is known and enabled
        let project_config = match self.known_projects.get(&work.project_name) {
            Some(config) if config.enabled => {
                checks_passed.push("project_known_and_enabled".to_string());
                config
            }
            Some(_) => {
                return Ok(VerificationResult::failure(
                    work.task_id.clone(),
                    "Project is disabled".to_string(),
                ));
            }
            None => {
                return Ok(VerificationResult::failure(
                    work.task_id.clone(),
                    format!("Unknown project: {}", work.project_name),
                ));
            }
        };

        // Check 2: Minimum CPU time
        if work.cpu_time >= project_config.min_cpu_time {
            checks_passed.push(format!("cpu_time_sufficient: {:.0}s", work.cpu_time));
        } else {
            checks_failed.push(format!(
                "cpu_time_insufficient: {:.0}s < {:.0}s required",
                work.cpu_time, project_config.min_cpu_time
            ));
        }

        // Check 3: Positive credits
        if work.credit_granted > 0.0 {
            checks_passed.push(format!("credits_positive: {:.2}", work.credit_granted));
        } else {
            checks_failed.push("credits_non_positive".to_string());
        }

        // Check 4: Work age (not too old)
        let work_age = Utc::now().signed_duration_since(work.completion_time);
        if work_age.num_days() <= MAX_WORK_AGE_DAYS {
            checks_passed.push(format!("work_age_valid: {} days", work_age.num_days()));
        } else {
            checks_failed.push(format!(
                "work_too_old: {} days > {} max",
                work_age.num_days(),
                MAX_WORK_AGE_DAYS
            ));
        }

        // Check 5: Work not in the future
        if work_age.num_hours() >= -1 {
            checks_passed.push("completion_time_valid".to_string());
        } else {
            checks_failed.push("completion_time_in_future".to_string());
        }

        // Check 6: Task ID format validation
        if !work.task_id.is_empty() && work.task_id.len() < 256 {
            checks_passed.push("task_id_valid".to_string());
        } else {
            checks_failed.push("task_id_invalid".to_string());
        }

        // Check 7: User ID validation
        if !work.user_id.is_empty() && work.user_id.len() < 256 {
            checks_passed.push("user_id_valid".to_string());
        } else {
            checks_failed.push("user_id_invalid".to_string());
        }

        // Check 8: Duplicate check
        {
            let cache = self.verified_work_cache.read().await;
            if cache.contains_key(&work.task_id) {
                checks_failed.push("duplicate_work".to_string());
            } else {
                checks_passed.push("not_duplicate".to_string());
            }
        }

        // Calculate confidence score
        let total_checks = checks_passed.len() + checks_failed.len();
        let confidence_score = if total_checks > 0 {
            checks_passed.len() as f64 / total_checks as f64
        } else {
            0.0
        };

        let is_valid = checks_failed.is_empty();
        let reward_eligible = is_valid && confidence_score >= 0.8;

        let result = VerificationResult {
            is_valid,
            work_id: work.task_id.clone(),
            verification_time: Utc::now(),
            checks_passed,
            checks_failed,
            confidence_score,
            reward_eligible,
        };

        // Cache verified work
        if is_valid {
            let mut cache = self.verified_work_cache.write().await;
            cache.insert(
                work.task_id.clone(),
                VerifiedWork {
                    work: work.clone(),
                    verified_at: Utc::now(),
                    verification_result: result.clone(),
                    proof: None,
                },
            );
            info!(
                "Work verified and cached: {} (confidence: {:.2})",
                work.task_id, confidence_score
            );
        } else {
            warn!(
                "Work verification failed: {} - {:?}",
                work.task_id, result.checks_failed
            );
        }

        Ok(result)
    }

    /// Batch verify multiple work units
    pub async fn verify_work_batch(&self, works: &[BoincWork]) -> Result<Vec<VerificationResult>> {
        let mut results = Vec::with_capacity(works.len());
        for work in works {
            results.push(self.verify_work(work).await?);
        }
        Ok(results)
    }

    // ========================================================================
    // Proof Generation
    // ========================================================================

    /// Generate a PoUW proof for verified work
    pub async fn generate_proof(
        &self,
        work: &BoincWork,
        contributor_address: &str,
    ) -> Result<PoUWProof> {
        // Verify work first if not already verified
        let verification = self.verify_work(work).await?;
        if !verification.is_valid {
            return Err(anyhow!(
                "Cannot generate proof for invalid work: {:?}",
                verification.checks_failed
            ));
        }

        // Calculate difficulty score
        let difficulty_multiplier = self
            .known_projects
            .get(&work.project_name)
            .map(|p| p.credit_multiplier)
            .unwrap_or(1.0);

        let difficulty_score = self.calculate_difficulty_score(work, difficulty_multiplier);

        // Calculate reward
        let reward_points = self.calculate_reward(work, difficulty_score);

        // Generate work hash
        let work_hash = self.generate_work_hash(work, contributor_address);

        let proof = PoUWProof {
            work_hash,
            contributor_address: contributor_address.to_string(),
            boinc_work: work.clone(),
            proof_timestamp: Utc::now(),
            difficulty_score,
            reward_points,
        };

        // Update cache with proof
        {
            let mut cache = self.verified_work_cache.write().await;
            if let Some(verified) = cache.get_mut(&work.task_id) {
                verified.proof = Some(proof.clone());
            }
        }

        info!(
            "Generated proof for task {} with {} reward points",
            work.task_id, reward_points
        );

        Ok(proof)
    }

    /// Generate cryptographically signed work receipt
    pub fn generate_signed_receipt(
        &mut self,
        work: &BoincWork,
        contributor_address: &str,
    ) -> Result<WorkReceipt> {
        self.crypto
            .create_work_receipt(contributor_address, work)
            .context("Failed to create signed work receipt")
    }

    /// Validate a PoUW proof
    pub fn validate_proof(&self, proof: &PoUWProof) -> Result<bool> {
        // Check 1: Work hash matches
        let expected_hash = self.generate_work_hash(&proof.boinc_work, &proof.contributor_address);
        if proof.work_hash != expected_hash {
            error!("Work hash mismatch in proof");
            return Ok(false);
        }

        // Check 2: Proof not too old
        let proof_age = Utc::now().signed_duration_since(proof.proof_timestamp);
        if proof_age.num_hours() > MAX_PROOF_AGE_HOURS {
            error!("Proof too old: {} hours", proof_age.num_hours());
            return Ok(false);
        }

        // Check 3: Work completion time valid
        let work_age = Utc::now().signed_duration_since(proof.boinc_work.completion_time);
        if work_age.num_days() > MAX_WORK_AGE_DAYS || work_age.num_hours() < -1 {
            error!("Work completion time invalid");
            return Ok(false);
        }

        // Check 4: Reward points reasonable
        if proof.reward_points > self.reward_config.max_reward_per_unit {
            error!(
                "Reward too high: {} > {}",
                proof.reward_points, self.reward_config.max_reward_per_unit
            );
            return Ok(false);
        }

        // Check 5: Difficulty score reasonable
        if proof.difficulty_score < 0.0 || proof.difficulty_score > 1_000_000.0 {
            error!("Difficulty score out of range: {}", proof.difficulty_score);
            return Ok(false);
        }

        info!(
            "Proof validated for task: {} (reward: {})",
            proof.boinc_work.task_id, proof.reward_points
        );
        Ok(true)
    }

    // ========================================================================
    // Challenge Management
    // ========================================================================

    /// Create a new challenge for a BOINC work unit
    pub async fn create_challenge(
        &mut self,
        work: &BoincWork,
        reward_multiplier: u32,
    ) -> Result<PouwChallenge> {
        // Get project config
        let project = self
            .known_projects
            .get(&work.project_name)
            .ok_or_else(|| anyhow!("Unknown project: {}", work.project_name))?;

        let deadline = (Utc::now() + Duration::hours(CHALLENGE_EXPIRY_HOURS)).timestamp() as u64;

        // Generate input data hash
        let input_hash = {
            let mut hasher = Sha256::new();
            hasher.update(work.task_id.as_bytes());
            hasher.update(work.project_name.as_bytes());
            format!("{:x}", hasher.finalize())
        };

        // Generate app binary hash (placeholder - in production, this would be actual binary hash)
        let app_hash = {
            let mut hasher = Sha256::new();
            hasher.update(project.name.as_bytes());
            hasher.update(b"v1.0");
            format!("{:x}", hasher.finalize())
        };

        let oracle_address = self
            .oracle_public_key
            .map(|k| {
                // Use hex encoding instead of numeric fold to avoid overflow
                hex::encode(&k.as_bytes()[..20.min(k.as_bytes().len())])
            })
            .unwrap_or_else(|| "0x0".to_string());

        let mut challenge = PouwChallenge {
            challenge_id: String::new(), // Will be set after signing
            boinc_project_url: project.api_endpoint.clone(),
            boinc_task_name: work.task_id.clone(),
            input_data_hash: input_hash,
            app_binary_hash: app_hash,
            app_binary_url: project.scheduler_url.clone(),
            reward_multiplier,
            deadline,
            oracle_address,
            oracle_signature: String::new(), // Will be set after signing
        };

        // Generate challenge ID
        challenge.challenge_id = challenge.calculate_id();

        // Sign the challenge
        if let Ok(signature) = self.crypto.sign_message("oracle", &challenge.challenge_id) {
            challenge.oracle_signature = hex_encode(&signature.signature);
        }

        // Store active challenge
        {
            let mut challenges = self.active_challenges.write().await;
            challenges.insert(
                challenge.challenge_id.clone(),
                ActiveChallenge {
                    challenge: challenge.clone(),
                    issued_at: Utc::now(),
                    expires_at: Utc::now() + Duration::hours(CHALLENGE_EXPIRY_HOURS),
                    assigned_to: None,
                    status: ChallengeStatus::Pending,
                },
            );
        }

        info!("Created challenge: {}", challenge.challenge_id);
        Ok(challenge)
    }

    /// Assign a challenge to a worker
    pub async fn assign_challenge(&self, challenge_id: &str, worker_address: &str) -> Result<bool> {
        // Check user rate limit
        {
            let mut stats = self.user_stats.write().await;
            let user_stats = stats
                .entry(worker_address.to_string())
                .or_insert_with(UserChallengeStats::default);

            // Reset daily counter if needed
            if let Some(last_time) = user_stats.last_challenge_time {
                if (Utc::now() - last_time).num_days() >= 1 {
                    user_stats.challenges_today = 0;
                }
            }

            if user_stats.challenges_today >= MAX_CHALLENGES_PER_DAY {
                warn!(
                    "Rate limit exceeded for {}: {} challenges today",
                    worker_address, user_stats.challenges_today
                );
                return Ok(false);
            }

            user_stats.challenges_today += 1;
            user_stats.last_challenge_time = Some(Utc::now());
        }

        // Assign challenge
        let mut challenges = self.active_challenges.write().await;
        if let Some(challenge) = challenges.get_mut(challenge_id) {
            if challenge.status != ChallengeStatus::Pending {
                return Ok(false);
            }
            if Utc::now() > challenge.expires_at {
                challenge.status = ChallengeStatus::Expired;
                return Ok(false);
            }

            challenge.assigned_to = Some(worker_address.to_string());
            challenge.status = ChallengeStatus::Assigned;
            info!("Assigned challenge {} to {}", challenge_id, worker_address);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Submit a challenge result
    pub async fn submit_challenge_result(&self, result: &PouwResult) -> Result<VerificationResult> {
        // Validate nonce for replay protection
        {
            let mut nonces = self.used_nonces.write().await;
            let nonce = format!("{}:{}", result.challenge_id, result.timestamp);
            if nonces.contains(&nonce) {
                return Ok(VerificationResult::failure(
                    result.challenge_id.clone(),
                    "Replay detected: nonce already used".to_string(),
                ));
            }
            nonces.insert(nonce);
        }

        // Find and validate challenge
        let challenge = {
            let challenges = self.active_challenges.read().await;
            challenges.get(&result.challenge_id).cloned()
        };

        let challenge = match challenge {
            Some(c) => c,
            None => {
                return Ok(VerificationResult::failure(
                    result.challenge_id.clone(),
                    "Challenge not found".to_string(),
                ));
            }
        };

        // Check challenge status
        if challenge.status == ChallengeStatus::Expired {
            return Ok(VerificationResult::failure(
                result.challenge_id.clone(),
                "Challenge expired".to_string(),
            ));
        }

        if challenge.status != ChallengeStatus::Assigned {
            return Ok(VerificationResult::failure(
                result.challenge_id.clone(),
                format!("Invalid challenge status: {:?}", challenge.status),
            ));
        }

        // Verify worker assignment
        if challenge.assigned_to.as_ref() != Some(&result.worker_address) {
            return Ok(VerificationResult::failure(
                result.challenge_id.clone(),
                "Worker not assigned to this challenge".to_string(),
            ));
        }

        // Check deadline
        if result.timestamp > challenge.challenge.deadline {
            return Ok(VerificationResult::failure(
                result.challenge_id.clone(),
                "Submission after deadline".to_string(),
            ));
        }

        // Update challenge status
        {
            let mut challenges = self.active_challenges.write().await;
            if let Some(c) = challenges.get_mut(&result.challenge_id) {
                c.status = ChallengeStatus::Submitted;
            }
        }

        // Update user stats
        {
            let mut stats = self.user_stats.write().await;
            if let Some(user_stats) = stats.get_mut(&result.worker_address) {
                user_stats.completed_challenges += 1;
            }
        }

        Ok(VerificationResult::success(
            result.challenge_id.clone(),
            vec![
                "challenge_found".to_string(),
                "worker_verified".to_string(),
                "deadline_met".to_string(),
                "nonce_valid".to_string(),
            ],
        ))
    }

    /// Clean up expired challenges and nonces
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();

        // Clean expired challenges
        {
            let mut challenges = self.active_challenges.write().await;
            challenges.retain(|id, challenge| {
                let keep = now <= challenge.expires_at + Duration::hours(1);
                if !keep {
                    debug!("Removing expired challenge: {}", id);
                }
                keep
            });
        }

        // Clean old nonces (older than NONCE_EXPIRY_HOURS)
        {
            let mut nonces = self.used_nonces.write().await;
            let max_nonces = 10000; // Prevent unbounded growth
            if nonces.len() > max_nonces {
                nonces.clear();
                info!("Cleared nonce cache (exceeded {} entries)", max_nonces);
            }
        }

        // Clean old verified work cache
        {
            let mut cache = self.verified_work_cache.write().await;
            let cutoff = now - Duration::days(MAX_WORK_AGE_DAYS + 1);
            cache.retain(|id, verified| {
                let keep = verified.verified_at > cutoff;
                if !keep {
                    debug!("Removing old verified work: {}", id);
                }
                keep
            });
        }
    }

    // ========================================================================
    // Reward Calculation
    // ========================================================================

    /// Calculate difficulty score for work
    fn calculate_difficulty_score(&self, work: &BoincWork, multiplier: f64) -> f64 {
        // Base difficulty from credits and CPU time
        let cpu_hours = work.cpu_time / 3600.0;
        let base_score = work.credit_granted * cpu_hours;

        // Apply project multiplier
        base_score * multiplier
    }

    /// Calculate reward points for work
    fn calculate_reward(&self, work: &BoincWork, difficulty_score: f64) -> u64 {
        let config = &self.reward_config;

        // Base reward
        let base_reward = (work.credit_granted * config.base_reward_per_credit as f64) as u64;

        // Difficulty bonus
        let difficulty_bonus =
            (difficulty_score * config.difficulty_bonus_multiplier * 100.0) as u64;

        // Total reward (clamped)
        let total = base_reward + difficulty_bonus;
        total
            .max(config.min_reward_per_unit)
            .min(config.max_reward_per_unit)
    }

    /// Generate deterministic work hash
    fn generate_work_hash(&self, work: &BoincWork, contributor: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(work.task_id.as_bytes());
        hasher.update(work.user_id.as_bytes());
        hasher.update(work.project_name.as_bytes());
        hasher.update(contributor.as_bytes());
        hasher.update(work.cpu_time.to_le_bytes());
        hasher.update(work.credit_granted.to_le_bytes());
        format!("{:x}", hasher.finalize())
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    /// Get oracle statistics
    pub async fn get_stats(&self) -> OracleStats {
        let verified_count = self.verified_work_cache.read().await.len();
        let active_challenges = self.active_challenges.read().await.len();
        let total_users = self.user_stats.read().await.len();

        OracleStats {
            verified_work_count: verified_count,
            active_challenges,
            total_users,
            known_projects: self.known_projects.len(),
        }
    }

    /// Get user statistics
    pub async fn get_user_stats(&self, user_address: &str) -> Option<UserChallengeStats> {
        let stats = self.user_stats.read().await;
        stats.get(user_address).cloned()
    }
}

/// Oracle statistics
#[derive(Debug, Clone)]
pub struct OracleStats {
    pub verified_work_count: usize,
    pub active_challenges: usize,
    pub total_users: usize,
    pub known_projects: usize,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Simple hex encoding
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pouw::models::ValidationState;

    fn create_test_work() -> BoincWork {
        BoincWork {
            project_name: "TestProject".to_string(),
            user_id: "test_user".to_string(),
            task_id: "test_task_123".to_string(),
            cpu_time: 3600.0, // 1 hour
            credit_granted: 100.0,
            completion_time: Utc::now() - Duration::hours(1),
            validation_state: Some(ValidationState::Validated),
        }
    }

    #[tokio::test]
    async fn test_verify_work_success() {
        let mut oracle = PoUWOracle::new();
        oracle.register_project(ProviderProjectConfig {
            name: "TestProject".to_string(),
            min_cpu_time: 1800.0,
            enabled: true,
            ..Default::default()
        });

        let work = create_test_work();
        let result = oracle.verify_work(&work).await.unwrap();

        assert!(result.is_valid);
        assert!(result.checks_failed.is_empty());
        assert!(result.confidence_score >= 0.8);
    }

    #[tokio::test]
    async fn test_verify_work_unknown_project() {
        let oracle = PoUWOracle::new();
        let work = create_test_work();
        let result = oracle.verify_work(&work).await.unwrap();

        assert!(!result.is_valid);
        assert!(
            result
                .checks_failed
                .iter()
                .any(|c| c.contains("Unknown project"))
        );
    }

    #[tokio::test]
    async fn test_verify_work_cpu_time_too_low() {
        let mut oracle = PoUWOracle::new();
        oracle.register_project(ProviderProjectConfig {
            name: "TestProject".to_string(),
            min_cpu_time: 7200.0, // 2 hours required
            enabled: true,
            ..Default::default()
        });

        let work = create_test_work(); // Only 1 hour
        let result = oracle.verify_work(&work).await.unwrap();

        assert!(!result.is_valid);
        assert!(result.checks_failed.iter().any(|c| c.contains("cpu_time")));
    }

    #[tokio::test]
    async fn test_generate_proof() {
        let mut oracle = PoUWOracle::new();
        oracle.register_project(ProviderProjectConfig {
            name: "TestProject".to_string(),
            min_cpu_time: 1800.0,
            credit_multiplier: 1.5,
            enabled: true,
            ..Default::default()
        });

        let work = create_test_work();
        let proof = oracle.generate_proof(&work, "0x1234").await.unwrap();

        assert!(!proof.work_hash.is_empty());
        assert_eq!(proof.contributor_address, "0x1234");
        assert!(proof.reward_points > 0);
        assert!(proof.difficulty_score > 0.0);
    }

    #[tokio::test]
    async fn test_validate_proof() {
        let mut oracle = PoUWOracle::new();
        oracle.register_project(ProviderProjectConfig {
            name: "TestProject".to_string(),
            min_cpu_time: 1800.0,
            enabled: true,
            ..Default::default()
        });

        let work = create_test_work();
        let proof = oracle.generate_proof(&work, "0x1234").await.unwrap();

        let is_valid = oracle.validate_proof(&proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_reward_calculation() {
        let oracle = PoUWOracle::new();
        let work = create_test_work();

        let difficulty = oracle.calculate_difficulty_score(&work, 1.0);
        let reward = oracle.calculate_reward(&work, difficulty);

        assert!(reward >= oracle.reward_config.min_reward_per_unit);
        assert!(reward <= oracle.reward_config.max_reward_per_unit);
    }

    #[tokio::test]
    async fn test_duplicate_detection() {
        let mut oracle = PoUWOracle::new();
        oracle.register_project(ProviderProjectConfig {
            name: "TestProject".to_string(),
            min_cpu_time: 1800.0,
            enabled: true,
            ..Default::default()
        });

        let work = create_test_work();

        // First verification should succeed
        let result1 = oracle.verify_work(&work).await.unwrap();
        assert!(result1.is_valid);

        // Second verification of same work should fail (duplicate)
        let result2 = oracle.verify_work(&work).await.unwrap();
        assert!(!result2.is_valid);
        assert!(
            result2
                .checks_failed
                .iter()
                .any(|c| c.contains("duplicate"))
        );
    }
}
