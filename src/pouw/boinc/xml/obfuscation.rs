//! Task ID Obfuscation for Anti-Gaming
//!
//! Obfuscates BOINC work unit and result names using HMAC-based hashing.
//! Each user sees different obfuscated IDs for the same task, preventing:
//! - Task ID enumeration attacks
//! - Result submission for unassigned work
//! - Cross-user result replay
//!
//! ## How It Works
//!
//! ```text
//! Real WU Name: "milkyway_wu_12345"
//! User Auth: "user_auth_abc"
//! Secret Key: [secret bytes]
//!
//! Obfuscated ID = "chert_" + HMAC-SHA256(user_auth || wu_name, secret_key)[0:8].hex()
//! Result: "chert_a1b2c3d4"
//! ```
//!
//! The proxy maintains an in-memory mapping to translate between real and obfuscated IDs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, warn};

/// Configuration for task obfuscation
#[derive(Debug, Clone)]
pub struct ObfuscationConfig {
    /// Secret key for HMAC (should be loaded from secure config)
    pub hmac_key: [u8; 32],

    /// Prefix for obfuscated IDs
    pub id_prefix: String,

    /// Number of hex bytes to use (8 bytes = 16 hex chars)
    pub hash_length: usize,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            hmac_key: [0u8; 32], // Should be overridden with secure key
            id_prefix: "chert_".to_string(),
            hash_length: 8,
        }
    }
}

impl ObfuscationConfig {
    /// Create config with a secret key from environment
    pub fn from_secret(secret: &[u8]) -> Self {
        let mut config = Self::default();
        let key_bytes = Sha256::digest(secret);
        config.hmac_key.copy_from_slice(&key_bytes);
        config
    }
}

/// Mapping between real and obfuscated task IDs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMapping {
    /// The obfuscated task ID shown to user
    pub obfuscated_id: String,

    /// The real BOINC work unit name
    pub real_wu_name: String,

    /// The real BOINC result name (if applicable)
    pub real_result_name: Option<String>,

    /// User this task is assigned to
    pub assigned_to: String,

    /// When this mapping was created
    pub created_at: DateTime<Utc>,

    /// When this mapping expires
    pub expires_at: DateTime<Utc>,

    /// Whether this task has been submitted
    pub submitted: bool,
}

/// Task ID Obfuscator
pub struct TaskObfuscator {
    config: ObfuscationConfig,

    /// Mapping: obfuscated_id -> TaskMapping
    mappings: HashMap<String, TaskMapping>,

    /// Reverse lookup: real_wu_name -> obfuscated_id (for a specific user)
    /// Key format: "{user_auth}:{wu_name}"
    reverse_lookup: HashMap<String, String>,
}

impl TaskObfuscator {
    pub fn new(config: ObfuscationConfig) -> Self {
        Self {
            config,
            mappings: HashMap::new(),
            reverse_lookup: HashMap::new(),
        }
    }

    /// Generate obfuscated ID for a work unit name and user
    pub fn obfuscate_wu_name(&mut self, wu_name: &str, user_auth: &str) -> String {
        let obfuscated = self.compute_obfuscated_id(wu_name, user_auth);

        // Check if we already have a mapping
        let lookup_key = format!("{}:{}", user_auth, wu_name);
        if let Some(existing) = self.reverse_lookup.get(&lookup_key) {
            return existing.clone();
        }

        // Create new mapping
        let mapping = TaskMapping {
            obfuscated_id: obfuscated.clone(),
            real_wu_name: wu_name.to_string(),
            real_result_name: None,
            assigned_to: user_auth.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            submitted: false,
        };

        self.mappings.insert(obfuscated.clone(), mapping);
        self.reverse_lookup.insert(lookup_key, obfuscated.clone());

        debug!(
            obfuscated = %obfuscated,
            real_wu = %wu_name,
            user = %user_auth,
            "Obfuscated work unit name"
        );

        obfuscated
    }

    /// Generate obfuscated ID for a result name and user
    pub fn obfuscate_result_name(
        &mut self,
        result_name: &str,
        wu_name: &str,
        user_auth: &str,
    ) -> String {
        let obfuscated = self.compute_obfuscated_id(result_name, user_auth);

        // Update the mapping to include result name
        if let Some(mapping) = self.mappings.get_mut(&obfuscated) {
            mapping.real_result_name = Some(result_name.to_string());
        } else {
            // Create mapping for result
            let mapping = TaskMapping {
                obfuscated_id: obfuscated.clone(),
                real_wu_name: wu_name.to_string(),
                real_result_name: Some(result_name.to_string()),
                assigned_to: user_auth.to_string(),
                created_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::hours(24),
                submitted: false,
            };

            self.mappings.insert(obfuscated.clone(), mapping);
        }

        obfuscated
    }

    /// Deobfuscate a task ID and verify it belongs to the user
    pub fn deobfuscate_for_user(
        &self,
        obfuscated_id: &str,
        user_auth: &str,
    ) -> Option<&TaskMapping> {
        let mapping = self.mappings.get(obfuscated_id)?;

        // Verify this obfuscated ID belongs to this user
        if mapping.assigned_to != user_auth {
            warn!(
                obfuscated = %obfuscated_id,
                claimed_by = %user_auth,
                assigned_to = %mapping.assigned_to,
                "User attempted to deobfuscate another user's task"
            );
            return None;
        }

        // Check expiration
        if Utc::now() > mapping.expires_at {
            debug!(obfuscated = %obfuscated_id, "Task mapping expired");
            return None;
        }

        Some(mapping)
    }

    /// Mark a task as submitted (prevents replay)
    pub fn mark_submitted(&mut self, obfuscated_id: &str) -> bool {
        if let Some(mapping) = self.mappings.get_mut(obfuscated_id) {
            mapping.submitted = true;
            true
        } else {
            false
        }
    }

    /// Check if a task was already submitted
    pub fn is_submitted(&self, obfuscated_id: &str) -> bool {
        self.mappings
            .get(obfuscated_id)
            .map(|m| m.submitted)
            .unwrap_or(false)
    }

    /// Validate that an obfuscated ID was assigned to a user and not yet submitted
    /// Returns a cloned TaskMapping to avoid lifetime issues
    pub fn validate_submission(
        &mut self,
        obfuscated_id: &str,
        user_auth: &str,
    ) -> Result<TaskMapping, ValidationError> {
        let mapping = self
            .mappings
            .get(obfuscated_id)
            .ok_or(ValidationError::UnknownTask)?;

        if mapping.assigned_to != user_auth {
            return Err(ValidationError::NotAssignedToUser);
        }

        if mapping.submitted {
            return Err(ValidationError::AlreadySubmitted);
        }

        if Utc::now() > mapping.expires_at {
            return Err(ValidationError::Expired);
        }

        Ok(mapping.clone())
    }

    /// Compute the obfuscated ID using HMAC-SHA256
    fn compute_obfuscated_id(&self, input: &str, user_auth: &str) -> String {
        // Simple HMAC-like construction: H(key || user_auth || input)
        let mut hasher = Sha256::new();
        hasher.update(&self.config.hmac_key);
        hasher.update(user_auth.as_bytes());
        hasher.update(input.as_bytes());
        let hash = hasher.finalize();

        // Take first N bytes and convert to hex
        let hex_len = self.config.hash_length * 2;
        let hex: String = hash
            .iter()
            .take(self.config.hash_length)
            .map(|b| format!("{:02x}", b))
            .collect();

        format!(
            "{}{}",
            self.config.id_prefix,
            &hex[..hex_len.min(hex.len())]
        )
    }

    /// Clean up expired mappings
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Utc::now();
        let expired: Vec<String> = self
            .mappings
            .iter()
            .filter(|(_, m)| now > m.expires_at)
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();

        for id in &expired {
            if let Some(mapping) = self.mappings.remove(id) {
                let lookup_key = format!("{}:{}", mapping.assigned_to, mapping.real_wu_name);
                self.reverse_lookup.remove(&lookup_key);
            }
        }

        if count > 0 {
            debug!("Cleaned up {} expired task mappings", count);
        }

        count
    }

    /// Get mapping count (for monitoring)
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
}

/// Validation errors for task submission
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    /// Task ID not recognized
    UnknownTask,
    /// Task was assigned to a different user
    NotAssignedToUser,
    /// Task was already submitted
    AlreadySubmitted,
    /// Task assignment has expired
    Expired,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::UnknownTask => write!(f, "Unknown task ID"),
            ValidationError::NotAssignedToUser => write!(f, "Task not assigned to this user"),
            ValidationError::AlreadySubmitted => write!(f, "Task already submitted"),
            ValidationError::Expired => write!(f, "Task assignment expired"),
        }
    }
}

impl std::error::Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscation_deterministic() {
        let config = ObfuscationConfig::from_secret(b"test_secret");
        let mut obfuscator = TaskObfuscator::new(config);

        let id1 = obfuscator.obfuscate_wu_name("wu_123", "user_abc");
        let id2 = obfuscator.obfuscate_wu_name("wu_123", "user_abc");

        assert_eq!(id1, id2);
        assert!(id1.starts_with("chert_"));
    }

    #[test]
    fn test_obfuscation_user_specific() {
        let config = ObfuscationConfig::from_secret(b"test_secret");
        let mut obfuscator = TaskObfuscator::new(config);

        let id1 = obfuscator.obfuscate_wu_name("wu_123", "user_abc");
        let id2 = obfuscator.obfuscate_wu_name("wu_123", "user_xyz");

        // Same task, different users should have different obfuscated IDs
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_deobfuscation_validation() {
        let config = ObfuscationConfig::from_secret(b"test_secret");
        let mut obfuscator = TaskObfuscator::new(config);

        let obfuscated = obfuscator.obfuscate_wu_name("wu_123", "user_abc");

        // Correct user can deobfuscate
        let result = obfuscator.validate_submission(&obfuscated, "user_abc");
        assert!(result.is_ok());

        // Wrong user cannot
        let result = obfuscator.validate_submission(&obfuscated, "user_xyz");
        assert_eq!(result.unwrap_err(), ValidationError::NotAssignedToUser);
    }

    #[test]
    fn test_prevent_replay() {
        let config = ObfuscationConfig::from_secret(b"test_secret");
        let mut obfuscator = TaskObfuscator::new(config);

        let obfuscated = obfuscator.obfuscate_wu_name("wu_123", "user_abc");

        // First submission succeeds
        let result = obfuscator.validate_submission(&obfuscated, "user_abc");
        assert!(result.is_ok());
        obfuscator.mark_submitted(&obfuscated);

        // Second submission fails
        let result = obfuscator.validate_submission(&obfuscated, "user_abc");
        assert_eq!(result.unwrap_err(), ValidationError::AlreadySubmitted);
    }
}
