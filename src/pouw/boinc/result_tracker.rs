//! Result Replay Detection
//!
//! Tracks result submissions to detect potential gaming while avoiding false positives.
//!
//! ## Detection Philosophy
//!
//! BOINC tasks can legitimately produce identical results (e.g., same protein fold found).
//! We use multi-factor analysis instead of simple hash matching:
//!
//! | Pattern | Interpretation | Action |
//! |---------|----------------|--------|
//! | Same task + same user + same hash | Network retry | Allow (dedupe) |
//! | Different task + same hash | Possibly legitimate | Flag for review |
//! | Same task + different user + same hash | Could be collusion | Flag for review |
//! | BOINC validation fails | Definitely wrong | Slash |
//!
//! ## Reward Locking
//!
//! Rewards are locked in "pending" state until BOINC validates the result.
//! Only upon successful validation do rewards become claimable.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Status of a submitted result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResultStatus {
    /// Submitted to BOINC, awaiting validation
    Pending,
    /// BOINC validated successfully
    Validated,
    /// BOINC rejected the result
    Rejected,
    /// Timed out waiting for validation
    Timeout,
}

/// Record of a submitted result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultRecord {
    /// Obfuscated task ID
    pub obfuscated_id: String,
    /// Real work unit name
    pub wu_name: String,
    /// User who submitted
    pub user_auth: String,
    /// Hash of result content
    pub result_hash: String,
    /// When submitted
    pub submitted_at: DateTime<Utc>,
    /// Current status
    pub status: ResultStatus,
    /// BOINC validation response (if received)
    pub validation_response: Option<String>,
    /// Credits granted by BOINC (if validated)
    pub credits_granted: Option<f64>,
}

/// Suspicious activity flag for review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousActivity {
    /// Unique ID for this flag
    pub id: String,
    /// Type of suspicious activity
    pub activity_type: SuspiciousActivityType,
    /// Result records involved
    pub result_hashes: Vec<String>,
    /// Users involved
    pub users_involved: Vec<String>,
    /// Tasks involved
    pub tasks_involved: Vec<String>,
    /// When detected
    pub detected_at: DateTime<Utc>,
    /// Whether reviewed by admin
    pub reviewed: bool,
    /// Admin decision (if reviewed)
    pub decision: Option<AdminDecision>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuspiciousActivityType {
    /// Same result submitted for different tasks (could be legitimate)
    CrossTaskDuplicate,
    /// Multiple users submitted identical result for same task
    PossibleCollusion,
    /// Unusual result pattern detected
    AnomalousPattern,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminDecision {
    /// Confirmed malicious, apply slash
    ConfirmedMalicious,
    /// False positive, no action
    FalsePositive,
    /// Needs more investigation
    PendingInvestigation,
}

/// Result tracking and replay detection
pub struct ResultTracker {
    /// Result records by obfuscated ID
    records: HashMap<String, ResultRecord>,

    /// Index: result_hash -> list of obfuscated IDs with this hash
    hash_index: HashMap<String, Vec<String>>,

    /// Index: user_auth -> list of their obfuscated IDs
    user_index: HashMap<String, Vec<String>>,

    /// Suspicious activities flagged for review
    suspicious_activities: Vec<SuspiciousActivity>,

    /// How long to wait for BOINC validation before considering result timed out
    validation_timeout_hours: u64,
}

impl ResultTracker {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            hash_index: HashMap::new(),
            user_index: HashMap::new(),
            suspicious_activities: Vec::new(),
            validation_timeout_hours: 24,
        }
    }

    /// Compute hash of result content for deduplication
    pub fn compute_result_hash(
        wu_name: &str,
        result_name: &str,
        cpu_time: f64,
        exit_status: i32,
        result_data: Option<&[u8]>,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(wu_name.as_bytes());
        hasher.update(result_name.as_bytes());
        hasher.update(cpu_time.to_le_bytes());
        hasher.update(exit_status.to_le_bytes());

        if let Some(data) = result_data {
            hasher.update(data);
        }

        format!("{:x}", hasher.finalize())
    }

    /// Record a new result submission
    /// Returns Ok(()) for normal submission, Err if it's a duplicate
    pub fn record_submission(
        &mut self,
        obfuscated_id: String,
        wu_name: String,
        user_auth: String,
        result_hash: String,
    ) -> Result<SubmissionResult, SubmissionError> {
        // Check if this exact submission already exists (same task + same user)
        if let Some(existing) = self.records.get(&obfuscated_id) {
            if existing.user_auth == user_auth && existing.result_hash == result_hash {
                // Same user, same task, same result = network retry (not malicious)
                debug!(
                    obfuscated_id = %obfuscated_id,
                    user = %user_auth,
                    "Duplicate submission detected (network retry)"
                );
                return Ok(SubmissionResult::DuplicateSend);
            }
        }

        // Check for cross-user or cross-task duplicates
        let mut flags = Vec::new();

        if let Some(other_ids) = self.hash_index.get(&result_hash) {
            for other_id in other_ids {
                if let Some(other_record) = self.records.get(other_id) {
                    // Same result hash found elsewhere
                    if other_record.user_auth != user_auth {
                        // Different user, same result hash
                        if other_record.wu_name == wu_name {
                            // Same task too = possible collusion
                            flags.push(DuplicateFlag::PossibleCollusion {
                                other_user: other_record.user_auth.clone(),
                                task_id: wu_name.clone(),
                            });
                        }
                        // Different task = could be legitimate, flag for review
                    } else if other_record.wu_name != wu_name {
                        // Same user, different task, same result = suspicious
                        flags.push(DuplicateFlag::CrossTaskDuplicate {
                            other_task: other_record.wu_name.clone(),
                        });
                    }
                }
            }
        }

        // Create the record
        let record = ResultRecord {
            obfuscated_id: obfuscated_id.clone(),
            wu_name: wu_name.clone(),
            user_auth: user_auth.clone(),
            result_hash: result_hash.clone(),
            submitted_at: Utc::now(),
            status: ResultStatus::Pending,
            validation_response: None,
            credits_granted: None,
        };

        // Store the record
        self.records.insert(obfuscated_id.clone(), record);

        // Update indexes
        self.hash_index
            .entry(result_hash.clone())
            .or_insert_with(Vec::new)
            .push(obfuscated_id.clone());

        self.user_index
            .entry(user_auth.clone())
            .or_insert_with(Vec::new)
            .push(obfuscated_id.clone());

        // Create suspicious activity flags if needed
        if !flags.is_empty() {
            let activity =
                self.create_suspicious_activity(&flags, &user_auth, &wu_name, &result_hash);
            self.suspicious_activities.push(activity.clone());

            info!(
                user = %user_auth,
                task = %wu_name,
                flags = ?flags,
                "Flagged suspicious activity for review"
            );

            Ok(SubmissionResult::FlaggedForReview(flags))
        } else {
            Ok(SubmissionResult::Accepted)
        }
    }

    /// Update result status after BOINC validation
    pub fn update_validation(
        &mut self,
        obfuscated_id: &str,
        validated: bool,
        credits: Option<f64>,
        response: Option<String>,
    ) -> Option<ResultStatus> {
        if let Some(record) = self.records.get_mut(obfuscated_id) {
            record.status = if validated {
                ResultStatus::Validated
            } else {
                ResultStatus::Rejected
            };
            record.credits_granted = credits;
            record.validation_response = response;

            debug!(
                obfuscated_id = %obfuscated_id,
                status = ?record.status,
                credits = ?credits,
                "Updated result validation status"
            );

            Some(record.status)
        } else {
            None
        }
    }

    /// Check if a result is validated (rewards can be claimed)
    pub fn is_validated(&self, obfuscated_id: &str) -> bool {
        self.records
            .get(obfuscated_id)
            .map(|r| r.status == ResultStatus::Validated)
            .unwrap_or(false)
    }

    /// Get pending results (awaiting validation)
    pub fn get_pending_results(&self) -> Vec<&ResultRecord> {
        self.records
            .values()
            .filter(|r| r.status == ResultStatus::Pending)
            .collect()
    }

    /// Get timed out results (pending for too long)
    pub fn get_timed_out_results(&self) -> Vec<&ResultRecord> {
        let timeout = Utc::now() - chrono::Duration::hours(self.validation_timeout_hours as i64);
        self.records
            .values()
            .filter(|r| r.status == ResultStatus::Pending && r.submitted_at < timeout)
            .collect()
    }

    /// Get suspicious activities awaiting review
    pub fn get_pending_reviews(&self) -> Vec<&SuspiciousActivity> {
        self.suspicious_activities
            .iter()
            .filter(|a| !a.reviewed)
            .collect()
    }

    /// Resolve a suspicious activity
    pub fn resolve_suspicious_activity(
        &mut self,
        activity_id: &str,
        decision: AdminDecision,
    ) -> bool {
        if let Some(activity) = self
            .suspicious_activities
            .iter_mut()
            .find(|a| a.id == activity_id)
        {
            activity.reviewed = true;
            activity.decision = Some(decision);
            true
        } else {
            false
        }
    }

    /// Get result record
    pub fn get_record(&self, obfuscated_id: &str) -> Option<&ResultRecord> {
        self.records.get(obfuscated_id)
    }

    /// Get user's result history
    pub fn get_user_results(&self, user_auth: &str) -> Vec<&ResultRecord> {
        self.user_index
            .get(user_auth)
            .map(|ids| ids.iter().filter_map(|id| self.records.get(id)).collect())
            .unwrap_or_default()
    }

    /// Clean up old records
    pub fn cleanup_old_records(&mut self, max_age_days: u64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::days(max_age_days as i64);

        let to_remove: Vec<String> = self
            .records
            .iter()
            .filter(|(_, r)| r.submitted_at < cutoff)
            .map(|(id, _)| id.clone())
            .collect();

        let count = to_remove.len();

        for id in &to_remove {
            if let Some(record) = self.records.remove(id) {
                // Remove from indexes
                if let Some(hash_records) = self.hash_index.get_mut(&record.result_hash) {
                    hash_records.retain(|i| i != id);
                }
                if let Some(user_records) = self.user_index.get_mut(&record.user_auth) {
                    user_records.retain(|i| i != id);
                }
            }
        }

        if count > 0 {
            debug!("Cleaned up {} old result records", count);
        }

        count
    }

    fn create_suspicious_activity(
        &self,
        flags: &[DuplicateFlag],
        user_auth: &str,
        wu_name: &str,
        result_hash: &str,
    ) -> SuspiciousActivity {
        let activity_type = flags
            .iter()
            .find_map(|f| match f {
                DuplicateFlag::PossibleCollusion { .. } => {
                    Some(SuspiciousActivityType::PossibleCollusion)
                }
                DuplicateFlag::CrossTaskDuplicate { .. } => {
                    Some(SuspiciousActivityType::CrossTaskDuplicate)
                }
            })
            .unwrap_or(SuspiciousActivityType::AnomalousPattern);

        // Collect all involved parties
        let mut users = vec![user_auth.to_string()];
        let mut tasks = vec![wu_name.to_string()];

        for flag in flags {
            match flag {
                DuplicateFlag::PossibleCollusion {
                    other_user,
                    task_id,
                } => {
                    if !users.contains(other_user) {
                        users.push(other_user.clone());
                    }
                    if !tasks.contains(task_id) {
                        tasks.push(task_id.clone());
                    }
                }
                DuplicateFlag::CrossTaskDuplicate { other_task } => {
                    if !tasks.contains(other_task) {
                        tasks.push(other_task.clone());
                    }
                }
            }
        }

        SuspiciousActivity {
            id: format!("sus_{}_{}", user_auth, Utc::now().timestamp_millis()),
            activity_type,
            result_hashes: vec![result_hash.to_string()],
            users_involved: users,
            tasks_involved: tasks,
            detected_at: Utc::now(),
            reviewed: false,
            decision: None,
        }
    }
}

impl Default for ResultTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a submission attempt
#[derive(Debug, Clone)]
pub enum SubmissionResult {
    /// Normal acceptance
    Accepted,
    /// Same task/user/result - network retry
    DuplicateSend,
    /// Flagged for admin review
    FlaggedForReview(Vec<DuplicateFlag>),
}

/// Flags that can be raised during submission
#[derive(Debug, Clone)]
pub enum DuplicateFlag {
    /// Different users submitted same result for same task
    PossibleCollusion { other_user: String, task_id: String },
    /// Same result submitted for different tasks
    CrossTaskDuplicate { other_task: String },
}

/// Error during submission
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionError {
    /// Result already submitted and validated
    AlreadyValidated,
    /// Result already rejected by BOINC
    AlreadyRejected,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_hash_consistency() {
        let hash1 = ResultTracker::compute_result_hash(
            "wu_123",
            "result_456",
            3600.0,
            0,
            Some(b"test_data"),
        );

        let hash2 = ResultTracker::compute_result_hash(
            "wu_123",
            "result_456",
            3600.0,
            0,
            Some(b"test_data"),
        );

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_duplicate_send_detection() {
        let mut tracker = ResultTracker::new();

        let hash = ResultTracker::compute_result_hash("wu_123", "result_456", 3600.0, 0, None);

        // First submission
        let result1 = tracker.record_submission(
            "obf_123".to_string(),
            "wu_123".to_string(),
            "user_a".to_string(),
            hash.clone(),
        );
        assert!(matches!(result1, Ok(SubmissionResult::Accepted)));

        // Same submission again (network retry)
        let result2 = tracker.record_submission(
            "obf_123".to_string(),
            "wu_123".to_string(),
            "user_a".to_string(),
            hash.clone(),
        );
        assert!(matches!(result2, Ok(SubmissionResult::DuplicateSend)));
    }

    #[test]
    fn test_cross_task_duplicate_flagging() {
        let mut tracker = ResultTracker::new();

        let hash = ResultTracker::compute_result_hash("wu_123", "result_456", 3600.0, 0, None);

        // First task
        tracker
            .record_submission(
                "obf_1".to_string(),
                "wu_123".to_string(),
                "user_a".to_string(),
                hash.clone(),
            )
            .unwrap();

        // Same user, different task, same result
        let result = tracker.record_submission(
            "obf_2".to_string(),
            "wu_456".to_string(),
            "user_a".to_string(),
            hash.clone(),
        );

        assert!(matches!(result, Ok(SubmissionResult::FlaggedForReview(_))));
    }

    #[test]
    fn test_validation_status() {
        let mut tracker = ResultTracker::new();

        let hash = ResultTracker::compute_result_hash("wu_123", "result_456", 3600.0, 0, None);

        tracker
            .record_submission(
                "obf_123".to_string(),
                "wu_123".to_string(),
                "user_a".to_string(),
                hash,
            )
            .unwrap();

        assert!(!tracker.is_validated("obf_123"));

        tracker.update_validation("obf_123", true, Some(100.0), None);

        assert!(tracker.is_validated("obf_123"));
    }
}
