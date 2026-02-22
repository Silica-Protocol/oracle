//! Reputation Score Types and Thresholds
//!
//! Score starts at 0 and increases with successful work submissions.
//! Malicious actions result in slashes (negative points).
//! Governance thresholds determine participation eligibility.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Global reputation score for a user (cross-project)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    pub user_id: String,

    /// Base score (starts at 0, can go negative from slashes)
    pub base_score: i32,

    /// Total successful submissions (contributes to score)
    pub successful_submissions: u64,

    /// Total credits earned across all projects
    pub total_credits_earned: f64,

    /// Per-project performance metrics (non-punitive tracking)
    pub project_metrics: HashMap<String, ProjectMetrics>,

    /// Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ReputationScore {
    pub fn new(user_id: String) -> Self {
        Self {
            user_id,
            base_score: 0,
            successful_submissions: 0,
            total_credits_earned: 0.0,
            project_metrics: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Calculate effective score including pending slash deductions
    /// On-demand computation - slashes decay after threshold days
    /// Note: pending_slash_points is negative (e.g., -50 for a slash)
    pub fn effective_score(&self, pending_slash_points: i32) -> i32 {
        self.base_score + (self.successful_submissions as i32) + pending_slash_points
    }
}

/// Per-project performance metrics (non-punitive)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMetrics {
    pub project_name: String,
    pub user_id: String,

    /// Task counts
    pub tasks_assigned: u32,
    pub tasks_completed: u32,
    pub tasks_failed: u32,
    pub deadline_misses: u32,

    /// Performance stats
    pub avg_compute_time_seconds: f64,
    pub total_credits_earned: f64,

    /// Last activity
    pub last_updated: DateTime<Utc>,
}

impl ProjectMetrics {
    pub fn new(project_name: String, user_id: String) -> Self {
        Self {
            project_name,
            user_id,
            tasks_assigned: 0,
            tasks_completed: 0,
            tasks_failed: 0,
            deadline_misses: 0,
            avg_compute_time_seconds: 0.0,
            total_credits_earned: 0.0,
            last_updated: Utc::now(),
        }
    }

    /// Calculate success rate (0.0 - 1.0)
    pub fn success_rate(&self) -> f64 {
        if self.tasks_assigned == 0 {
            return 1.0;
        }
        self.tasks_completed as f64 / self.tasks_assigned as f64
    }
}

/// Governance-configurable thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationThresholds {
    /// Points awarded per successful submission
    pub good_behavior_reward: u32,

    /// Score below which user is restricted (lower priority tasks)
    pub restricted_threshold: i32,

    /// Score below which user is temporarily banned
    pub temp_ban_threshold: i32,

    /// Days for temp ban duration
    pub temp_ban_days: u32,

    /// Score below which user is permanently banned
    pub perm_ban_threshold: i32,

    /// Days before a slash decays (forgiveness period)
    pub slash_decay_days: u32,
}

impl Default for ReputationThresholds {
    fn default() -> Self {
        Self {
            good_behavior_reward: 1,
            restricted_threshold: -50,
            temp_ban_threshold: -100,
            temp_ban_days: 30,
            perm_ban_threshold: -200,
            slash_decay_days: 90,
        }
    }
}

/// User eligibility status based on reputation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EligibilityStatus {
    /// Full participation allowed
    FullAccess,
    /// Restricted - lower priority tasks only
    Restricted,
    /// Temporarily banned
    TempBanned { until: DateTime<Utc> },
    /// Permanently banned
    PermBanned,
}

impl EligibilityStatus {
    pub fn can_participate(&self) -> bool {
        matches!(
            self,
            EligibilityStatus::FullAccess | EligibilityStatus::Restricted
        )
    }

    pub fn is_banned(&self) -> bool {
        matches!(
            self,
            EligibilityStatus::TempBanned { .. } | EligibilityStatus::PermBanned
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_calculation() {
        let score = ReputationScore::new("user_1".to_string());
        assert_eq!(score.effective_score(0), 0);
    }

    #[test]
    fn test_project_metrics_success_rate() {
        let mut metrics = ProjectMetrics::new("milkyway".to_string(), "user_1".to_string());
        metrics.tasks_assigned = 10;
        metrics.tasks_completed = 8;
        assert!((metrics.success_rate() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_eligibility() {
        assert!(EligibilityStatus::FullAccess.can_participate());
        assert!(EligibilityStatus::Restricted.can_participate());
        assert!(!EligibilityStatus::PermBanned.can_participate());
    }
}
