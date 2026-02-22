//! Slashing for Malicious Actions
//!
//! Slashes are applied ONLY for malicious behavior, not for performance issues.
//! Each slash deducts points and is recorded with evidence for audit.
//! Slashes decay after the configured period (default 90 days).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Reasons for slashing (MALICIOUS ACTIONS ONLY)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashReason {
    /// Submitted result for work not assigned to this user
    UnassignedWork,

    /// Replayed another user's result
    ResultReplay,

    /// Forged or falsified work receipt
    ReceiptForgery,

    /// Consistently invalid cryptographic signatures
    SignatureFraud,

    /// Attempted to game the reputation system
    ReputationGaming,
}

impl SlashReason {
    /// Get the point deduction for this slash reason
    pub fn point_deduction(&self) -> i32 {
        match self {
            SlashReason::UnassignedWork => -50,
            SlashReason::ResultReplay => -100,
            SlashReason::ReceiptForgery => -200,
            SlashReason::SignatureFraud => -75,
            SlashReason::ReputationGaming => -150,
        }
    }

    /// Human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            SlashReason::UnassignedWork => "Submitted result for unassigned work",
            SlashReason::ResultReplay => "Replayed another user's result",
            SlashReason::ReceiptForgery => "Forged or falsified work receipt",
            SlashReason::SignatureFraud => "Invalid cryptographic signature",
            SlashReason::ReputationGaming => "Attempted to manipulate reputation",
        }
    }
}

/// Evidence supporting a slash decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashEvidence {
    /// The task/work unit involved
    pub task_id: Option<String>,

    /// The project involved
    pub project_name: Option<String>,

    /// Additional context (JSON-serializable)
    pub details: serde_json::Value,

    /// Source that detected the violation
    pub detected_by: String,
}

impl SlashEvidence {
    pub fn new(
        task_id: Option<String>,
        project_name: Option<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            task_id,
            project_name,
            details,
            detected_by: "boinc_proxy".to_string(),
        }
    }

    pub fn unassigned_work(task_id: &str, project: &str, assigned_to: Option<&str>) -> Self {
        Self {
            task_id: Some(task_id.to_string()),
            project_name: Some(project.to_string()),
            details: serde_json::json!({
                "violation": "submitted_unassigned_work",
                "actually_assigned_to": assigned_to,
            }),
            detected_by: "boinc_proxy".to_string(),
        }
    }

    pub fn result_replay(task_id: &str, project: &str, original_submitter: &str) -> Self {
        Self {
            task_id: Some(task_id.to_string()),
            project_name: Some(project.to_string()),
            details: serde_json::json!({
                "violation": "replayed_result",
                "original_submitter": original_submitter,
            }),
            detected_by: "boinc_proxy".to_string(),
        }
    }
}

/// A recorded slash event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashEvent {
    /// Unique ID for this slash event
    pub id: String,

    /// User who was slashed
    pub user_id: String,

    /// Reason for the slash
    pub reason: SlashReason,

    /// Points deducted
    pub points_deducted: i32,

    /// Evidence supporting the slash
    pub evidence: SlashEvidence,

    /// When the slash was applied
    pub slashed_at: DateTime<Utc>,

    /// When the slash decays (computed on-demand, stored for quick lookup)
    pub decays_at: DateTime<Utc>,

    /// Whether the slash has decayed (for caching)
    pub is_decayed: bool,
}

impl SlashEvent {
    pub fn new(
        user_id: String,
        reason: SlashReason,
        evidence: SlashEvidence,
        decay_days: u32,
    ) -> Self {
        let now = Utc::now();
        let id = format!("slash_{}_{}", user_id, now.timestamp_millis());

        Self {
            id,
            user_id,
            points_deducted: reason.point_deduction(),
            reason,
            evidence,
            slashed_at: now,
            decays_at: now + chrono::Duration::days(decay_days as i64),
            is_decayed: false,
        }
    }

    /// Check if this slash has decayed (on-demand computation)
    pub fn check_decayed(&mut self) -> bool {
        if self.is_decayed {
            return true;
        }

        if Utc::now() >= self.decays_at {
            self.is_decayed = true;
            return true;
        }

        false
    }

    /// Get effective points (0 if decayed, full deduction if not)
    pub fn effective_points(&mut self) -> i32 {
        if self.check_decayed() {
            0
        } else {
            self.points_deducted
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slash_reason_points() {
        assert_eq!(SlashReason::UnassignedWork.point_deduction(), -50);
        assert_eq!(SlashReason::ResultReplay.point_deduction(), -100);
        assert_eq!(SlashReason::ReceiptForgery.point_deduction(), -200);
    }

    #[test]
    fn test_slash_event_creation() {
        let evidence = SlashEvidence::unassigned_work("task_123", "milkyway", Some("user_other"));
        let event = SlashEvent::new(
            "user_1".to_string(),
            SlashReason::UnassignedWork,
            evidence,
            90,
        );

        assert_eq!(event.points_deducted, -50);
        assert!(!event.is_decayed);
    }

    #[test]
    fn test_slash_decay() {
        let mut event = SlashEvent {
            id: "test".to_string(),
            user_id: "user_1".to_string(),
            reason: SlashReason::UnassignedWork,
            points_deducted: -50,
            evidence: SlashEvidence::new(None, None, serde_json::json!({})),
            slashed_at: Utc::now() - chrono::Duration::days(91),
            decays_at: Utc::now() - chrono::Duration::days(1),
            is_decayed: false,
        };

        assert!(event.check_decayed());
        assert_eq!(event.effective_points(), 0);
    }
}
