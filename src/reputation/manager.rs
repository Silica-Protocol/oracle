//! Reputation Manager - Main Orchestrator
//!
//! Coordinates reputation tracking, slashing, and eligibility checks.
//! Persists all data to database for durability.

use crate::database::pool::DatabasePool;
use crate::reputation::{
    EligibilityStatus, ProjectMetrics, ReputationScore, ReputationThresholds,
    SlashEvidence, SlashEvent, SlashReason,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Event types for per-project metric tracking (non-punitive)
#[derive(Debug, Clone)]
pub enum MetricEvent {
    TaskAssigned,
    TaskCompleted { credits: f64, compute_time_seconds: f64 },
    TaskFailed,
    DeadlineMissed,
}

/// Main reputation manager
pub struct ReputationManager {
    db: Option<Arc<DatabasePool>>,
    thresholds: ReputationThresholds,
    
    /// In-memory cache of scores (for performance)
    score_cache: Arc<RwLock<HashMap<String, ReputationScore>>>,
    
    /// In-memory cache of pending slash events
    slash_cache: Arc<RwLock<HashMap<String, Vec<SlashEvent>>>>,
    
    /// Temp ban tracking (user_id -> ban expiry)
    temp_bans: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

impl ReputationManager {
    pub fn new(thresholds: ReputationThresholds) -> Self {
        Self {
            db: None,
            thresholds,
            score_cache: Arc::new(RwLock::new(HashMap::new())),
            slash_cache: Arc::new(RwLock::new(HashMap::new())),
            temp_bans: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub fn with_database(mut self, db: Arc<DatabasePool>) -> Self {
        self.db = Some(db);
        self
    }
    
    /// Get or create reputation score for a user
    pub async fn get_score(&self, user_id: &str) -> ReputationScore {
        // Check cache first
        {
            let cache = self.score_cache.read().await;
            if let Some(score) = cache.get(user_id) {
                return score.clone();
            }
        }
        
        // Try database
        if let Some(ref db) = self.db {
            if let Ok(Some(score)) = self.load_score_from_db(db, user_id).await {
                // Cache it
                let mut cache = self.score_cache.write().await;
                cache.insert(user_id.to_string(), score.clone());
                return score;
            }
        }
        
        // Create new score
        ReputationScore::new(user_id.to_string())
    }
    
    /// Get effective score (including pending slash deductions)
    pub async fn get_effective_score(&self, user_id: &str) -> i32 {
        let score = self.get_score(user_id).await;
        let pending_slash_points = self.get_pending_slash_points(user_id).await;
        score.effective_score(pending_slash_points)
    }
    
    /// Calculate total pending slash points (non-decayed only)
    async fn get_pending_slash_points(&self, user_id: &str) -> i32 {
        let slash_cache = self.slash_cache.read().await;
        
        if let Some(events) = slash_cache.get(user_id) {
            let mut total = 0i32;
            let mut events_mut = events.clone();
            
            for event in events_mut.iter_mut() {
                if !event.check_decayed() {
                    total += event.points_deducted;
                }
            }
            
            total
        } else {
            0
        }
    }
    
    /// Check user eligibility based on effective score
    pub async fn check_eligibility(&self, user_id: &str) -> EligibilityStatus {
        // Check temp ban first
        {
            let temp_bans = self.temp_bans.read().await;
            if let Some(until) = temp_bans.get(user_id) {
                if Utc::now() < *until {
                    return EligibilityStatus::TempBanned { until: *until };
                }
            }
        }
        
        let effective_score = self.get_effective_score(user_id).await;
        
        if effective_score < self.thresholds.perm_ban_threshold {
            EligibilityStatus::PermBanned
        } else if effective_score < self.thresholds.temp_ban_threshold {
            // Apply temp ban
            let until = Utc::now() + chrono::Duration::days(self.thresholds.temp_ban_days as i64);
            {
                let mut temp_bans = self.temp_bans.write().await;
                temp_bans.insert(user_id.to_string(), until);
            }
            EligibilityStatus::TempBanned { until }
        } else if effective_score < self.thresholds.restricted_threshold {
            EligibilityStatus::Restricted
        } else {
            EligibilityStatus::FullAccess
        }
    }
    
    /// Record a successful submission (increases score)
    pub async fn record_success(
        &self,
        user_id: &str,
        project_name: &str,
        credits: f64,
    ) -> Result<()> {
        let mut score = self.get_score(user_id).await;
        
        score.successful_submissions += 1;
        score.total_credits_earned += credits;
        score.updated_at = Utc::now();
        
        // Update project metrics
        let metrics = score.project_metrics
            .entry(project_name.to_string())
            .or_insert_with(|| ProjectMetrics::new(project_name.to_string(), user_id.to_string()));
        
        metrics.tasks_completed += 1;
        metrics.total_credits_earned += credits;
        metrics.last_updated = Utc::now();
        
        // Persist
        self.save_score(&score).await?;
        
        // Update cache
        {
            let mut cache = self.score_cache.write().await;
            cache.insert(user_id.to_string(), score);
        }
        
        debug!(
            user_id = %user_id,
            project = %project_name,
            credits = credits,
            "Recorded successful submission"
        );
        
        Ok(())
    }
    
    /// Record a project metric event (non-punitive)
    pub async fn record_metric_event(
        &self,
        user_id: &str,
        project_name: &str,
        event: MetricEvent,
    ) -> Result<()> {
        let mut score = self.get_score(user_id).await;
        
        let metrics = score.project_metrics
            .entry(project_name.to_string())
            .or_insert_with(|| ProjectMetrics::new(project_name.to_string(), user_id.to_string()));
        
        match event {
            MetricEvent::TaskAssigned => {
                metrics.tasks_assigned += 1;
            }
            MetricEvent::TaskCompleted { credits, compute_time_seconds } => {
                metrics.tasks_completed += 1;
                metrics.total_credits_earned += credits;
                
                // Update rolling average compute time
                let total = metrics.tasks_completed as f64;
                metrics.avg_compute_time_seconds = 
                    (metrics.avg_compute_time_seconds * (total - 1.0) + compute_time_seconds) / total;
            }
            MetricEvent::TaskFailed => {
                metrics.tasks_failed += 1;
            }
            MetricEvent::DeadlineMissed => {
                metrics.deadline_misses += 1;
            }
        }
        
        metrics.last_updated = Utc::now();
        
        // Persist
        self.save_score(&score).await?;
        
        // Update cache
        {
            let mut cache = self.score_cache.write().await;
            cache.insert(user_id.to_string(), score);
        }
        
        Ok(())
    }
    
    /// Apply a slash for malicious behavior
    pub async fn slash(
        &self,
        user_id: &str,
        reason: SlashReason,
        evidence: SlashEvidence,
    ) -> Result<SlashEvent> {
        let event = SlashEvent::new(
            user_id.to_string(),
            reason,
            evidence,
            self.thresholds.slash_decay_days,
        );
        
        info!(
            user_id = %user_id,
            reason = ?reason,
            points = event.points_deducted,
            "Applying slash to user"
        );
        
        // Add to slash cache
        {
            let mut slash_cache = self.slash_cache.write().await;
            slash_cache
                .entry(user_id.to_string())
                .or_insert_with(Vec::new)
                .push(event.clone());
        }
        
        // Persist to database
        if let Some(ref db) = self.db {
            self.save_slash_event(db, &event).await?;
        }
        
        Ok(event)
    }
    
    /// Get user's project metrics
    pub async fn get_project_metrics(
        &self,
        user_id: &str,
        project_name: &str,
    ) -> Option<ProjectMetrics> {
        let score = self.get_score(user_id).await;
        score.project_metrics.get(project_name).cloned()
    }
    
    /// Get all slash events for a user
    pub async fn get_slash_history(&self, user_id: &str) -> Vec<SlashEvent> {
        let slash_cache = self.slash_cache.read().await;
        slash_cache.get(user_id).cloned().unwrap_or_default()
    }
    
    /// Get current thresholds
    pub fn get_thresholds(&self) -> &ReputationThresholds {
        &self.thresholds
    }
    
    /// Update thresholds (governance action)
    pub fn update_thresholds(&mut self, thresholds: ReputationThresholds) {
        self.thresholds = thresholds;
    }
    
    // Database operations
    
    async fn load_score_from_db(&self, db: &DatabasePool, user_id: &str) -> Result<Option<ReputationScore>> {
        // Placeholder - implement with actual database query
        // SELECT * FROM reputation.scores WHERE user_id = $1
        let _ = db;
        let _ = user_id;
        Ok(None)
    }
    
    async fn save_score(&self, score: &ReputationScore) -> Result<()> {
        if let Some(ref db) = self.db {
            // Placeholder - implement with actual database upsert
            // INSERT INTO reputation.scores (...) VALUES (...) ON CONFLICT (user_id) DO UPDATE ...
            let _ = db;
        }
        
        // Always update cache
        {
            let mut cache = self.score_cache.write().await;
            cache.insert(score.user_id.clone(), score.clone());
        }
        
        Ok(())
    }
    
    async fn save_slash_event(&self, db: &DatabasePool, event: &SlashEvent) -> Result<()> {
        // Placeholder - implement with actual database insert
        // INSERT INTO reputation.slash_events (...) VALUES (...)
        let _ = db;
        let _ = event;
        Ok(())
    }
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new(ReputationThresholds::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_eligibility_full_access() {
        let manager = ReputationManager::new(ReputationThresholds::default());
        let status = manager.check_eligibility("user_1").await;
        assert_eq!(status, EligibilityStatus::FullAccess);
    }
    
    #[tokio::test]
    async fn test_record_success() {
        let manager = ReputationManager::new(ReputationThresholds::default());
        
        manager.record_success("user_1", "milkyway", 100.0).await.unwrap();
        
        let score = manager.get_score("user_1").await;
        assert_eq!(score.successful_submissions, 1);
        assert_eq!(score.total_credits_earned, 100.0);
    }
    
    #[tokio::test]
    async fn test_slash_reduces_score() {
        let manager = ReputationManager::new(ReputationThresholds::default());
        
        // Record some successes first
        manager.record_success("user_1", "milkyway", 100.0).await.unwrap();
        
        let score_before = manager.get_effective_score("user_1").await;
        
        // Apply slash
        let evidence = SlashEvidence::unassigned_work("task_123", "milkyway", None);
        manager.slash("user_1", SlashReason::UnassignedWork, evidence).await.unwrap();
        
        let score_after = manager.get_effective_score("user_1").await;
        
        assert!(score_after < score_before);
    }
    
    #[tokio::test]
    async fn test_project_metrics_tracking() {
        let manager = ReputationManager::new(ReputationThresholds::default());
        
        manager.record_metric_event("user_1", "milkyway", MetricEvent::TaskAssigned).await.unwrap();
        manager.record_metric_event("user_1", "milkyway", MetricEvent::TaskCompleted { 
            credits: 50.0, 
            compute_time_seconds: 3600.0 
        }).await.unwrap();
        
        let metrics = manager.get_project_metrics("user_1", "milkyway").await.unwrap();
        assert_eq!(metrics.tasks_assigned, 1);
        assert_eq!(metrics.tasks_completed, 1);
    }
}
