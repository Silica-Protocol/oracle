//! Reputation Repository - Database operations for reputation system
//!
//! Handles persistence of reputation scores, slash events, and project metrics.

use sqlx::postgres::PgPool;
use sqlx::Row;
use chrono::{DateTime, Utc};
use tracing::{debug, error, info};

use crate::reputation::{
    ProjectMetrics, ReputationScore, ReputationThresholds,
    SlashEvidence, SlashEvent, SlashReason,
};

pub struct ReputationRepository {
    pool: PgPool,
}

impl ReputationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    
    /// Initialize reputation schema and tables
    pub async fn init_schema(&self) -> Result<(), String> {
        info!("Initializing reputation schema...");
        
        // Create schema
        sqlx::query("CREATE SCHEMA IF NOT EXISTS reputation")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to create reputation schema: {}", e))?;
        
        // Create scores table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS reputation.scores (
                user_id VARCHAR(255) PRIMARY KEY,
                base_score INTEGER DEFAULT 0,
                successful_submissions BIGINT DEFAULT 0,
                total_credits_earned DOUBLE PRECISION DEFAULT 0.0,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        "#)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to create scores table: {}", e))?;
        
        // Create slash_events table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS reputation.slash_events (
                id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL REFERENCES reputation.scores(user_id),
                reason VARCHAR(50) NOT NULL,
                points_deducted INTEGER NOT NULL,
                evidence JSONB NOT NULL,
                slashed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                decays_at TIMESTAMP WITH TIME ZONE NOT NULL,
                is_decayed BOOLEAN DEFAULT FALSE
            )
        "#)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to create slash_events table: {}", e))?;
        
        // Create project_metrics table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS reputation.project_metrics (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL REFERENCES reputation.scores(user_id),
                project_name VARCHAR(255) NOT NULL,
                tasks_assigned INTEGER DEFAULT 0,
                tasks_completed INTEGER DEFAULT 0,
                tasks_failed INTEGER DEFAULT 0,
                deadline_misses INTEGER DEFAULT 0,
                avg_compute_time_seconds DOUBLE PRECISION DEFAULT 0.0,
                total_credits_earned DOUBLE PRECISION DEFAULT 0.0,
                last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                UNIQUE(user_id, project_name)
            )
        "#)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to create project_metrics table: {}", e))?;
        
        // Create indexes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_slash_events_user ON reputation.slash_events(user_id)")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to create slash_events index: {}", e))?;
        
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_slash_events_decay ON reputation.slash_events(user_id, is_decayed, decays_at)")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to create slash_events decay index: {}", e))?;
        
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_project_metrics_user ON reputation.project_metrics(user_id)")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to create project_metrics index: {}", e))?;
        
        info!("Reputation schema initialized");
        Ok(())
    }
    
    /// Get reputation score for a user
    pub async fn get_score(&self, user_id: &str) -> Result<Option<ReputationScore>, String> {
        let row = sqlx::query(r#"
            SELECT user_id, base_score, successful_submissions, total_credits_earned, created_at, updated_at
            FROM reputation.scores
            WHERE user_id = $1
        "#)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Failed to get score: {}", e))?;
        
        match row {
            Some(row) => {
                let user_id: String = row.get("user_id");
                let base_score: i32 = row.get("base_score");
                let successful_submissions: i64 = row.get("successful_submissions");
                let total_credits_earned: f64 = row.get("total_credits_earned");
                let created_at: DateTime<Utc> = row.get("created_at");
                let updated_at: DateTime<Utc> = row.get("updated_at");
                
                // Load project metrics
                let project_metrics = self.get_all_project_metrics(&user_id).await?;
                
                Ok(Some(ReputationScore {
                    user_id,
                    base_score,
                    successful_submissions: successful_submissions as u64,
                    total_credits_earned,
                    project_metrics,
                    created_at,
                    updated_at,
                }))
            }
            None => Ok(None),
        }
    }
    
    /// Save or update reputation score
    pub async fn upsert_score(&self, score: &ReputationScore) -> Result<(), String> {
        sqlx::query(r#"
            INSERT INTO reputation.scores (user_id, base_score, successful_submissions, total_credits_earned, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id) DO UPDATE SET
                base_score = EXCLUDED.base_score,
                successful_submissions = EXCLUDED.successful_submissions,
                total_credits_earned = EXCLUDED.total_credits_earned,
                updated_at = EXCLUDED.updated_at
        "#)
        .bind(&score.user_id)
        .bind(score.base_score)
        .bind(score.successful_submissions as i64)
        .bind(score.total_credits_earned)
        .bind(score.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to upsert score: {}", e))?;
        
        // Save project metrics
        for (project_name, metrics) in &score.project_metrics {
            self.upsert_project_metrics(metrics).await?;
        }
        
        Ok(())
    }
    
    /// Get all project metrics for a user
    async fn get_all_project_metrics(&self, user_id: &str) -> Result<std::collections::HashMap<String, ProjectMetrics>, String> {
        let rows = sqlx::query(r#"
            SELECT project_name, tasks_assigned, tasks_completed, tasks_failed, 
                   deadline_misses, avg_compute_time_seconds, total_credits_earned, last_updated
            FROM reputation.project_metrics
            WHERE user_id = $1
        "#)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Failed to get project metrics: {}", e))?;
        
        let mut metrics = std::collections::HashMap::new();
        for row in rows {
            let project_name: String = row.get("project_name");
            let tasks_assigned: i32 = row.get("tasks_assigned");
            let tasks_completed: i32 = row.get("tasks_completed");
            let tasks_failed: i32 = row.get("tasks_failed");
            let deadline_misses: i32 = row.get("deadline_misses");
            
            let m = ProjectMetrics {
                project_name: project_name.clone(),
                user_id: user_id.to_string(),
                tasks_assigned: tasks_assigned as u32,
                tasks_completed: tasks_completed as u32,
                tasks_failed: tasks_failed as u32,
                deadline_misses: deadline_misses as u32,
                avg_compute_time_seconds: row.get("avg_compute_time_seconds"),
                total_credits_earned: row.get("total_credits_earned"),
                last_updated: row.get("last_updated"),
            };
            metrics.insert(project_name, m);
        }
        
        Ok(metrics)
    }
    
    /// Save or update project metrics
    pub async fn upsert_project_metrics(&self, metrics: &ProjectMetrics) -> Result<(), String> {
        sqlx::query(r#"
            INSERT INTO reputation.project_metrics 
                (user_id, project_name, tasks_assigned, tasks_completed, tasks_failed, 
                 deadline_misses, avg_compute_time_seconds, total_credits_earned, last_updated)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (user_id, project_name) DO UPDATE SET
                tasks_assigned = EXCLUDED.tasks_assigned,
                tasks_completed = EXCLUDED.tasks_completed,
                tasks_failed = EXCLUDED.tasks_failed,
                deadline_misses = EXCLUDED.deadline_misses,
                avg_compute_time_seconds = EXCLUDED.avg_compute_time_seconds,
                total_credits_earned = EXCLUDED.total_credits_earned,
                last_updated = EXCLUDED.last_updated
        "#)
        .bind(&metrics.user_id)
        .bind(&metrics.project_name)
        .bind(metrics.tasks_assigned as i32)
        .bind(metrics.tasks_completed as i32)
        .bind(metrics.tasks_failed as i32)
        .bind(metrics.deadline_misses as i32)
        .bind(metrics.avg_compute_time_seconds)
        .bind(metrics.total_credits_earned)
        .bind(metrics.last_updated)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to upsert project metrics: {}", e))?;
        
        Ok(())
    }
    
    /// Get pending (non-decayed) slash events for a user
    pub async fn get_pending_slashes(&self, user_id: &str, thresholds: &ReputationThresholds) -> Result<Vec<SlashEvent>, String> {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::days(thresholds.slash_decay_days as i64);
        
        let rows = sqlx::query(r#"
            SELECT id, user_id, reason, points_deducted, evidence, slashed_at, decays_at, is_decayed
            FROM reputation.slash_events
            WHERE user_id = $1 AND (is_decayed = FALSE OR decays_at > $2)
        "#)
        .bind(user_id)
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Failed to get pending slashes: {}", e))?;
        
        let mut events = Vec::new();
        for row in rows {
            let reason_str: String = row.get("reason");
            let reason = match reason_str.as_str() {
                "UnassignedWork" => SlashReason::UnassignedWork,
                "ResultReplay" => SlashReason::ResultReplay,
                "ReceiptForgery" => SlashReason::ReceiptForgery,
                "SignatureFraud" => SlashReason::SignatureFraud,
                "ReputationGaming" => SlashReason::ReputationGaming,
                _ => {
                    error!("Unknown slash reason: {}", reason_str);
                    continue;
                }
            };
            
            let evidence_json: serde_json::Value = row.get("evidence");
            let evidence: SlashEvidence = serde_json::from_value(evidence_json)
                .unwrap_or_else(|_| SlashEvidence::new(None, None, serde_json::json!({})));
            
            events.push(SlashEvent {
                id: row.get("id"),
                user_id: row.get("user_id"),
                reason,
                points_deducted: row.get("points_deducted"),
                evidence,
                slashed_at: row.get("slashed_at"),
                decays_at: row.get("decays_at"),
                is_decayed: row.get("is_decayed"),
            });
        }
        
        Ok(events)
    }
    
    /// Save a slash event
    pub async fn insert_slash_event(&self, event: &SlashEvent) -> Result<(), String> {
        let reason_str = match event.reason {
            SlashReason::UnassignedWork => "UnassignedWork",
            SlashReason::ResultReplay => "ResultReplay",
            SlashReason::ReceiptForgery => "ReceiptForgery",
            SlashReason::SignatureFraud => "SignatureFraud",
            SlashReason::ReputationGaming => "ReputationGaming",
        };
        
        let evidence_json = serde_json::to_value(&event.evidence)
            .unwrap_or_else(|_| serde_json::json!({}));
        
        sqlx::query(r#"
            INSERT INTO reputation.slash_events 
                (id, user_id, reason, points_deducted, evidence, slashed_at, decays_at, is_decayed)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#)
        .bind(&event.id)
        .bind(&event.user_id)
        .bind(reason_str)
        .bind(event.points_deducted)
        .bind(evidence_json)
        .bind(event.slashed_at)
        .bind(event.decays_at)
        .bind(event.is_decayed)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to insert slash event: {}", e))?;
        
        Ok(())
    }
    
    /// Mark slash events as decayed (cleanup)
    pub async fn mark_decayed_slashes(&self) -> Result<u64, String> {
        let now = Utc::now();
        
        let result = sqlx::query(r#"
            UPDATE reputation.slash_events
            SET is_decayed = TRUE
            WHERE is_decayed = FALSE AND decays_at <= $1
        "#)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to mark decayed slashes: {}", e))?;
        
        let count = result.rows_affected();
        if count > 0 {
            debug!("Marked {} slash events as decayed", count);
        }
        
        Ok(count)
    }
    
    /// Get total pending slash points for a user
    pub async fn get_pending_slash_points(&self, user_id: &str, thresholds: &ReputationThresholds) -> Result<i32, String> {
        let events = self.get_pending_slashes(user_id, thresholds).await?;
        Ok(events.iter().map(|e| e.points_deducted).sum())
    }
}
