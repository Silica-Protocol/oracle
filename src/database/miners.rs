//! Miner Repository - PostgreSQL operations for miners using sqlx

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerProfile {
    pub miner_id: String,
    pub public_key: Vec<u8>,
    pub registered_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub cpu_cores: Option<i16>,
    pub total_ram_gb: Option<i16>,
    pub gpu_count: Option<i16>,
    pub gpu_models: Option<Vec<String>>,
    pub supported_tasks: Option<Vec<String>>,
    pub has_gpu: bool,
    pub valid_submissions: i64,
    pub invalid_submissions: i64,
    pub total_earnings: i64,
    pub is_active: bool,
    pub is_banned: bool,
    pub ban_reason: Option<String>,
}

pub struct MinerRepository {
    pool: PgPool,
}

impl MinerRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert_miner(&self, profile: &MinerProfile) -> Result<(), String> {
        sqlx::query(
            r#"
            INSERT INTO miners.profiles 
            (miner_id, public_key, registered_at, last_seen_at, 
             cpu_cores, total_ram_gb, gpu_count, gpu_models,
             supported_tasks, has_gpu, valid_submissions, invalid_submissions,
             total_earnings, is_active, is_banned)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            ON CONFLICT (miner_id) DO UPDATE SET
                last_seen_at = EXCLUDED.last_seen_at,
                supported_tasks = COALESCE(EXCLUDED.supported_tasks, miners.profiles.supported_tasks)
            "#,
        )
        .bind(&profile.miner_id)
        .bind(&profile.public_key)
        .bind(profile.registered_at)
        .bind(profile.last_seen_at)
        .bind(profile.cpu_cores)
        .bind(profile.total_ram_gb)
        .bind(profile.gpu_count)
        .bind(&profile.gpu_models)
        .bind(&profile.supported_tasks)
        .bind(profile.has_gpu)
        .bind(profile.valid_submissions)
        .bind(profile.invalid_submissions)
        .bind(profile.total_earnings)
        .bind(profile.is_active)
        .bind(profile.is_banned)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to insert miner: {}", e))?;

        debug!(miner_id = %profile.miner_id, "Miner inserted");
        Ok(())
    }

    pub async fn get_miner(&self, miner_id: &str) -> Result<Option<MinerProfile>, String> {
        let row = sqlx::query(
            r#"
            SELECT miner_id, public_key, registered_at, last_seen_at,
                   cpu_cores, total_ram_gb, gpu_count, gpu_models,
                   supported_tasks, has_gpu, valid_submissions, invalid_submissions,
                   total_earnings, is_active, is_banned, ban_reason
            FROM miners.profiles 
            WHERE miner_id = $1
            "#,
        )
        .bind(miner_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Failed to get miner: {}", e))?;

        if let Some(row) = row {
            Ok(Some(MinerProfile {
                miner_id: row.get("miner_id"),
                public_key: row.get("public_key"),
                registered_at: row.get("registered_at"),
                last_seen_at: row.get("last_seen_at"),
                cpu_cores: row.get("cpu_cores"),
                total_ram_gb: row.get("total_ram_gb"),
                gpu_count: row.get("gpu_count"),
                gpu_models: row.get("gpu_models"),
                supported_tasks: row.get("supported_tasks"),
                has_gpu: row.get("has_gpu"),
                valid_submissions: row.get("valid_submissions"),
                invalid_submissions: row.get("invalid_submissions"),
                total_earnings: row.get("total_earnings"),
                is_active: row.get("is_active"),
                is_banned: row.get("is_banned"),
                ban_reason: row.get("ban_reason"),
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn update_last_seen(&self, miner_id: &str) -> Result<(), String> {
        sqlx::query(
            "UPDATE miners.profiles SET last_seen_at = NOW() WHERE miner_id = $1"
        )
        .bind(miner_id)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update last seen: {}", e))?;

        Ok(())
    }

    pub async fn update_reputation(
        &self,
        miner_id: &str,
        valid_delta: i64,
        invalid_delta: i64,
        earnings_delta: i64,
    ) -> Result<(), String> {
        sqlx::query(
            r#"
            UPDATE miners.profiles 
            SET valid_submissions = valid_submissions + $2,
                invalid_submissions = invalid_submissions + $3,
                total_earnings = total_earnings + $4
            WHERE miner_id = $1
            "#,
        )
        .bind(miner_id)
        .bind(valid_delta)
        .bind(invalid_delta)
        .bind(earnings_delta)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update reputation: {}", e))?;

        sqlx::query(
            r#"
            INSERT INTO miners.reputation_log 
            (miner_id, event_type, change_amount, new_valid_count, new_invalid_count)
            SELECT $1, 
                   CASE WHEN $2 > 0 THEN 'valid_submission' ELSE 'invalid_submission' END,
                   $2,
                   valid_submissions,
                   invalid_submissions
            FROM miners.profiles WHERE miner_id = $1
            "#,
        )
        .bind(miner_id)
        .bind(valid_delta)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to log reputation: {}", e))?;

        Ok(())
    }

    pub async fn get_active_miners(&self) -> Result<Vec<MinerProfile>, String> {
        let rows = sqlx::query(
            r#"
            SELECT miner_id, public_key, registered_at, last_seen_at,
                   cpu_cores, total_ram_gb, gpu_count, gpu_models,
                   supported_tasks, has_gpu, valid_submissions, invalid_submissions,
                   total_earnings, is_active, is_banned, ban_reason
            FROM miners.profiles 
            WHERE is_active = true AND is_banned = false 
              AND last_seen_at > NOW() - INTERVAL '5 minutes'
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Failed to get active miners: {}", e))?;

        let miners: Vec<MinerProfile> = rows
            .into_iter()
            .map(|row| MinerProfile {
                miner_id: row.get("miner_id"),
                public_key: row.get("public_key"),
                registered_at: row.get("registered_at"),
                last_seen_at: row.get("last_seen_at"),
                cpu_cores: row.get("cpu_cores"),
                total_ram_gb: row.get("total_ram_gb"),
                gpu_count: row.get("gpu_count"),
                gpu_models: row.get("gpu_models"),
                supported_tasks: row.get("supported_tasks"),
                has_gpu: row.get("has_gpu"),
                valid_submissions: row.get("valid_submissions"),
                invalid_submissions: row.get("invalid_submissions"),
                total_earnings: row.get("total_earnings"),
                is_active: row.get("is_active"),
                is_banned: row.get("is_banned"),
                ban_reason: row.get("ban_reason"),
            })
            .collect();

        Ok(miners)
    }

    pub async fn get_miners_for_task(&self, task_type: &str) -> Result<Vec<MinerProfile>, String> {
        let rows = sqlx::query(
            r#"
            SELECT miner_id, public_key, registered_at, last_seen_at,
                   cpu_cores, total_ram_gb, gpu_count, gpu_models,
                   supported_tasks, has_gpu, valid_submissions, invalid_submissions,
                   total_earnings, is_active, is_banned, ban_reason
            FROM miners.profiles 
            WHERE is_active = true 
              AND is_banned = false 
              AND last_seen_at > NOW() - INTERVAL '5 minutes'
              AND supported_tasks @> ARRAY[$1]::text[]
            ORDER BY valid_submissions DESC
            "#,
        )
        .bind(task_type)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Failed to get miners for task: {}", e))?;

        let miners: Vec<MinerProfile> = rows
            .into_iter()
            .map(|row| MinerProfile {
                miner_id: row.get("miner_id"),
                public_key: row.get("public_key"),
                registered_at: row.get("registered_at"),
                last_seen_at: row.get("last_seen_at"),
                cpu_cores: row.get("cpu_cores"),
                total_ram_gb: row.get("total_ram_gb"),
                gpu_count: row.get("gpu_count"),
                gpu_models: row.get("gpu_models"),
                supported_tasks: row.get("supported_tasks"),
                has_gpu: row.get("has_gpu"),
                valid_submissions: row.get("valid_submissions"),
                invalid_submissions: row.get("invalid_submissions"),
                total_earnings: row.get("total_earnings"),
                is_active: row.get("is_active"),
                is_banned: row.get("is_banned"),
                ban_reason: row.get("ban_reason"),
            })
            .collect();

        Ok(miners)
    }
}
