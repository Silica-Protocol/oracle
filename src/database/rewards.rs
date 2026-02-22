//! Reward Repository - PostgreSQL operations for rewards using sqlx

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingReward {
    pub id: i64,
    pub task_id: String,
    pub miner_id: String,
    pub amount: i64,
    pub created_at: DateTime<Utc>,
    pub lockup_until: DateTime<Utc>,
    pub finalized_at: Option<DateTime<Utc>>,
    pub status: String,
    pub tb_transfer_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardHistory {
    pub id: i64,
    pub task_id: String,
    pub miner_id: String,
    pub amount: i64,
    pub task_completed_at: DateTime<Utc>,
    pub finalized_at: DateTime<Utc>,
    pub tb_transfer_id: Uuid,
}

pub struct RewardRepository {
    pool: PgPool,
}

impl RewardRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert_pending(&self, reward: &PendingReward) -> Result<i64, String> {
        let row = sqlx::query(
            r#"
            INSERT INTO rewards.pending 
            (task_id, miner_id, amount, created_at, lockup_until, status)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(&reward.task_id)
        .bind(&reward.miner_id)
        .bind(reward.amount)
        .bind(reward.created_at)
        .bind(reward.lockup_until)
        .bind(&reward.status)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| format!("Failed to insert pending reward: {}", e))?;

        let id: i64 = row.get("id");
        debug!(task_id = %reward.task_id, miner_id = %reward.miner_id, "Pending reward created");
        Ok(id)
    }

    pub async fn get_pending(&self, miner_id: &str) -> Result<Vec<PendingReward>, String> {
        let rows = sqlx::query(
            r#"
            SELECT id, task_id, miner_id, amount, created_at, 
                   lockup_until, finalized_at, status, tb_transfer_id
            FROM rewards.pending 
            WHERE miner_id = $1 AND status IN ('pending', 'finalized')
            ORDER BY lockup_until ASC
            "#,
        )
        .bind(miner_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Failed to get pending rewards: {}", e))?;

        let rewards: Vec<PendingReward> = rows
            .into_iter()
            .map(|row| PendingReward {
                id: row.get("id"),
                task_id: row.get("task_id"),
                miner_id: row.get("miner_id"),
                amount: row.get("amount"),
                created_at: row.get("created_at"),
                lockup_until: row.get("lockup_until"),
                finalized_at: row.get("finalized_at"),
                status: row.get("status"),
                tb_transfer_id: row.get("tb_transfer_id"),
            })
            .collect();

        Ok(rewards)
    }

    pub async fn get_finalizable(&self) -> Result<Vec<PendingReward>, String> {
        let rows = sqlx::query(
            r#"
            SELECT id, task_id, miner_id, amount, created_at, 
                   lockup_until, finalized_at, status, tb_transfer_id
            FROM rewards.pending 
            WHERE status = 'pending' AND lockup_until <= NOW()
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Failed to get finalizable rewards: {}", e))?;

        let rewards: Vec<PendingReward> = rows
            .into_iter()
            .map(|row| PendingReward {
                id: row.get("id"),
                task_id: row.get("task_id"),
                miner_id: row.get("miner_id"),
                amount: row.get("amount"),
                created_at: row.get("created_at"),
                lockup_until: row.get("lockup_until"),
                finalized_at: row.get("finalized_at"),
                status: row.get("status"),
                tb_transfer_id: row.get("tb_transfer_id"),
            })
            .collect();

        Ok(rewards)
    }

    pub async fn finalize(&self, id: i64, tb_transfer_id: Uuid) -> Result<(), String> {
        sqlx::query(
            r#"
            UPDATE rewards.pending 
            SET status = 'finalized', finalized_at = NOW(), tb_transfer_id = $2
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(tb_transfer_id)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to finalize reward: {}", e))?;

        debug!(reward_id = %id, "Reward finalized");
        Ok(())
    }

    pub async fn mark_claimed(&self, id: i64) -> Result<(), String> {
        sqlx::query(
            "UPDATE rewards.pending SET status = 'claimed' WHERE id = $1"
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to mark claimed: {}", e))?;

        Ok(())
    }

    pub async fn mark_clawed_back(&self, id: i64) -> Result<(), String> {
        sqlx::query(
            "UPDATE rewards.pending SET status = 'clawed_back' WHERE id = $1"
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to mark clawed back: {}", e))?;

        Ok(())
    }

    pub async fn insert_history(&self, reward: &RewardHistory) -> Result<(), String> {
        sqlx::query(
            r#"
            INSERT INTO rewards.history 
            (task_id, miner_id, amount, task_completed_at, finalized_at, tb_transfer_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (task_id, miner_id) DO NOTHING
            "#,
        )
        .bind(&reward.task_id)
        .bind(&reward.miner_id)
        .bind(reward.amount)
        .bind(reward.task_completed_at)
        .bind(reward.finalized_at)
        .bind(reward.tb_transfer_id)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to insert history: {}", e))?;

        Ok(())
    }

    pub async fn get_history(&self, miner_id: &str, limit: i64) -> Result<Vec<RewardHistory>, String> {
        let rows = sqlx::query(
            r#"
            SELECT id, task_id, miner_id, amount, task_completed_at, finalized_at, tb_transfer_id
            FROM rewards.history 
            WHERE miner_id = $1
            ORDER BY finalized_at DESC
            LIMIT $2
            "#,
        )
        .bind(miner_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Failed to get history: {}", e))?;

        let history: Vec<RewardHistory> = rows
            .into_iter()
            .map(|row| RewardHistory {
                id: row.get("id"),
                task_id: row.get("task_id"),
                miner_id: row.get("miner_id"),
                amount: row.get("amount"),
                task_completed_at: row.get("task_completed_at"),
                finalized_at: row.get("finalized_at"),
                tb_transfer_id: row.get("tb_transfer_id"),
            })
            .collect();

        Ok(history)
    }
}
