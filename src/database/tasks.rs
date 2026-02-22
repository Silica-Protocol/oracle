//! Task Repository - PostgreSQL operations for tasks using sqlx

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDefinition {
    pub task_id: String,
    pub task_type: String,
    pub payload_hash: Vec<u8>,
    pub payload_size: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: String,
    pub priority: String,
    pub consensus_result: Option<String>,
    pub valid_miners: Option<Vec<String>>,
    pub reward_amount: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuadAssignment {
    pub id: i64,
    pub task_id: String,
    pub miner_1_id: Option<String>,
    pub miner_2_id: Option<String>,
    pub miner_3_id: Option<String>,
    pub miner_4_id: Option<String>,
    pub miner_1_result: Option<Vec<u8>>,
    pub miner_1_submitted: Option<DateTime<Utc>>,
    pub miner_2_result: Option<Vec<u8>>,
    pub miner_2_submitted: Option<DateTime<Utc>>,
    pub miner_3_result: Option<Vec<u8>>,
    pub miner_3_submitted: Option<DateTime<Utc>>,
    pub miner_4_result: Option<Vec<u8>>,
    pub miner_4_submitted: Option<DateTime<Utc>>,
    pub consensus_reached: Option<bool>,
    pub consensus_time: Option<DateTime<Utc>>,
    pub timeout_at: DateTime<Utc>,
    pub extended_at: Option<DateTime<Utc>>,
}

pub struct TaskRepository {
    pool: PgPool,
}

impl TaskRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert_task(&self, task: &TaskDefinition) -> Result<(), String> {
        sqlx::query(
            r#"
            INSERT INTO tasks.definitions 
            (task_id, task_type, payload_hash, payload_size, created_at, expires_at, status, priority)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (task_id) DO UPDATE SET
                status = EXCLUDED.status,
                priority = EXCLUDED.priority
            "#,
        )
        .bind(&task.task_id)
        .bind(&task.task_type)
        .bind(&task.payload_hash)
        .bind(task.payload_size)
        .bind(task.created_at)
        .bind(task.expires_at)
        .bind(&task.status)
        .bind(&task.priority)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to insert task: {}", e))?;

        debug!(task_id = %task.task_id, "Task inserted");
        Ok(())
    }

    pub async fn get_task(&self, task_id: &str) -> Result<Option<TaskDefinition>, String> {
        let row = sqlx::query(
            r#"
            SELECT task_id, task_type, payload_hash, payload_size, created_at, 
                   expires_at, completed_at, status, priority, consensus_result,
                   valid_miners, reward_amount
            FROM tasks.definitions 
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Failed to get task: {}", e))?;

        if let Some(row) = row {
            Ok(Some(TaskDefinition {
                task_id: row.get("task_id"),
                task_type: row.get("task_type"),
                payload_hash: row.get("payload_hash"),
                payload_size: row.get("payload_size"),
                created_at: row.get("created_at"),
                expires_at: row.get("expires_at"),
                completed_at: row.get("completed_at"),
                status: row.get("status"),
                priority: row.get("priority"),
                consensus_result: row.get("consensus_result"),
                valid_miners: row.get("valid_miners"),
                reward_amount: row.get("reward_amount"),
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn update_status(&self, task_id: &str, status: &str) -> Result<(), String> {
        let completed_at: Option<DateTime<Utc>> = if status == "completed" {
            Some(Utc::now())
        } else {
            None
        };

        sqlx::query(
            r#"
            UPDATE tasks.definitions 
            SET status = $2, completed_at = COALESCE($3, completed_at)
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .bind(status)
        .bind(completed_at)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update task status: {}", e))?;

        debug!(task_id = %task_id, status = %status, "Task status updated");
        Ok(())
    }

    pub async fn update_consensus(
        &self,
        task_id: &str,
        consensus_result: &str,
        valid_miners: &[String],
        reward_amount: i64,
    ) -> Result<(), String> {
        sqlx::query(
            r#"
            UPDATE tasks.definitions 
            SET consensus_result = $2, 
                valid_miners = $3, 
                reward_amount = $4,
                status = 'completed',
                completed_at = NOW()
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .bind(consensus_result)
        .bind(valid_miners)
        .bind(reward_amount)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update consensus: {}", e))?;

        Ok(())
    }

    pub async fn insert_assignment(&self, assignment: &QuadAssignment) -> Result<i64, String> {
        let row = sqlx::query(
            r#"
            INSERT INTO tasks.assignments 
            (task_id, miner_1_id, miner_2_id, miner_3_id, miner_4_id, 
             consensus_reached, timeout_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
        )
        .bind(&assignment.task_id)
        .bind(&assignment.miner_1_id)
        .bind(&assignment.miner_2_id)
        .bind(&assignment.miner_3_id)
        .bind(&assignment.miner_4_id)
        .bind(assignment.consensus_reached)
        .bind(assignment.timeout_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| format!("Failed to insert assignment: {}", e))?;

        let id: i64 = row.get("id");
        debug!(task_id = %assignment.task_id, assignment_id = %id, "Assignment created");
        Ok(id)
    }

    pub async fn get_assignment(&self, task_id: &str) -> Result<Option<QuadAssignment>, String> {
        let row = sqlx::query(
            r#"
            SELECT id, task_id, miner_1_id, miner_2_id, miner_3_id, miner_4_id,
                   miner_1_result, miner_1_submitted, miner_2_result, miner_2_submitted,
                   miner_3_result, miner_3_submitted, miner_4_result, miner_4_submitted,
                   consensus_reached, consensus_time, timeout_at, extended_at
            FROM tasks.assignments 
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Failed to get assignment: {}", e))?;

        if let Some(row) = row {
            Ok(Some(QuadAssignment {
                id: row.get("id"),
                task_id: row.get("task_id"),
                miner_1_id: row.get("miner_1_id"),
                miner_2_id: row.get("miner_2_id"),
                miner_3_id: row.get("miner_3_id"),
                miner_4_id: row.get("miner_4_id"),
                miner_1_result: row.get("miner_1_result"),
                miner_1_submitted: row.get("miner_1_submitted"),
                miner_2_result: row.get("miner_2_result"),
                miner_2_submitted: row.get("miner_2_submitted"),
                miner_3_result: row.get("miner_3_result"),
                miner_3_submitted: row.get("miner_3_submitted"),
                miner_4_result: row.get("miner_4_result"),
                miner_4_submitted: row.get("miner_4_submitted"),
                consensus_reached: row.get("consensus_reached"),
                consensus_time: row.get("consensus_time"),
                timeout_at: row.get("timeout_at"),
                extended_at: row.get("extended_at"),
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn update_solution(
        &self,
        task_id: &str,
        miner_index: i32,
        result: Vec<u8>,
    ) -> Result<(), String> {
        let now = Utc::now();
        
        let query = match miner_index {
            1 => "UPDATE tasks.assignments SET miner_1_result = $2, miner_1_submitted = $3 WHERE task_id = $1",
            2 => "UPDATE tasks.assignments SET miner_2_result = $2, miner_2_submitted = $3 WHERE task_id = $1",
            3 => "UPDATE tasks.assignments SET miner_3_result = $2, miner_3_submitted = $3 WHERE task_id = $1",
            4 => "UPDATE tasks.assignments SET miner_4_result = $2, miner_4_submitted = $3 WHERE task_id = $1",
            _ => return Err(format!("Invalid miner index: {}", miner_index)),
        };

        sqlx::query(query)
            .bind(task_id)
            .bind(&result)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to update solution: {}", e))?;

        Ok(())
    }

    pub async fn update_consensus_result(
        &self,
        task_id: &str,
        consensus_reached: bool,
    ) -> Result<(), String> {
        sqlx::query(
            r#"
            UPDATE tasks.assignments 
            SET consensus_reached = $2, consensus_time = NOW()
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .bind(consensus_reached)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update consensus: {}", e))?;

        Ok(())
    }

    pub async fn get_pending_tasks(&self, limit: i64) -> Result<Vec<TaskDefinition>, String> {
        let rows = sqlx::query(
            r#"
            SELECT task_id, task_type, payload_hash, payload_size, created_at, 
                   expires_at, completed_at, status, priority, consensus_result,
                   valid_miners, reward_amount
            FROM tasks.definitions 
            WHERE status = 'pending' AND expires_at > NOW()
            ORDER BY 
                CASE priority 
                    WHEN 'P0' THEN 1 
                    WHEN 'P1' THEN 2 
                    WHEN 'P2' THEN 3 
                    WHEN 'Special' THEN 4 
                END,
                created_at ASC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Failed to get pending tasks: {}", e))?;

        let tasks: Vec<TaskDefinition> = rows
            .into_iter()
            .map(|row| TaskDefinition {
                task_id: row.get("task_id"),
                task_type: row.get("task_type"),
                payload_hash: row.get("payload_hash"),
                payload_size: row.get("payload_size"),
                created_at: row.get("created_at"),
                expires_at: row.get("expires_at"),
                completed_at: row.get("completed_at"),
                status: row.get("status"),
                priority: row.get("priority"),
                consensus_result: row.get("consensus_result"),
                valid_miners: row.get("valid_miners"),
                reward_amount: row.get("reward_amount"),
            })
            .collect();

        Ok(tasks)
    }
}
