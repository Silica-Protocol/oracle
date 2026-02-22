//! Database Connection Pool using sqlx

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::migrate::MigrateDatabase;
use tracing::{info, error};

use crate::database::tasks::TaskRepository;
use crate::database::miners::MinerRepository;
use crate::database::rewards::RewardRepository;
use crate::database::reputation::ReputationRepository;

pub struct DatabasePool {
    pool: PgPool,
    tasks: TaskRepository,
    miners: MinerRepository,
    rewards: RewardRepository,
    reputation: ReputationRepository,
}

impl DatabasePool {
    pub async fn new(connection_string: &str) -> Result<Self, String> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(connection_string)
            .await
            .map_err(|e| format!("Failed to connect to PostgreSQL: {}", e))?;

        info!("Connected to PostgreSQL");

        let tasks = TaskRepository::new(pool.clone());
        let miners = MinerRepository::new(pool.clone());
        let rewards = RewardRepository::new(pool.clone());
        let reputation = ReputationRepository::new(pool.clone());

        Ok(Self {
            pool,
            tasks,
            miners,
            rewards,
            reputation,
        })
    }

    pub async fn init_schema(&self) -> Result<(), String> {
        info!("Initializing database schema...");
        
        // Create schemas using sqlx
        sqlx::query("CREATE SCHEMA IF NOT EXISTS tasks")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to create tasks schema: {}", e))?;
        
        sqlx::query("CREATE SCHEMA IF NOT EXISTS miners")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to create miners schema: {}", e))?;
        
        sqlx::query("CREATE SCHEMA IF NOT EXISTS rewards")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to create rewards schema: {}", e))?;
        
        sqlx::query("CREATE SCHEMA IF NOT EXISTS disputes")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to create disputes schema: {}", e))?;
        
        sqlx::query("CREATE SCHEMA IF NOT EXISTS cache")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to create cache schema: {}", e))?;
        
        sqlx::query("CREATE SCHEMA IF NOT EXISTS reputation")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to create reputation schema: {}", e))?;

        info!("Database schema initialized");
        Ok(())
    }

    pub fn tasks(&self) -> &TaskRepository {
        &self.tasks
    }

    pub fn miners(&self) -> &MinerRepository {
        &self.miners
    }

    pub fn rewards(&self) -> &RewardRepository {
        &self.rewards
    }

    pub fn reputation(&self) -> &ReputationRepository {
        &self.reputation
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
