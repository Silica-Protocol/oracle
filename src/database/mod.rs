//! PostgreSQL Database Module
//!
//! Provides database operations for NUW tasks, miners, rewards, and reputation.

pub mod pool;
pub mod tasks;
pub mod miners;
pub mod rewards;
pub mod reputation;

pub use pool::DatabasePool;
pub use tasks::TaskRepository;
pub use miners::MinerRepository;
pub use rewards::RewardRepository;
pub use reputation::ReputationRepository;
