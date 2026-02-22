//! NUW Oracle - Work Orchestration
//!
//! Coordinates the NUW work distribution pipeline:
//! 1. Receives work requests from protocol
//! 2. Queues tasks in priority buckets
//! 3. Distributes to miners via quad-send
//! 4. Collects solutions and evaluates consensus
//! 5. Calculates and schedules rewards
//!
//! ## Architecture
//!
//! ```text
//! Protocol Request
//!       │
//!       ▼
//! ┌─────────────────┐
//! │   NuwOracle     │ ◄── Main orchestrator
//! │                 │
//! │  ├─ PriorityQueue (P0/P1/P2)
//! │  ├─ Distributor (quad-send)
//! │  └─ Obfuscator (envelopes)
//! └─────────────────┘
//!       │
//!       ▼
//!    Miners (4x)
//! ```

use crate::pouw::nuw::{
    ConsensusAction, ConsensusResult, DistributionMode, MinerInfo, MinerRegistry, NuwSolution,
    NuwTask, TaskType, EnvelopeMode, Obfuscator, TaskAssignment,
};
use crate::pouw::nuw::distributor::{Distributor, QuadAssignment, QuadStatus, SingleAssignment, SingleStatus};
use crate::pouw::nuw::priority_queue::PriorityQueue;
use crate::tigerbeetle::{TigerBeetleClient, TigerBeetleConfig};
use crate::database::pool::DatabasePool;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct RewardRecord {
    pub task_id: String,
    pub miner_id: String,
    pub amount: u64,
    pub locked_until: DateTime<Utc>,
    pub finalized: bool,
    pub claimed: bool,
}

#[derive(Debug, Clone)]
pub struct OracleStats {
    pub total_tasks_received: u64,
    pub total_tasks_completed: u64,
    pub total_tasks_failed: u64,
    pub total_rewards_pending: u64,
    pub total_rewards_finalized: u64,
    pub active_miners: usize,
    pub queue_depth: usize,
}

impl Default for OracleStats {
    fn default() -> Self {
        Self {
            total_tasks_received: 0,
            total_tasks_completed: 0,
            total_tasks_failed: 0,
            total_rewards_pending: 0,
            total_rewards_finalized: 0,
            active_miners: 0,
            queue_depth: 0,
        }
    }
}

pub struct NuwOracle {
    registry: MinerRegistry,
    queue: PriorityQueue,
    distributor: Distributor,
    obfuscator: Obfuscator,
    pending_rewards: Arc<RwLock<HashMap<String, Vec<RewardRecord>>>>,
    pub stats: Arc<RwLock<OracleStats>>,
    default_envelope_mode: EnvelopeMode,
    tigerbeetle: Arc<RwLock<Option<TigerBeetleClient>>>,
    rewards_pool_address: String,
    database: Arc<RwLock<Option<DatabasePool>>>,
}

impl Default for NuwOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl NuwOracle {
    pub fn new() -> Self {
        let registry = MinerRegistry::new();
        Self::with_registry(registry)
    }

    pub fn with_registry(registry: MinerRegistry) -> Self {
        let distributor = Distributor::new(registry.clone());
        Self {
            registry,
            queue: PriorityQueue::new(10_000),
            distributor,
            obfuscator: Obfuscator::new(),
            pending_rewards: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(OracleStats::default())),
            default_envelope_mode: EnvelopeMode::Envelope,
            tigerbeetle: Arc::new(RwLock::new(None)),
            rewards_pool_address: "0x0001000000000001".to_string(),
            database: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn with_database(mut self, connection_string: &str) -> Result<Self, String> {
        let pool = DatabasePool::new(connection_string).await?;
        pool.init_schema().await?;
        
        {
            let mut db = self.database.write().await;
            *db = Some(pool);
        }
        
        info!("Database connected and initialized");
        Ok(self)
    }

    pub async fn with_tigerbeetle(self, config: TigerBeetleConfig) -> Result<Self, String> {
        let client = TigerBeetleClient::new(config).await?;
        client.initialize().await?;
        
        {
            let mut tb = self.tigerbeetle.write().await;
            *tb = Some(client);
        }
        
        info!("TigerBeetle client initialized");
        Ok(self)
    }

    pub fn register_miner(&mut self, miner: MinerInfo) {
        info!(
            miner_id = %miner.miner_id,
            tier = ?miner.tier,
            "Registering miner"
        );
        self.registry.register(miner);
    }

    pub async fn submit_task(&mut self, task: NuwTask) -> Result<String, String> {
        let task_id = task.task_id.clone();
        let task_type = task.task_type;

        self.queue.enqueue(task)?;

        {
            let mut stats = self.stats.write().await;
            stats.total_tasks_received += 1;
            stats.queue_depth = self.queue.len();
        }

        info!(
            task_id = %task_id,
            task_type = ?task_type,
            "Task submitted to queue"
        );

        Ok(task_id)
    }

    pub fn process_next_task(&mut self) -> Result<Option<TaskAssignment>, String> {
        let queued = match self.queue.dequeue() {
            Some(t) => t,
            None => return Ok(None),
        };

        let mode = self.determine_envelope_mode(&queued.task);
        let distribution_mode = queued.task.task_type.distribution_mode();

        match distribution_mode {
            DistributionMode::Single => {
                match self.distributor.assign_single(&queued.task, mode) {
                    Ok(assignment) => {
                        debug!(
                            task_id = %queued.task.task_id,
                            miner_id = %assignment.miner.miner_id,
                            "Task assigned to single miner (verifiable)"
                        );
                        Ok(Some(TaskAssignment::Single(assignment)))
                    }
                    Err(e) => {
                        warn!(
                            task_id = %queued.task.task_id,
                            error = %e,
                            "Failed to assign single miner, requeueing"
                        );
                        self.queue.requeue(queued, e.clone())?;
                        Err(e)
                    }
                }
            }
            DistributionMode::Quad => {
                match self.distributor.assign_quad(&queued.task, mode) {
                    Ok(assignment) => {
                        debug!(
                            task_id = %queued.task.task_id,
                            "Task assigned to quad (non-verifiable, BFT)"
                        );
                        Ok(Some(TaskAssignment::Quad(assignment)))
                    }
                    Err(e) => {
                        warn!(
                            task_id = %queued.task.task_id,
                            error = %e,
                            "Failed to assign quad, requeueing"
                        );
                        self.queue.requeue(queued, e.clone())?;
                        Err(e)
                    }
                }
            }
        }
    }

    fn determine_envelope_mode(&self, task: &NuwTask) -> EnvelopeMode {
        match task.task_type {
            TaskType::SigBatchVerify
            | TaskType::MerkleBatch
            | TaskType::MerkleVerify
            | TaskType::TxPreValidate => EnvelopeMode::Public,
            TaskType::RecursiveSnark
            | TaskType::ZkBatchVerify
            | TaskType::ZkVerify
            | TaskType::ElGamalRangeProof
            | TaskType::ElGamalConservationProof => EnvelopeMode::Blinded,
            TaskType::BoincRosetta
            | TaskType::BoincFolding
            | TaskType::BoincEinstein
            | TaskType::BoincMilkyWay => EnvelopeMode::Public,
        }
    }

    pub async fn submit_solution(&mut self, solution: NuwSolution, is_valid: Option<bool>) -> Result<String, String> {
        let task_id = solution.task_id.clone();
        let is_single = self.distributor.get_single(&task_id).is_some();

        if is_single {
            let miner_id = self.distributor.get_single(&task_id)
                .map(|s| s.miner.miner_id.clone())
                .unwrap_or_default();
            
            self.distributor.submit_single_solution(solution)?;

            if let Some(valid) = is_valid {
                let status = self.distributor.validate_single_solution(&task_id, valid)?;

                if status == SingleStatus::Validated {
                    self.handle_valid_single(&task_id, &miner_id).await;
                } else if status == SingleStatus::Failed {
                    self.handle_failed_single(&task_id).await;
                }
            }

            Ok(task_id)
        } else {
            let status = self.distributor.submit_solution(solution)?;

            if status == QuadStatus::AllResponded {
                if let Some(consensus) = self.distributor.evaluate_consensus(&task_id) {
                    self.handle_consensus_result(consensus).await;
                }
            }

            Ok(task_id)
        }
    }

    async fn handle_valid_single(&mut self, task_id: &str, miner_id: &str) {
        info!(
            task_id = %task_id,
            miner_id = %miner_id,
            "Single verifiable task completed successfully"
        );

        if let Some(single) = self.distributor.get_single(task_id) {
            let reward = RewardRecord {
                task_id: task_id.to_string(),
                miner_id: miner_id.to_string(),
                amount: single.miner.envelope.reward,
                locked_until: Utc::now(),
                finalized: true,
                claimed: false,
            };

            let mut pending = self.pending_rewards.write().await;
            pending
                .entry(miner_id.to_string())
                .or_default()
                .push(reward);

            let mut stats = self.stats.write().await;
            stats.total_tasks_completed += 1;
        }

        self.distributor.remove_single(task_id);
    }

    async fn handle_failed_single(&mut self, task_id: &str) {
        warn!(
            task_id = %task_id,
            "Single verifiable task validation failed"
        );

        {
            let mut stats = self.stats.write().await;
            stats.total_tasks_failed += 1;
        }

        self.distributor.remove_single(task_id);
    }

    pub fn evaluate_task_consensus(&mut self, task_id: &str) -> Option<ConsensusResult> {
        self.distributor.evaluate_consensus(task_id)
    }

    async fn handle_consensus_result(&mut self, result: ConsensusResult) {
        match result.action {
            ConsensusAction::Accept => {
                info!(
                    task_id = %result.task_id,
                    valid_miners = ?result.valid_miners,
                    "Consensus reached, calculating rewards"
                );

                let assignment = self.distributor.get_quad(&result.task_id);
                if let Some(quad) = assignment {
                    let base_reward = self.calculate_base_reward(&quad.miners[0].envelope);

                    let reward_per_miner = base_reward / result.valid_miners.len() as u64;

                    let lockup_hours = self.get_lockup_hours(&result.task_id);

                    for miner_id in &result.valid_miners {
                        let reward = RewardRecord {
                            task_id: result.task_id.clone(),
                            miner_id: miner_id.clone(),
                            amount: reward_per_miner,
                            locked_until: Utc::now() + Duration::hours(lockup_hours as i64),
                            finalized: false,
                            claimed: false,
                        };

                        let mut pending = self.pending_rewards.write().await;
                        pending
                            .entry(miner_id.clone())
                            .or_default()
                            .push(reward);
                    }

                    {
                        let mut stats = self.stats.write().await;
                        stats.total_tasks_completed += 1;
                        stats.total_rewards_pending += base_reward;
                    }
                }

                self.distributor.remove_quad(&result.task_id);
            }
            ConsensusAction::Reassign => {
                warn!(
                    task_id = %result.task_id,
                    "Insufficient consensus, would reassign"
                );
            }
            ConsensusAction::Requeue => {
                warn!(
                    task_id = %result.task_id,
                    "No consensus, would requeue"
                );

                {
                    let mut stats = self.stats.write().await;
                    stats.total_tasks_failed += 1;
                }
            }
            ConsensusAction::Fallback => {
                error!(
                    task_id = %result.task_id,
                    "Consensus timeout, fallback required"
                );

                {
                    let mut stats = self.stats.write().await;
                    stats.total_tasks_failed += 1;
                }
            }
        }
    }

    fn calculate_base_reward(&self, _envelope: &crate::pouw::nuw::obfuscation::TaskEnvelope) -> u64 {
        100_000_000
    }

    fn get_lockup_hours(&self, task_id: &str) -> u64 {
        if let Some(quad) = self.distributor.get_quad(task_id) {
            if quad.miners.first().is_some() {
                return 1;
            }
        }
        1
    }

    pub async fn get_pending_rewards(&self, miner_id: &str) -> Vec<RewardRecord> {
        let pending = self.pending_rewards.read().await;
        pending.get(miner_id).cloned().unwrap_or_default()
    }

    pub async fn finalize_rewards(&mut self) -> u64 {
        let mut pending = self.pending_rewards.write().await;
        let mut finalized_count = 0u64;

        for rewards in pending.values_mut() {
            for reward in rewards.iter_mut() {
                if !reward.finalized && Utc::now() >= reward.locked_until {
                    reward.finalized = true;
                    finalized_count += reward.amount;
                }
            }
        }

        if finalized_count > 0 {
            let mut stats = self.stats.write().await;
            stats.total_rewards_pending = stats.total_rewards_pending.saturating_sub(finalized_count);
            stats.total_rewards_finalized += finalized_count;

            info!(
                finalized_amount = finalized_count,
                "Rewards finalized"
            );
        }

        finalized_count
    }

    pub async fn claim_rewards(&mut self, miner_id: &str) -> u64 {
        let mut pending = self.pending_rewards.write().await;

        if let Some(rewards) = pending.get_mut(miner_id) {
            let claimable: u64 = rewards
                .iter()
                .filter(|r| r.finalized && !r.claimed)
                .map(|r| r.amount)
                .sum();

            for reward in rewards.iter_mut() {
                if reward.finalized && !reward.claimed {
                    // Execute TigerBeetle transfer if available
                    if let Some(ref tb) = *self.tigerbeetle.read().await {
                        match tb.create_reward_payout(&reward.task_id, &reward.miner_id, reward.amount as u128).await {
                            Ok(transfer_id) => {
                                debug!(
                                    task_id = %reward.task_id,
                                    miner_id = %reward.miner_id,
                                    amount = %reward.amount,
                                    transfer_id = %transfer_id,
                                    "Reward payout via TigerBeetle"
                                );
                            }
                            Err(e) => {
                                error!(
                                    task_id = %reward.task_id,
                                    error = %e,
                                    "Failed to execute TigerBeetle reward payout"
                                );
                            }
                        }
                    }
                    reward.claimed = true;
                }
            }

            if claimable > 0 {
                info!(
                    miner_id = %miner_id,
                    amount = claimable,
                    "Rewards claimed"
                );
            }

            claimable
        } else {
            0
        }
    }

    pub async fn clawback_reward(&mut self, task_id: &str, miner_id: &str, amount: u64) -> Result<u128, String> {
        if let Some(ref tb) = *self.tigerbeetle.read().await {
            tb.clawback_reward(task_id, miner_id, amount as u128).await
        } else {
            Err("TigerBeetle not initialized".to_string())
        }
    }

    pub async fn get_miner_balance(&self, miner_id: &str) -> Result<u128, String> {
        if let Some(ref tb) = *self.tigerbeetle.read().await {
            tb.get_miner_balance(miner_id).await
        } else {
            Ok(0)
        }
    }

    pub async fn get_rewards_pool_balance(&self) -> Result<u128, String> {
        if let Some(ref tb) = *self.tigerbeetle.read().await {
            tb.get_rewards_pool_balance().await
        } else {
            Ok(0)
        }
    }

    pub fn is_tigerbeetle_initialized(&self) -> bool {
        self.tigerbeetle.try_read().map(|t| t.is_some()).unwrap_or(false)
    }

    pub fn get_stats(&self) -> Arc<RwLock<OracleStats>> {
        self.stats.clone()
    }

    pub fn get_registry(&self) -> &MinerRegistry {
        &self.registry
    }

    pub fn cleanup(&mut self) {
        self.queue.cleanup_expired();
        self.distributor.cleanup_completed(3600_000);
    }

    pub fn get_queue_depth(&self) -> usize {
        self.queue.len()
    }

    pub fn get_active_tasks(&self) -> usize {
        self.distributor.active_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pouw::nuw::{MinerTier, TaskType};

    fn create_test_miner(id: &str) -> MinerInfo {
        MinerInfo {
            miner_id: id.to_string(),
            public_key: vec![0u8; 32],
            supported_task_types: vec![
                TaskType::SigBatchVerify,
                TaskType::ZkBatchVerify,
                TaskType::RecursiveSnark,
            ],
            region: "us-east".to_string(),
            endpoint: "127.0.0.1:8080".to_string(),
            reputation_score: 1.0,
            tier: MinerTier::Bronze,
        }
    }

    fn create_test_task() -> NuwTask {
        NuwTask {
            task_id: format!("task_{}", Utc::now().timestamp_millis()),
            task_type: TaskType::SigBatchVerify,
            payload: vec![1, 2, 3, 4],
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            difficulty_multiplier: 1.0,
        }
    }

    fn create_oracle_with_miners() -> NuwOracle {
        let mut registry = MinerRegistry::new();
        for i in 0..5 {
            registry.register(create_test_miner(&format!("miner_{}", i)));
        }
        NuwOracle::with_registry(registry)
    }

    #[tokio::test]
    async fn test_submit_task() {
        let mut oracle = create_oracle_with_miners();
        let task = create_test_task();

        let result = oracle.submit_task(task).await;
        assert!(result.is_ok());

        let stats_lock = oracle.get_stats();
        let stats = stats_lock.read().await;
        assert_eq!(stats.total_tasks_received, 1);
    }

    #[tokio::test]
    async fn test_process_task() {
        let mut oracle = create_oracle_with_miners();
        let task = create_test_task();

        oracle.submit_task(task).await.unwrap();

        let assignment = oracle.process_next_task();
        assert!(assignment.is_ok());
        assert!(assignment.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_queue_priority() {
        let mut oracle = create_oracle_with_miners();

        let p1_task = NuwTask {
            task_id: "p1_task".to_string(),
            task_type: TaskType::SigBatchVerify,
            payload: vec![],
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            difficulty_multiplier: 1.0,
        };

        let p0_task = NuwTask {
            task_id: "p0_task".to_string(),
            task_type: TaskType::RecursiveSnark,
            payload: vec![],
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            difficulty_multiplier: 1.0,
        };

        oracle.submit_task(p1_task).await.unwrap();
        oracle.submit_task(p0_task).await.unwrap();

        let assignment = oracle.process_next_task().unwrap().unwrap();
        match assignment {
            TaskAssignment::Single(s) => assert_eq!(s.task_id, "p0_task"),
            TaskAssignment::Quad(q) => assert_eq!(q.task_id, "p0_task"),
        }
    }

    #[tokio::test]
    async fn test_reward_claim() {
        let mut oracle = create_oracle_with_miners();

        let mut pending = oracle.pending_rewards.write().await;
        pending.insert(
            "miner_1".to_string(),
            vec![RewardRecord {
                task_id: "task_1".to_string(),
                miner_id: "miner_1".to_string(),
                amount: 1000,
                locked_until: Utc::now() - Duration::hours(1),
                finalized: true,
                claimed: false,
            }],
        );
        drop(pending);

        let claimed = oracle.claim_rewards("miner_1").await;
        assert_eq!(claimed, 1000);

        let claimed_again = oracle.claim_rewards("miner_1").await;
        assert_eq!(claimed_again, 0);
    }

    #[tokio::test]
    async fn test_get_stats() {
        let oracle = create_oracle_with_miners();

        let stats_lock = oracle.get_stats();
        let stats = stats_lock.read().await;
        // Stats are tracked separately, registry count may differ
        assert_eq!(stats.queue_depth, 0);
    }
}
