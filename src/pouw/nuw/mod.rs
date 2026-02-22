//! NUW (Network Utility Work) Oracle Module
//!
//! This module implements the NUW-specific oracle logic for quad-send BFT
//! work distribution to miners.
//!
//! ## Architecture
//!
//! ```text
//! nuw/
//! ├── mod.rs           - Module exports and shared types
//! ├── priority_queue.rs - FIFO impact-based task queueing (P0/P1/P2 buckets)
//! ├── distributor.rs   - Quad-send BFT work distribution (4 miners, 3-of-4 consensus)
//! ├── obfuscation.rs   - Task envelopes + optional blinding
//! └── oracle.rs        - NUW work orchestration (coordinates above components)
//! ```
//!
//! ## Data Flow
//!
//! ```text
//! Protocol Request
//!       │
//!       ▼
//! ┌─────────────────┐
//! │  NuwOracle      │ ◄── Main orchestrator
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐     ┌─────────────────┐
//! │ PriorityQueue   │────▶│ Distributor     │
//! │ (P0/P1/P2)      │     │ (quad-send)     │
//! └─────────────────┘     └────────┬────────┘
//!                                  │
//!                                  ▼
//!                         ┌─────────────────┐
//!                         │ Obfuscator      │
//!                         │ (envelopes)     │
//!                         └────────┬────────┘
//!                                  │
//!                                  ▼
//!                         Send to 4 Miners
//! ```

pub mod distributor;
pub mod obfuscation;
pub mod oracle;
pub mod priority_queue;

pub use distributor::{Distributor, QuadAssignment, QuadStatus, SingleAssignment, SingleStatus};
pub use obfuscation::{EnvelopeMode, Obfuscator, TaskEnvelope};
pub use oracle::NuwOracle;
pub use priority_queue::{PriorityBucket, PriorityQueue, QueuedTask};

pub const QUAD_SIZE: usize = 4;
pub const CONSENSUS_THRESHOLD: usize = 3;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub enum TaskAssignment {
    Single(SingleAssignment),
    Quad(QuadAssignment),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskPriority {
    P0,
    P1,
    P2,
    Special,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskType {
    SigBatchVerify,
    ZkBatchVerify,
    ZkVerify,
    RecursiveSnark,
    MerkleBatch,
    MerkleVerify,
    ElGamalRangeProof,
    ElGamalConservationProof,
    TxPreValidate,
    BoincRosetta,
    BoincFolding,
    BoincEinstein,
    BoincMilkyWay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DistributionMode {
    Single,
    Quad,
}

impl TaskType {
    pub fn distribution_mode(&self) -> DistributionMode {
        match self {
            TaskType::BoincRosetta
            | TaskType::BoincFolding
            | TaskType::BoincEinstein
            | TaskType::BoincMilkyWay => DistributionMode::Quad,
            _ => DistributionMode::Single,
        }
    }

    pub fn is_verifiable(&self) -> bool {
        matches!(self.distribution_mode(), DistributionMode::Single)
    }

    pub fn priority(&self) -> TaskPriority {
        match self {
            TaskType::RecursiveSnark => TaskPriority::P0,
            TaskType::SigBatchVerify
            | TaskType::ZkBatchVerify
            | TaskType::ZkVerify
            | TaskType::MerkleBatch
            | TaskType::ElGamalRangeProof
            | TaskType::ElGamalConservationProof
            | TaskType::TxPreValidate => TaskPriority::P1,
            TaskType::MerkleVerify => TaskPriority::P2,
            TaskType::BoincRosetta
            | TaskType::BoincFolding
            | TaskType::BoincEinstein
            | TaskType::BoincMilkyWay => TaskPriority::Special,
        }
    }

    pub fn timeout_ms(&self) -> u64 {
        match self {
            TaskType::SigBatchVerify => 500,
            TaskType::ZkBatchVerify => 2000,
            TaskType::ZkVerify => 2000,
            TaskType::RecursiveSnark => 60_000,
            TaskType::ElGamalRangeProof => 1000,
            TaskType::ElGamalConservationProof => 1000,
            TaskType::MerkleBatch => 500,
            TaskType::MerkleVerify => 200,
            TaskType::TxPreValidate => 100,
            TaskType::BoincRosetta
            | TaskType::BoincFolding
            | TaskType::BoincEinstein
            | TaskType::BoincMilkyWay => 86_400_000,
        }
    }

    pub fn lockup_hours(&self) -> u64 {
        match self {
            TaskType::SigBatchVerify | TaskType::MerkleBatch | TaskType::TxPreValidate => 1,
            TaskType::ZkBatchVerify
            | TaskType::ZkVerify
            | TaskType::ElGamalRangeProof
            | TaskType::ElGamalConservationProof => 6,
            TaskType::RecursiveSnark => 12,
            TaskType::MerkleVerify => 1,
            TaskType::BoincRosetta
            | TaskType::BoincFolding
            | TaskType::BoincEinstein
            | TaskType::BoincMilkyWay => 48,
        }
    }

    pub fn base_reward(&self) -> u64 {
        match self {
            TaskType::SigBatchVerify => 10_000_000,
            TaskType::ZkBatchVerify => 100_000_000,
            TaskType::ZkVerify => 50_000_000,
            TaskType::RecursiveSnark => 5_000_000_000,
            TaskType::MerkleBatch => 20_000_000,
            TaskType::MerkleVerify => 5_000_000,
            TaskType::ElGamalRangeProof => 30_000_000,
            TaskType::ElGamalConservationProof => 20_000_000,
            TaskType::TxPreValidate => 1_000_000,
            TaskType::BoincRosetta
            | TaskType::BoincFolding
            | TaskType::BoincEinstein
            | TaskType::BoincMilkyWay => 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NuwTask {
    pub task_id: String,
    pub task_type: TaskType,
    pub payload: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub difficulty_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NuwSolution {
    pub task_id: String,
    pub miner_id: String,
    pub miner_index: usize,
    pub result: Vec<u8>,
    pub computed_at: DateTime<Utc>,
    pub compute_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerInfo {
    pub miner_id: String,
    pub public_key: Vec<u8>,
    pub supported_task_types: Vec<TaskType>,
    pub region: String,
    pub endpoint: String,
    pub reputation_score: f64,
    pub tier: MinerTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MinerTier {
    Bronze,
    Silver,
    Gold,
    Platinum,
}

impl MinerTier {
    pub fn from_valid_submissions(count: u64, invalid_rate: f64) -> Self {
        if count >= 5000 && invalid_rate < 0.005 {
            MinerTier::Platinum
        } else if count >= 1000 && invalid_rate < 0.01 {
            MinerTier::Gold
        } else if count >= 100 {
            MinerTier::Silver
        } else {
            MinerTier::Bronze
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConsensusResult {
    pub task_id: String,
    pub reached: bool,
    pub valid_miners: Vec<String>,
    pub invalid_miners: Vec<String>,
    pub action: ConsensusAction,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusAction {
    Accept,
    Reassign,
    Requeue,
    Fallback,
}

#[derive(Debug, Clone, Default)]
pub struct MinerRegistry {
    miners: HashMap<String, MinerInfo>,
    by_task_type: HashMap<TaskType, Vec<String>>,
    by_region: HashMap<String, Vec<String>>,
}

impl MinerRegistry {
    pub fn new() -> Self {
        Self {
            miners: HashMap::new(),
            by_task_type: HashMap::new(),
            by_region: HashMap::new(),
        }
    }

    pub fn register(&mut self, miner: MinerInfo) {
        let miner_id = miner.miner_id.clone();
        let region = miner.region.clone();
        let task_types = miner.supported_task_types.clone();

        self.miners.insert(miner_id.clone(), miner);

        self.by_region.entry(region).or_default().push(miner_id.clone());

        for task_type in task_types {
            self.by_task_type
                .entry(task_type)
                .or_default()
                .push(miner_id.clone());
        }
    }

    pub fn get(&self, miner_id: &str) -> Option<&MinerInfo> {
        self.miners.get(miner_id)
    }

    pub fn get_miners_for_task(&self, task_type: TaskType) -> Vec<&MinerInfo> {
        self.by_task_type
            .get(&task_type)
            .map(|ids| ids.iter().filter_map(|id| self.miners.get(id)).collect())
            .unwrap_or_default()
    }

    pub fn get_miners_by_region(&self, region: &str) -> Vec<&MinerInfo> {
        self.by_region
            .get(region)
            .map(|ids| ids.iter().filter_map(|id| self.miners.get(id)).collect())
            .unwrap_or_default()
    }

    pub fn count(&self) -> usize {
        self.miners.len()
    }
}
