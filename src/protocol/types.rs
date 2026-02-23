//! Shared Types for Protocol-Oracle Communication
//!
//! These types are shared between the Silica protocol and the Oracle.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Task priority bucket (matches protocol)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityBucket {
    P0,
    P1,
    P2,
    P3,
    Special,
}

/// NUW task type (matches protocol)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NuwTaskType {
    // Hot Path
    SigBatchVerify,
    ZkBatchVerify,
    ZkVerify,
    RecursiveSnark,
    MerkleBatch,
    MerkleVerify,
    PoseidonBatch,
    TxPreValidate,

    // Homomorphic Encryption
    ElGamalRangeProof,
    ElGamalConservationProof,
    ElGamalBatchVerify,

    // BOINC
    BoincRosetta,
    BoincFolding,
    BoincEinstein,
    BoincMilkyWay,
}

impl NuwTaskType {
    pub fn priority(&self) -> PriorityBucket {
        match self {
            Self::RecursiveSnark => PriorityBucket::P0,
            Self::SigBatchVerify
            | Self::ZkBatchVerify
            | Self::ZkVerify
            | Self::MerkleBatch
            | Self::ElGamalRangeProof
            | Self::ElGamalConservationProof
            | Self::TxPreValidate => PriorityBucket::P1,
            Self::MerkleVerify | Self::PoseidonBatch | Self::ElGamalBatchVerify => {
                PriorityBucket::P2
            }
            Self::BoincRosetta | Self::BoincFolding | Self::BoincEinstein | Self::BoincMilkyWay => {
                PriorityBucket::Special
            }
        }
    }

    pub fn is_boinc(&self) -> bool {
        matches!(
            self,
            Self::BoincRosetta | Self::BoincFolding | Self::BoincEinstein | Self::BoincMilkyWay
        )
    }
}

/// Task received from protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolTask {
    /// Unique task ID
    pub task_id: String,

    /// Task type
    pub task_type: NuwTaskType,

    /// Priority bucket
    pub priority: PriorityBucket,

    /// Task payload (type-specific)
    pub payload: TaskPayload,

    /// Base reward in CHERT base units
    pub reward_base: u64,

    /// When the task was created
    pub created_at: DateTime<Utc>,

    /// When the task expires
    pub expires_at: DateTime<Utc>,

    /// Requester (optional - for tracking)
    pub requester: Option<String>,

    /// Metadata
    pub metadata: TaskMetadata,
}

/// Task payload variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum TaskPayload {
    /// BOINC work unit
    Boinc(BoincPayload),

    /// Signature batch verification
    SigBatch(SigBatchPayload),

    /// ZK proof verification
    ZkVerify(ZkVerifyPayload),

    /// Generic bytes
    Raw(Vec<u8>),
}

/// BOINC task payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoincPayload {
    /// Project name (e.g., "MilkyWay@Home")
    pub project: String,

    /// Work unit name
    pub wu_name: String,

    /// Result name
    pub result_name: String,

    /// Estimated FLOPs
    pub rsc_fpops_est: f64,

    /// Credit estimate
    pub credit_estimate: f64,
}

/// Signature batch verification payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigBatchPayload {
    /// Number of signatures
    pub batch_size: usize,

    /// Hash of signature data
    pub batch_hash: String,
}

/// ZK proof verification payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkVerifyPayload {
    /// Proof ID
    pub proof_id: String,

    /// Proof type
    pub proof_type: String,

    /// Verification key hash
    pub vk_hash: String,
}

/// Task metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMetadata {
    /// Lockup window in seconds
    pub lockup_secs: u64,

    /// Difficulty multiplier
    pub difficulty_multiplier: f64,

    /// Any additional context
    #[serde(default)]
    pub extra: std::collections::HashMap<String, String>,
}

/// Proof to submit back to protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSubmission {
    /// Task ID this proof is for
    pub task_id: String,

    /// Task type
    pub task_type: NuwTaskType,

    /// Proof type
    pub proof_type: ProofType,

    /// Proof data
    pub proof_data: ProofData,

    /// Miners who contributed
    pub miners: Vec<MinerContribution>,

    /// Consensus information
    pub consensus: ConsensusInfo,

    /// When the proof was generated
    pub generated_at: DateTime<Utc>,

    /// Oracle signature
    pub signature: String,
}

/// Type of proof
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofType {
    /// BOINC credit proof
    BoincCredit,

    /// Signature batch verification proof
    SigBatch,

    /// ZK proof verification
    ZkVerify,

    /// Merkle proof
    Merkle,

    /// Recursive SNARK checkpoint
    RecursiveSnark,
}

/// Proof data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ProofData {
    /// BOINC-specific proof
    Boinc(BoincProofData),

    /// Hash-based proof
    Hash(HashProofData),

    /// ZK proof
    Zk(ZkProofData),
}

/// BOINC proof data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoincProofData {
    /// Work unit name
    pub wu_name: String,

    /// Result name
    pub result_name: String,

    /// Credits earned
    pub credits: f64,

    /// CPU time
    pub cpu_time: f64,

    /// Exit status
    pub exit_status: i32,

    /// BOINC validation status
    pub validate_state: String,

    /// Hash of result files
    pub result_hash: String,
}

/// Hash-based proof data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashProofData {
    /// Result hash
    pub hash: String,

    /// Salt used
    pub salt: String,

    /// Additional context
    pub context: String,
}

/// ZK proof data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofData {
    /// Proof bytes
    pub proof: Vec<u8>,

    /// Public inputs
    pub public_inputs: Vec<Vec<u8>>,

    /// Verification key ID
    pub vk_id: String,
}

/// Miner contribution to a proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerContribution {
    /// Miner ID
    pub miner_id: String,

    /// Miner's account address
    pub account_address: String,

    /// Compute time in milliseconds
    pub compute_time_ms: u64,

    /// Whether this miner's result matched consensus
    pub matched_consensus: bool,

    /// Reward share (basis points, 10000 = 100%)
    pub reward_share_bps: u16,
}

/// Consensus information for the proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusInfo {
    /// Whether consensus was reached
    pub reached: bool,

    /// Number of miners that agreed
    pub agreeing_miners: usize,

    /// Total miners assigned
    pub total_miners: usize,

    /// Consensus threshold (e.g., 3 for quad-send)
    pub threshold: usize,
}

/// Epoch event from protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochEvent {
    /// Event type
    pub event_type: EpochEventType,

    /// Epoch number
    pub epoch: u64,

    /// When the event occurred
    pub timestamp: DateTime<Utc>,

    /// Event details
    pub details: EpochDetails,
}

/// Type of epoch event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochEventType {
    /// Epoch started
    Started,

    /// Epoch finalized
    Finalized,

    /// Rewards calculated
    RewardsCalculated,
}

/// Epoch details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochDetails {
    /// Block height at epoch boundary
    pub block_height: u64,

    /// Number of proofs accepted
    pub proofs_accepted: usize,

    /// Total rewards distributed (CHERT base units)
    pub total_rewards: u64,

    /// Validators participating
    pub validators: Vec<String>,

    /// Any slashing events
    pub slashes: Vec<SlashRecord>,
}

/// Record of a slash event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashRecord {
    /// Miner/account slashed
    pub account: String,

    /// Reason
    pub reason: String,

    /// Amount slashed
    pub amount: u64,
}

/// Claim request from user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// Miner ID
    pub miner_id: String,

    /// Account address to receive rewards
    pub account_address: String,

    /// Signature proving ownership
    pub signature: String,

    /// Nonce for replay protection
    pub nonce: u64,
}

/// Claim response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimResponse {
    /// Whether claim was successful
    pub success: bool,

    /// Amount claimed (CHERT base units)
    pub amount: u64,

    /// Transaction ID (if successful)
    pub tx_id: Option<String>,

    /// Error message (if failed)
    pub error: Option<String>,

    /// Remaining pending balance
    pub remaining_pending: u64,

    /// Remaining finalized balance
    pub remaining_finalized: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_type_priority() {
        assert_eq!(NuwTaskType::RecursiveSnark.priority(), PriorityBucket::P0);
        assert_eq!(NuwTaskType::SigBatchVerify.priority(), PriorityBucket::P1);
        assert_eq!(
            NuwTaskType::BoincMilkyWay.priority(),
            PriorityBucket::Special
        );
    }

    #[test]
    fn test_task_serialization() {
        let task = ProtocolTask {
            task_id: "task_123".to_string(),
            task_type: NuwTaskType::BoincMilkyWay,
            priority: PriorityBucket::Special,
            payload: TaskPayload::Raw(vec![1, 2, 3]),
            reward_base: 1_000_000,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            requester: Some("protocol".to_string()),
            metadata: TaskMetadata {
                lockup_secs: 86400,
                difficulty_multiplier: 1.0,
                extra: std::collections::HashMap::new(),
            },
        };

        let json = serde_json::to_string(&task).unwrap();
        let parsed: ProtocolTask = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.task_id, "task_123");
    }
}
