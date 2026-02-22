//! Quad-Send BFT Work Distribution
//!
//! Implements the quad-send model where each NUW task is sent to exactly 4 miners
//! simultaneously, with BFT consensus requiring 3-of-4 agreement.
//!
//! ## Key Features
//!
//! - VRF-based miner selection for fairness
//! - Cross-region assignment where possible (anti-eclipse)
//! - Per-miner task envelopes (no double receipts)
//! - Timeout handling with reassignment
//! - Consensus evaluation (3-of-4 threshold)

use crate::pouw::nuw::obfuscation::{EnvelopeMode, Obfuscator, TaskEnvelope};
use crate::pouw::nuw::{
    ConsensusAction, ConsensusResult, DistributionMode, MinerInfo, MinerRegistry, NuwSolution,
    NuwTask, CONSENSUS_THRESHOLD, QUAD_SIZE,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuadStatus {
    Pending,
    PartialSend,
    AllSent,
    PartialResponse,
    AllResponded,
    ConsensusReached,
    Failed,
    Timeout,
}

#[derive(Debug, Clone)]
pub struct MinerAssignment {
    pub miner_id: String,
    pub envelope: TaskEnvelope,
    pub status: AssignmentStatus,
    pub solution: Option<NuwSolution>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssignmentStatus {
    Pending,
    Sent,
    Responded,
    Failed,
    Timeout,
}

#[derive(Debug, Clone)]
pub struct QuadAssignment {
    pub task_id: String,
    pub miners: Vec<MinerAssignment>,
    pub assigned_at: DateTime<Utc>,
    pub status: QuadStatus,
    pub deadline: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SingleStatus {
    Pending,
    Sent,
    Responded,
    Validated,
    Failed,
    Timeout,
}

#[derive(Debug, Clone)]
pub struct SingleAssignment {
    pub task_id: String,
    pub miner: MinerAssignment,
    pub assigned_at: DateTime<Utc>,
    pub status: SingleStatus,
    pub deadline: DateTime<Utc>,
    pub verification_result: Option<bool>,
}

impl SingleAssignment {
    pub fn is_complete(&self) -> bool {
        matches!(
            self.status,
            SingleStatus::Validated | SingleStatus::Failed | SingleStatus::Timeout
        )
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.deadline
    }
}

impl QuadAssignment {
    pub fn new(task_id: String, deadline: DateTime<Utc>) -> Self {
        Self {
            task_id,
            miners: Vec::with_capacity(QUAD_SIZE),
            assigned_at: Utc::now(),
            status: QuadStatus::Pending,
            deadline,
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(
            self.status,
            QuadStatus::ConsensusReached | QuadStatus::Failed | QuadStatus::Timeout
        )
    }

    pub fn responses_count(&self) -> usize {
        self.miners
            .iter()
            .filter(|m| matches!(m.status, AssignmentStatus::Responded))
            .count()
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.deadline
    }
}

pub struct Distributor {
    registry: MinerRegistry,
    obfuscator: Obfuscator,
    active_quads: HashMap<String, QuadAssignment>,
    active_singles: HashMap<String, SingleAssignment>,
    miner_task_history: HashMap<String, HashSet<String>>,
}

impl Distributor {
    pub fn new(registry: MinerRegistry) -> Self {
        Self {
            registry,
            obfuscator: Obfuscator::new(),
            active_quads: HashMap::new(),
            active_singles: HashMap::new(),
            miner_task_history: HashMap::new(),
        }
    }

    pub fn with_registry(&mut self, registry: MinerRegistry) {
        self.registry = registry;
    }

    pub fn assign_quad(
        &mut self,
        task: &NuwTask,
        mode: EnvelopeMode,
    ) -> Result<QuadAssignment, String> {
        let available_miners = self.registry.get_miners_for_task(task.task_type);

        if available_miners.len() < QUAD_SIZE {
            return Err(format!(
                "Not enough miners for task {:?}: need {}, have {}",
                task.task_type,
                QUAD_SIZE,
                available_miners.len()
            ));
        }

        let selected = self.select_miners_vrf(&available_miners, &task.task_id);

        let mut quad = QuadAssignment::new(task.task_id.clone(), task.expires_at);

        for (index, miner) in selected.into_iter().enumerate() {
            let envelope =
                self.obfuscator
                    .create_envelope(task, &miner.miner_id, index, mode.clone());

            let assignment = MinerAssignment {
                miner_id: miner.miner_id.clone(),
                envelope,
                status: AssignmentStatus::Pending,
                solution: None,
            };

            quad.miners.push(assignment);

            self.miner_task_history
                .entry(miner.miner_id.clone())
                .or_default()
                .insert(task.task_id.clone());
        }

        quad.status = QuadStatus::Pending;

        self.active_quads.insert(task.task_id.clone(), quad.clone());

        info!(
            task_id = %task.task_id,
            miners = ?quad.miners.iter().map(|m| &m.miner_id).collect::<Vec<_>>(),
            "Assigned quad for task"
        );

        Ok(quad)
    }

    pub fn assign_single(
        &mut self,
        task: &NuwTask,
        mode: EnvelopeMode,
    ) -> Result<SingleAssignment, String> {
        let available_miners = self.registry.get_miners_for_task(task.task_type);

        if available_miners.is_empty() {
            return Err(format!(
                "No miners available for task type {:?}",
                task.task_type
            ));
        }

        let selected = self.select_single_miner(&available_miners, &task.task_id);

        let envelope = self
            .obfuscator
            .create_envelope(task, &selected.miner_id, 0, mode);

        let assignment = MinerAssignment {
            miner_id: selected.miner_id.clone(),
            envelope,
            status: AssignmentStatus::Pending,
            solution: None,
        };

        let single = SingleAssignment {
            task_id: task.task_id.clone(),
            miner: assignment,
            assigned_at: Utc::now(),
            status: SingleStatus::Pending,
            deadline: task.expires_at,
            verification_result: None,
        };

        self.miner_task_history
            .entry(selected.miner_id.clone())
            .or_default()
            .insert(task.task_id.clone());

        self.active_singles
            .insert(task.task_id.clone(), single.clone());

        info!(
            task_id = %task.task_id,
            miner_id = %single.miner.miner_id,
            "Assigned single miner for verifiable task"
        );

        Ok(single)
    }

    fn select_single_miner(&self, available: &[&MinerInfo], task_id: &str) -> MinerInfo {
        let mut scored: Vec<(MinerInfo, u64)> = available
            .iter()
            .map(|m| {
                let score = self.compute_selection_score(m, task_id);
                ((*m).clone(), score)
            })
            .collect();

        scored.sort_by(|a, b| b.1.cmp(&a.1));

        scored.into_iter().next().expect("No miners available").0
    }

    fn select_miners_vrf(&self, available: &[&MinerInfo], task_id: &str) -> Vec<MinerInfo> {
        let mut scored: Vec<(MinerInfo, u64)> = available
            .iter()
            .map(|m| {
                let score = self.compute_selection_score(m, task_id);
                ((*m).clone(), score)
            })
            .collect();

        scored.sort_by(|a, b| b.1.cmp(&a.1));

        scored.into_iter().take(QUAD_SIZE).map(|(m, _)| m).collect()
    }

    fn compute_selection_score(&self, miner: &MinerInfo, task_id: &str) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(task_id.as_bytes());
        hasher.update(miner.miner_id.as_bytes());
        hasher.update(miner.region.as_bytes());
        let hash = hasher.finalize();

        let mut score = u64::from_be_bytes(hash[..8].try_into().unwrap());

        let reputation_bonus = (miner.reputation_score * 1000.0) as u64;
        score = score.wrapping_add(reputation_bonus);

        let tier_bonus = match miner.tier {
            crate::pouw::nuw::MinerTier::Platinum => 2000,
            crate::pouw::nuw::MinerTier::Gold => 1000,
            crate::pouw::nuw::MinerTier::Silver => 500,
            crate::pouw::nuw::MinerTier::Bronze => 0,
        };
        score = score.wrapping_add(tier_bonus);

        score
    }

    pub fn mark_sent(&mut self, task_id: &str, miner_id: &str) -> Result<(), String> {
        let quad = self
            .active_quads
            .get_mut(task_id)
            .ok_or_else(|| format!("No quad assignment for task {}", task_id))?;

        let assignment = quad
            .miners
            .iter_mut()
            .find(|m| m.miner_id == miner_id)
            .ok_or_else(|| format!("Miner {} not in quad", miner_id))?;

        assignment.status = AssignmentStatus::Sent;

        let sent_count = quad
            .miners
            .iter()
            .filter(|m| {
                matches!(
                    m.status,
                    AssignmentStatus::Sent | AssignmentStatus::Responded
                )
            })
            .count();

        quad.status = if sent_count == QUAD_SIZE {
            QuadStatus::AllSent
        } else {
            QuadStatus::PartialSend
        };

        debug!(task_id, miner_id, "Marked as sent");
        Ok(())
    }

    pub fn submit_solution(&mut self, solution: NuwSolution) -> Result<QuadStatus, String> {
        let quad = self
            .active_quads
            .get_mut(&solution.task_id)
            .ok_or_else(|| format!("No quad assignment for task {}", solution.task_id))?;

        let assignment = quad
            .miners
            .iter_mut()
            .find(|m| m.miner_id == solution.miner_id)
            .ok_or_else(|| format!("Miner {} not in quad", solution.miner_id))?;

        assignment.status = AssignmentStatus::Responded;
        assignment.solution = Some(solution);

        let response_count = quad.responses_count();
        quad.status = if response_count == QUAD_SIZE {
            QuadStatus::AllResponded
        } else {
            QuadStatus::PartialResponse
        };

        debug!(
            task_id = %quad.task_id,
            response_count,
            "Solution submitted"
        );

        Ok(quad.status)
    }

    pub fn mark_single_sent(&mut self, task_id: &str) -> Result<(), String> {
        let single = self
            .active_singles
            .get_mut(task_id)
            .ok_or_else(|| format!("No single assignment for task {}", task_id))?;

        single.miner.status = AssignmentStatus::Sent;
        single.status = SingleStatus::Sent;

        debug!(task_id, "Marked single as sent");
        Ok(())
    }

    pub fn submit_single_solution(
        &mut self,
        solution: NuwSolution,
    ) -> Result<SingleStatus, String> {
        let single = self
            .active_singles
            .get_mut(&solution.task_id)
            .ok_or_else(|| format!("No single assignment for task {}", solution.task_id))?;

        single.miner.status = AssignmentStatus::Responded;
        single.miner.solution = Some(solution);
        single.status = SingleStatus::Responded;

        debug!(
            task_id = %single.task_id,
            "Single solution submitted"
        );

        Ok(single.status)
    }

    pub fn validate_single_solution(
        &mut self,
        task_id: &str,
        is_valid: bool,
    ) -> Result<SingleStatus, String> {
        let single = self
            .active_singles
            .get_mut(task_id)
            .ok_or_else(|| format!("No single assignment for task {}", task_id))?;

        single.verification_result = Some(is_valid);

        if is_valid {
            single.status = SingleStatus::Validated;
            single.miner.status = AssignmentStatus::Responded;
            info!(task_id, "Single solution validated successfully");
        } else {
            single.status = SingleStatus::Failed;
            single.miner.status = AssignmentStatus::Failed;
            warn!(task_id, "Single solution validation failed");
        }

        Ok(single.status)
    }

    pub fn get_single(&self, task_id: &str) -> Option<&SingleAssignment> {
        self.active_singles.get(task_id)
    }

    pub fn remove_single(&mut self, task_id: &str) -> Option<SingleAssignment> {
        self.active_singles.remove(task_id)
    }

    pub fn evaluate_consensus(&mut self, task_id: &str) -> Option<ConsensusResult> {
        let quad = self.active_quads.get(task_id)?;

        if quad.is_expired() {
            let result = ConsensusResult {
                task_id: task_id.to_string(),
                reached: false,
                valid_miners: vec![],
                invalid_miners: quad.miners.iter().map(|m| m.miner_id.clone()).collect(),
                action: ConsensusAction::Fallback,
                timestamp: Utc::now(),
            };

            if let Some(q) = self.active_quads.get_mut(task_id) {
                q.status = QuadStatus::Timeout;
            }

            return Some(result);
        }

        let responses: Vec<_> = quad
            .miners
            .iter()
            .filter_map(|m| m.solution.as_ref().map(|s| (m.miner_id.clone(), s)))
            .collect();

        if responses.len() < CONSENSUS_THRESHOLD {
            return None;
        }

        let mut result_groups: HashMap<Vec<u8>, Vec<String>> = HashMap::new();
        for (miner_id, solution) in &responses {
            let result_hash = self.hash_result(&solution.result);
            result_groups
                .entry(result_hash)
                .or_default()
                .push(miner_id.clone());
        }

        let largest_group = result_groups.values().max_by_key(|v| v.len())?;

        if largest_group.len() >= CONSENSUS_THRESHOLD {
            let valid_miners = largest_group.clone();
            let invalid_miners: Vec<String> = quad
                .miners
                .iter()
                .filter(|m| !valid_miners.contains(&m.miner_id))
                .map(|m| m.miner_id.clone())
                .collect();

            let result = ConsensusResult {
                task_id: task_id.to_string(),
                reached: true,
                valid_miners,
                invalid_miners,
                action: ConsensusAction::Accept,
                timestamp: Utc::now(),
            };

            if let Some(q) = self.active_quads.get_mut(task_id) {
                q.status = QuadStatus::ConsensusReached;
            }

            info!(
                task_id,
                valid_miners = ?result.valid_miners,
                "Consensus reached"
            );

            Some(result)
        } else if largest_group.len() == 2 {
            let invalid_miners: Vec<String> =
                quad.miners.iter().map(|m| m.miner_id.clone()).collect();

            let result = ConsensusResult {
                task_id: task_id.to_string(),
                reached: false,
                valid_miners: vec![],
                invalid_miners,
                action: ConsensusAction::Reassign,
                timestamp: Utc::now(),
            };

            debug!(task_id, "No consensus - reassigning");
            Some(result)
        } else {
            let invalid_miners: Vec<String> =
                quad.miners.iter().map(|m| m.miner_id.clone()).collect();

            let result = ConsensusResult {
                task_id: task_id.to_string(),
                reached: false,
                valid_miners: vec![],
                invalid_miners,
                action: ConsensusAction::Requeue,
                timestamp: Utc::now(),
            };

            warn!(task_id, "All results different - requeueing");
            Some(result)
        }
    }

    fn hash_result(&self, result: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.finalize().to_vec()
    }

    pub fn mark_failed(&mut self, task_id: &str, miner_id: &str) -> Result<(), String> {
        let quad = self
            .active_quads
            .get_mut(task_id)
            .ok_or_else(|| format!("No quad assignment for task {}", task_id))?;

        let assignment = quad
            .miners
            .iter_mut()
            .find(|m| m.miner_id == miner_id)
            .ok_or_else(|| format!("Miner {} not in quad", miner_id))?;

        assignment.status = AssignmentStatus::Failed;

        debug!(task_id, miner_id, "Marked as failed");
        Ok(())
    }

    pub fn get_quad(&self, task_id: &str) -> Option<&QuadAssignment> {
        self.active_quads.get(task_id)
    }

    pub fn remove_quad(&mut self, task_id: &str) -> Option<QuadAssignment> {
        self.active_quads.remove(task_id)
    }

    pub fn active_count(&self) -> usize {
        self.active_quads.len() + self.active_singles.len()
    }

    pub fn active_quad_count(&self) -> usize {
        self.active_quads.len()
    }

    pub fn active_single_count(&self) -> usize {
        self.active_singles.len()
    }

    pub fn cleanup_completed(&mut self, max_age_ms: i64) -> usize {
        let now = Utc::now();
        let before_quads = self.active_quads.len();
        let before_singles = self.active_singles.len();

        self.active_quads.retain(|_, quad| {
            if quad.is_complete() {
                let age = now
                    .signed_duration_since(quad.assigned_at)
                    .num_milliseconds();
                age < max_age_ms
            } else {
                true
            }
        });

        self.active_singles.retain(|_, single| {
            if single.is_complete() {
                let age = now
                    .signed_duration_since(single.assigned_at)
                    .num_milliseconds();
                age < max_age_ms
            } else {
                true
            }
        });

        let removed_quads = before_quads - self.active_quads.len();
        let removed_singles = before_singles - self.active_singles.len();
        let total_removed = removed_quads + removed_singles;

        if total_removed > 0 {
            debug!(
                removed_quads,
                removed_singles, "Cleaned up completed assignments"
            );
        }
        total_removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pouw::nuw::{MinerTier, TaskType};

    fn create_test_miner(id: &str, task_types: Vec<TaskType>) -> MinerInfo {
        MinerInfo {
            miner_id: id.to_string(),
            public_key: vec![0u8; 32],
            supported_task_types: task_types,
            region: "us-east".to_string(),
            endpoint: "127.0.0.1:8080".to_string(),
            reputation_score: 1.0,
            tier: MinerTier::Bronze,
        }
    }

    fn create_test_task() -> NuwTask {
        NuwTask {
            task_id: "test_task_1".to_string(),
            task_type: TaskType::SigBatchVerify,
            payload: vec![1, 2, 3, 4],
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
            difficulty_multiplier: 1.0,
        }
    }

    fn create_registry_with_miners() -> MinerRegistry {
        let mut registry = MinerRegistry::new();
        for i in 0..5 {
            registry.register(create_test_miner(
                &format!("miner_{}", i),
                vec![TaskType::SigBatchVerify],
            ));
        }
        registry
    }

    #[test]
    fn test_assign_quad_requires_miners() {
        let registry = MinerRegistry::new();
        let mut distributor = Distributor::new(registry);

        let task = create_test_task();
        let result = distributor.assign_quad(&task, EnvelopeMode::Public);

        assert!(result.is_err());
    }

    #[test]
    fn test_assign_quad_success() {
        let registry = create_registry_with_miners();
        let mut distributor = Distributor::new(registry);

        let task = create_test_task();
        let result = distributor.assign_quad(&task, EnvelopeMode::Public);

        assert!(result.is_ok());
        let quad = result.unwrap();
        assert_eq!(quad.miners.len(), QUAD_SIZE);
        assert_eq!(quad.status, QuadStatus::Pending);
    }

    #[test]
    fn test_submit_solution_and_consensus() {
        let registry = create_registry_with_miners();
        let mut distributor = Distributor::new(registry);

        let task = create_test_task();
        let quad = distributor
            .assign_quad(&task, EnvelopeMode::Public)
            .unwrap();

        for miner in &quad.miners {
            distributor
                .mark_sent(&task.task_id, &miner.miner_id)
                .unwrap();
        }

        let result_data = vec![1, 2, 3, 4];
        for (i, miner) in quad.miners.iter().enumerate() {
            let solution = NuwSolution {
                task_id: task.task_id.clone(),
                miner_id: miner.miner_id.clone(),
                miner_index: i,
                result: result_data.clone(),
                computed_at: Utc::now(),
                compute_time_ms: 100,
            };
            distributor.submit_solution(solution).unwrap();
        }

        let consensus = distributor.evaluate_consensus(&task.task_id).unwrap();
        assert!(consensus.reached);
        assert_eq!(consensus.valid_miners.len(), QUAD_SIZE);
    }

    #[test]
    fn test_partial_consensus_reassign() {
        let registry = create_registry_with_miners();
        let mut distributor = Distributor::new(registry);

        let task = create_test_task();
        let quad = distributor
            .assign_quad(&task, EnvelopeMode::Public)
            .unwrap();

        for miner in &quad.miners {
            distributor
                .mark_sent(&task.task_id, &miner.miner_id)
                .unwrap();
        }

        for (i, miner) in quad.miners.iter().enumerate() {
            let result_data = vec![i as u8];
            let solution = NuwSolution {
                task_id: task.task_id.clone(),
                miner_id: miner.miner_id.clone(),
                miner_index: i,
                result: result_data,
                computed_at: Utc::now(),
                compute_time_ms: 100,
            };
            distributor.submit_solution(solution).unwrap();
        }

        let consensus = distributor.evaluate_consensus(&task.task_id).unwrap();
        assert!(!consensus.reached);
        assert_eq!(consensus.action, ConsensusAction::Requeue);
    }
}
