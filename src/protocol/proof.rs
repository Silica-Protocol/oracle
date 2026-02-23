//! Proof Generation and Submission for Silica Protocol
//!
//! Generates cryptographic proofs of completed work for submission
//! back to the Silica consensus layer.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use super::types::{
    BoincProofData, ConsensusInfo, HashProofData, MinerContribution, NuwTaskType, ProofData,
    ProofSubmission, ProofType, ProtocolTask, TaskMetadata, TaskPayload, ZkProofData,
};

#[derive(Debug, Clone)]
pub struct ProofConfig {
    pub oracle_private_key: Vec<u8>,
    pub oracle_public_key: Vec<u8>,
    pub proof_version: u32,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            oracle_private_key: vec![],
            oracle_public_key: vec![],
            proof_version: 1,
        }
    }
}

pub struct ProofGenerator {
    config: ProofConfig,
    signing_key: Option<SigningKey>,
}

impl ProofGenerator {
    pub fn new(config: ProofConfig) -> Result<Self> {
        let signing_key =
            if !config.oracle_private_key.is_empty() && config.oracle_private_key.len() >= 32 {
                let bytes: [u8; 32] = config.oracle_private_key[..32]
                    .try_into()
                    .context("Invalid private key length")?;
                Some(SigningKey::from_bytes(&bytes))
            } else {
                warn!("No valid signing key configured, proofs will not be signed");
                None
            };

        Ok(Self {
            config,
            signing_key,
        })
    }

    pub fn generate_boinc_proof(
        &self,
        task: &ProtocolTask,
        result: &BoincWorkResult,
        miners: Vec<MinerContribution>,
        consensus: ConsensusInfo,
    ) -> Result<ProofSubmission> {
        let proof_data = ProofData::Boinc(BoincProofData {
            wu_name: result.wu_name.clone(),
            result_name: result.result_name.clone(),
            credits: result.credits_granted,
            cpu_time: result.cpu_time,
            exit_status: result.exit_status,
            validate_state: result.validate_state.clone(),
            result_hash: result.result_hash.clone(),
        });

        self.build_proof(task, ProofType::BoincCredit, proof_data, miners, consensus)
    }

    pub fn generate_nuw_proof(
        &self,
        task: &ProtocolTask,
        result_hash: &str,
        miners: Vec<MinerContribution>,
        consensus: ConsensusInfo,
    ) -> Result<ProofSubmission> {
        let salt = generate_salt();

        let proof_data = ProofData::Hash(HashProofData {
            hash: result_hash.to_string(),
            salt,
            context: format!("nuw_{}", task.task_type.as_str()),
        });

        let proof_type = match task.task_type {
            NuwTaskType::SigBatchVerify => ProofType::SigBatch,
            NuwTaskType::ZkVerify | NuwTaskType::ZkBatchVerify => ProofType::ZkVerify,
            NuwTaskType::RecursiveSnark => ProofType::RecursiveSnark,
            NuwTaskType::MerkleBatch | NuwTaskType::MerkleVerify => ProofType::Merkle,
            _ => ProofType::SigBatch,
        };

        self.build_proof(task, proof_type, proof_data, miners, consensus)
    }

    pub fn generate_zk_proof(
        &self,
        task: &ProtocolTask,
        proof_bytes: Vec<u8>,
        public_inputs: Vec<Vec<u8>>,
        vk_id: String,
        miners: Vec<MinerContribution>,
        consensus: ConsensusInfo,
    ) -> Result<ProofSubmission> {
        let proof_data = ProofData::Zk(ZkProofData {
            proof: proof_bytes,
            public_inputs,
            vk_id,
        });

        self.build_proof(task, ProofType::ZkVerify, proof_data, miners, consensus)
    }

    fn build_proof(
        &self,
        task: &ProtocolTask,
        proof_type: ProofType,
        proof_data: ProofData,
        miners: Vec<MinerContribution>,
        consensus: ConsensusInfo,
    ) -> Result<ProofSubmission> {
        let generated_at = Utc::now();

        let mut proof = ProofSubmission {
            task_id: task.task_id.clone(),
            task_type: task.task_type,
            proof_type,
            proof_data,
            miners,
            consensus,
            generated_at,
            signature: String::new(),
        };

        let signing_payload = self.create_signing_payload(&proof);
        proof.signature = self.sign(&signing_payload)?;

        info!(
            "Generated {} proof for task {} (consensus: {}/{})",
            proof.proof_type.as_str(),
            proof.task_id,
            proof.consensus.agreeing_miners,
            proof.consensus.total_miners
        );

        Ok(proof)
    }

    fn create_signing_payload(&self, proof: &ProofSubmission) -> Vec<u8> {
        let mut hasher = Sha256::new();

        hasher.update(proof.task_id.as_bytes());
        hasher.update(proof.proof_type.as_str().as_bytes());
        hasher.update(proof.generated_at.to_rfc3339().as_bytes());

        for miner in &proof.miners {
            hasher.update(miner.miner_id.as_bytes());
            hasher.update(miner.account_address.as_bytes());
            hasher.update(&miner.reward_share_bps.to_le_bytes());
        }

        hasher.update(&proof.consensus.agreeing_miners.to_le_bytes());
        hasher.update(&proof.consensus.total_miners.to_le_bytes());

        hasher.finalize().to_vec()
    }

    fn sign(&self, payload: &[u8]) -> Result<String> {
        match &self.signing_key {
            Some(key) => {
                let signature = key.sign(payload);
                Ok(hex::encode(signature.to_bytes()))
            }
            None => {
                warn!("No signing key available, using unsigned proof");
                Ok(String::new())
            }
        }
    }

    pub fn verify_proof(&self, proof: &ProofSubmission, public_key: &[u8]) -> Result<bool> {
        if proof.signature.is_empty() {
            return Ok(false);
        }

        let signature_bytes =
            hex::decode(&proof.signature).context("Invalid signature encoding")?;

        let signature = Signature::from_bytes(
            signature_bytes
                .as_slice()
                .try_into()
                .context("Invalid signature length")?,
        );

        let payload = self.create_signing_payload(proof);

        match &self.signing_key {
            Some(key) => {
                let verifying_key = key.verifying_key();
                Ok(verifying_key.verify_strict(&payload, &signature).is_ok())
            }
            None => Ok(false),
        }
    }

    pub fn hash_result_data(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }
}

fn generate_salt() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

impl ProofType {
    fn as_str(&self) -> &'static str {
        match self {
            ProofType::BoincCredit => "boinc_credit",
            ProofType::SigBatch => "sig_batch",
            ProofType::ZkVerify => "zk_verify",
            ProofType::Merkle => "merkle",
            ProofType::RecursiveSnark => "recursive_snark",
        }
    }
}

impl NuwTaskType {
    fn as_str(&self) -> &'static str {
        match self {
            NuwTaskType::SigBatchVerify => "sig_batch_verify",
            NuwTaskType::ZkBatchVerify => "zk_batch_verify",
            NuwTaskType::ZkVerify => "zk_verify",
            NuwTaskType::RecursiveSnark => "recursive_snark",
            NuwTaskType::MerkleBatch => "merkle_batch",
            NuwTaskType::MerkleVerify => "merkle_verify",
            NuwTaskType::PoseidonBatch => "poseidon_batch",
            NuwTaskType::TxPreValidate => "tx_pre_validate",
            NuwTaskType::ElGamalRangeProof => "elgamal_range_proof",
            NuwTaskType::ElGamalConservationProof => "elgamal_conservation_proof",
            NuwTaskType::ElGamalBatchVerify => "elgamal_batch_verify",
            NuwTaskType::BoincRosetta => "boinc_rosetta",
            NuwTaskType::BoincFolding => "boinc_folding",
            NuwTaskType::BoincEinstein => "boinc_einstein",
            NuwTaskType::BoincMilkyWay => "boinc_milkyway",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoincWorkResult {
    pub wu_name: String,
    pub result_name: String,
    pub credits_granted: f64,
    pub cpu_time: f64,
    pub exit_status: i32,
    pub validate_state: String,
    pub result_hash: String,
}

pub struct ProofBuilder {
    task_id: String,
    task_type: NuwTaskType,
    proof_type: ProofType,
    proof_data: Option<ProofData>,
    miners: Vec<MinerContribution>,
    consensus: Option<ConsensusInfo>,
}

impl ProofBuilder {
    pub fn new(task_id: String, task_type: NuwTaskType) -> Self {
        Self {
            task_id,
            task_type,
            proof_type: ProofType::SigBatch,
            proof_data: None,
            miners: Vec::new(),
            consensus: None,
        }
    }

    pub fn proof_type(mut self, proof_type: ProofType) -> Self {
        self.proof_type = proof_type;
        self
    }

    pub fn proof_data(mut self, data: ProofData) -> Self {
        self.proof_data = Some(data);
        self
    }

    pub fn add_miner(mut self, contribution: MinerContribution) -> Self {
        self.miners.push(contribution);
        self
    }

    pub fn consensus(mut self, info: ConsensusInfo) -> Self {
        self.consensus = Some(info);
        self
    }

    pub fn build(self, generator: &ProofGenerator) -> Result<ProofSubmission> {
        let proof_data = self
            .proof_data
            .ok_or_else(|| anyhow::anyhow!("Proof data is required"))?;

        let consensus = self.consensus.unwrap_or(ConsensusInfo {
            reached: false,
            agreeing_miners: 0,
            total_miners: 0,
            threshold: 3,
        });

        let task = ProtocolTask {
            task_id: self.task_id,
            task_type: self.task_type,
            priority: self.task_type.priority(),
            payload: TaskPayload::Raw(vec![]),
            reward_base: 0,
            created_at: Utc::now(),
            expires_at: Utc::now(),
            requester: None,
            metadata: TaskMetadata {
                lockup_secs: 0,
                difficulty_multiplier: 1.0,
                extra: HashMap::new(),
            },
        };

        generator.build_proof(&task, self.proof_type, proof_data, self.miners, consensus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_proof_generator_creation() {
        let config = ProofConfig::default();
        let generator = ProofGenerator::new(config);
        assert!(generator.is_ok());
    }

    #[test]
    fn test_proof_generator_with_key() {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);

        let config = ProofConfig {
            oracle_private_key: signing_key.to_bytes().to_vec(),
            oracle_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            proof_version: 1,
        };

        let generator = ProofGenerator::new(config);
        assert!(generator.is_ok());
    }

    #[test]
    fn test_hash_result_data() {
        let config = ProofConfig::default();
        let generator = ProofGenerator::new(config).unwrap();

        let hash = generator.hash_result_data(b"test data");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_consensus_info() {
        let consensus = ConsensusInfo {
            reached: true,
            agreeing_miners: 3,
            total_miners: 4,
            threshold: 3,
        };
        assert!(consensus.reached);
        assert!(consensus.agreeing_miners >= consensus.threshold);
    }
}
