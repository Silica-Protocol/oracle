use crate::crypto::{CryptoEngine, WorkReceipt};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Merkle tree implementation for batch job verification
/// Enables efficient verification of multiple work receipts

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: Vec<u8>,
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
    pub receipt: Option<WorkReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub target_hash: Vec<u8>,
    pub proof_hashes: Vec<Vec<u8>>,
    pub proof_positions: Vec<bool>, // true = right, false = left
}

pub struct MerkleTree {
    root: Option<MerkleNode>,
    receipts: Vec<WorkReceipt>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            root: None,
            receipts: Vec::new(),
        }
    }

    /// Build Merkle tree from work receipts
    pub fn build(&mut self, receipts: Vec<WorkReceipt>) -> Result<()> {
        if receipts.is_empty() {
            return Ok(());
        }

        self.receipts = receipts;
        let mut nodes: Vec<MerkleNode> = self
            .receipts
            .iter()
            .map(|receipt| MerkleNode {
                hash: CryptoEngine::hash(&serde_json::to_vec(receipt).unwrap_or_default()),
                left: None,
                right: None,
                receipt: Some(receipt.clone()),
            })
            .collect();

        while nodes.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in nodes.chunks(2) {
                let (left, right) = if chunk.len() == 2 {
                    (&chunk[0], &chunk[1])
                } else {
                    (&chunk[0], &chunk[0]) // Duplicate last node if odd number
                };

                let combined_hash =
                    CryptoEngine::hash(&[left.hash.clone(), right.hash.clone()].concat());

                let node = MerkleNode {
                    hash: combined_hash,
                    left: Some(Box::new(left.clone())),
                    right: Some(Box::new(right.clone())),
                    receipt: None,
                };

                next_level.push(node);
            }

            nodes = next_level;
        }

        self.root = nodes.into_iter().next();
        Ok(())
    }

    /// Get Merkle root hash
    pub fn root_hash(&self) -> Option<Vec<u8>> {
        self.root.as_ref().map(|node| node.hash.clone())
    }

    /// Generate proof for a specific receipt
    pub fn generate_proof(&self, receipt_index: usize) -> Result<MerkleProof> {
        if receipt_index >= self.receipts.len() {
            return Err(anyhow::anyhow!("Receipt index out of bounds"));
        }

        let target_receipt = &self.receipts[receipt_index];
        let target_hash =
            CryptoEngine::hash(&serde_json::to_vec(target_receipt).unwrap_or_default());

        let mut proof_hashes = Vec::new();
        let mut proof_positions = Vec::new();

        // Start from the leaf and work up to root
        let mut current_index = receipt_index;
        let mut current_level_size = self.receipts.len();

        while current_level_size > 1 {
            let is_even = current_index % 2 == 0;
            let sibling_index = if is_even {
                current_index + 1
            } else {
                current_index - 1
            };

            // If we have a sibling, add it to proof
            if sibling_index < current_level_size {
                let sibling_receipt = &self.receipts[sibling_index];
                let sibling_hash =
                    CryptoEngine::hash(&serde_json::to_vec(sibling_receipt).unwrap_or_default());
                proof_hashes.push(sibling_hash);
                proof_positions.push(is_even); // true if sibling is on right
            } else {
                // Duplicate the current node for odd-length levels
                proof_hashes.push(target_hash.clone());
                proof_positions.push(is_even);
            }

            current_index /= 2;
            current_level_size = (current_level_size + 1) / 2;
        }

        Ok(MerkleProof {
            target_hash,
            proof_hashes,
            proof_positions,
        })
    }

    /// Verify a Merkle proof
    pub fn verify_proof(&self, proof: &MerkleProof, root_hash: &[u8]) -> bool {
        let mut current_hash = proof.target_hash.clone();

        for (i, sibling_hash) in proof.proof_hashes.iter().enumerate() {
            let combined = if proof.proof_positions[i] {
                // sibling is on right
                [current_hash.clone(), sibling_hash.clone()].concat()
            } else {
                // sibling is on left
                [sibling_hash.clone(), current_hash.clone()].concat()
            };

            current_hash = CryptoEngine::hash(&combined);
        }

        current_hash == root_hash
    }

    /// Get all receipts in the tree
    pub fn receipts(&self) -> &[WorkReceipt] {
        &self.receipts
    }
}

/// Batch verification of multiple work receipts
pub struct BatchVerifier {
    crypto: CryptoEngine,
    merkle_tree: MerkleTree,
}

impl BatchVerifier {
    pub fn new() -> Self {
        Self {
            crypto: CryptoEngine::new(),
            merkle_tree: MerkleTree::new(),
        }
    }

    /// Verify a batch of work receipts
    pub async fn verify_batch(
        &mut self,
        receipts: Vec<WorkReceipt>,
    ) -> Result<BatchVerificationResult> {
        self.merkle_tree.build(receipts.clone())?;

        let root_hash = self
            .merkle_tree
            .root_hash()
            .ok_or_else(|| anyhow::anyhow!("Failed to get Merkle root"))?;

        let mut valid_receipts = Vec::new();
        let mut invalid_receipts = Vec::new();

        for (i, receipt) in receipts.iter().enumerate() {
            // Verify individual receipt signature
            if receipt.verify(&self.crypto).unwrap_or(false) {
                // Generate and verify Merkle proof
                let proof = self.merkle_tree.generate_proof(i)?;
                if self.merkle_tree.verify_proof(&proof, &root_hash) {
                    valid_receipts.push(receipt.clone());
                } else {
                    invalid_receipts.push(receipt.clone());
                }
            } else {
                invalid_receipts.push(receipt.clone());
            }
        }

        Ok(BatchVerificationResult {
            valid_receipts,
            invalid_receipts,
            merkle_root: root_hash,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BatchVerificationResult {
    pub valid_receipts: Vec<WorkReceipt>,
    pub invalid_receipts: Vec<WorkReceipt>,
    pub merkle_root: Vec<u8>,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}
