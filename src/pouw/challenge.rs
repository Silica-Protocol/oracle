//! PoUW Challenge/Response structures
//!
//! Defines the challenge and result structures for Proof of Useful Work.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Represents a Proof-of-Useful-Work Challenge issued by the Oracle to miners.
/// This challenge is derived from an actual BOINC work unit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PouwChallenge {
    pub challenge_id: String, // Unique ID for this challenge (SHA-256 hash of its contents)
    pub boinc_project_url: String, // Original BOINC project URL (for reference)
    pub boinc_task_name: String, // Original BOINC task name (for reference)
    pub input_data_hash: String, // SHA-256 hash of the input data for the scientific computation
    pub app_binary_hash: String, // SHA-256 hash of the specific scientific application binary required
    pub app_binary_url: String,  // URL where miners can download the *specific* binary executable
    pub reward_multiplier: u32,  // Reward boost factor for successfully completing this useful work
    pub deadline: u64, // Unix timestamp by which the PoUW result must be submitted by miners
    pub oracle_address: String, // Public address of the oracle issuing this challenge
    pub oracle_signature: String, // Digital signature from the oracle, authenticating the challenge
}

impl PouwChallenge {
    /// Generates a unique `challenge_id` by hashing the challenge's core contents.
    /// The `oracle_signature` is excluded as it's part of the challenge's validation, not its inherent identity.
    pub fn calculate_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.boinc_project_url.as_bytes());
        hasher.update(self.boinc_task_name.as_bytes());
        hasher.update(self.input_data_hash.as_bytes());
        hasher.update(self.app_binary_hash.as_bytes());
        hasher.update(self.app_binary_url.as_bytes());
        hasher.update(self.reward_multiplier.to_le_bytes());
        hasher.update(self.deadline.to_le_bytes());
        hasher.update(self.oracle_address.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Verifies the oracle's digital signature on the challenge.
    /// This ensures the challenge is authentic and comes from a trusted oracle.
    ///
    /// # Security Notes
    /// - Uses Ed25519 signature verification
    /// - Validates all inputs to prevent malformed data attacks
    /// - Returns false on any validation failure
    pub fn verify_oracle_signature(&self, public_key: &VerifyingKey) -> bool {
        let message = self.calculate_id();
        verify_ed25519_signature(&message, &self.oracle_signature, public_key)
    }
}

/// Represents the result of a PoUW Challenge, submitted by a miner.
/// This structure will be embedded within a miner's DAG transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PouwResult {
    pub challenge_id: String, // Reference to the PoUW Challenge being completed
    pub worker_address: String, // Public address of the miner who performed the useful work (hex-encoded)
    pub output_data_hash: String, // SHA-256 hash of the computed scientific output data
    pub computation_proof: String, // Cryptographic proof that the computation was performed correctly
    pub timestamp: u64,            // Unix timestamp of result submission by the miner
    pub worker_signature: String, // Digital signature of the worker (miner) on this result (hex-encoded)
}

impl PouwResult {
    /// Generates a unique ID for the PoUW result.
    /// The `worker_signature` is excluded as it's part of the result's validation, not its inherent identity.
    pub fn calculate_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.challenge_id.as_bytes());
        hasher.update(self.worker_address.as_bytes());
        hasher.update(self.output_data_hash.as_bytes());
        hasher.update(self.computation_proof.as_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Verifies the worker's digital signature on the PoUW result.
    ///
    /// # Security Notes
    /// - Uses Ed25519 signature verification
    /// - Validates all inputs to prevent malformed data attacks
    /// - Returns false on any validation failure
    pub fn verify_worker_signature(&self, public_key: &VerifyingKey) -> bool {
        let message = self.calculate_id();
        verify_ed25519_signature(&message, &self.worker_signature, public_key)
    }
}

/// Helper function for Ed25519 signature verification
fn verify_ed25519_signature(message: &str, signature_hex: &str, public_key: &VerifyingKey) -> bool {
    // Decode hex signature using standard library
    let signature_bytes = match hex_decode(signature_hex) {
        Some(bytes) => bytes,
        None => return false,
    };

    // Convert to Ed25519 signature (64 bytes required)
    if signature_bytes.len() != 64 {
        return false;
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&signature_bytes);

    let signature = Signature::from_bytes(&sig_array);

    // Verify signature
    public_key.verify(message.as_bytes(), &signature).is_ok()
}

/// Simple hex decoding without external dependency
fn hex_decode(hex_str: &str) -> Option<Vec<u8>> {
    if hex_str.len() % 2 != 0 {
        return None;
    }

    let mut bytes = Vec::with_capacity(hex_str.len() / 2);
    for chunk in hex_str.as_bytes().chunks(2) {
        let high = hex_char_to_byte(chunk[0])?;
        let low = hex_char_to_byte(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn hex_char_to_byte(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
