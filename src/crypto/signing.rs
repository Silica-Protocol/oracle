use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Post-Quantum ready cryptographic operations
/// Uses Ed25519 for now, but designed to be easily upgraded to Dilithium

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoSignature {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: String,
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: VerifyingKey,
    pub secret_key: SigningKey,
}

pub struct CryptoEngine {
    key_pairs: HashMap<String, KeyPair>,
}

impl CryptoEngine {
    pub fn new() -> Self {
        Self {
            key_pairs: HashMap::new(),
        }
    }

    /// Generate a new key pair for an entity (oracle, miner, etc.)
    pub fn generate_keypair(&mut self, entity_id: &str) -> Result<VerifyingKey> {
        let mut csprng = OsRng;
        let mut secret_bytes: [u8; 32] = [0u8; 32];

        csprng.fill_bytes(&mut secret_bytes);
        let secret_key = SigningKey::from_bytes(&secret_bytes);
        let public_key = secret_key.verifying_key();

        let key_pair = KeyPair {
            public_key,
            secret_key: secret_key.clone(),
        };

        self.key_pairs.insert(entity_id.to_string(), key_pair);
        Ok(public_key)
    }

    /// Sign data with an entity's private key
    pub fn sign(&self, entity_id: &str, data: &[u8]) -> Result<CryptoSignature> {
        let key_pair = self
            .key_pairs
            .get(entity_id)
            .ok_or_else(|| anyhow::anyhow!("No key pair found for entity: {}", entity_id))?;

        let signature = key_pair.secret_key.sign(data);

        Ok(CryptoSignature {
            signature: signature.to_bytes().to_vec(),
            public_key: key_pair.public_key.to_bytes().to_vec(),
            algorithm: "Ed25519".to_string(),
        })
    }

    /// Sign a message string (convenience method)
    pub fn sign_message(&self, entity_id: &str, message: &str) -> Result<CryptoSignature> {
        self.sign(entity_id, message.as_bytes())
    }

    /// Verify a signature
    pub fn verify(&self, signature: &CryptoSignature, data: &[u8]) -> Result<bool> {
        let public_key_bytes: [u8; 32] = signature
            .public_key
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

        let signature_bytes: [u8; 64] = signature
            .signature
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
        let sig = Signature::from_bytes(&signature_bytes);

        Ok(public_key.verify(data, &sig).is_ok())
    }

    /// Create a work receipt from BOINC work
    pub fn create_work_receipt(
        &self,
        worker_id: &str,
        work: &crate::pouw::models::BoincWork,
    ) -> Result<WorkReceipt> {
        let mut receipt = WorkReceipt::new(
            work.task_id.clone(),
            worker_id.to_string(),
            work.project_name.clone(),
            work.cpu_time,
            work.credit_granted,
        );

        // Sign with oracle key if available
        if self.key_pairs.contains_key("oracle") {
            receipt.sign(self, "oracle")?;
        }

        Ok(receipt)
    }

    /// Hash data using SHA-256
    pub fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Create a Merkle tree root hash from multiple data items
    pub fn merkle_root(hashes: &[Vec<u8>]) -> Vec<u8> {
        if hashes.is_empty() {
            return Self::hash(&[]);
        }

        if hashes.len() == 1 {
            return hashes[0].clone();
        }

        let mut current_level = hashes.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    [chunk[0].clone(), chunk[1].clone()].concat()
                } else {
                    [chunk[0].clone(), chunk[0].clone()].concat()
                };
                next_level.push(Self::hash(&combined));
            }

            current_level = next_level;
        }

        current_level[0].clone()
    }

    /// Get public key for an entity
    pub fn get_public_key(&self, entity_id: &str) -> Option<VerifyingKey> {
        self.key_pairs.get(entity_id).map(|kp| kp.public_key)
    }
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Receipt structure for PoUW work verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkReceipt {
    pub work_id: String,
    pub worker_id: String,
    pub project_name: String,
    pub cpu_time: f64,
    pub credit_granted: f64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub signature: CryptoSignature,
}

impl WorkReceipt {
    /// Create a new work receipt
    pub fn new(
        work_id: String,
        worker_id: String,
        project_name: String,
        cpu_time: f64,
        credit_granted: f64,
    ) -> Self {
        Self {
            work_id,
            worker_id,
            project_name,
            cpu_time,
            credit_granted,
            timestamp: chrono::Utc::now(),
            signature: CryptoSignature {
                signature: vec![],
                public_key: vec![],
                algorithm: "Ed25519".to_string(),
            },
        }
    }

    /// Sign the receipt
    pub fn sign(&mut self, crypto: &CryptoEngine, signer_id: &str) -> Result<()> {
        let data = self.canonical_data();
        self.signature = crypto.sign(signer_id, &data)?;
        Ok(())
    }

    /// Verify the receipt signature
    pub fn verify(&self, crypto: &CryptoEngine) -> Result<bool> {
        let data = self.canonical_data();
        crypto.verify(&self.signature, &data)
    }

    /// Get canonical data for signing/verification
    fn canonical_data(&self) -> Vec<u8> {
        format!(
            "{}{}{}{}{}",
            self.work_id, self.worker_id, self.project_name, self.cpu_time, self.credit_granted
        )
        .as_bytes()
        .to_vec()
    }
}
