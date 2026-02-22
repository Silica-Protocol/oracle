//! Task Obfuscation and Envelopes
//!
//! Provides per-miner task envelopes for transport privacy and anti-replay,
//! with optional blinded inputs for gaming-resistant task classes.
//!
//! ## Envelope Modes
//!
//! - **Public**: No secrecy, used for non-sensitive operations like signature batches
//! - **Envelope**: Per-miner encrypted transport + task metadata minimization
//! - **Blinded**: Blind inputs/indices/math to reduce gaming opportunities

use crate::pouw::nuw::NuwTask;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::debug;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvelopeMode {
    Public,
    Envelope,
    Blinded,
}

impl Default for EnvelopeMode {
    fn default() -> Self {
        Self::Public
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskEnvelope {
    pub task_id: String,
    pub miner_id: String,
    pub miner_index: usize,
    pub mode: EnvelopeMode,
    pub payload: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: Vec<u8>,
    pub reward: u64,
}

impl TaskEnvelope {
    pub fn envelope_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.task_id.as_bytes());
        hasher.update(self.miner_id.as_bytes());
        hasher.update(&self.nonce);
        format!("{:x}", hasher.finalize())
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

pub struct Obfuscator {
    key: [u8; 32],
}

impl Default for Obfuscator {
    fn default() -> Self {
        Self::new()
    }
}

impl Obfuscator {
    pub fn new() -> Self {
        let key = {
            let mut hasher = Sha256::new();
            hasher.update(b"nuw_obfuscator_key");
            hasher.update(Utc::now().timestamp().to_le_bytes());
            let hash = hasher.finalize();
            let mut key = [0u8; 32];
            key.copy_from_slice(&hash);
            key
        };
        Self { key }
    }

    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn create_envelope(
        &self,
        task: &NuwTask,
        miner_id: &str,
        miner_index: usize,
        mode: EnvelopeMode,
    ) -> TaskEnvelope {
        let nonce = self.generate_nonce(&task.task_id, miner_id);

        let payload = match &mode {
            EnvelopeMode::Public => task.payload.clone(),
            EnvelopeMode::Envelope => self.encrypt_payload(&task.payload, &nonce),
            EnvelopeMode::Blinded => self.blind_payload(&task.payload, miner_index),
        };

        let envelope = TaskEnvelope {
            task_id: task.task_id.clone(),
            miner_id: miner_id.to_string(),
            miner_index,
            mode: mode.clone(),
            payload,
            nonce: nonce.clone(),
            created_at: Utc::now(),
            expires_at: task.expires_at,
            signature: vec![],
            reward: task.task_type.base_reward(),
        };

        let signature = self.sign_envelope(&envelope);

        TaskEnvelope {
            signature,
            ..envelope
        }
    }

    fn generate_nonce(&self, task_id: &str, miner_id: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(task_id.as_bytes());
        hasher.update(miner_id.as_bytes());
        hasher.update(Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        hasher.update(&self.key);
        hasher.finalize().to_vec()
    }

    fn encrypt_payload(&self, payload: &[u8], nonce: &[u8]) -> Vec<u8> {
        let encrypted: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                let key_byte = self.key[i % 32];
                let nonce_byte = nonce.get(i % nonce.len()).copied().unwrap_or(0);
                byte ^ key_byte ^ nonce_byte
            })
            .collect();

        debug!(
            payload_len = payload.len(),
            encrypted_len = encrypted.len(),
            "Encrypted payload for envelope mode"
        );

        encrypted
    }

    fn blind_payload(&self, payload: &[u8], miner_index: usize) -> Vec<u8> {
        let blind_factor = self.key[miner_index % 32];

        let blinded: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                let offset = ((miner_index + i) % 256) as u8;
                byte.wrapping_add(blind_factor).wrapping_add(offset)
            })
            .collect();

        debug!(
            payload_len = payload.len(),
            miner_index, "Blinded payload for blinded mode"
        );

        blinded
    }

    fn sign_envelope(&self, envelope: &TaskEnvelope) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(envelope.task_id.as_bytes());
        hasher.update(envelope.miner_id.as_bytes());
        hasher.update(envelope.miner_index.to_le_bytes());
        hasher.update(&envelope.payload);
        hasher.update(&envelope.nonce);
        hasher.update(envelope.created_at.timestamp().to_le_bytes());
        hasher.update(&self.key);

        hasher.finalize().to_vec()
    }

    pub fn verify_envelope(&self, envelope: &TaskEnvelope) -> bool {
        if envelope.is_expired() {
            return false;
        }

        let expected_sig = self.sign_envelope(envelope);
        envelope.signature == expected_sig
    }

    pub fn decrypt_payload(&self, encrypted: &[u8], nonce: &[u8]) -> Vec<u8> {
        self.encrypt_payload(encrypted, nonce)
    }

    pub fn unblind_payload(&self, blinded: &[u8], miner_index: usize) -> Vec<u8> {
        let blind_factor = self.key[miner_index % 32];

        blinded
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                let offset = ((miner_index + i) % 256) as u8;
                byte.wrapping_sub(blind_factor).wrapping_sub(offset)
            })
            .collect()
    }
}

impl TaskEnvelope {
    pub fn task_type_hint(&self) -> Option<&str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pouw::nuw::TaskType;
    use chrono::Duration;

    fn create_test_task() -> NuwTask {
        NuwTask {
            task_id: "test_task".to_string(),
            task_type: TaskType::SigBatchVerify,
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8],
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            difficulty_multiplier: 1.0,
        }
    }

    #[test]
    fn test_public_envelope() {
        let obfuscator = Obfuscator::new();
        let task = create_test_task();

        let envelope = obfuscator.create_envelope(&task, "miner_1", 0, EnvelopeMode::Public);

        assert_eq!(envelope.task_id, task.task_id);
        assert_eq!(envelope.miner_id, "miner_1");
        assert_eq!(envelope.miner_index, 0);
        assert_eq!(envelope.mode, EnvelopeMode::Public);
        assert_eq!(envelope.payload, task.payload);
        assert!(obfuscator.verify_envelope(&envelope));
    }

    #[test]
    fn test_envelope_mode_encryption() {
        let obfuscator = Obfuscator::new();
        let task = create_test_task();

        let envelope = obfuscator.create_envelope(&task, "miner_1", 0, EnvelopeMode::Envelope);

        assert_eq!(envelope.mode, EnvelopeMode::Envelope);
        assert_ne!(envelope.payload, task.payload);
        assert!(obfuscator.verify_envelope(&envelope));

        let decrypted = obfuscator.decrypt_payload(&envelope.payload, &envelope.nonce);
        assert_eq!(decrypted, task.payload);
    }

    #[test]
    fn test_blinded_mode() {
        let obfuscator = Obfuscator::new();
        let task = create_test_task();

        let envelope = obfuscator.create_envelope(&task, "miner_1", 0, EnvelopeMode::Blinded);

        assert_eq!(envelope.mode, EnvelopeMode::Blinded);
        assert_ne!(envelope.payload, task.payload);
        assert!(obfuscator.verify_envelope(&envelope));

        let unblinded = obfuscator.unblind_payload(&envelope.payload, envelope.miner_index);
        assert_eq!(unblinded, task.payload);
    }

    #[test]
    fn test_different_miners_different_envelopes() {
        let obfuscator = Obfuscator::new();
        let task = create_test_task();

        let envelope1 = obfuscator.create_envelope(&task, "miner_1", 0, EnvelopeMode::Envelope);
        let envelope2 = obfuscator.create_envelope(&task, "miner_2", 1, EnvelopeMode::Envelope);

        assert_ne!(envelope1.nonce, envelope2.nonce);
        assert_ne!(envelope1.envelope_id(), envelope2.envelope_id());
    }

    #[test]
    fn test_expired_envelope_fails_verification() {
        let obfuscator = Obfuscator::new();
        let mut task = create_test_task();
        task.expires_at = Utc::now() - Duration::hours(1);

        let envelope = obfuscator.create_envelope(&task, "miner_1", 0, EnvelopeMode::Public);

        assert!(!obfuscator.verify_envelope(&envelope));
    }

    #[test]
    fn test_tampered_signature_fails() {
        let obfuscator = Obfuscator::new();
        let task = create_test_task();

        let mut envelope = obfuscator.create_envelope(&task, "miner_1", 0, EnvelopeMode::Public);
        envelope.signature[0] ^= 0xff;

        assert!(!obfuscator.verify_envelope(&envelope));
    }
}
