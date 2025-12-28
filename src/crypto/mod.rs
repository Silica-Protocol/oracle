//! Cryptographic utilities for the PoUW Oracle
//!
//! Provides signing, verification, and Merkle tree operations for:
//! - Work receipt signing (Ed25519, future: Dilithium PQ)
//! - Batch verification via Merkle proofs
//! - Fraud proof generation and validation
//! - Audit logging for security-critical operations
//! - Request signature validation with replay protection
//! - Key management

pub mod merkle;
pub mod security;
pub mod signing;

pub use merkle::{BatchVerifier, MerkleTree};
pub use security::{
    AuditEntry, AuditEventType, AuditLogger, AuditSeverity, FraudDetector, FraudEvidence,
    FraudProof, FraudProofStatus, FraudType, RequestValidator, SignedRequest, ValidationResult,
};
pub use signing::{CryptoEngine, CryptoSignature, KeyPair, WorkReceipt};
