//! Enhanced Security Module for PoUW Oracle
//!
//! Provides:
//! - Fraud proof generation and validation
//! - Audit logging for all security-critical operations
//! - Request signature validation
//! - Replay attack prevention
//! - Rate limiting with sliding windows
//! - Suspicious activity detection

use anyhow::{Result, anyhow};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::crypto::{CryptoEngine, CryptoSignature};
use crate::pouw::models::BoincWork;

// ============================================================================
// Constants
// ============================================================================

/// Maximum nonce age before expiry (prevent replay attacks)
const NONCE_EXPIRY_SECONDS: i64 = 3600; // 1 hour

/// Maximum number of nonces to track per user
const MAX_NONCES_PER_USER: usize = 1000;

/// Maximum number of failed attempts before temporary ban
const MAX_FAILED_ATTEMPTS: usize = 10;

/// Ban duration after exceeding failed attempts
const BAN_DURATION_MINUTES: i64 = 30;

/// Suspicious activity threshold (requests per minute)
const SUSPICIOUS_RATE_THRESHOLD: usize = 100;

/// Audit log retention (days) - reserved for future use
#[allow(dead_code)]
const AUDIT_LOG_RETENTION_DAYS: i64 = 90;

// ============================================================================
// Fraud Proofs
// ============================================================================

/// Types of fraud that can be detected and proven
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FraudType {
    /// Same work submitted by multiple miners
    DuplicateWorkSubmission,
    /// Work claimed for non-existent or invalid BOINC task
    InvalidWorkClaim,
    /// Signature on proof doesn't match claimed signer
    InvalidSignature,
    /// Work completed time doesn't match BOINC records
    TimestampManipulation,
    /// Credit amount doesn't match BOINC project records
    CreditManipulation,
    /// Same nonce used multiple times (replay attack)
    ReplayAttack,
    /// Worker claimed work from a different user
    IdentityFraud,
    /// Proof contains impossible difficulty score
    DifficultyManipulation,
}

/// A fraud proof that can be submitted to the blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProof {
    /// Unique identifier for this fraud proof
    pub fraud_id: String,
    /// Type of fraud detected
    pub fraud_type: FraudType,
    /// Address of the accused party
    pub accused_address: String,
    /// Address of the reporter
    pub reporter_address: String,
    /// Evidence supporting the fraud claim
    pub evidence: FraudEvidence,
    /// Timestamp of fraud proof creation
    pub created_at: DateTime<Utc>,
    /// Cryptographic signature of the proof
    pub signature: Option<CryptoSignature>,
    /// Current status of the fraud proof
    pub status: FraudProofStatus,
}

/// Evidence supporting a fraud claim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudEvidence {
    /// The original work or proof that was fraudulent
    pub original_data: String,
    /// Conflicting data that proves fraud
    pub conflicting_data: Option<String>,
    /// Hash of the evidence for integrity verification
    pub evidence_hash: String,
    /// Additional context or explanation
    pub description: String,
    /// External references (e.g., BOINC task URLs)
    pub external_references: Vec<String>,
}

/// Status of a fraud proof
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FraudProofStatus {
    /// Fraud proof submitted, awaiting verification
    Pending,
    /// Fraud proof verified and accepted
    Verified,
    /// Fraud proof rejected (insufficient evidence)
    Rejected,
    /// Fraud proof is under dispute
    Disputed,
    /// Penalty has been applied
    Resolved,
}

impl FraudProof {
    /// Create a new fraud proof
    pub fn new(
        fraud_type: FraudType,
        accused_address: String,
        reporter_address: String,
        evidence: FraudEvidence,
    ) -> Self {
        let fraud_id = Self::generate_id(&fraud_type, &accused_address, &evidence);

        Self {
            fraud_id,
            fraud_type,
            accused_address,
            reporter_address,
            evidence,
            created_at: Utc::now(),
            signature: None,
            status: FraudProofStatus::Pending,
        }
    }

    /// Generate a unique ID for the fraud proof
    fn generate_id(fraud_type: &FraudType, accused: &str, evidence: &FraudEvidence) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", fraud_type).as_bytes());
        hasher.update(accused.as_bytes());
        hasher.update(evidence.evidence_hash.as_bytes());
        hasher.update(Utc::now().timestamp().to_le_bytes());
        format!("fraud_{:x}", hasher.finalize())
    }

    /// Sign the fraud proof
    pub fn sign(&mut self, crypto: &CryptoEngine, signer_id: &str) -> Result<()> {
        let data = self.canonical_data();
        self.signature = Some(crypto.sign(signer_id, &data)?);
        Ok(())
    }

    /// Verify the fraud proof signature
    pub fn verify_signature(&self, crypto: &CryptoEngine) -> Result<bool> {
        match &self.signature {
            Some(sig) => {
                let data = self.canonical_data();
                crypto.verify(sig, &data)
            }
            None => Ok(false),
        }
    }

    /// Get canonical data for signing
    fn canonical_data(&self) -> Vec<u8> {
        format!(
            "{}:{:?}:{}:{}:{}",
            self.fraud_id,
            self.fraud_type,
            self.accused_address,
            self.reporter_address,
            self.evidence.evidence_hash
        )
        .into_bytes()
    }
}

// ============================================================================
// Fraud Detection System
// ============================================================================

/// Fraud detection and proof generation system
pub struct FraudDetector {
    /// Known work hashes to detect duplicates
    known_work_hashes: Arc<RwLock<HashMap<String, WorkRecord>>>,
    /// Pending fraud proofs
    pending_proofs: Arc<RwLock<Vec<FraudProof>>>,
    /// Verified fraud proofs
    verified_proofs: Arc<RwLock<Vec<FraudProof>>>,
    /// Crypto engine for signing (reserved for future fraud proof signing)
    #[allow(dead_code)]
    crypto: CryptoEngine,
}

/// Record of a work submission for fraud detection
#[derive(Debug, Clone)]
pub struct WorkRecord {
    pub work_hash: String,
    pub submitter: String,
    pub submitted_at: DateTime<Utc>,
    pub task_id: String,
    pub project_name: String,
}

impl Default for FraudDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FraudDetector {
    pub fn new() -> Self {
        Self {
            known_work_hashes: Arc::new(RwLock::new(HashMap::new())),
            pending_proofs: Arc::new(RwLock::new(Vec::new())),
            verified_proofs: Arc::new(RwLock::new(Vec::new())),
            crypto: CryptoEngine::new(),
        }
    }

    /// Check work for potential fraud and generate proof if found
    pub async fn check_work(
        &self,
        work: &BoincWork,
        submitter: &str,
    ) -> Result<Option<FraudProof>> {
        let work_hash = self.compute_work_hash(work);

        // Check for duplicate submission
        let known = self.known_work_hashes.read().await;
        if let Some(existing) = known.get(&work_hash) {
            if existing.submitter != submitter {
                // Different submitter claiming same work - fraud!
                let evidence = FraudEvidence {
                    original_data: serde_json::to_string(&work)?,
                    conflicting_data: Some(format!(
                        "Previously submitted by {} at {}",
                        existing.submitter, existing.submitted_at
                    )),
                    evidence_hash: work_hash.clone(),
                    description: format!(
                        "Work {} was already submitted by {} but is now being claimed by {}",
                        work.task_id, existing.submitter, submitter
                    ),
                    external_references: vec![],
                };

                let fraud_proof = FraudProof::new(
                    FraudType::DuplicateWorkSubmission,
                    submitter.to_string(),
                    "oracle".to_string(),
                    evidence,
                );

                warn!(
                    "Fraud detected: duplicate work submission for task {} by {}",
                    work.task_id, submitter
                );

                return Ok(Some(fraud_proof));
            }
        }
        drop(known);

        // Record this work for future duplicate detection
        let record = WorkRecord {
            work_hash: work_hash.clone(),
            submitter: submitter.to_string(),
            submitted_at: Utc::now(),
            task_id: work.task_id.clone(),
            project_name: work.project_name.clone(),
        };

        let mut known = self.known_work_hashes.write().await;
        known.insert(work_hash, record);

        Ok(None)
    }

    /// Submit a fraud proof for verification
    pub async fn submit_proof(&self, proof: FraudProof) -> Result<String> {
        let fraud_id = proof.fraud_id.clone();

        let mut pending = self.pending_proofs.write().await;
        pending.push(proof);

        info!("Fraud proof submitted: {}", fraud_id);
        Ok(fraud_id)
    }

    /// Verify a pending fraud proof
    pub async fn verify_proof(&self, fraud_id: &str) -> Result<bool> {
        let mut pending = self.pending_proofs.write().await;

        if let Some(index) = pending.iter().position(|p| p.fraud_id == fraud_id) {
            let mut proof = pending.remove(index);

            // Perform verification logic based on fraud type
            let is_valid = match proof.fraud_type {
                FraudType::DuplicateWorkSubmission => {
                    // Verify the duplicate claim is legitimate
                    self.verify_duplicate_claim(&proof).await?
                }
                FraudType::InvalidSignature => {
                    // Verify signature is actually invalid
                    self.verify_invalid_signature_claim(&proof).await?
                }
                _ => {
                    // Default to pending for manual review
                    false
                }
            };

            if is_valid {
                proof.status = FraudProofStatus::Verified;
                let mut verified = self.verified_proofs.write().await;
                verified.push(proof);
                info!("Fraud proof verified: {}", fraud_id);
                Ok(true)
            } else {
                proof.status = FraudProofStatus::Rejected;
                info!("Fraud proof rejected: {}", fraud_id);
                Ok(false)
            }
        } else {
            Err(anyhow!("Fraud proof not found: {}", fraud_id))
        }
    }

    /// Get all verified fraud proofs for an address
    pub async fn get_proofs_for_address(&self, address: &str) -> Vec<FraudProof> {
        let verified = self.verified_proofs.read().await;
        verified
            .iter()
            .filter(|p| p.accused_address == address)
            .cloned()
            .collect()
    }

    /// Compute hash of work for duplicate detection
    fn compute_work_hash(&self, work: &BoincWork) -> String {
        let mut hasher = Sha256::new();
        hasher.update(work.task_id.as_bytes());
        hasher.update(work.project_name.as_bytes());
        hasher.update(work.user_id.as_bytes());
        hasher.update(work.cpu_time.to_le_bytes());
        hasher.update(work.credit_granted.to_le_bytes());
        format!("{:x}", hasher.finalize())
    }

    async fn verify_duplicate_claim(&self, proof: &FraudProof) -> Result<bool> {
        // Check if we have records of both submissions
        let known = self.known_work_hashes.read().await;

        if let Some(record) = known.get(&proof.evidence.evidence_hash) {
            // Verify the original submitter is different from accused
            Ok(record.submitter != proof.accused_address)
        } else {
            Ok(false)
        }
    }

    async fn verify_invalid_signature_claim(&self, _proof: &FraudProof) -> Result<bool> {
        // Would verify the signature is actually invalid
        // For now, return false (requires manual review)
        Ok(false)
    }
}

// ============================================================================
// Audit Logging
// ============================================================================

/// Types of auditable events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    // Authentication events
    AuthSuccess {
        user: String,
        method: String,
    },
    AuthFailure {
        user: String,
        reason: String,
    },

    // Work events
    WorkSubmitted {
        task_id: String,
        submitter: String,
    },
    WorkVerified {
        task_id: String,
        result: bool,
    },
    ProofGenerated {
        work_id: String,
        reward: u64,
    },

    // Challenge events
    ChallengeCreated {
        challenge_id: String,
    },
    ChallengeAssigned {
        challenge_id: String,
        worker: String,
    },
    ChallengeCompleted {
        challenge_id: String,
        success: bool,
    },

    // Security events
    FraudDetected {
        fraud_type: String,
        accused: String,
    },
    RateLimitExceeded {
        user: String,
        requests: usize,
    },
    SuspiciousActivity {
        user: String,
        reason: String,
    },
    ReplayAttempt {
        user: String,
        nonce: String,
    },

    // Administrative events
    ConfigChanged {
        setting: String,
        by: String,
    },
    ProjectRegistered {
        project: String,
    },
    UserBanned {
        user: String,
        reason: String,
    },
}

/// A single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub severity: AuditSeverity,
    pub metadata: HashMap<String, String>,
}

/// Severity levels for audit events
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditSeverity {
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Critical = 4,
}

impl AuditEntry {
    pub fn new(event_type: AuditEventType, severity: AuditSeverity) -> Self {
        let id = format!("audit_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));

        Self {
            id,
            timestamp: Utc::now(),
            event_type,
            source_ip: None,
            user_agent: None,
            request_id: None,
            severity,
            metadata: HashMap::new(),
        }
    }

    pub fn with_source_ip(mut self, ip: String) -> Self {
        self.source_ip = Some(ip);
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Audit logger for security-critical operations
pub struct AuditLogger {
    entries: Arc<RwLock<VecDeque<AuditEntry>>>,
    max_entries: usize,
    min_severity: AuditSeverity,
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(VecDeque::new())),
            max_entries: 100_000,
            min_severity: AuditSeverity::Info,
        }
    }

    pub fn with_min_severity(mut self, severity: AuditSeverity) -> Self {
        self.min_severity = severity;
        self
    }

    /// Log an audit event
    pub async fn log(&self, entry: AuditEntry) {
        if entry.severity < self.min_severity {
            return;
        }

        // Also log to tracing for immediate visibility
        match entry.severity {
            AuditSeverity::Debug => tracing::debug!("AUDIT: {:?}", entry.event_type),
            AuditSeverity::Info => tracing::info!("AUDIT: {:?}", entry.event_type),
            AuditSeverity::Warning => tracing::warn!("AUDIT: {:?}", entry.event_type),
            AuditSeverity::Error => tracing::error!("AUDIT: {:?}", entry.event_type),
            AuditSeverity::Critical => tracing::error!("AUDIT CRITICAL: {:?}", entry.event_type),
        }

        let mut entries = self.entries.write().await;
        entries.push_back(entry);

        // Trim old entries
        while entries.len() > self.max_entries {
            entries.pop_front();
        }
    }

    /// Log authentication success
    pub async fn log_auth_success(&self, user: &str, method: &str) {
        let entry = AuditEntry::new(
            AuditEventType::AuthSuccess {
                user: user.to_string(),
                method: method.to_string(),
            },
            AuditSeverity::Info,
        );
        self.log(entry).await;
    }

    /// Log authentication failure
    pub async fn log_auth_failure(&self, user: &str, reason: &str) {
        let entry = AuditEntry::new(
            AuditEventType::AuthFailure {
                user: user.to_string(),
                reason: reason.to_string(),
            },
            AuditSeverity::Warning,
        );
        self.log(entry).await;
    }

    /// Log fraud detection
    pub async fn log_fraud_detected(&self, fraud_type: &str, accused: &str) {
        let entry = AuditEntry::new(
            AuditEventType::FraudDetected {
                fraud_type: fraud_type.to_string(),
                accused: accused.to_string(),
            },
            AuditSeverity::Critical,
        );
        self.log(entry).await;
    }

    /// Log suspicious activity
    pub async fn log_suspicious_activity(&self, user: &str, reason: &str) {
        let entry = AuditEntry::new(
            AuditEventType::SuspiciousActivity {
                user: user.to_string(),
                reason: reason.to_string(),
            },
            AuditSeverity::Warning,
        );
        self.log(entry).await;
    }

    /// Get recent entries
    pub async fn get_recent(&self, count: usize) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        entries.iter().rev().take(count).cloned().collect()
    }

    /// Get entries by severity
    pub async fn get_by_severity(&self, min_severity: AuditSeverity) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.severity >= min_severity)
            .cloned()
            .collect()
    }

    /// Get entries for a specific user
    pub async fn get_for_user(&self, user: &str) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| match &e.event_type {
                AuditEventType::AuthSuccess { user: u, .. } => u == user,
                AuditEventType::AuthFailure { user: u, .. } => u == user,
                AuditEventType::WorkSubmitted { submitter, .. } => submitter == user,
                AuditEventType::RateLimitExceeded { user: u, .. } => u == user,
                AuditEventType::SuspiciousActivity { user: u, .. } => u == user,
                AuditEventType::ReplayAttempt { user: u, .. } => u == user,
                AuditEventType::UserBanned { user: u, .. } => u == user,
                _ => false,
            })
            .cloned()
            .collect()
    }
}

// ============================================================================
// Request Validation
// ============================================================================

/// Signed request for API authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRequest {
    /// The actual request payload
    pub payload: String,
    /// Unix timestamp of the request
    pub timestamp: i64,
    /// Random nonce for replay protection
    pub nonce: String,
    /// Public key of the signer
    pub public_key: Vec<u8>,
    /// Signature over payload + timestamp + nonce
    pub signature: Vec<u8>,
}

impl SignedRequest {
    /// Create and sign a new request
    pub fn new(payload: String, crypto: &CryptoEngine, signer_id: &str) -> Result<Self> {
        let timestamp = Utc::now().timestamp();
        let nonce = Self::generate_nonce();

        let sig_data = Self::create_signature_data(&payload, timestamp, &nonce);
        let signature = crypto.sign(signer_id, &sig_data)?;

        Ok(Self {
            payload,
            timestamp,
            nonce,
            public_key: signature.public_key,
            signature: signature.signature,
        })
    }

    /// Verify the request signature and validity
    pub fn verify(&self, crypto: &CryptoEngine, max_age_secs: i64) -> Result<bool> {
        // Check timestamp is recent
        let now = Utc::now().timestamp();
        if (now - self.timestamp).abs() > max_age_secs {
            return Ok(false);
        }

        // Verify signature
        let sig_data = Self::create_signature_data(&self.payload, self.timestamp, &self.nonce);
        let crypto_sig = CryptoSignature {
            signature: self.signature.clone(),
            public_key: self.public_key.clone(),
            algorithm: "Ed25519".to_string(),
        };

        crypto.verify(&crypto_sig, &sig_data)
    }

    fn generate_nonce() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    fn create_signature_data(payload: &str, timestamp: i64, nonce: &str) -> Vec<u8> {
        format!("{}:{}:{}", payload, timestamp, nonce).into_bytes()
    }
}

/// Request validator with replay protection
type FailedAttempt = (usize, DateTime<Utc>);
type FailedAttemptMap = HashMap<String, FailedAttempt>;
type SharedFailedAttempts = Arc<RwLock<FailedAttemptMap>>;

pub struct RequestValidator {
    /// Used nonces per user (for replay protection)
    used_nonces: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Failed attempt tracking per user
    failed_attempts: SharedFailedAttempts,
    /// Banned users
    banned_users: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
    /// Request rate tracking
    request_rates: Arc<RwLock<HashMap<String, VecDeque<DateTime<Utc>>>>>,
    /// Audit logger
    audit: Arc<AuditLogger>,
    /// Crypto engine for signature verification
    crypto: CryptoEngine,
}

impl RequestValidator {
    pub fn new(audit: Arc<AuditLogger>) -> Self {
        let mut crypto = CryptoEngine::new();
        // Generate validator keypair
        let _ = crypto.generate_keypair("validator");

        Self {
            used_nonces: Arc::new(RwLock::new(HashMap::new())),
            failed_attempts: Arc::new(RwLock::new(HashMap::new())),
            banned_users: Arc::new(RwLock::new(HashMap::new())),
            request_rates: Arc::new(RwLock::new(HashMap::new())),
            audit,
            crypto,
        }
    }

    /// Validate a signed request
    pub async fn validate_request(
        &self,
        request: &SignedRequest,
        user_id: &str,
    ) -> Result<ValidationResult> {
        // Check if user is banned
        if self.is_banned(user_id).await {
            self.audit
                .log_auth_failure(user_id, "User is temporarily banned")
                .await;
            return Ok(ValidationResult::Banned);
        }

        // Check rate limit
        if self.is_rate_limited(user_id).await {
            self.audit
                .log(AuditEntry::new(
                    AuditEventType::RateLimitExceeded {
                        user: user_id.to_string(),
                        requests: SUSPICIOUS_RATE_THRESHOLD,
                    },
                    AuditSeverity::Warning,
                ))
                .await;
            return Ok(ValidationResult::RateLimited);
        }

        // Check for replay attack
        if self.is_replay(user_id, &request.nonce).await {
            self.record_failed_attempt(user_id).await;
            self.audit
                .log(AuditEntry::new(
                    AuditEventType::ReplayAttempt {
                        user: user_id.to_string(),
                        nonce: request.nonce.clone(),
                    },
                    AuditSeverity::Warning,
                ))
                .await;
            return Ok(ValidationResult::ReplayDetected);
        }

        // Verify signature
        match request.verify(&self.crypto, NONCE_EXPIRY_SECONDS) {
            Ok(true) => {
                // Record nonce to prevent replay
                self.record_nonce(user_id, &request.nonce).await;
                // Record request for rate limiting
                self.record_request(user_id).await;

                self.audit.log_auth_success(user_id, "signed_request").await;
                Ok(ValidationResult::Valid)
            }
            Ok(false) => {
                self.record_failed_attempt(user_id).await;
                self.audit
                    .log_auth_failure(user_id, "Invalid signature or expired timestamp")
                    .await;
                Ok(ValidationResult::InvalidSignature)
            }
            Err(e) => {
                self.record_failed_attempt(user_id).await;
                self.audit
                    .log_auth_failure(user_id, &format!("Verification error: {}", e))
                    .await;
                Ok(ValidationResult::VerificationError(e.to_string()))
            }
        }
    }

    async fn is_banned(&self, user_id: &str) -> bool {
        let banned = self.banned_users.read().await;
        if let Some(ban_until) = banned.get(user_id) {
            if Utc::now() < *ban_until {
                return true;
            }
        }
        false
    }

    async fn is_rate_limited(&self, user_id: &str) -> bool {
        let rates = self.request_rates.read().await;
        if let Some(requests) = rates.get(user_id) {
            let one_minute_ago = Utc::now() - Duration::minutes(1);
            let recent_count = requests.iter().filter(|t| **t > one_minute_ago).count();
            return recent_count >= SUSPICIOUS_RATE_THRESHOLD;
        }
        false
    }

    async fn is_replay(&self, user_id: &str, nonce: &str) -> bool {
        let nonces = self.used_nonces.read().await;
        if let Some(user_nonces) = nonces.get(user_id) {
            return user_nonces.contains(nonce);
        }
        false
    }

    async fn record_nonce(&self, user_id: &str, nonce: &str) {
        let mut nonces = self.used_nonces.write().await;
        let user_nonces = nonces
            .entry(user_id.to_string())
            .or_insert_with(HashSet::new);

        // Limit nonces per user
        if user_nonces.len() >= MAX_NONCES_PER_USER {
            user_nonces.clear();
        }

        user_nonces.insert(nonce.to_string());
    }

    async fn record_request(&self, user_id: &str) {
        let mut rates = self.request_rates.write().await;
        let requests = rates
            .entry(user_id.to_string())
            .or_insert_with(VecDeque::new);

        requests.push_back(Utc::now());

        // Keep only recent requests
        let one_hour_ago = Utc::now() - Duration::hours(1);
        while requests.front().map(|t| *t < one_hour_ago).unwrap_or(false) {
            requests.pop_front();
        }
    }

    async fn record_failed_attempt(&self, user_id: &str) {
        let mut attempts = self.failed_attempts.write().await;
        let (count, _) = attempts
            .entry(user_id.to_string())
            .or_insert((0, Utc::now()));

        *count += 1;

        if *count >= MAX_FAILED_ATTEMPTS {
            // Ban the user
            let mut banned = self.banned_users.write().await;
            let ban_until = Utc::now() + Duration::minutes(BAN_DURATION_MINUTES);
            banned.insert(user_id.to_string(), ban_until);

            warn!(
                "User {} banned until {} due to excessive failed attempts",
                user_id, ban_until
            );

            // Reset failed attempts
            *count = 0;
        }
    }

    /// Clean up expired data
    pub async fn cleanup(&self) {
        let now = Utc::now();

        // Clean expired bans
        {
            let mut banned = self.banned_users.write().await;
            banned.retain(|_, ban_until| *ban_until > now);
        }

        // Clean old request rates
        {
            let one_hour_ago = now - Duration::hours(1);
            let mut rates = self.request_rates.write().await;
            for requests in rates.values_mut() {
                while requests.front().map(|t| *t < one_hour_ago).unwrap_or(false) {
                    requests.pop_front();
                }
            }
        }

        // Clean old nonces periodically (keep recent ones for replay protection)
        // In production, would use a more sophisticated expiry mechanism
    }
}

/// Result of request validation
#[derive(Debug, Clone)]
pub enum ValidationResult {
    Valid,
    InvalidSignature,
    ReplayDetected,
    RateLimited,
    Banned,
    VerificationError(String),
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fraud_proof_creation() {
        let evidence = FraudEvidence {
            original_data: "test_data".to_string(),
            conflicting_data: Some("conflicting".to_string()),
            evidence_hash: "abc123".to_string(),
            description: "Test fraud".to_string(),
            external_references: vec![],
        };

        let proof = FraudProof::new(
            FraudType::DuplicateWorkSubmission,
            "0xaccused".to_string(),
            "0xreporter".to_string(),
            evidence,
        );

        assert!(proof.fraud_id.starts_with("fraud_"));
        assert_eq!(proof.fraud_type, FraudType::DuplicateWorkSubmission);
        assert_eq!(proof.status, FraudProofStatus::Pending);
    }

    #[test]
    fn test_audit_entry_creation() {
        let entry = AuditEntry::new(
            AuditEventType::AuthSuccess {
                user: "test_user".to_string(),
                method: "api_key".to_string(),
            },
            AuditSeverity::Info,
        )
        .with_source_ip("192.168.1.1".to_string())
        .with_metadata("key", "value");

        assert!(entry.id.starts_with("audit_"));
        assert_eq!(entry.source_ip, Some("192.168.1.1".to_string()));
        assert_eq!(entry.metadata.get("key"), Some(&"value".to_string()));
    }

    #[tokio::test]
    async fn test_audit_logger() {
        let logger = AuditLogger::new();

        logger.log_auth_success("user1", "api_key").await;
        logger.log_auth_failure("user2", "invalid_key").await;

        let recent = logger.get_recent(10).await;
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn test_signed_request() {
        let mut crypto = CryptoEngine::new();
        crypto.generate_keypair("test").unwrap();

        let request = SignedRequest::new("test_payload".to_string(), &crypto, "test").unwrap();

        assert!(request.verify(&crypto, 60).unwrap());
    }

    #[tokio::test]
    async fn test_request_validator() {
        let audit = Arc::new(AuditLogger::new());
        let validator = RequestValidator::new(audit);

        let mut crypto = CryptoEngine::new();
        crypto.generate_keypair("user1").unwrap();

        let request = SignedRequest::new("test".to_string(), &crypto, "user1").unwrap();

        // The validator uses its own crypto engine, so signature verification
        // will succeed or fail based on whether the public key is self-validating.
        // Since SignedRequest includes the public key and signature, the verify
        // method on CryptoEngine can validate using just the embedded public key.
        let result = validator.validate_request(&request, "user1").await.unwrap();

        // The signature is self-contained and verifiable
        assert!(result.is_valid());

        // Same request again should be detected as replay
        let result2 = validator.validate_request(&request, "user1").await.unwrap();
        assert!(matches!(result2, ValidationResult::ReplayDetected));
    }
}
