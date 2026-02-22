//! Chert PoUW Oracle
//!
//! Proof of Useful Work oracle for verifying and rewarding computational work
//! from distributed computing platforms like BOINC and Folding@Home.
//!
//! ## Module Structure
//!
//! ```text
//! oracle/src/
//! ├── lib.rs         - Crate root with re-exports
//! ├── main.rs        - Server entrypoint
//! ├── config.rs      - Configuration management
//! ├── pouw/          - Proof of Useful Work system
//! │   ├── oracle.rs     - Core verification & proof generation
//! │   ├── aggregator.rs - Multi-provider aggregation
//! │   ├── challenge.rs  - Challenge/response structures
//! │   ├── task_selection.rs - Smart task assignment
//! │   ├── models/       - Data models (work, proofs)
//! │   └── boinc/        - BOINC integration
//! │       ├── client.rs  - XML-RPC client
//! │       ├── proxy.rs   - BOINC proxy server
//! │       ├── project.rs - Project management
//! │       └── xml/       - XML processing & task obfuscation
//! ├── crypto/        - Cryptographic utilities
//! │   ├── signing.rs - Ed25519/Dilithium signing
//! │   ├── merkle.rs  - Merkle tree verification
//! │   └── security.rs - Fraud proofs, audit logging, request validation
//! ├── api/           - HTTP API endpoints
//! │   ├── oracle.rs  - Oracle API (verify, proof, challenge)
//! │   ├── web.rs     - Web interface
//! │   ├── miner.rs   - Miner integration (with smart task selection)
//! │   └── http.rs    - Secure HTTP client
//! ├── reputation/    - Anti-gaming reputation system
//! │   ├── score.rs   - Reputation scores & thresholds
//! │   ├── slash.rs   - Slashing for malicious actions
//! │   └── manager.rs - Reputation orchestrator
//! └── database/      - PostgreSQL persistence
//! ```

pub mod api;
pub mod config;
pub mod crypto;
pub mod database;
pub mod pouw;
pub mod reputation;
pub mod tigerbeetle;

// Re-export main types for convenience
pub use config::PoiConfig;
pub use crypto::{
    AuditEntry, AuditEventType, AuditLogger, AuditSeverity, BatchVerifier, CryptoEngine,
    CryptoSignature, FraudDetector, FraudEvidence, FraudProof, FraudProofStatus, FraudType,
    MerkleTree, RequestValidator, SignedRequest, ValidationResult as CryptoValidationResult,
    WorkReceipt,
};
pub use database::pool::DatabasePool;
pub use database::tasks::TaskDefinition;
pub use database::miners::MinerProfile as DbMinerProfile;
pub use database::rewards::{PendingReward, RewardHistory};
pub use pouw::aggregator::PoUWAggregator;
pub use pouw::boinc::{
    BoincClient, BoincCompatClient, BoincProject, BoincProxyState, ProjectConfig, ProjectManager,
    ProjectStats, UserStats,
};
pub use pouw::models::{BoincWork, PoUWProof, PoUWServiceConfig, ValidationState};
pub use pouw::oracle::PoUWOracle;

// Re-export task selection types
pub use pouw::task_selection::{
    CompatibilityResult, CpuArchitecture, CpuInfo, GpuInfo, GpuTier, GpuVendor, MinerPreferences,
    MinerProfile, OperatingSystem, ProjectRequirements, ScienceArea, TaskRecommendation,
    TaskSelector, check_compatibility, create_default_project_requirements,
};

// Re-export API types
pub use api::{
    HttpSecurityConfig, MinerApiState, OracleApiState, SecureHttpClient, SecurityMiddlewareConfig,
    SecurityState, WebApiState, NuwApiState, create_nuw_router,
};

// Re-export TigerBeetle types
pub use tigerbeetle::{
    TigerBeetleClient, TigerBeetleConfig,
    AccountIds, AccountType, LEDGER_CHERT,
};

// Re-export reputation types
pub use reputation::{
    ReputationManager, ReputationScore, ReputationThresholds,
    EligibilityStatus, ProjectMetrics, SlashEvent, SlashEvidence, SlashReason,
};

// Re-export obfuscation types
pub use pouw::boinc::xml::{
    ObfuscationConfig, TaskObfuscator, TaskMapping, ValidationError,
};

// Re-export result tracker types
pub use pouw::boinc::result_tracker::{
    ResultTracker, ResultRecord, ResultStatus, SubmissionResult,
    SuspiciousActivity, SuspiciousActivityType, AdminDecision,
};
