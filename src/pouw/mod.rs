//! Proof of Useful Work (PoUW) Module
//!
//! This module implements the PoUW system for the Chert blockchain, which validates
//! and rewards computational work from distributed computing platforms like BOINC
//! and Folding@Home.
//!
//! ## Architecture
//!
//! ```text
//! pouw/
//! ├── oracle.rs         - Core oracle for work verification and proof generation
//! ├── aggregator.rs     - Aggregates work from multiple sources
//! ├── challenge.rs      - Challenge/response structures for PoUW
//! ├── task_selection.rs - Smart task assignment based on hardware/preferences
//! ├── models/           - Data models (work units, proofs)
//! ├── boinc/            - BOINC-specific integration
//! │   ├── client.rs     - XML-RPC client
//! │   ├── proxy.rs      - BOINC proxy server
//! │   ├── project.rs    - Project management
//! │   └── xml/          - XML processing
//! └── nuw/              - NUW-specific oracle logic
//!     ├── mod.rs        - Module exports and shared types
//!     ├── priority_queue.rs - FIFO impact-based queueing
//!     ├── distributor.rs   - Quad-send BFT work distribution
//!     ├── obfuscation.rs   - Task envelopes + optional blinding
//!     └── oracle.rs        - NUW work orchestration
//! ```
//!
//! ## Task Selection System
//!
//! The task selection module provides intelligent work assignment:
//! - Hardware detection (CPU, GPU, RAM)
//! - Compatibility checking with project requirements
//! - User preference management
//! - Ranked recommendations
//!
//! ## NUW System
//!
//! The NUW (Network Utility Work) module provides:
//! - Priority-based task queueing (P0/P1/P2 buckets)
//! - Quad-send BFT work distribution (4 miners, 3-of-4 consensus)
//! - Task obfuscation and envelopes for anti-gaming
//! - Reward calculation and finalization

pub mod aggregator;
pub mod boinc;
pub mod challenge;
pub mod models;
pub mod nuw;
pub mod oracle;
pub mod task_selection;

// Re-export main types
pub use aggregator::{PoUWAggregator, ProjectStats, UserPoUWStats};
pub use boinc::{BoincClient, BoincCompatClient, BoincProject, ProjectConfig, ProjectManager};
pub use challenge::{PouwChallenge, PouwResult};
pub use models::{BoincWork, PoUWProof, PoUWServiceConfig, ValidationState};
pub use oracle::{
    ActiveChallenge, ChallengeStatus, OracleStats, PoUWOracle, ProviderProjectConfig, RewardConfig,
    VerificationResult,
};

// Re-export task selection types
pub use task_selection::{
    CompatibilityResult, CpuArchitecture, CpuInfo, GpuInfo, GpuTier, GpuVendor, MinerPreferences,
    MinerProfile, OperatingSystem, ProjectRequirements, ScienceArea, TaskRecommendation,
    TaskSelector, check_compatibility, create_default_project_requirements,
};

// Re-export NUW types
pub use nuw::{
    ConsensusAction, ConsensusResult, MinerInfo, MinerRegistry, MinerTier, NuwSolution, NuwTask,
    TaskPriority, TaskType,
    Distributor, QuadAssignment, QuadStatus,
    EnvelopeMode, Obfuscator, TaskEnvelope,
    NuwOracle as NuwWorkOracle,
    PriorityBucket, PriorityQueue, QueuedTask,
};
