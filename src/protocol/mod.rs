//! Protocol Integration Module
//!
//! Provides communication between the Oracle and Silica consensus:
//! - Task submission (protocol → oracle)
//! - Proof submission (oracle → protocol)
//! - Epoch finalization events (protocol → oracle)
//! - Reward claims (user → oracle → tigerbeetle)
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │ Silica Protocol │
//! │   (consensus)   │
//! └────────┬────────┘
//!          │ RPC
//!          ▼
//! ┌─────────────────┐     ┌─────────────────┐
//! │ ProtocolClient  │────►│ OracleCore      │
//! │ (this module)   │     │ (NUW + BOINC)   │
//! └─────────────────┘     └─────────────────┘
//!          │                      │
//!          │                      ▼
//!          │              ┌─────────────────┐
//!          │              │ TigerBeetle     │
//!          │              │ (rewards)       │
//!          │              └─────────────────┘
//!          │
//!          ▼
//!   Proof Submission
//!   (back to protocol)
//! ```

pub mod client;
pub mod epoch;
pub mod proof;
pub mod types;

pub use client::ProtocolClient;
pub use client::ProtocolStatus;
pub use epoch::EpochListener;
pub use epoch::EpochEvent;
pub use proof::ProofGenerator;
pub use proof::ProofBuilder;
pub use proof::BoincWorkResult;
pub use types::*;
