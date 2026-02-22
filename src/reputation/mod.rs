//! Reputation System for Anti-Gaming
//!
//! Tracks user behavior and implements slashing for malicious actions.
//! Non-malicious performance issues are tracked per-project without penalties.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
//! │ ReputationScore │────►│ ReputationManager │◄────│ SlashEvent      │
//! │ (global score)  │     │ (orchestrator)    │     │ (malicious)     │
//! └─────────────────┘     └──────────────────┘     └─────────────────┘
//!                                  │
//!                                  ▼
//!                          ┌──────────────────┐
//!                          │ ProjectMetrics   │
//!                          │ (per-project,    │
//!                          │  non-punitive)   │
//!                          └──────────────────┘
//! ```
//!
//! ## Score Model
//!
//! - Global score starts at 0, increases with good behavior (+1 per success)
//! - Slashes deduct points for MALICIOUS actions only
//! - Performance issues tracked per-project, no score impact
//! - Slashes decay after 90 days (computed on-demand)

mod manager;
mod score;
mod slash;

pub use manager::{MetricEvent, ReputationManager};
pub use score::{EligibilityStatus, ProjectMetrics, ReputationScore, ReputationThresholds};
pub use slash::{SlashEvidence, SlashEvent, SlashReason};
