//! BOINC integration for Proof of Useful Work
//!
//! This module provides integration with BOINC (Berkeley Open Infrastructure for Network Computing)
//! distributed computing platform. It handles:
//! - XML-RPC client communication with BOINC servers
//! - Work unit management and verification
//! - Project registration and lifecycle
//! - Proxy functionality for BOINC clients
//! - Result tracking and replay detection

pub mod apis;
pub mod client;
pub mod compat;
pub mod logger;
pub mod project;
pub mod proxy;
pub mod result_tracker;
pub mod xml;

// Re-export commonly used types
pub use client::{BoincClient, BoincProject, BoincResult, BoincWorkUnit};
pub use compat::BoincCompatClient;
pub use project::{ProjectConfig, ProjectManager, ProjectStats, UserStats};
pub use proxy::{BoincProxyState, ProxiedProject, create_boinc_proxy_router};
pub use result_tracker::{
    ResultTracker, ResultRecord, ResultStatus, SubmissionResult,
    SuspiciousActivity, SuspiciousActivityType, AdminDecision,
};
pub use xml::{BoincXmlProcessor, SecureXmlValidator};
