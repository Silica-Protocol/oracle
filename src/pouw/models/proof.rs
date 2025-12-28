//! PoUW Proof models
//!
//! Re-exports and type aliases for PoUW proof structures.
//! These map to the underlying silica_models::poi types but use PoUW naming.

// Re-export from shared models with type aliases for consistent naming
pub use silica_models::poi::{HardwareType, ProjectInfo, ValidationState};

// Type aliases for PoI -> PoUW naming consistency
pub type PoUWProof = silica_models::poi::PoIProof;
pub type PoUWServiceConfig = silica_models::poi::PoIServiceConfig;

// Re-export the original types for backwards compatibility during migration
pub use silica_models::poi::PoIProof;
pub use silica_models::poi::PoIServiceConfig;
