//! XML processing for BOINC protocol
//!
//! Handles XML parsing, generation, security validation, and task obfuscation for BOINC RPC.

pub mod processor;
pub mod security;
pub mod obfuscation;

pub use processor::{BoincXmlProcessor, ExtractedResult, ExtractedWorkUnit, ValidationResult};
pub use security::{SecureXmlValidator, validate_xml_wellformed};
pub use obfuscation::{ObfuscationConfig, TaskObfuscator, TaskMapping, ValidationError};
