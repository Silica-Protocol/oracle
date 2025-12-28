//! XML processing for BOINC protocol
//!
//! Handles XML parsing, generation, and security validation for BOINC RPC.

pub mod processor;
pub mod security;

pub use processor::BoincXmlProcessor;
pub use security::{SecureXmlValidator, validate_xml_wellformed};
