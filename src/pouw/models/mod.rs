//! PoUW data models
//!
//! Contains data structures for Proof of Useful Work:
//! - Work units and results
//! - Proof structures
//! - Validation states

pub mod proof;
pub mod work;

pub use proof::*;
pub use work::BoincWork;
