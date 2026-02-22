//! TigerBeetle Integration Module
//!
//! Provides financial ledger functionality for NUW rewards using TigerBeetle.
//! TigerBeetle is a double-entry accounting database with built-in audit trail.
//!
//! ## Account Types
//!
//! - Rewards Pool: Holds allocated NUW rewards
//! - Miner Accounts: Individual miner reward accounts
//! - Treasury: Protocol treasury
//!
//! ## Transfer Types
//!
//! - Reward Payout: Transfer from rewards pool to miner
//! - Reward Clawback: Reverse invalid reward (dispute)
//! - Reward Holdback: Two-phase transfer during challenge window

pub mod accounts;
pub mod client;
pub mod transfers;

pub use accounts::*;
pub use client::*;
pub use transfers::*;
