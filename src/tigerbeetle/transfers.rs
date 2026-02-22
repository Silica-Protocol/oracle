//! TigerBeetle Transfer Definitions
//!
//! Defines transfer types for NUW reward operations.

use serde::{Deserialize, Serialize};

use super::transfer_codes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferType {
    RewardPayout,
    RewardClawback,
    RewardHoldback,
    FeeDistribution,
    Burn,
}

impl TransferType {
    pub fn code(&self) -> u16 {
        match self {
            TransferType::RewardPayout => transfer_codes::REWARD_PAYOUT,
            TransferType::RewardClawback => transfer_codes::REWARD_CLAWBACK,
            TransferType::RewardHoldback => transfer_codes::REWARD_HOLDBACK,
            TransferType::FeeDistribution => transfer_codes::FEE_DISTRIBUTION,
            TransferType::Burn => transfer_codes::BURN,
        }
    }
}
