//! TigerBeetle Account Definitions
//!
//! Defines account types and ID conventions for NUW financial operations.

use serde::{Deserialize, Serialize};

pub const LEDGER_CHERT: u16 = 1;

pub mod account_codes {
    pub const REWARDS_POOL: u16 = 1;
    pub const TREASURY: u16 = 2;
    pub const FEE_COLLECTOR: u16 = 3;
    pub const BURN_ADDRESS: u16 = 4;
    pub const MINER_ACCOUNT_BASE: u16 = 10;
}

pub mod transfer_codes {
    pub const REWARD_PAYOUT: u16 = 1;
    pub const REWARD_CLAWBACK: u16 = 2;
    pub const REWARD_HOLDBACK: u16 = 3;
    pub const FEE_DISTRIBUTION: u16 = 4;
    pub const BURN: u16 = 5;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccountType {
    RewardsPool,
    Treasury,
    FeeCollector,
    BurnAddress,
    Miner,
}

impl AccountType {
    pub fn code(&self) -> u16 {
        match self {
            AccountType::RewardsPool => account_codes::REWARDS_POOL,
            AccountType::Treasury => account_codes::TREASURY,
            AccountType::FeeCollector => account_codes::FEE_COLLECTOR,
            AccountType::BurnAddress => account_codes::BURN_ADDRESS,
            AccountType::Miner => account_codes::MINER_ACCOUNT_BASE,
        }
    }

    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(AccountType::RewardsPool),
            2 => Some(AccountType::Treasury),
            3 => Some(AccountType::FeeCollector),
            4 => Some(AccountType::BurnAddress),
            10..=65535 => Some(AccountType::Miner),
            _ => None,
        }
    }
}

pub struct AccountIds;

impl AccountIds {
    pub const REWARDS_POOL: u128 = 0x0001_0000_0000_0001;
    pub const TREASURY: u128 = 0x0001_0000_0000_0002;
    pub const FEE_COLLECTOR: u128 = 0x0001_0000_0000_0003;
    pub const BURN_ADDRESS: u128 = 0x0001_0000_0000_0004;

    pub fn miner_account(miner_index: u64) -> u128 {
        0x0002_0000_0000_0000u128 | ((miner_index as u128) & 0xFFFF_FFFF_FFFF)
    }

    pub fn is_miner_account(id: u128) -> bool {
        (id >> 48) == 0x0002
    }
}
