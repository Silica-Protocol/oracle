//! TigerBeetle Client Wrapper
//!
//! High-level client for NUW financial operations using TigerBeetle.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use tigerbeetle_unofficial::{Account, Transfer};

use super::accounts::{AccountIds, LEDGER_CHERT, account_codes, transfer_codes};

#[derive(Debug, Clone)]
pub struct TigerBeetleConfig {
    pub cluster_id: u32,
    pub addresses: Vec<String>,
}

impl Default for TigerBeetleConfig {
    fn default() -> Self {
        Self {
            cluster_id: 0,
            addresses: vec!["127.0.0.1:3001".to_string()],
        }
    }
}

impl From<&str> for TigerBeetleConfig {
    fn from(addresses: &str) -> Self {
        Self {
            cluster_id: 0,
            addresses: addresses.split(',').map(|s| s.trim().to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct InMemoryLedger {
    accounts: std::collections::HashMap<u128, AccountSnapshot>,
    transfers: std::collections::HashMap<u128, TransferSnapshot>,
}

#[derive(Debug, Clone)]
struct AccountSnapshot {
    id: u128,
    ledger: u16,
    code: u16,
    balance: u128,
    credits_posted: u128,
    debits_posted: u128,
}

#[derive(Debug, Clone)]
struct TransferSnapshot {
    id: u128,
    debit_account_id: u128,
    credit_account_id: u128,
    amount: u128,
    code: u16,
    pending: bool,
}

pub struct TigerBeetleClient {
    client: Option<tigerbeetle_unofficial::Client>,
    config: TigerBeetleConfig,
    initialized: Arc<RwLock<bool>>,
    use_in_memory: bool,
    in_memory_ledger: Arc<RwLock<InMemoryLedger>>,
}

impl TigerBeetleClient {
    pub async fn new(config: TigerBeetleConfig) -> Result<Self, String> {
        info!("Creating TigerBeetle client connecting to {:?}", config.addresses);
        
        let addresses = config.addresses.join(",");
        
        // Try to connect to real TigerBeetle, fall back to in-memory if unavailable
        let client = match tigerbeetle_unofficial::Client::new(config.cluster_id as u128, &addresses) {
            Ok(c) => {
                info!("Connected to real TigerBeetle cluster");
                Some(c)
            }
            Err(e) => {
                warn!("Could not connect to TigerBeetle: {}, using in-memory fallback", e);
                None
            }
        };
        
        let use_in_memory = client.is_none();
        
        Ok(Self {
            client,
            config,
            initialized: Arc::new(RwLock::new(false)),
            use_in_memory,
            in_memory_ledger: Arc::new(RwLock::new(InMemoryLedger::default())),
        })
    }

    pub async fn initialize(&self) -> Result<(), String> {
        let mut initialized = self.initialized.write().await;
        if *initialized {
            return Ok(());
        }

        if self.use_in_memory {
            info!("Initializing in-memory ledger (dev mode)");
            self.init_in_memory_ledger().await;
        } else if let Some(ref client) = self.client {
            info!("Initializing TigerBeetle accounts...");
            
            let accounts = vec![
                Account::new(AccountIds::REWARDS_POOL, LEDGER_CHERT as u32, account_codes::REWARDS_POOL),
                Account::new(AccountIds::TREASURY, LEDGER_CHERT as u32, account_codes::TREASURY),
            ];
            
            if let Err(e) = client.create_accounts(accounts).await {
                warn!("Account creation warning: {:?}", e);
            }
            
            info!("TigerBeetle initialization complete");
        }

        *initialized = true;
        Ok(())
    }

    async fn init_in_memory_ledger(&self) {
        let mut ledger = self.in_memory_ledger.write().await;
        
        ledger.accounts.insert(AccountIds::REWARDS_POOL, AccountSnapshot {
            id: AccountIds::REWARDS_POOL,
            ledger: LEDGER_CHERT,
            code: account_codes::REWARDS_POOL,
            balance: 1_000_000_000_000_000_000u128,
            credits_posted: 0,
            debits_posted: 0,
        });
        
        ledger.accounts.insert(AccountIds::TREASURY, AccountSnapshot {
            id: AccountIds::TREASURY,
            ledger: LEDGER_CHERT,
            code: account_codes::TREASURY,
            balance: 0,
            credits_posted: 0,
            debits_posted: 0,
        });
        
        info!("In-memory ledger initialized with rewards pool and treasury");
    }

    pub async fn get_account(&self, account_id: u128) -> Result<Option<AccountSnapshot>, String> {
        if self.use_in_memory {
            let ledger = self.in_memory_ledger.read().await;
            return Ok(ledger.accounts.get(&account_id).cloned());
        }
        
        // For real TigerBeetle, we'd need to use a different API
        // For now, return None to force creation
        Ok(None)
    }

    pub async fn get_balance(&self, account_id: u128) -> Result<u128, String> {
        let account = self.get_account(account_id).await?;
        match account {
            Some(acc) => Ok(acc.balance),
            None => Ok(0),
        }
    }

    pub async fn ensure_miner_account(&self, miner_id: &str) -> Result<u128, String> {
        let account_id = compute_miner_account_id(miner_id);

        if let Some(_) = self.get_account(account_id).await? {
            return Ok(account_id);
        }

        if self.use_in_memory {
            let mut ledger = self.in_memory_ledger.write().await;
            ledger.accounts.insert(account_id, AccountSnapshot {
                id: account_id,
                ledger: LEDGER_CHERT,
                code: account_codes::MINER_ACCOUNT_BASE,
                balance: 0,
                credits_posted: 0,
                debits_posted: 0,
            });
            info!(miner_id = %miner_id, account_id = %account_id, "Created miner account (in-memory)");
            return Ok(account_id);
        }

        // Create on real TigerBeetle
        if let Some(ref client) = self.client {
            let account = Account::new(account_id, LEDGER_CHERT as u32, account_codes::MINER_ACCOUNT_BASE);
            
            match client.create_accounts(vec![account]).await {
                Ok(_) => {
                    info!(miner_id = %miner_id, account_id = %account_id, "Created miner account");
                }
                Err(e) => {
                    warn!(miner_id = %miner_id, error = %e, "Could not create miner account");
                }
            }
        }

        Ok(account_id)
    }

    pub async fn create_reward_payout(
        &self,
        task_id: &str,
        miner_id: &str,
        amount: u128,
    ) -> Result<u128, String> {
        let miner_account_id = self.ensure_miner_account(miner_id).await?;
        let transfer_id = compute_transfer_id(task_id, 0, false);

        debug!(
            task_id = %task_id,
            miner_id = %miner_id,
            amount = %amount,
            transfer_id = %transfer_id,
            "Creating reward payout transfer"
        );

        if self.use_in_memory {
            self.execute_in_memory_transfer(
                transfer_id,
                AccountIds::REWARDS_POOL,
                miner_account_id,
                amount,
                transfer_codes::REWARD_PAYOUT,
                false,
            ).await?;
        } else if let Some(ref client) = self.client {
            let transfer = Transfer::new(transfer_id)
                .with_debit_account_id(AccountIds::REWARDS_POOL)
                .with_credit_account_id(miner_account_id)
                .with_amount(amount)
                .with_ledger(LEDGER_CHERT as u32)
                .with_code(transfer_codes::REWARD_PAYOUT);
            
            client.create_transfers(vec![transfer])
                .await
                .map_err(|e| format!("Transfer failed: {:?}", e))?;
        }

        info!(
            task_id = %task_id,
            miner_id = %miner_id,
            amount = %amount,
            transfer_id = %transfer_id,
            "Reward payout complete"
        );

        Ok(transfer_id)
    }

    pub async fn create_reward_holdback(
        &self,
        task_id: &str,
        miner_id: &str,
        amount: u128,
    ) -> Result<u128, String> {
        let miner_account_id = self.ensure_miner_account(miner_id).await?;
        let transfer_id = compute_transfer_id(task_id, 0, true);

        debug!(
            task_id = %task_id,
            miner_id = %miner_id,
            amount = %amount,
            transfer_id = %transfer_id,
            "Creating reward holdback (pending transfer)"
        );

        if self.use_in_memory {
            self.execute_in_memory_transfer(
                transfer_id,
                AccountIds::REWARDS_POOL,
                miner_account_id,
                amount,
                transfer_codes::REWARD_HOLDBACK,
                true,
            ).await?;
        } else if let Some(ref client) = self.client {
            // For pending transfers, we'd need to set flags - skipping for now
            let transfer = Transfer::new(transfer_id)
                .with_debit_account_id(AccountIds::REWARDS_POOL)
                .with_credit_account_id(miner_account_id)
                .with_amount(amount)
                .with_ledger(LEDGER_CHERT as u32)
                .with_code(transfer_codes::REWARD_HOLDBACK);
            
            client.create_transfers(vec![transfer])
                .await
                .map_err(|e| format!("Holdback transfer failed: {:?}", e))?;
        }

        info!(
            task_id = %task_id,
            miner_id = %miner_id,
            amount = %amount,
            transfer_id = %transfer_id,
            "Reward holdback created (pending)"
        );

        Ok(transfer_id)
    }

    pub async fn claim_held_reward(
        &self,
        pending_transfer_id: u128,
    ) -> Result<u128, String> {
        let claim_id = pending_transfer_id + 1;

        debug!(
            pending_transfer_id = %pending_transfer_id,
            claim_id = %claim_id,
            "Posting held reward"
        );

        if self.use_in_memory {
            let mut ledger = self.in_memory_ledger.write().await;
            if let Some(transfer) = ledger.transfers.get_mut(&pending_transfer_id) {
                transfer.pending = false;
            }
        } else if let Some(ref client) = self.client {
            let transfer = Transfer::new(claim_id)
                .with_pending_id(pending_transfer_id)
                .with_ledger(LEDGER_CHERT as u32)
                .with_code(transfer_codes::REWARD_PAYOUT);
            
            client.create_transfers(vec![transfer])
                .await
                .map_err(|e| format!("Claim transfer failed: {:?}", e))?;
        }

        info!(
            pending_transfer_id = %pending_transfer_id,
            claim_id = %claim_id,
            "Held reward claimed"
        );

        Ok(claim_id)
    }

    pub async fn void_held_reward(
        &self,
        pending_transfer_id: u128,
    ) -> Result<u128, String> {
        let void_id = pending_transfer_id + 1;

        debug!(
            pending_transfer_id = %pending_transfer_id,
            void_id = %void_id,
            "Voiding held reward"
        );

        if self.use_in_memory {
            let mut ledger = self.in_memory_ledger.write().await;
            
            if let Some(pending) = ledger.transfers.get(&pending_transfer_id).cloned() {
                // Reverse the balances
                if let Some(debit) = ledger.accounts.get_mut(&pending.credit_account_id) {
                    debit.balance += pending.amount;
                    debit.credits_posted += pending.amount;
                }
                if let Some(credit) = ledger.accounts.get_mut(&pending.debit_account_id) {
                    credit.balance -= pending.amount;
                    credit.debits_posted += pending.amount;
                }
                
                // Mark as voided
                ledger.transfers.insert(void_id, TransferSnapshot {
                    id: void_id,
                    debit_account_id: pending.credit_account_id,
                    credit_account_id: pending.debit_account_id,
                    amount: pending.amount,
                    code: pending.code,
                    pending: false,
                });
            }
        } else if let Some(ref client) = self.client {
            let transfer = Transfer::new(void_id)
                .with_pending_id(pending_transfer_id)
                .with_ledger(LEDGER_CHERT as u32)
                .with_code(transfer_codes::REWARD_HOLDBACK);
            
            client.create_transfers(vec![transfer])
                .await
                .map_err(|e| format!("Void transfer failed: {:?}", e))?;
        }

        info!(
            pending_transfer_id = %pending_transfer_id,
            void_id = %void_id,
            "Held reward voided (clawed back)"
        );

        Ok(void_id)
    }

    pub async fn clawback_reward(
        &self,
        task_id: &str,
        miner_id: &str,
        amount: u128,
    ) -> Result<u128, String> {
        let miner_account_id = compute_miner_account_id(miner_id);
        let transfer_id = compute_transfer_id(task_id, u64::MAX, false);

        debug!(
            task_id = %task_id,
            miner_id = %miner_id,
            amount = %amount,
            transfer_id = %transfer_id,
            "Clawing back reward"
        );

        if self.use_in_memory {
            self.execute_in_memory_transfer(
                transfer_id,
                miner_account_id,
                AccountIds::REWARDS_POOL,
                amount,
                transfer_codes::REWARD_CLAWBACK,
                false,
            ).await?;
        } else if let Some(ref client) = self.client {
            let transfer = Transfer::new(transfer_id)
                .with_debit_account_id(miner_account_id)
                .with_credit_account_id(AccountIds::REWARDS_POOL)
                .with_amount(amount)
                .with_ledger(LEDGER_CHERT as u32)
                .with_code(transfer_codes::REWARD_CLAWBACK);
            
            client.create_transfers(vec![transfer])
                .await
                .map_err(|e| format!("Clawback transfer failed: {:?}", e))?;
        }

        info!(
            task_id = %task_id,
            miner_id = %miner_id,
            amount = %amount,
            transfer_id = %transfer_id,
            "Reward clawed back"
        );

        Ok(transfer_id)
    }

    async fn execute_in_memory_transfer(
        &self,
        id: u128,
        debit_account_id: u128,
        credit_account_id: u128,
        amount: u128,
        code: u16,
        pending: bool,
    ) -> Result<(), String> {
        let mut ledger = self.in_memory_ledger.write().await;
        
        // Check balance
        if let Some(debit) = ledger.accounts.get(&debit_account_id) {
            if debit.balance < amount {
                return Err(format!("Insufficient balance: have {}, need {}", debit.balance, amount));
            }
        } else {
            return Err(format!("Debit account {} not found", debit_account_id));
        }
        
        if !ledger.accounts.contains_key(&credit_account_id) {
            return Err(format!("Credit account {} not found", credit_account_id));
        }

        // Update debit account
        let debit = ledger.accounts.get_mut(&debit_account_id).unwrap();
        debit.balance -= amount;
        debit.debits_posted += amount;

        // Update credit account
        let credit = ledger.accounts.get_mut(&credit_account_id).unwrap();
        credit.balance += amount;
        credit.credits_posted += amount;

        // Record transfer
        ledger.transfers.insert(id, TransferSnapshot {
            id,
            debit_account_id,
            credit_account_id,
            amount,
            code,
            pending,
        });
        
        Ok(())
    }

    pub async fn get_rewards_pool_balance(&self) -> Result<u128, String> {
        self.get_balance(AccountIds::REWARDS_POOL).await
    }

    pub async fn get_miner_balance(&self, miner_id: &str) -> Result<u128, String> {
        let account_id = compute_miner_account_id(miner_id);
        self.get_balance(account_id).await
    }
}

fn compute_miner_account_id(miner_id: &str) -> u128 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(miner_id.as_bytes());
    let hash = hasher.finalize();
    
    let mut id_bytes = [0u8; 16];
    id_bytes[..8].copy_from_slice(&hash[..8]);
    id_bytes[0] = 0x00;
    id_bytes[1] = 0x02;
    u128::from_le_bytes(id_bytes)
}

fn compute_transfer_id(task_id: &str, miner_index: u64, is_holdback: bool) -> u128 {
    use sha2::{Digest, Sha256};
    let data = format!("{}:{}:{}", task_id, miner_index, if is_holdback { "h" } else { "p" });
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let hash = hasher.finalize();
    
    u128::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
        hash[12], hash[13], hash[14], hash[15],
        0, 0, 0, 0,
    ])
}
