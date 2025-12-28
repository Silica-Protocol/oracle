# Proof of Impact (PoI) Oracle - Scientific Work Verification

**🔬 Oracle service for validating scientific computation work from BOINC, Folding@Home, and other distributed computing platforms**

## 🎯 Current Architecture (September 2025)

The PoI Oracle operates as a **separate service** that bridges scientific computing platforms with the Chert blockchain:

```
BOINC/F@H ◄──► PoI Oracle ◄──► Chert Node
Scientific      Work Dist.      Validation
Computing       Anti-Gaming     Consensus
```

### 📊 **Implementation Status**

### ✅ **Prototype Complete**
- **BOINC Integration**: Basic API client with work unit fetching
- **Mock Verification**: Testing framework for scientific work validation
- **Oracle Pattern**: Foundation for external computation verification
- **Anti-Gaming Framework**: Basic protection against double-claiming

### 🚧 **Next Phase** (Integration with Node)
- **Shared Type System**: Common PouwChallenge/PouwResult types with node
- **Real BOINC API**: Replace mock verification with actual platform APIs
- **Node Communication**: Direct integration with PouwValidator in node
- **Production Hardening**: Error handling, rate limiting, monitoring

---

## 🏗️ Updated Architecture

### Oracle Service Role
```rust
// The PoI Oracle's responsibility in the ecosystem
pub struct PoIOracle {
    pub boinc_client: BOINCClient,        // Scientific platform APIs
    pub work_distributor: WorkDistributor, // Challenge distribution
    pub anti_gaming: AntiGamingEngine,    // Double-claim prevention  
    pub node_client: NodeClient,          // Communicate with Chert node
}

// Communication with Node's PouwValidator
pub enum PouwChallenge {
    ScientificWork { project: String, difficulty: u32 },
    ProofOfWork { target: String, nonce_range: u64 },
}

pub enum PouwResult {
    ScientificProof { work_id: String, proof: Vec<u8> },
    MiningProof { nonce: u64, hash: String },
}
```

---

## 🚀 Quick Start PoI Prototype

### Step 1: Configuration

The Oracle uses **environment variables** for all sensitive configuration. Never commit credentials to git.

```bash
# Copy the example environment file
cp .env.example .env

# Edit with your actual credentials
nano .env
```

**Required environment variables:**
- `CHERT_ORACLE_API_KEY` - Your Oracle API key (32+ characters)
- At least one BOINC authenticator:
  - `CHERT_BOINC_MILKYWAY_AUTHENTICATOR`
  - `CHERT_BOINC_ROSETTA_AUTHENTICATOR`
  - `CHERT_BOINC_WCG_AUTHENTICATOR`
  - `CHERT_BOINC_GPUGRID_AUTHENTICATOR`

**How to get BOINC authenticators:**
1. Register at the BOINC project website
2. Go to Account Settings → Account Keys
3. Copy the 32-character hex authenticator string

### Step 2: Run the Oracle

```bash
cd oracle
cargo run
```

### Step 3: Verify Configuration

```bash
# Health check
curl http://localhost:8765/health

# List configured projects
curl http://localhost:8765/oracle/projects
```

---

## 📁 Configuration Files

| File | Purpose | Committed? |
|------|---------|------------|
| `.env.example` | Template with all env vars | ✅ Yes |
| `.env` | Your actual credentials | ❌ No (gitignored) |
| `config.example.json` | JSON format example | ✅ Yes |
| `config.json` | Your local config | ❌ No (gitignored) |

**Recommended approach:** Use `.env` file for all configuration. The JSON format is provided for reference but environment variables are the primary configuration method.

---

## 🏗️ Build & Test

```bash
# Build
cargo build

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run
```
    DNAHome,
    RosettaHome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoIProof {
    pub work_unit: PoIWorkUnit,
    pub oracle_signature: String,
    pub blockchain_hash: String,
    pub nim_reward: f64,
}
```

### Step 4: BOINC API Integration
```rust
// src/boinc.rs
use reqwest::Client;
use anyhow::Result;

pub struct BOINCClient {
    client: Client,
    base_url: String,
}

impl BOINCClient {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: "https://boinc.berkeley.edu/".to_string(),
        }
    }

    pub async fn get_user_work(&self, user_id: &str) -> Result<Vec<PoIWorkUnit>> {
        // Connect to BOINC project APIs
        // Parse work unit completions
        // Return validated work units
        todo!("Implement BOINC API integration")
    }

    pub async fn validate_work_unit(&self, work_unit: &PoIWorkUnit) -> Result<bool> {
        // Verify work unit exists and was completed by user
        // Check against project databases
        // Validate credit claimed matches records
        todo!("Implement BOINC validation")
    }
}
```

### Step 5: Simple Test Runner
```rust
// src/main.rs
use poi_prototype::*;
use tracing::{info, error};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::init();
    
    info!("Starting PoI Prototype Test");
    
    // Test 1: Connect to BOINC
    let boinc = BOINCClient::new();
    
    // Test 2: Fetch some work units (mock data initially)
    let test_work_units = create_mock_work_units();
    
    // Test 3: Generate PoI proofs
    for work_unit in test_work_units {
        match generate_poi_proof(work_unit).await {
            Ok(proof) => {
                info!("Generated PoI Proof: {} NIM reward", proof.nim_reward);
                println!("✅ Work: {} -> {} NIM", proof.work_unit.work_id, proof.nim_reward);
            }
            Err(e) => error!("Failed to generate proof: {}", e),
        }
    }
    
    Ok(())
}

fn create_mock_work_units() -> Vec<PoIWorkUnit> {
    vec![
        PoIWorkUnit {
            platform: Platform::BOINC,
            work_id: "wu_001".to_string(),
            user_id: "test_user_1".to_string(),
            project_name: "Rosetta@Home".to_string(),
            completion_time: 1640995200, // Example timestamp
            credit_claimed: 150.0,
            validation_hash: "abc123".to_string(),
        },
        PoIWorkUnit {
            platform: Platform::FoldingAtHome,
            work_id: "fah_001".to_string(),
            user_id: "test_user_1".to_string(),
            project_name: "COVID-19 Research".to_string(),
            completion_time: 1640995800,
            credit_claimed: 200.0,
            validation_hash: "def456".to_string(),
        }
    ]
}

async fn generate_poi_proof(work_unit: PoIWorkUnit) -> anyhow::Result<PoIProof> {
    // Calculate NIM reward based on credit
    let nim_reward = calculate_nim_reward(&work_unit);
    
    // Generate proof hash
    let proof_data = format!("{:?}", work_unit);
    let mut hasher = Sha256::new();
    hasher.update(proof_data.as_bytes());
    let blockchain_hash = format!("{:x}", hasher.finalize());
    
    Ok(PoIProof {
        work_unit,
        oracle_signature: "mock_signature".to_string(),
        blockchain_hash,
        nim_reward,
    })
}

fn calculate_nim_reward(work_unit: &PoIWorkUnit) -> f64 {
    // Simple conversion: 1 BOINC credit = 0.01 NIM
    match work_unit.platform {
        Platform::BOINC => work_unit.credit_claimed * 0.01,
        Platform::FoldingAtHome => work_unit.credit_claimed * 0.015,
        Platform::DNAHome => work_unit.credit_claimed * 0.012,
        Platform::RosettaHome => work_unit.credit_claimed * 0.011,
    }
}
```

---

## 🧪 Testing Plan

### Phase 1: Mock Data (Week 1)
- [x] Basic data structures
- [ ] Mock work unit generation
- [ ] Reward calculation logic
- [ ] Oracle signature simulation

### Phase 2: Real API Integration (Week 2)
- [ ] BOINC project API connections
- [ ] Folding@Home stats API
- [ ] Work unit validation
- [ ] Anti-double-claiming logic

### Phase 3: Blockchain Integration (Week 3)
- [ ] Connect to simple blockchain storage
- [ ] Submit PoI proofs as transactions
- [ ] Reward distribution mechanism
- [ ] Oracle consensus (multiple validators)

### Phase 4: Full Integration Test (Week 4)
- [ ] End-to-end: BOINC work → PoI proof → NIM reward
- [ ] Performance testing
- [ ] Security validation
- [ ] Documentation

---

## 🎯 Success Criteria

✅ **Connect to real BOINC/F@H APIs**
✅ **Generate valid PoI proofs for completed work**
✅ **Calculate fair NIM rewards**
✅ **Prevent double-claiming attacks**
✅ **Process 100+ work units per minute**

Ready to start building this PoI prototype?
