# Protocol Integration Design

## Overview

The Oracle needs to integrate with Silica consensus to:
1. Receive NUW tasks from the protocol
2. Submit PoUW proofs back to consensus
3. Distribute rewards via TigerBeetle after finality
4. Handle reward claims from users

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SILICA PROTOCOL                                 │
│  ┌─────────────┐   ┌──────────────┐   ┌─────────────┐   ┌──────────────┐   │
│  │ Consensus   │   │ NUW Task     │   │ Proof       │   │ Finality     │   │
│  │ (aBFT)      │   │ Generator    │   │ Verifier    │   │ Layer        │   │
│  └──────┬──────┘   └──────┬───────┘   └──────┬──────┘   └──────┬───────┘   │
│         │                 │                  │                 │            │
│         │    ┌────────────┴──────────────────┴─────────────────┘            │
│         │    │                                                              │
│         ▼    ▼                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    ORACLE RPC INTERFACE                               │  │
│  │  • POST /oracle/task        (protocol → oracle)                       │  │
│  │  • POST /oracle/proof       (oracle → protocol)                       │  │
│  │  • GET  /oracle/status      (health check)                            │  │
│  │  • POST /oracle/claim       (user claim)                              │  │
│  │  • WS   /oracle/epoch       (epoch events)                            │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CHERT ORACLE                                    │
│  ┌─────────────┐   ┌──────────────┐   ┌─────────────┐   ┌──────────────┐   │
│  │ Task        │   │ Proof        │   │ Reward      │   │ Anti-Gaming  │   │
│  │ Processor   │   │ Generator    │   │ Manager     │   │ System       │   │
│  └──────┬──────┘   └──────┬───────┘   └──────┬──────┘   └──────────────┘   │
│         │                 │                  │                             │
│         ▼                 ▼                  ▼                             │
│  ┌─────────────┐   ┌──────────────┐   ┌─────────────┐                      │
│  │ NUW Oracle  │   │ BOINC Proxy  │   │ TigerBeetle │                      │
│  │ (quad-send) │   │ (obfuscation)│   │ (rewards)   │                      │
│  └─────────────┘   └──────────────┘   └─────────────┘                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Integration Points

### 1. Protocol → Oracle: Task Submission

```rust
// Protocol sends NUW tasks to oracle
POST /oracle/v1/task
{
    "task_id": "nuw_xxx",
    "task_type": "BoincMilkyWay",
    "payload": {...},
    "priority": "Special",
    "reward_base": 1000000,
    "expires_at": "2026-02-24T00:00:00Z"
}
```

### 2. Oracle → Protocol: Proof Submission

```rust
// Oracle submits proof after verification
POST /oracle/v1/proof
{
    "task_id": "nuw_xxx",
    "proof_type": "BoincProof",
    "miner_ids": ["miner_1", "miner_2", "miner_3"],
    "result_hash": "0x...",
    "consensus_reached": true,
    "credits_earned": 150.5,
    "timestamp": "2026-02-23T12:00:00Z",
    "signature": "..."
}
```

### 3. Protocol → Oracle: Epoch Finalization

```rust
// WebSocket stream of epoch events
WS /oracle/v1/epoch
{
    "event": "epoch_finalized",
    "epoch": 12345,
    "finalized_at": "2026-02-23T12:00:00Z",
    "validators": [...],
    "proofs_accepted": [...],
    "rewards_finalized": 50000000000
}
```

### 4. User → Oracle: Reward Claim

```rust
// User claims finalized rewards
POST /oracle/v1/claim
{
    "miner_id": "miner_xxx",
    "account_address": "chert1...",
    "signature": "..."
}
```

## Files to Create

| File | Purpose |
|------|---------|
| `oracle/src/protocol/client.rs` | RPC client for protocol communication |
| `oracle/src/protocol/types.rs` | Shared types between protocol and oracle |
| `oracle/src/protocol/proof.rs` | Proof generation and verification |
| `oracle/src/protocol/epoch.rs` | Epoch listener and finality handling |
| `oracle/src/api/protocol.rs` | API endpoints for protocol integration |
