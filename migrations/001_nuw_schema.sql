-- Migration: 001_nuw_schema
-- Creates NUW tables for task tracking, assignments, and miner profiles

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- SCHEMA: tasks
-- ============================================================================

CREATE SCHEMA tasks;

-- Task definitions
CREATE TABLE tasks.definitions (
    task_id             VARCHAR(64) PRIMARY KEY,
    task_type           VARCHAR(30) NOT NULL,
    payload_hash        BYTEA NOT NULL,
    payload_size        INTEGER NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    completed_at        TIMESTAMPTZ,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    priority            VARCHAR(10) NOT NULL DEFAULT 'P1',
    consensus_result    VARCHAR(20),
    valid_miners        TEXT[],
    reward_amount       BIGINT,
    
    CONSTRAINT valid_task_status CHECK (status IN ('pending', 'assigned', 'in_progress', 'completed', 'failed', 'expired')),
    CONSTRAINT valid_priority CHECK (priority IN ('P0', 'P1', 'P2', 'Special'))
);

CREATE INDEX idx_tasks_status ON tasks.definitions(status, created_at);
CREATE INDEX idx_tasks_priority ON tasks.definitions(priority, created_at);
CREATE INDEX idx_tasks_type ON tasks.definitions(task_type);

-- Task assignments (quad-send tracking)
CREATE TABLE tasks.assignments (
    id                  BIGSERIAL PRIMARY KEY,
    task_id             VARCHAR(64) NOT NULL REFERENCES tasks.definitions(task_id),
    
    -- The 4 miners assigned
    miner_1_id          VARCHAR(64),
    miner_2_id          VARCHAR(64),
    miner_3_id          VARCHAR(64),
    miner_4_id          VARCHAR(64),
    
    -- Their responses
    miner_1_result      BYTEA,
    miner_1_submitted   TIMESTAMPTZ,
    miner_2_result      BYTEA,
    miner_2_submitted   TIMESTAMPTZ,
    miner_3_result      BYTEA,
    miner_3_submitted   TIMESTAMPTZ,
    miner_4_result      BYTEA,
    miner_4_submitted   TIMESTAMPTZ,
    
    -- Consensus state
    consensus_reached   BOOLEAN,
    consensus_time      TIMESTAMPTZ,
    
    -- Timeout tracking
    timeout_at          TIMESTAMPTZ NOT NULL,
    extended_at         TIMESTAMPTZ
);

CREATE INDEX idx_assignments_task ON tasks.assignments(task_id);
CREATE INDEX idx_assignments_miners ON tasks.assignments(miner_1_id, miner_2_id, miner_3_id, miner_4_id);

-- ============================================================================
-- SCHEMA: miners
-- ============================================================================

CREATE SCHEMA miners;

-- Miner profiles
CREATE TABLE miners.profiles (
    miner_id            VARCHAR(64) PRIMARY KEY,
    public_key          BYTEA NOT NULL,
    registered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Hardware info
    cpu_cores           SMALLINT,
    total_ram_gb        SMALLINT,
    gpu_count           SMALLINT DEFAULT 0,
    gpu_models          TEXT[],
    
    -- Capabilities
    supported_tasks     TEXT[],
    has_gpu             BOOLEAN DEFAULT FALSE,
    
    -- Reputation
    valid_submissions   BIGINT DEFAULT 0,
    invalid_submissions BIGINT DEFAULT 0,
    total_earnings      BIGINT DEFAULT 0,
    
    -- Status
    is_active           BOOLEAN DEFAULT TRUE,
    is_banned           BOOLEAN DEFAULT FALSE,
    ban_reason          TEXT
);

CREATE INDEX idx_miners_active ON miners.profiles(is_active) WHERE is_active = TRUE;

-- Miner reputation history
CREATE TABLE miners.reputation_log (
    id                  BIGSERIAL PRIMARY KEY,
    miner_id            VARCHAR(64) NOT NULL REFERENCES miners.profiles(miner_id),
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type          VARCHAR(50) NOT NULL,
    task_id             VARCHAR(64),
    change_amount       BIGINT NOT NULL,
    new_valid_count     BIGINT,
    new_invalid_count   BIGINT
);

CREATE INDEX idx_reputation_log_miner ON miners.reputation_log(miner_id, timestamp DESC);

-- ============================================================================
-- SCHEMA: rewards
-- ============================================================================

CREATE SCHEMA rewards;

-- Pending rewards (before TigerBeetle)
CREATE TABLE rewards.pending (
    id                  BIGSERIAL PRIMARY KEY,
    task_id             VARCHAR(64) NOT NULL,
    miner_id            VARCHAR(64) NOT NULL,
    amount              BIGINT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lockup_until        TIMESTAMPTZ NOT NULL,
    finalized_at        TIMESTAMPTZ,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    tb_transfer_id      UUID,
    
    CONSTRAINT valid_reward_status CHECK (status IN ('pending', 'finalized', 'claimed', 'clawed_back', 'voided'))
);

CREATE INDEX idx_rewards_pending_miner ON rewards.pending(miner_id, status);
CREATE INDEX idx_rewards_pending_lockup ON rewards.pending(lockup_until) WHERE status = 'pending';

-- Completed reward history
CREATE TABLE rewards.history (
    id                  BIGSERIAL PRIMARY KEY,
    task_id             VARCHAR(64) NOT NULL,
    miner_id            VARCHAR(64) NOT NULL,
    amount              BIGINT NOT NULL,
    task_completed_at   TIMESTAMPTZ NOT NULL,
    finalized_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tb_transfer_id      UUID NOT NULL,
    
    CONSTRAINT unique_task_miner UNIQUE(task_id, miner_id)
);

CREATE INDEX idx_rewards_history_miner ON rewards.history(miner_id, finalized_at DESC);

-- ============================================================================
-- SCHEMA: disputes
-- ============================================================================

CREATE SCHEMA disputes;

CREATE TABLE disputes.cases (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id             VARCHAR(64) NOT NULL,
    challenger_id       VARCHAR(64) NOT NULL,
    respondent_ids      TEXT[],
    evidence_type       VARCHAR(30) NOT NULL,
    evidence_data       JSONB NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    resolution          VARCHAR(20),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ
);

CREATE INDEX idx_disputes_task ON disputes.cases(task_id);
CREATE INDEX idx_disputes_status ON disputes.cases(status);

-- ============================================================================
-- SCHEMA: cache (unlogged tables for hot data)
-- ============================================================================

CREATE SCHEMA cache;

-- Active task queue state
CREATE UNLOGGED TABLE cache.active_tasks (
    task_id         VARCHAR(64) PRIMARY KEY,
    task_type       VARCHAR(30) NOT NULL,
    priority        VARCHAR(10) NOT NULL,
    enqueued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    position        BIGINT NOT NULL,
    assignment_id   BIGINT,
    assigned_at     TIMESTAMPTZ
);

CREATE INDEX idx_cache_active_priority ON cache.active_tasks(priority, position);

-- Miner availability status
CREATE UNLOGGED TABLE cache.miner_status (
    miner_id            VARCHAR(64) PRIMARY KEY,
    is_online           BOOLEAN NOT NULL DEFAULT FALSE,
    last_ping           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active_tasks        INTEGER NOT NULL DEFAULT 0,
    max_concurrent      INTEGER NOT NULL DEFAULT 4,
    supported_tasks     TEXT[],
    has_gpu             BOOLEAN,
    region              VARCHAR(20)
);

CREATE INDEX idx_cache_miner_online ON cache.miner_status(is_online) WHERE is_online = TRUE;

-- Recent solutions (for consensus)
CREATE UNLOGGED TABLE cache.recent_solutions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id         VARCHAR(64) NOT NULL,
    miner_id        VARCHAR(64) NOT NULL,
    miner_index     SMALLINT NOT NULL,
    result_hash     BYTEA NOT NULL,
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    compute_time_ms INTEGER
);

CREATE INDEX idx_cache_solutions_task ON cache.recent_solutions(task_id);

-- Rate limiting
CREATE UNLOGGED TABLE cache.rate_limits (
    key             VARCHAR(128) PRIMARY KEY,
    count           INTEGER NOT NULL DEFAULT 1,
    window_start    TIMESTAMPTZ NOT NULL,
    window_end     TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_cache_rate_limits_window ON cache.rate_limits(window_end);
