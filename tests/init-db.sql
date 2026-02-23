-- PostgreSQL initialization for Chert Oracle
-- Creates required schemas and tables for reputation system

-- Create schemas
CREATE SCHEMA IF NOT EXISTS cache;
CREATE SCHEMA IF NOT EXISTS reputation;

-- Reputation scores table
CREATE TABLE IF NOT EXISTS reputation.scores (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL UNIQUE,
    base_score INTEGER NOT NULL DEFAULT 0,
    successful_submissions BIGINT NOT NULL DEFAULT 0,
    total_credits_earned DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    CONSTRAINT valid_user_id CHECK (user_id <> '')
);

CREATE INDEX idx_reputation_scores_user ON reputation.scores(user_id);
CREATE INDEX idx_reputation_scores_updated ON reputation.scores(updated_at);

-- Slash events table
CREATE TABLE IF NOT EXISTS reputation.slash_events (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    reason VARCHAR(50) NOT NULL,
    points_deducted INTEGER NOT NULL,
    evidence JSONB NOT NULL,
    slashed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    is_decayed BOOLEAN NOT NULL DEFAULT FALSE,
    
    CONSTRAINT valid_slash_reason CHECK (reason IN (
        'UnassignedWork',
        'ResultReplay',
        'ReceiptForgery',
        'SignatureFraud',
        'ReputationGaming'
    ))
);

CREATE INDEX idx_slash_events_user ON reputation.slash_events(user_id);
CREATE INDEX idx_slash_events_slashed ON reputation.slash_events(slashed_at);
CREATE INDEX idx_slash_events_decayed ON reputation.slash_events(is_decayed);

-- Project metrics table
CREATE TABLE IF NOT EXISTS reputation.project_metrics (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    project_name VARCHAR(255) NOT NULL,
    tasks_assigned INTEGER NOT NULL DEFAULT 0,
    tasks_completed INTEGER NOT NULL DEFAULT 0,
    tasks_failed INTEGER NOT NULL DEFAULT 0,
    deadline_misses INTEGER NOT NULL DEFAULT 0,
    avg_compute_time_seconds DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    total_credits_earned DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    UNIQUE(user_id, project_name),
    CONSTRAINT valid_project_name CHECK (project_name <> '')
);

CREATE INDEX idx_project_metrics_user ON reputation.project_metrics(user_id);
CREATE INDEX idx_project_metrics_project ON reputation.project_metrics(project_name);

-- Suspicious activity table (for review)
CREATE TABLE IF NOT EXISTS reputation.suspicious_activities (
    id VARCHAR(255) PRIMARY KEY,
    activity_type VARCHAR(50) NOT NULL,
    result_hashes JSONB NOT NULL,
    users_involved JSONB NOT NULL,
    tasks_involved JSONB NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    reviewed BOOLEAN NOT NULL DEFAULT FALSE,
    decision VARCHAR(50),
    
    CONSTRAINT valid_activity_type CHECK (activity_type IN (
        'CrossTaskDuplicate',
        'PossibleCollusion',
        'AnomalousPattern'
    )),
    CONSTRAINT valid_decision CHECK (decision IS NULL OR decision IN (
        'ConfirmedMalicious',
        'FalsePositive',
        'PendingInvestigation'
    ))
);

CREATE INDEX idx_suspicious_activities_detected ON reputation.suspicious_activities(detected_at);
CREATE INDEX idx_suspicious_activities_reviewed ON reputation.suspicious_activities(reviewed);

-- Result tracking table
CREATE TABLE IF NOT EXISTS reputation.result_records (
    obfuscated_id VARCHAR(255) PRIMARY KEY,
    wu_name VARCHAR(255) NOT NULL,
    user_auth VARCHAR(255) NOT NULL,
    result_hash VARCHAR(64) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'Pending',
    submitted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    credits_granted DOUBLE PRECISION,
    validation_response TEXT,
    
    CONSTRAINT valid_result_status CHECK (status IN (
        'Pending',
        'Validated',
        'Rejected',
        'Timeout'
    ))
);

CREATE INDEX idx_result_records_user ON reputation.result_records(user_auth);
CREATE INDEX idx_result_records_status ON reputation.result_records(status);
CREATE INDEX idx_result_records_hash ON reputation.result_records(result_hash);

-- Grant permissions
GRANT ALL PRIVILEGES ON SCHEMA reputation TO silica;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA reputation TO silica;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA reputation TO silica;
GRANT ALL PRIVILEGES ON SCHEMA cache TO silica;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA cache TO silica;
