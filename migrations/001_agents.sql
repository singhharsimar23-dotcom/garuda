-- Migration 001: Monitored Agents Schema
-- Idempotent DDL for Northflank PostgreSQL

CREATE TABLE IF NOT EXISTS monitored_agents (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    os_version TEXT,
    kernel_version TEXT,
    arch TEXT,
    status TEXT DEFAULT 'ONLINE',
    poll_interval_sec REAL DEFAULT 1.0,
    trust_established BOOLEAN DEFAULT FALSE,
    total_observations BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_monitored_agents_status ON monitored_agents (status);
CREATE INDEX IF NOT EXISTS idx_monitored_agents_last_seen ON monitored_agents (last_seen_at);
