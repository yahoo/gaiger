-- Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

-- PostgreSQL Table Setup for Flink Autoscaler
-- Database: flink_autoscaler
-- Host: <your-postgres-host>

-- ========================================
-- Table 1: Autoscaler State Store
-- ========================================
-- Stores scaling decisions, parallelism changes, and metrics snapshots

CREATE TABLE IF NOT EXISTS t_flink_autoscaler_state_store (
    job_key VARCHAR(255) PRIMARY KEY,
    state_value TEXT NOT NULL,
    update_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_state_update_time
    ON t_flink_autoscaler_state_store(update_time);

COMMENT ON TABLE t_flink_autoscaler_state_store IS 'Stores Flink autoscaler state including parallelism decisions and metrics';
COMMENT ON COLUMN t_flink_autoscaler_state_store.job_key IS 'Unique identifier for the Flink job';
COMMENT ON COLUMN t_flink_autoscaler_state_store.state_value IS 'JSON blob containing autoscaler state';
COMMENT ON COLUMN t_flink_autoscaler_state_store.update_time IS 'Timestamp of last state update';


-- ========================================
-- Table 2: Autoscaler Event Store
-- ========================================
-- Stores autoscaler events: ScalingReport, Normal, Warning, AutoscalerError

CREATE TABLE IF NOT EXISTS t_flink_autoscaler_event_handler (
    event_key VARCHAR(255) PRIMARY KEY,
    job_key VARCHAR(255) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    reason VARCHAR(255),
    message TEXT,
    event_count INTEGER DEFAULT 1,
    create_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    update_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_event_job_key
    ON t_flink_autoscaler_event_handler(job_key);

CREATE INDEX IF NOT EXISTS idx_event_update_time
    ON t_flink_autoscaler_event_handler(update_time);

CREATE INDEX IF NOT EXISTS idx_event_type
    ON t_flink_autoscaler_event_handler(event_type);

COMMENT ON TABLE t_flink_autoscaler_event_handler IS 'Stores Flink autoscaler events and alerts';
COMMENT ON COLUMN t_flink_autoscaler_event_handler.event_key IS 'Unique event identifier';
COMMENT ON COLUMN t_flink_autoscaler_event_handler.job_key IS 'Job identifier this event belongs to';
COMMENT ON COLUMN t_flink_autoscaler_event_handler.event_type IS 'Event type: ScalingReport, Normal, Warning, AutoscalerError';
COMMENT ON COLUMN t_flink_autoscaler_event_handler.reason IS 'Short reason for the event';
COMMENT ON COLUMN t_flink_autoscaler_event_handler.message IS 'Detailed event message';
COMMENT ON COLUMN t_flink_autoscaler_event_handler.event_count IS 'Number of times this event occurred';


-- ========================================
-- Verification Queries
-- ========================================

-- Check tables exist
SELECT
    schemaname,
    tablename,
    tableowner
FROM pg_tables
WHERE tablename IN ('t_flink_autoscaler_state_store', 't_flink_autoscaler_event_handler');

-- Check indexes
SELECT
    schemaname,
    tablename,
    indexname,
    indexdef
FROM pg_indexes
WHERE tablename IN ('t_flink_autoscaler_state_store', 't_flink_autoscaler_event_handler');

-- Check table row counts (should be 0 initially)
SELECT 'state_store' AS table_name, COUNT(*) AS row_count
FROM t_flink_autoscaler_state_store
UNION ALL
SELECT 'event_store' AS table_name, COUNT(*) AS row_count
FROM t_flink_autoscaler_event_handler;
