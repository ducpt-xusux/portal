CREATE TABLE IF NOT EXISTS workload_quarantine (
    operation_id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    quarantine_sg TEXT NOT NULL,
    request_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    ports_json TEXT NOT NULL,
    state TEXT NOT NULL,
    started_at TEXT NOT NULL,
    quarantined_at TEXT,
    restore_at TEXT NOT NULL,
    restored_at TEXT,
    restore_request_id TEXT,
    restore_actor_id TEXT,
    restore_trigger TEXT,
    next_attempt_at TEXT,
    error_code TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS workload_quarantine_active ON workload_quarantine(server_id)
    WHERE state IN ('APPLYING', 'QUARANTINED', 'RESTORING', 'RESTORE_FAILED');
