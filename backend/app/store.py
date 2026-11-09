from contextlib import contextmanager
import sqlite3
from pathlib import Path


class Store:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            legacy = db.execute("SELECT 1 FROM sqlite_master WHERE name='security_events'").fetchone()
            migrated = db.execute("SELECT 1 FROM sqlite_master WHERE name='p16h_events_v1'").fetchone()
            backup = self.path.with_name(self.path.name + ".pre-p16h-v1.bak")
            if legacy and not migrated and not backup.exists():
                # SQLite backup includes committed WAL pages; never copy only the DB file.
                with sqlite3.connect(backup) as destination:
                    db.backup(destination)
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    db_user TEXT,
                    severity TEXT,
                    policy_decision TEXT NOT NULL,
                    action_result TEXT NOT NULL,
                    query_masked TEXT,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
                CREATE INDEX IF NOT EXISTS idx_events_client ON security_events(client_ip);
                CREATE TABLE IF NOT EXISTS audit_checkpoints (
                    source TEXT PRIMARY KEY,
                    identity TEXT NOT NULL,
                    byte_offset INTEGER NOT NULL,
                    anchor TEXT NOT NULL,
                    invalid_records INTEGER NOT NULL,
                    duplicate_records INTEGER NOT NULL,
                    conflicting_records INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS portal_health_probe (
                    id INTEGER PRIMARY KEY, checked_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS p16h_events_v1 (
                    stream_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    db_user TEXT,
                    severity TEXT,
                    policy_decision TEXT NOT NULL,
                    action_result TEXT NOT NULL,
                    query_masked TEXT,
                    payload TEXT NOT NULL,
                    imported_at TEXT NOT NULL,
                    PRIMARY KEY (stream_id,event_id)
                );
                CREATE INDEX IF NOT EXISTS idx_p16h_time ON p16h_events_v1(timestamp DESC,event_id DESC,stream_id DESC);
                CREATE TABLE IF NOT EXISTS p16h_import_refs_v1 (
                    stream_id TEXT NOT NULL,event_id TEXT NOT NULL,source_json TEXT NOT NULL,
                    imported_at TEXT NOT NULL,PRIMARY KEY(stream_id,event_id,source_json)
                );
                CREATE TABLE IF NOT EXISTS p16h_store_context_v1 (
                    id INTEGER PRIMARY KEY CHECK(id=1), context TEXT NOT NULL
                );
                CREATE VIEW IF NOT EXISTS p16h_audit_index_v1 AS
                    SELECT event_id,timestamp,client_ip,db_user,severity,policy_decision,
                           action_result,query_masked,payload,NULL AS stream_id,NULL AS imported_at
                    FROM security_events
                    UNION ALL
                    SELECT event_id,timestamp,client_ip,db_user,severity,policy_decision,
                           action_result,query_masked,payload,stream_id,imported_at
                    FROM p16h_events_v1;
            """)

    @staticmethod
    def counts(db, where="", parameters=()):
        rows = db.execute(
            "SELECT policy_decision, severity, COUNT(*) AS n FROM security_events "
            + where + " GROUP BY policy_decision, severity", parameters,
        ).fetchall()
        result = {"total": 0, "allowed": 0, "blocked": 0, "high_risk": 0,
                  "by_severity": dict.fromkeys(["LOW", "WARNING", "HIGH", "CRITICAL", "UNKNOWN"], 0)}
        for row in rows:
            n = row["n"]
            result["total"] += n
            result["allowed" if row["policy_decision"] == "ALLOW" else "blocked"] += n
            result["by_severity"][row["severity"] or "UNKNOWN"] += n
            if row["severity"] in {"HIGH", "CRITICAL"}:
                result["high_risk"] += n
        return result
