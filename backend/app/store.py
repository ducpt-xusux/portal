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
                CREATE TABLE IF NOT EXISTS workload_network_history (
                    id INTEGER PRIMARY KEY,
                    project_id TEXT NOT NULL, server_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL, state TEXT NOT NULL, source TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL, last_seen_source TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_workload_network_history
                    ON workload_network_history(project_id, server_id, observed_at DESC, id DESC);
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

    def record_workload_network(self, project_id, observations, source):
        insert = ("INSERT INTO workload_network_history(project_id,server_id,observed_at,state,source,last_seen_at,last_seen_source) "
                  "VALUES(?,?,?,?,?,?,?)")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            for server_id, observed_at, state in observations:
                key = (project_id, server_id)
                previous = db.execute(
                    "SELECT id,state,last_seen_at,last_seen_source FROM workload_network_history "
                    "WHERE project_id=? AND server_id=? AND observed_at<=? "
                    "ORDER BY observed_at DESC,id DESC LIMIT 1", (*key, observed_at),
                ).fetchone()
                if previous and previous["state"] == state:
                    db.execute("UPDATE workload_network_history SET last_seen_at=?,last_seen_source=? WHERE id=? AND last_seen_at<?",
                               (observed_at, source, previous["id"], observed_at))
                    continue
                following = db.execute(
                    "SELECT id,state,last_seen_at,last_seen_source FROM workload_network_history "
                    "WHERE project_id=? AND server_id=? AND observed_at>? "
                    "ORDER BY observed_at,id LIMIT 1", (*key, observed_at),
                ).fetchone()
                last_seen, last_source = observed_at, source
                if following and following["state"] == state:
                    last_seen, last_source = following["last_seen_at"], following["last_seen_source"]
                    db.execute("DELETE FROM workload_network_history WHERE id=?", (following["id"],))
                db.execute(insert, (*key, observed_at, state, source, last_seen, last_source))
                if previous and previous["last_seen_at"] > observed_at:
                    # A delayed quarantine confirmation can fall inside a run of
                    # normal samples that already included the restored port.
                    stamp, via = previous["last_seen_at"], previous["last_seen_source"]
                    db.execute(insert, (*key, stamp, previous["state"], via, stamp, via))
                    db.execute("UPDATE workload_network_history SET last_seen_at=workload_network_history.observed_at,"
                               "last_seen_source=workload_network_history.source WHERE id=?", (previous["id"],))
                db.execute(
                    "DELETE FROM workload_network_history WHERE id IN (SELECT id FROM workload_network_history "
                    "WHERE project_id=? AND server_id=? ORDER BY observed_at DESC,id DESC LIMIT -1 OFFSET 50)", key,
                )

    def workload_network_history(self, project_id, server_ids):
        with self.connection() as db:
            result = {}
            for server_id in server_ids:
                history = db.execute(
                    "SELECT state,observed_at,source FROM workload_network_history WHERE project_id=? AND server_id=? "
                    "ORDER BY observed_at DESC,id DESC LIMIT 11", (project_id, server_id),
                ).fetchall()
                result[server_id] = [
                    {**dict(row), "previous_state": history[index + 1]["state"] if index + 1 < len(history) else None}
                    for index, row in enumerate(history[:10])
                ]
            return result

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
