import hashlib
import json
import sqlite3
import threading

from pydantic import ValidationError

from .config import Settings
from .schemas import AuditEvent, utc_now
from .store import Store
from .sync_status import read_sync_status
from .p16h_normalizer import normalize_line, unpack, storage_record, evidence_content, ImportError


MAX_LINE_BYTES = 1024 * 1024
MAX_BATCH_BYTES = 8 * 1024 * 1024


def anchor_at(file, offset):
    """Detect copytruncate/regrowth as well as rename-based rotation."""
    file.seek(0)
    head = file.read(min(offset, 128))
    file.seek(max(0, offset - 128))
    return hashlib.sha256(head + file.read(min(offset, 128))).hexdigest()


class Importer:
    def __init__(self, settings: Settings, store: Store):
        self.settings = settings
        self.store = store
        self.lock = threading.RLock()
        self.status = {"state": "UNKNOWN", "last_attempt_at": None, "last_sync_at": None,
                       "error_code": None, "invalid_records": 0, "duplicate_records": 0,
                       "conflicting_records": 0, "pending_bytes": 0}
        self.status["last_record_error"] = None

    def snapshot(self):
        with self.lock:
            return {**self.status, "mode": self.settings.mode, "source": "p16_audit_jsonl"}

    def sync(self):
        with self.lock:
            self.status["last_attempt_at"] = utc_now()
            try:
                self._sync_file()
            except FileNotFoundError:
                self.status.update(state="UNREACHABLE", error_code="AUDIT_FILE_NOT_FOUND")
            except PermissionError:
                self.status.update(state="UNREACHABLE", error_code="AUDIT_FILE_NOT_READABLE")
            except OSError:
                self.status.update(state="UNREACHABLE", error_code="AUDIT_IO_ERROR")
            except sqlite3.Error:
                self.status.update(state="STORE_ERROR", error_code="AUDIT_STORE_UNAVAILABLE")
            if self.settings.mode == "live" and self.settings.proxy_sync_status_path is not None:
                transport, transport_error = read_sync_status(self.settings.proxy_sync_status_path, "audit")
                self.status["transport"] = transport
                if transport_error:
                    self.status.update(state="UNREACHABLE", error_code=transport_error)
                else:
                    self.status["pending_bytes"] += transport.get("pending_bytes", 0)
            return self.snapshot()

    def _sync_file(self):
        path = self.settings.audit_path
        # The evidence source is opened read-only. Import never changes this file.
        with path.open("rb") as file, self.store.connection() as db:
            import os
            stat = os.fstat(file.fileno())
            identity = f"{stat.st_dev}:{stat.st_ino}"
            source = str(path.resolve())
            checkpoint = db.execute("SELECT * FROM audit_checkpoints WHERE source=?", (source,)).fetchone()
            offset = checkpoint["byte_offset"] if checkpoint else 0
            invalid = checkpoint["invalid_records"] if checkpoint else 0
            duplicates = checkpoint["duplicate_records"] if checkpoint else 0
            conflicts = checkpoint["conflicting_records"] if checkpoint else 0
            if checkpoint and (checkpoint["identity"] != identity or stat.st_size < offset
                               or anchor_at(file, offset) != checkpoint["anchor"]):
                offset = 0
                invalid = duplicates = conflicts = 0
                self.status["last_record_error"] = None
            file.seek(offset)
            start = offset
            while file.tell() - start < MAX_BATCH_BYTES:
                line_start = file.tell()
                line = file.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                if not line.endswith(b"\n"):
                    # Writer may still be appending this record. Do not advance its checkpoint.
                    if len(line) <= MAX_LINE_BYTES:
                        file.seek(line_start)
                        break
                    # An oversized complete line is discarded without storing/logging its contents.
                    while line and not line.endswith(b"\n"):
                        line = file.readline(MAX_LINE_BYTES + 1)
                    if not line:
                        file.seek(line_start)
                        break
                    invalid += 1
                    offset = file.tell()
                    continue
                offset = file.tell()
                if len(line) > MAX_LINE_BYTES:
                    invalid += 1
                    continue
                if not line.strip():
                    continue
                try:
                    document = normalize_line(line)
                    event, stream = unpack(document)
                    if stream and document["context"] != self.settings.p16h_import_context:
                        raise ImportError("P16H_CONTEXT_NOT_ENABLED")
                    if stream and event.get("query_text_withheld") and self.settings.mode != "snapshot":
                        raise ImportError("P16H_PROJECTION_SNAPSHOT_REQUIRED")
                    if stream:
                        db.execute("INSERT OR IGNORE INTO p16h_store_context_v1 VALUES (1,?)", (document["context"],))
                        if db.execute("SELECT context FROM p16h_store_context_v1 WHERE id=1").fetchone()[0] != document["context"]:
                            raise ImportError("P16H_STORE_CONTEXT_MISMATCH")
                    event = storage_record(document)
                except (ValidationError, ValueError) as exc:
                    invalid += 1
                    self.status["last_record_error"] = exc.code if isinstance(exc, ImportError) else "INVALID_AUDIT_RECORD"
                    continue
                payload = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                table = "p16h_events_v1" if stream else "security_events"
                key = (stream, event["event_id"]) if stream else (event["event_id"],)
                predicate = "stream_id=? AND event_id=?" if stream else "event_id=?"
                previous = db.execute("SELECT payload FROM " + table + " WHERE " + predicate, key).fetchone()
                if previous:
                    if evidence_content(previous["payload"]) == evidence_content(payload):
                        duplicates += 1
                        if stream:
                            db.execute("INSERT OR IGNORE INTO p16h_import_refs_v1 VALUES (?,?,?,?)",
                                       (stream, event["event_id"], json.dumps(document["source"], sort_keys=True), utc_now()))
                    else:
                        # Immutable event IDs: never silently overwrite evidence.
                        conflicts += 1
                    continue
                values = (
                    event["event_id"], event["timestamp"], event["client_ip"], event["db_user"],
                    event["severity"], event["policy_decision"], event["action_result"],
                    event["query_masked"], payload,
                )
                if stream:
                    db.execute("INSERT INTO p16h_events_v1 VALUES (?,?,?,?,?,?,?,?,?,?,?)", (stream, *values, utc_now()))
                    db.execute("INSERT INTO p16h_import_refs_v1 VALUES (?,?,?,?)",
                               (stream, event["event_id"], json.dumps(document["source"], sort_keys=True), utc_now()))
                else:
                    db.execute("INSERT INTO security_events VALUES (?,?,?,?,?,?,?,?,?)", values)
            anchor = anchor_at(file, offset)
            db.execute("""INSERT INTO audit_checkpoints VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(source) DO UPDATE SET identity=excluded.identity,
                byte_offset=excluded.byte_offset, anchor=excluded.anchor,
                invalid_records=excluded.invalid_records, duplicate_records=excluded.duplicate_records,
                conflicting_records=excluded.conflicting_records""",
                (source, identity, offset, anchor, invalid, duplicates, conflicts))
            self.status.update(
                state="DEGRADED" if invalid or conflicts else "REACHABLE",
                last_sync_at=utc_now(), error_code=self.status["last_record_error"] or ("INVALID_AUDIT_RECORDS" if invalid or conflicts else None),
                invalid_records=invalid, duplicate_records=duplicates, conflicting_records=conflicts,
                pending_bytes=max(0, stat.st_size - offset),
            )
