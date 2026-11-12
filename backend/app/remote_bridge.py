"""Local polling bridge: SSH read -> validate -> atomic cache. Passwords only in memory."""
import argparse
import base64
import getpass
import hashlib
import json
import logging
from pathlib import Path
import tempfile
import threading

from pydantic import ValidationError

from .p17_snapshot import MAX_BYTES, Snapshot, SnapshotError
from .remote_connection import JumpReader, RemoteError, RemoteTarget
from .schemas import AuditEvent, utc_now
from .p16h_normalizer import normalize_line, unpack, ImportError


def atomic_write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".portal-", delete=False) as file:
        temporary = Path(file.name)
        file.write(raw)
        file.flush()
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def validate_audit(payload, expected_context=None):
    if len(payload["base64"]) > 12 * 1024 * 1024:
        raise ValueError()
    raw = base64.b64decode(payload["base64"], validate=True)
    if len(raw) > 8 * 1024 * 1024 or (raw and not raw.endswith(b"\n")):
        raise ValueError()
    records = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        if len(line) > 1024 * 1024:
            raise ValueError()
        # Privacy and risk validation run before anything reaches local cache.
        document = normalize_line(line)
        event, stream = unpack(document)
        if stream and event.get("query_text_withheld"):
            raise ImportError("P16H_PROJECTION_SNAPSHOT_REQUIRED")
        if stream and (expected_context != "IMPORTED_UNVERIFIED" or document["context"] != expected_context):
            raise ImportError("P16H_CONTEXT_NOT_ENABLED")
        records.append(document)
        if len(records) > 10000:
            raise ImportError("P16H_IMPORT_LIMIT")
    pending = payload.get("pending_bytes", 0)
    if type(pending) is not int or not 0 <= pending <= 8 * 1024 * 1024:
        raise ValueError()
    encoded = b"".join((json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for row in records)
    return encoded, len(records), pending


class Bridge:
    def __init__(self, reader, directory, audit_import_context=None):
        if audit_import_context not in {None, "IMPORTED_UNVERIFIED"}:
            raise ValueError("Bridge cannot populate LIVE cache with test/evaluation data")
        self.reader, self.directory = reader, directory
        self.audit_import_context = audit_import_context
        # A restart must earn freshness with a new successful read.
        self.status = {"version": 1, "p17": {}, "audit": {}}

    def poll(self):
        now = utc_now()
        try:
            source = Path(__file__).with_name("proxy_export.py").read_text(encoding="utf-8")
            bundle = json.loads(self.reader.python(source))
            if bundle.get("version") != 1:
                raise RemoteError("REMOTE_CONTRACT_INVALID")
        except (RemoteError, ValueError, TypeError, OSError) as exc:
            code = exc.code if isinstance(exc, RemoteError) else "REMOTE_CONTRACT_INVALID"
            for name in ("p17", "audit"):
                self.status[name].update(state="STALE", last_attempt=now, error_code=code)
        else:
            for name, filename in (("p17", "p17.json"), ("audit", "audit.jsonl")):
                try:
                    item = bundle[name]
                    if item.get("ok") is not True:
                        raise ValueError()
                    if name == "p17":
                        raw = json.dumps(item["payload"], ensure_ascii=False, separators=(",", ":")).encode()
                        if len(raw) > MAX_BYTES:
                            raise ValueError()
                        snapshot = Snapshot.parse(raw)
                        details = {"counts": {table: len(getattr(snapshot.export.tables, table))
                                              for table in ("metadata", "processed_events", "incidents", "outbox")}}
                    else:
                        raw, count, pending = validate_audit(item["payload"], self.audit_import_context)
                        details = {"records": count, "pending_bytes": pending}
                    destination = self.directory / filename
                    # Avoid resetting the audit import checkpoint for identical reads.
                    if not destination.exists() or destination.read_bytes() != raw:
                        atomic_write(destination, raw)
                    self.status[name] = {"state": "FRESH", "last_attempt": now, "last_success": utc_now(),
                                         "error_code": None, "sha256": hashlib.sha256(raw).hexdigest(), **details}
                except (ValueError, TypeError, KeyError, AttributeError, OSError, ValidationError, SnapshotError):
                    self.status[name].update(state="STALE", last_attempt=now, error_code=name.upper() + "_SOURCE_INVALID")
        atomic_write(self.directory / "status.json", json.dumps(self.status, separators=(",", ":")).encode())
        return self.status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jump-host", default="100.100.10.10")
    parser.add_argument("--jump-user", default="controller")
    parser.add_argument("--proxy-host", default="192.168.253.20")
    parser.add_argument("--proxy-user", default="ubuntu")
    parser.add_argument("--known-hosts", type=Path, default=Path.home() / ".ssh" / "known_hosts")
    parser.add_argument("--cache", type=Path, default=Path(__file__).resolve().parents[1] / "data" / "remote-proxy")
    parser.add_argument("--interval", type=float, default=5)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.interval <= 3600:
        parser.error("interval must be between 1 and 3600 seconds")
    logging.getLogger("paramiko").addHandler(logging.NullHandler())
    logging.getLogger("paramiko").propagate = False
    target = RemoteTarget(args.jump_host, args.jump_user, args.proxy_host, args.proxy_user, args.known_hosts)
    reader = JumpReader(target, getpass.getpass("Controller SSH password: "), getpass.getpass("Proxy SSH password: "))
    bridge = Bridge(reader, args.cache.resolve())
    stop = threading.Event()
    try:
        while True:
            status = bridge.poll()
            # Only counts and fixed status codes. Never print payloads, SQL or passwords.
            print(json.dumps({"p17": status["p17"].get("state"), "audit": status["audit"].get("state"),
                              "counts": status["p17"].get("counts"), "audit_records": status["audit"].get("records"),
                              "p17_error": status["p17"].get("error_code"), "audit_error": status["audit"].get("error_code")}), flush=True)
            if args.once:
                return 0 if all(status[name].get("state") == "FRESH" for name in ("p17", "audit")) else 1
            stop.wait(args.interval)
    except KeyboardInterrupt:
        return 0
    finally:
        reader.close()
        for name in ("p17", "audit"):
            bridge.status[name].update(state="STALE", error_code="BRIDGE_STOPPED")
        atomic_write(bridge.directory / "status.json", json.dumps(bridge.status).encode())


if __name__ == "__main__":
    raise SystemExit(main())
