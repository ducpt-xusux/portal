"""Durable quarantine and restoration for allowlisted OpenStack workloads."""
from contextlib import contextmanager
from datetime import timedelta
import json
import logging
import os
from pathlib import Path
import sqlite3
from threading import Lock
from uuid import uuid4

from .n91_business.service import BusinessError
from .openstack_inventory import InventoryError
from .schemas import iso
from .workload_quarantine import QuarantineError


ACTIVE = ("APPLYING", "QUARANTINED", "RESTORING", "RESTORE_FAILED")


class QuarantineRecovery:
    def __init__(self, cloud, audit, history):
        self.cloud, self.audit, self.history = cloud, audit, history
        self.settings = cloud.settings
        self.lock = Lock()

    def configured(self):
        return bool(self.audit and self.audit.config.context == "PORTAL"
                    and self.audit.config.database_path and self.cloud.configured())

    @contextmanager
    def exclusive(self):
        if not self.lock.acquire(blocking=False):
            raise QuarantineError(409, "QUARANTINE_BUSY")
        try:
            lock_path = Path(str(self.audit.config.database_path) + ".quarantine.lock")
            with lock_path.open("ab") as lockfile:
                if os.name == "posix":
                    import fcntl
                    try:
                        fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        raise QuarantineError(409, "QUARANTINE_BUSY") from None
                yield
        finally:
            self.lock.release()

    def _latest(self, db, server_id):
        return db.execute("SELECT * FROM workload_quarantine WHERE server_id=? ORDER BY rowid DESC LIMIT 1",
                          (server_id,)).fetchone()

    def status(self, server_id):
        if server_id not in self.settings.quarantine_allowed_server_ids or not self.configured():
            return {"allowed": False}
        with self.audit.connection() as db:
            row = self._latest(db, server_id)
            if not row:
                return {"allowed": True, "state": "IDLE"}
            return {"allowed": True, **{key: row[key] for key in (
                "operation_id", "state", "quarantined_at", "restored_at",
                "restore_trigger", "error_code",
            )}, "restore_at": (row["restore_at"] or None) if self.settings.quarantine_ttl_seconds else None}

    def _history(self, server_id, stamp, state, source):
        try:
            self.history.record_workload_network(self.settings.openstack_project_id,
                                                 [(server_id, stamp, state)], source)
            return True
        except sqlite3.Error:
            logging.getLogger(__name__).exception("Could not save quarantine network transition")
            return False

    def quarantine(self, server_id, actor, request_id):
        if "Executor" not in actor.roles:
            raise QuarantineError(403, "QUARANTINE_EXECUTOR_REQUIRED")
        self.cloud.require_allowed(server_id)
        if not self.configured():
            raise QuarantineError(503, "QUARANTINE_NOT_CONFIGURED")
        with self.exclusive():
            return self._quarantine(server_id, actor, request_id)

    def _quarantine(self, server_id, actor, request_id):
        if self.status(server_id).get("state") in ACTIVE:
            raise QuarantineError(409, "QUARANTINE_ALREADY_ACTIVE")
        operation = str(uuid4())
        written = False
        history_saved = True

        def prepare(ports):
            nonlocal written, history_saved
            started = self.cloud.identity.clock()
            with self.audit.connection(write=True) as db:
                latest = self._latest(db, server_id)
                if latest and latest["state"] in ACTIVE:
                    raise QuarantineError(409, "QUARANTINE_ALREADY_ACTIVE")
                db.execute(
                    "INSERT INTO workload_quarantine(operation_id,server_id,project_id,quarantine_sg,request_id,"
                    "actor_id,ports_json,state,started_at,restore_at) VALUES(?,?,?,?,?,?,?,'APPLYING',?,?)",
                    (operation, server_id, self.settings.openstack_project_id, self.settings.openstack_quarantine_sg_id,
                     request_id, actor.user_id, json.dumps(ports), iso(started), ""),
                )
                self.audit._audit(db, actor.user_id, "WORKLOAD_QUARANTINE", server_id, request_id,
                                  before=ports, after={"operation_id": operation}, outcome="ATTEMPTED")
            written = True
            history_saved = self._history(server_id, iso(started), "NORMAL", "PORTAL_QUARANTINE_BASELINE")

        def update_port(port_id, **changes):
            with self.audit.connection(write=True) as db:
                row = self._latest(db, server_id)
                ports = json.loads(row["ports_json"])
                next(port for port in ports if port["port_id"] == port_id).update(changes)
                db.execute("UPDATE workload_quarantine SET ports_json=? WHERE operation_id=?",
                           (json.dumps(ports), operation))

        def verified(observed_at):
            nonlocal history_saved
            stamp = iso(observed_at)
            ttl = self.settings.quarantine_ttl_seconds
            expiry = iso(observed_at + timedelta(seconds=ttl)) if ttl else None
            with self.audit.connection(write=True) as db:
                row = self._latest(db, server_id)
                ports = [{"port_id": port["port_id"], "security_group_ids": [row["quarantine_sg"]],
                          "revision_number": port["quarantine_revision"]} for port in json.loads(row["ports_json"])]
                db.execute("UPDATE workload_quarantine SET state='QUARANTINED',quarantined_at=?,restore_at=? "
                           "WHERE operation_id=?", (stamp, expiry or "", operation))
                self.audit._audit(db, actor.user_id, "WORKLOAD_QUARANTINE", server_id, request_id,
                                  after={"operation_id": operation, "ports": ports, "restore_at": expiry})
            history_saved = self._history(server_id, stamp, "QUARANTINED",
                                          "PORTAL_QUARANTINE_VERIFICATION") and history_saved

        try:
            status = self.cloud.apply(
                server_id, prepare, record_intent=lambda port_id: update_port(port_id, write_started=True),
                record_write=lambda port_id, revision: update_port(port_id, quarantine_revision=revision),
                record_verified=verified,
            )
        except (QuarantineError, BusinessError) as error:
            with self.audit.connection(write=True) as db:
                self.audit._audit(db, actor.user_id, "WORKLOAD_QUARANTINE", server_id, request_id,
                                  after={"operation_id": operation if written else None, "code": error.code},
                                  outcome="FAILED")
            if written:
                self._restore(server_id, None, str(uuid4()), "RECOVERY")
            raise
        return {"server_id": server_id, "status": status, "history_saved": history_saved, **self.status(server_id)}

    def restore(self, server_id, actor, request_id, operation_id):
        if "Executor" not in actor.roles:
            raise QuarantineError(403, "QUARANTINE_EXECUTOR_REQUIRED")
        self.cloud.require_allowed(server_id)
        if not self.configured():
            raise QuarantineError(503, "QUARANTINE_NOT_CONFIGURED")
        with self.exclusive():
            if self.status(server_id).get("operation_id") != operation_id:
                raise QuarantineError(409, "RESTORE_OPERATION_CHANGED")
            result = self._restore(server_id, actor.user_id, request_id, "MANUAL")
            if result["state"] == "RESTORE_FAILED":
                raise QuarantineError(409, result["error_code"])
            return result

    def _restore(self, server_id, actor_id, request_id, trigger):
        now = self.cloud.identity.clock()
        with self.audit.connection(write=True) as db:
            row = self._latest(db, server_id)
            if not row:
                raise QuarantineError(404, "RESTORE_OPERATION_NOT_FOUND")
            if row["state"] == "RESTORED":
                return {"allowed": True, "state": "RESTORED", "operation_id": row["operation_id"],
                        "restored_at": row["restored_at"]}
            op = row["operation_id"]
            actor_id = actor_id or "SYSTEM"
            if row["state"] in ("RESTORING", "RESTORE_FAILED") and actor_id == "SYSTEM" and row["restore_request_id"]:
                actor_id, request_id, trigger = row["restore_actor_id"], row["restore_request_id"], row["restore_trigger"]
            ports = json.loads(row["ports_json"])
            db.execute("UPDATE workload_quarantine SET state='RESTORING',restore_actor_id=?,restore_request_id=?,"
                       "restore_trigger=? WHERE operation_id=?", (actor_id, request_id, trigger, op))
            self.audit._audit(db, actor_id, "WORKLOAD_RESTORE", server_id, request_id,
                              after={"operation_id": op, "trigger": trigger}, outcome="ATTEMPTED")

        def record_before(observed_ports):
            with self.audit.connection(write=True) as db:
                self.audit._audit(db, actor_id, "WORKLOAD_RESTORE", server_id, request_id,
                                  before={"operation_id": op, "ports": observed_ports},
                                  after={"trigger": trigger}, outcome="VERIFIED_BEFORE")

        try:
            verified = self.cloud.restore_saved(server_id, row["project_id"], row["quarantine_sg"],
                                               ports, record_before)
        except (QuarantineError, InventoryError) as error:
            with self.audit.connection(write=True) as db:
                manual_review = error.code in (
                    "RESTORE_PORT_CHANGED", "RESTORE_PORT_SCOPE_CHANGED", "RESTORE_CONFIGURATION_CHANGED",
                    "QUARANTINE_PORT_SCOPE_UNVERIFIED", "QUARANTINE_REVISION_UNAVAILABLE",
                ) or isinstance(error, InventoryError) and error.http_status == 412
                retry_at = None if manual_review else iso(now + timedelta(seconds=15))
                db.execute("UPDATE workload_quarantine SET state='RESTORE_FAILED',error_code=?,next_attempt_at=? "
                           "WHERE operation_id=?", (error.code, retry_at, op))
                self.audit._audit(db, actor_id, "WORKLOAD_RESTORE", server_id, request_id,
                                  after={"operation_id": op, "code": error.code, "trigger": trigger}, outcome="FAILED")
        else:
            stamp = iso(self.cloud.identity.clock())
            prior_saved = not row["quarantined_at"] or self._history(
                server_id, row["quarantined_at"], "QUARANTINED", "PORTAL_QUARANTINE_VERIFICATION"
            )
            history_saved = self._history(server_id, stamp, "NORMAL", "PORTAL_RESTORE_VERIFICATION") and prior_saved
            with self.audit.connection(write=True) as db:
                db.execute("UPDATE workload_quarantine SET state='RESTORED',restored_at=?,error_code=?,next_attempt_at=NULL "
                           "WHERE operation_id=?", (stamp, None if history_saved else "RESTORE_HISTORY_UNAVAILABLE", op))
                self.audit._audit(db, actor_id, "WORKLOAD_RESTORE", server_id, request_id,
                                  after={"operation_id": op, "ports": verified, "trigger": trigger,
                                         "quarantine_request_id": row["request_id"], "initiator": row["actor_id"],
                                         "history_saved": history_saved})
        return self.status(server_id)

    def restore_due(self):
        if not self.configured():
            return
        with self.exclusive():
            stamp = iso(self.cloud.identity.clock())
            with self.audit.connection() as db:
                due = db.execute(
                    "SELECT server_id,state FROM workload_quarantine WHERE state IN ('APPLYING','RESTORING') "
                    "OR (state='QUARANTINED' AND ? AND restore_at<>'' AND restore_at<=?) "
                    "OR (state='RESTORE_FAILED' AND next_attempt_at<=?)",
                    (bool(self.settings.quarantine_ttl_seconds), stamp, stamp),
                ).fetchall()
            for row in due:
                trigger = "RECOVERY" if row["state"] == "APPLYING" else "TTL"
                self._restore(row["server_id"], None, str(uuid4()), trigger)
            return bool(due)
