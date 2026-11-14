from dataclasses import replace
from pathlib import Path
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.n91_business import BusinessConfig
from app.openstack_inventory import InventoryError
from app.workload_quarantine import QuarantineError, WorkloadQuarantine


VM = "12345678-1234-4321-8321-123456789abc"
SG = "20000000-0000-4000-8000-000000000001"
OLD = "20000000-0000-4000-8000-000000000002"
OLD_2 = "20000000-0000-4000-8000-000000000003"
PORTS = ("30000000-0000-4000-8000-000000000001", "30000000-0000-4000-8000-000000000002")


class FakeNeutron:
    def __init__(self):
        self.ports = {port: {"id": port, "device_id": VM, "project_id": VM,
                      "device_owner": "compute:nova", "port_security_enabled": True,
                      "security_groups": [OLD], "revision_number": 1} for port in PORTS}
        self.rules = []
        self.attachments = list(PORTS)
        self.writes = []
        self.fail = None
        self.port_links = []

    def send(self, method, url, *, body=None, token=None, revision=None):
        if method == "PUT":
            port = self.ports[url.rsplit("/", 1)[1]]
            self.writes.append((port["id"], revision, body["port"]["security_groups"]))
            if port["id"] == self.fail:
                raise InventoryError("OPENSTACK_HTTP_ERROR", 412)
            assert revision == port["revision_number"]
            port.update(body["port"], revision_number=revision + 1)
            return {"port": port.copy()}, None
        if url.endswith("/os-interface"):
            return {"interfaceAttachments": [{"port_id": port_id} for port_id in self.attachments]}, None
        if "/servers/" in url:
            return {"server": {"id": VM, "project_id": VM}}, None
        if "/extensions/" in url:
            return {"extension": {"alias": "revision-if-match"}}, None
        if "/security-groups/" in url:
            return {"security_group": {"id": SG, "project_id": VM, "security_group_rules": self.rules}}, None
        if "/ports?" in url:
            return {"ports": [port.copy() for port in self.ports.values()], "ports_links": self.port_links}, None
        return {"port": self.ports[url.rsplit("/", 1)[1]].copy()}, None


@pytest.fixture
def setup(monkeypatch):
    settings = replace(Settings(Path("audit.jsonl"), Path("cache.db")),
                       openstack_enabled=True,
                       quarantine_allowed_server_ids=(VM,),
                       openstack_project_id=VM, openstack_quarantine_sg_id=SG,
                       openstack_compute_url="https://nova/v2.1", openstack_network_url="https://neutron",
                       openstack_quarantine_credential_path=Path("writer.json"))
    neutron = FakeNeutron()
    service = WorkloadQuarantine(settings, transport=neutron)
    monkeypatch.setattr(service.identity, "configured", lambda: None)
    monkeypatch.setattr(service.identity, "authenticate", lambda: None)
    audit = []
    return neutron, service, audit


def test_sets_all_ports_and_saves_prior_groups_before_writing(setup):
    neutron, service, audit = setup

    def record(before):
        assert not neutron.writes
        audit.extend(before)

    assert service.apply(VM, record) == "QUARANTINED"
    assert {row["port_id"] for row in audit} == set(PORTS)
    assert all(row["security_group_ids"] == [OLD] for row in audit)
    assert service.apply(VM, lambda _: None) == "ALREADY_QUARANTINED"
    assert len(neutron.writes) == 2


def test_revision_conflict_restores_preceding_port(setup):
    neutron, service, _ = setup
    neutron.fail = PORTS[1]
    with pytest.raises(QuarantineError, match="QUARANTINE_CONFLICT"):
        service.apply(VM, lambda _: None)
    assert all(port["security_groups"] == [OLD] for port in neutron.ports.values())
    assert neutron.writes[-1] == (PORTS[0], 2, [OLD])


def test_accepts_neutron_previous_page_link(setup):
    neutron, service, _ = setup
    neutron.port_links = [{"rel": "previous", "href": "https://neutron/v2.0/ports"}]

    assert service.apply(VM, lambda _: None) == "QUARANTINED"
    assert len(neutron.writes) == len(PORTS)


@pytest.mark.parametrize("links", [[{"rel": "next"}], [{}], {"rel": "previous"}])
def test_blocks_incomplete_or_invalid_port_pagination(setup, links):
    neutron, service, _ = setup
    neutron.port_links = links

    with pytest.raises(QuarantineError, match="QUARANTINE_PORT_SCOPE_UNVERIFIED"):
        service.apply(VM, lambda _: None)
    assert not neutron.writes


@pytest.mark.parametrize("unsafe", ["foreign_port", "unlisted_port", "nonempty_sg", "audit_unavailable"])
def test_refuses_to_write_without_safe_prerequisites(setup, unsafe):
    neutron, service, _ = setup
    if unsafe == "foreign_port":
        neutron.ports[PORTS[1]]["project_id"] = "other"
    if unsafe == "nonempty_sg":
        neutron.rules.append({})
    if unsafe == "unlisted_port":
        neutron.attachments.append(VM)

    def record(_):
        if unsafe == "audit_unavailable":
            raise QuarantineError(503, "AUDIT_UNAVAILABLE")

    with pytest.raises(QuarantineError):
        service.apply(VM, record)
    assert not neutron.writes


def test_endpoint_requires_executor_and_csrf_and_writes_audit(tmp_path, setup):
    neutron, service, _ = setup
    origin = "https://portal.test"
    settings = replace(service.settings, audit_path=tmp_path / "events.jsonl",
                       database_path=tmp_path / "audit.db", session_auth_enabled=True)
    config = BusinessConfig(database_path=tmp_path / "business.db", trusted_origins=(origin,))
    app = create_app(settings, business_config=config)
    audit = app.state.quarantine_audit
    audit.initialize()
    password = "test-only-long-password"
    audit.bootstrap("executor", password, ["Executor"], portal_admin=True)
    app.state.workload_quarantine = service
    app.state.quarantine_recovery.cloud = service
    url = f"/api/v1/workloads/{VM}/quarantine"
    body = {"confirm": "QUARANTINE"}
    with TestClient(app, base_url=origin) as client:
        assert client.post(url, json=body, headers={"Origin": origin}).status_code == 401
        login = client.post("/api/v1/auth/login", json={"username": "executor", "password": password},
                            headers={"Origin": origin})
        assert login.status_code == 200
        assert client.post(url, json=body, headers={"Origin": origin}).status_code == 403
        assert not neutron.writes
        session = client.get("/api/v1/auth/me").json()["data"]
        headers = {"Origin": origin, "X-CSRF-Token": session["csrf_token"]}
        other = VM.replace("abc", "def")
        denied = client.post(f"/api/v1/workloads/{other}/quarantine", json=body, headers=headers)
        assert denied.status_code == 403 and denied.json()["error"]["code"] == "QUARANTINE_TARGET_NOT_ALLOWED"
        assert not neutron.writes
        viewer = client.post("/api/v1/portal/admin/users", json={
            "username": "viewer", "password": password, "roles": ["Viewer"],
        }, headers={**headers, "Idempotency-Key": "create-viewer-test"})
        assert viewer.status_code in (200, 201), viewer.json()
        response = client.post(url, json=body, headers={
            "Origin": origin, "X-CSRF-Token": session["csrf_token"],
        }).json()["data"]
        assert response["status"] == "QUARANTINED" and response["history_saved"] is True
        with TestClient(app, base_url=origin) as viewer_client:
            login = viewer_client.post("/api/v1/auth/login", json={"username": "viewer", "password": password},
                                       headers={"Origin": origin})
            assert login.status_code == 200
            viewer_csrf = viewer_client.get("/api/v1/auth/me").json()["data"]["csrf_token"]
            viewer_headers = {"Origin": origin, "X-CSRF-Token": viewer_csrf}
            assert viewer_client.post(url, json=body, headers=viewer_headers).status_code == 403
            restore_url = f"/api/v1/workloads/{VM}/restore"
            restore_body = {"confirm": "RESTORE", "operation_id": response["operation_id"]}
            assert viewer_client.post(restore_url, json=restore_body, headers=viewer_headers).status_code == 403
        restored = client.post(restore_url, json=restore_body, headers=headers)
        assert restored.status_code == 200 and restored.json()["data"]["state"] == "RESTORED"
        assert all(port["security_groups"] == [OLD] for port in neutron.ports.values())
    history = app.state.openstack_inventory.network_history([VM])[VM]
    assert [(row["state"], row["source"]) for row in history] == [
        ("NORMAL", "PORTAL_RESTORE_VERIFICATION"),
        ("QUARANTINED", "PORTAL_QUARANTINE_VERIFICATION"),
        ("NORMAL", "PORTAL_QUARANTINE_BASELINE"),
    ]
    with audit.connection() as db:
        rows = db.execute("SELECT outcome, before_json FROM admin_audit WHERE action='WORKLOAD_QUARANTINE' ORDER BY seq").fetchall()
        assert [row["outcome"] for row in rows] == ["ATTEMPTED", "SUCCESS"]
        assert OLD in rows[0]["before_json"]
        assert db.execute("SELECT count(*) FROM admin_audit WHERE action='WORKLOAD_RESTORE' AND outcome='SUCCESS'").fetchone()[0] == 1


@pytest.mark.parametrize("scenario", ["ttl", "revision_conflict", "interrupted_write", "manual_only", "disabled_pending"])
def test_expired_operation_survives_service_recreation(tmp_path, setup, monkeypatch, scenario):
    from app.quarantine_recovery import QuarantineRecovery
    from app.store import Store

    neutron, cloud, _ = setup
    if scenario == "manual_only":
        cloud.settings = replace(cloud.settings, quarantine_ttl_seconds=0)
    neutron.ports[PORTS[0]]["security_groups"] = [OLD, OLD_2]
    now = datetime.now(timezone.utc)
    cloud.identity.clock = lambda: now
    config = BusinessConfig(database_path=tmp_path / "business.db")
    from app.n91_business.service import BusinessService
    audit = BusinessService(config)
    audit.initialize()
    store = Store(tmp_path / "events.db")
    store.initialize()
    actor = SimpleNamespace(user_id="executor", roles=["Executor"])
    recovery = QuarantineRecovery(cloud, audit, store)
    if scenario == "interrupted_write":
        send = neutron.send

        def interrupted_send(method, url, **kwargs):
            result = send(method, url, **kwargs)
            if method == "PUT":
                raise SystemExit("simulated process death before acknowledgement")
            return result

        with monkeypatch.context() as patch:
            patch.setattr(neutron, "send", interrupted_send)
            with pytest.raises(SystemExit):
                recovery.quarantine(VM, actor, "quarantine-request")
        assert recovery.status(VM)["state"] == "APPLYING"
        assert neutron.ports[PORTS[0]]["security_groups"] == [SG]
    else:
        recovery.quarantine(VM, actor, "quarantine-request")
        assert all(port["security_groups"] == [SG] for port in neutron.ports.values())
        now += timedelta(seconds=91)
    if scenario == "revision_conflict":
        neutron.ports[PORTS[0]]["revision_number"] += 1
    if scenario == "disabled_pending":
        cloud.settings = replace(cloud.settings, quarantine_ttl_seconds=0)
    restarted = QuarantineRecovery(cloud, BusinessService(config), store)
    restarted.restore_due()
    if scenario in ("manual_only", "disabled_pending"):
        status = restarted.status(VM)
        assert status["state"] == "QUARANTINED" and status["restore_at"] is None
        assert all(port["security_groups"] == [SG] for port in neutron.ports.values())
        restored = restarted.restore(VM, actor, "restore-request", status["operation_id"])
        assert restored["restore_trigger"] == "MANUAL"
    if scenario == "revision_conflict":
        assert len(neutron.writes) == 2
        assert restarted.status(VM)["error_code"] == "RESTORE_PORT_CHANGED"
        return
    assert neutron.ports[PORTS[0]]["security_groups"] == [OLD, OLD_2]
    assert neutron.ports[PORTS[1]]["security_groups"] == [OLD]
    assert restarted.status(VM)["state"] == "RESTORED"
    if scenario == "ttl":
        assert [row["state"] for row in store.workload_network_history(VM, [VM])[VM]] == [
            "NORMAL", "QUARANTINED", "NORMAL",
        ]
