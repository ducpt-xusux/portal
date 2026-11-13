from dataclasses import replace
from pathlib import Path

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
            return {"ports": [port.copy() for port in self.ports.values()]}, None
        return {"port": self.ports[url.rsplit("/", 1)[1]].copy()}, None


@pytest.fixture
def setup(monkeypatch):
    settings = replace(Settings(Path("audit.jsonl"), Path("cache.db")),
                       openstack_enabled=True,
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
        response = client.post(url, json=body, headers={
            "Origin": origin, "X-CSRF-Token": session["csrf_token"],
        }).json()["data"]
        assert response["status"] == "QUARANTINED" and response["history_saved"] is True
    history = app.state.openstack_inventory.network_history([VM])[VM]
    assert [(row["state"], row["source"]) for row in history] == [
        ("QUARANTINED", "PORTAL_QUARANTINE_VERIFICATION"),
    ]
    with audit.connection() as db:
        rows = db.execute("SELECT outcome, before_json FROM admin_audit WHERE action='WORKLOAD_QUARANTINE' ORDER BY seq").fetchall()
        assert [row["outcome"] for row in rows] == ["ATTEMPTED", "SUCCESS"]
        assert OLD in rows[0]["before_json"]
