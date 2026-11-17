"""Exercise imported vNext routes through production auth and session middleware."""
from datetime import datetime, timezone
import json

from fastapi.testclient import TestClient
import pytest

from app.config import Settings
from app.main import create_app
from app.n91_business import BusinessConfig


@pytest.fixture
def snapshot(tmp_path, monkeypatch):
    payload = {
        "schema_version": "n91-portal-p17-vnext-1",
        "profile": "n91-vnext-source-evidence-v1",
        "source_mode": "COMMITTED_SQLITE_READONLY_EXPORT",
        "source_system": "TEST",
        "stream_id": "TEST-stream",
        "checkpoint": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "coverage": "BOUNDED_LAST_EVENTS_AND_CASES",
        "security_boundary": "REVIEW_ONLY_NO_OPENSTACK_ACTION",
        "legacy_incident_count": 0,
        "event_total": 1,
        "case_total": 1,
        "detector_manifest": {
            "profile": "n91-vnext-source-evidence-v1",
            "detectors": [{"id": f"CORR-{i:03d}"} for i in range(1, 23)],
        },
        "cases": [{
            "case_id": "TEST-case", "signals": ["CORR-002"], "evidence": [],
            "isolation_authorized": False, "response": "NO_ACTION",
        }],
        "events": [{
            "event_id": "TEST-event",
            "trace": {"event_id": "TEST-event", "p17": {"action_authorized": False}},
        }],
    }
    path = tmp_path / "vnext.json"
    path.write_text(json.dumps(payload))
    monkeypatch.setenv("P17_VNEXT_SNAPSHOT_PATH", str(path))
    return path, payload


ROUTES = [
    "/api/v1/p17-vnext/status",
    "/api/v1/p17-vnext/cases",
    "/api/v1/p17-vnext/cases/TEST-case",
    "/api/v1/p17-vnext/events",
    "/api/v1/p17-vnext/events/TEST-event",
]


@pytest.mark.parametrize("route", ROUTES)
def test_vnext_uses_production_api_key_guard(tmp_path, snapshot, route):
    settings = Settings(tmp_path / "audit.jsonl", tmp_path / "audit.db",
                        mode="snapshot", api_key="TEST-only-key")
    before = snapshot[0].read_bytes()
    with TestClient(create_app(settings)) as client:
        assert client.get(route).status_code == 401
        assert client.get(route, headers={"X-API-Key": "TEST-wrong"}).status_code == 401
        response = client.get(route, headers={"X-API-Key": "TEST-only-key"})
        assert response.status_code == 200, response.text
        assert response.json()["meta"]["review_only"] is True
        assert response.json()["meta"]["source_action_authority"] is False
        assert client.post(route, headers={"X-API-Key": "TEST-only-key"}, json={}).status_code == 405
    assert snapshot[0].read_bytes() == before


@pytest.mark.parametrize("route", ROUTES)
def test_vnext_requires_session_in_session_mode(tmp_path, snapshot, route):
    settings = Settings(tmp_path / "audit.jsonl", tmp_path / "audit.db",
                        mode="snapshot", session_auth_enabled=True)
    config = BusinessConfig(database_path=tmp_path / "business.db")
    with TestClient(create_app(settings, business_config=config),
                    base_url="https://portal.test") as client:
        response = client.get(route)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "SESSION_REQUIRED"


def test_vnext_rejects_export_that_authorizes_isolation(tmp_path, snapshot):
    path, data = snapshot
    data["cases"][0]["isolation_authorized"] = True
    path.write_text(json.dumps(data))
    settings = Settings(tmp_path / "audit.jsonl", tmp_path / "audit.db",
                        mode="snapshot", api_key="TEST-only-key")
    with TestClient(create_app(settings)) as client:
        response = client.get(ROUTES[0], headers={"X-API-Key": "TEST-only-key"})
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "VNEXT_SOURCE_INVALID"
