import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.openstack_inventory import network_state


def test_build_endpoint_is_available_without_source_and_masks_unknown_fields(tmp_path):
    manifest = tmp_path / "portal-build.json"
    manifest.write_text(json.dumps({
        "build_sha": "a" * 40,
        "build_utc": "2026-11-13T00:00:00Z",
        "backend_release": "b" * 64,
        "frontend_build_sha": "c" * 64,
        "collector_release": "/home/ubuntu/private",
        "credential": "must-not-leak",
    }), encoding="utf-8")
    settings = Settings(tmp_path / "audit.jsonl", tmp_path / "audit.db",
                        p17_local_readonly=True, build_manifest_path=manifest)
    app = create_app(settings)
    with TestClient(app, client=("127.0.0.1", 1)) as client:
        response = client.get("/api/v1/system/build")
        assert response.status_code == 200
        assert response.json()["data"] == {
            "build_sha": "a" * 40,
            "build_utc": "2026-11-13T00:00:00.000000Z",
            "backend_release": "b" * 64,
            "frontend_build_sha": "c" * 64,
            "collector_release": None,
        }
        assert "must-not-leak" not in response.text


def test_inventory_requires_all_ports_to_use_only_the_quarantine_group():
    normal = {"port_security_enabled": True, "security_group_ids": ["ordinary"]}
    isolated = {"port_security_enabled": True, "security_group_ids": ["quarantine"]}
    assert network_state([normal, normal], "quarantine") == "NORMAL"
    assert network_state([isolated, isolated], "quarantine") == "QUARANTINED"
    assert network_state([normal, isolated], "quarantine") == "MISMATCH"
    assert network_state([isolated, {**normal, "port_security_enabled": False}], "quarantine") == "UNKNOWN"


def test_canonical_duplicate_and_rotation_preserve_provenance(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "p16h-TEST-delivery.json"
    original = json.loads(fixture.read_bytes())
    audit = tmp_path / "audit.jsonl"
    audit.write_text(json.dumps(original) + "\n", encoding="utf-8")
    settings = Settings(audit, tmp_path / "audit.db", mode="snapshot",
                        p17_local_readonly=True, p17_snapshot_path=tmp_path / "p17.json",
                        v4_audit_enabled=True, p16h_import_context="TEST")
    with TestClient(create_app(settings), client=("127.0.0.1", 1)) as client:
        query = "/api/v1/events?source=canonical"
        initial = client.get(query).json()["data"]["items"][0]
        assert initial["request_id"] == "TEST-request-1"
        original_id = initial["event_id"]
        audit.rename(tmp_path / "audit.rotated")
        another = json.loads(fixture.read_bytes())
        another["delivery"]["envelope"]["record"]["event_id"] = "TEST-EVENT-ROTATED"
        audit.write_text(json.dumps(original) + "\n" + json.dumps(another) + "\n", encoding="utf-8")
        result = client.get(query).json()
        assert result["meta"]["total_count"] == 2
        assert result["meta"]["freshness_state"] == "HISTORICAL"
        assert result["meta"]["last_ingest_at"]
        assert result["meta"]["import_status"]["duplicate_records"] == 1
        saved = next(row for row in result["data"]["items"] if row["event_id"] == original_id)
        assert saved["imported_at"] == initial["imported_at"]
        assert saved["source_provenance"] == initial["source_provenance"]
