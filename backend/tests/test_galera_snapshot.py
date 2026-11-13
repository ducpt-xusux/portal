from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from io import BytesIO
import json
import os
from types import SimpleNamespace
from threading import Event
from uuid import uuid4

import pytest

from app.galera_snapshot import NODES, batch_lock, read_galera
from galera_periodic import receive


NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)
CLUSTER = "12345678-1234-4321-8321-123456789abc"


def write_batch(directory, *, size=3, failed=None, mixed=False, age=0, manual=False, now=NOW):
    batch = str(uuid4())
    stamp = (now - timedelta(seconds=age)).isoformat()
    for index, name in enumerate(NODES):
        failure = failed if index == 2 else None
        item = {
            "schema": "portal-galera-node-1",
            "source_host": name,
            "mode": "SNAPSHOT",
            "scope": "LOCAL_SOCKET_WSREP",
            "attempted_at": stamp,
            "observed_at": None if failure else stamp,
            "collected_at": stamp,
            "read_ok": failure is None,
            "error_code": failure,
            "metrics": {} if failure else {
                "wsrep_cluster_status": "Primary",
                "wsrep_cluster_size": str(size),
                "wsrep_local_state_comment": "Synced",
                "wsrep_ready": "ON",
                "wsrep_connected": "ON",
                "wsrep_cluster_state_uuid": CLUSTER,
                "wsrep_local_state_uuid": CLUSTER,
                "wsrep_cluster_conf_id": "4",
            },
        }
        if not manual:
            item["batch_id"] = str(uuid4()) if mixed and index == 2 else batch
        (directory / f"{name}.json").write_text(json.dumps(item), encoding="utf-8")


def test_fresh_batch_reports_healthy_and_observation_time(tmp_path):
    write_batch(tmp_path, age=6)
    result = read_galera(tmp_path, NOW)
    assert result["data"]["summary"]["current_status"] == "HEALTHY"
    assert result["meta"]["freshness_state"] == "FRESH"
    assert result["meta"]["last_successful_sample_at"] == result["meta"]["data_as_of"]
    assert result["meta"]["last_successful_sample_at"] != result["meta"]["read_at"]


@pytest.mark.parametrize(("error", "status"), [
    ("WSREP_READ_FAILED", "DB_READ_FAILED"),
    ("WSREP_SOURCE_UNREACHABLE", "COLLECTOR_UNREACHABLE"),
    ("WSREP_TIMEOUT", "DB_READ_FAILED"),
])
def test_fresh_two_node_primary_and_failed_attempt(tmp_path, error, status):
    write_batch(tmp_path, size=2, failed=error)
    result = read_galera(tmp_path, NOW)
    assert result["data"]["summary"]["current_status"] == "DEGRADED"
    assert result["meta"]["freshness_state"] == "FRESH"
    assert result["meta"]["coverage_state"] == "PARTIAL"
    row = result["data"]["nodes"][2]
    assert row["observation_status"] == status
    assert row["observed_at"] is None and row["attempted_at"] is not None


@pytest.mark.parametrize(("options", "freshness"), [
    ({"size": 3, "failed": "WSREP_SOURCE_UNREACHABLE"}, "FRESH"),
    ({"size": 2}, "FRESH"),
    ({"mixed": True}, "UNKNOWN"),
    ({"age": 46}, "STALE"),
    ({"manual": True, "age": 46}, "STALE"),
    ({"manual": True}, "UNKNOWN"),
])
def test_inconclusive_evidence_never_reports_healthy(tmp_path, options, freshness):
    write_batch(tmp_path, **options)
    result = read_galera(tmp_path, NOW)
    assert result["data"]["summary"]["current_status"] == "UNKNOWN"
    assert result["meta"]["freshness_state"] == freshness


def test_invalid_file_does_not_turn_partial_batch_into_proof(tmp_path):
    write_batch(tmp_path, size=2)
    (tmp_path / "galera-3.json").write_text("{}", encoding="utf-8")
    result = read_galera(tmp_path, NOW)
    assert result["data"]["summary"]["current_status"] == "UNKNOWN"
    assert result["data"]["nodes"][2]["observation_status"] == "INVALID"


@pytest.mark.skipif(os.name != "posix", reason="Linux directory lock")
def test_reader_waits_for_writer_to_finish_batch(tmp_path):
    write_batch(tmp_path)
    reader_started = Event()

    def read():
        reader_started.set()
        return read_galera(tmp_path, NOW)["data"]["summary"]["current_status"]

    with ThreadPoolExecutor(max_workers=1) as pool:
        with batch_lock(tmp_path, exclusive=True):
            result = pool.submit(read)
            assert reader_started.wait(timeout=2)
            with pytest.raises(TimeoutError):
                result.result(timeout=0.1)
            write_batch(tmp_path, size=2, failed="WSREP_SOURCE_UNREACHABLE")
        assert result.result(timeout=2) == "DEGRADED"


def test_receiver_rejects_replay_without_replacing_any_files(tmp_path, monkeypatch):
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    write_batch(incoming, now=datetime.now(timezone.utc))
    data = [(incoming / f"{name}.json").read_bytes() for name in NODES]
    payload = b"[" + b",".join(data) + b"]"
    destination = tmp_path / "received"
    monkeypatch.setattr("sys.stdin", SimpleNamespace(buffer=BytesIO(payload)))
    receive(destination)
    before = {path.name: path.read_bytes() for path in destination.iterdir()}
    monkeypatch.setattr("sys.stdin", SimpleNamespace(buffer=BytesIO(payload)))
    with pytest.raises(ValueError, match="Replayed"):
        receive(destination)
    assert {path.name: path.read_bytes() for path in destination.iterdir()} == before
