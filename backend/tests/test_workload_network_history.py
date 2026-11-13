from dataclasses import replace
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from uuid import UUID

from app.config import Settings
from app.openstack_inventory import InventoryReader, network_state
from app.store import Store
from app.schemas import iso


def uid(value):
    return str(UUID(int=value))


def test_background_samples_keep_short_isolation_and_restore_after_restart(tmp_path, monkeypatch):
    project, vm, port, quarantine, original = map(uid, range(1, 6))
    settings = replace(
        Settings(tmp_path / "audit.jsonl", tmp_path / "audit.db"),
        openstack_enabled=True, openstack_project_id=project, openstack_quarantine_sg_id=quarantine,
        openstack_compute_url="http://nova/v2.1", openstack_network_url="http://neutron",
    )
    store = Store(settings.database_path)
    store.initialize()
    start = datetime.now(timezone.utc)
    tick = 0
    sg = original
    owner = project
    cloud_reads = []

    def cloud(url):
        path = urlsplit(url).path.rsplit("/", 1)[-1]
        cloud_reads.append(path)
        return {
            "detail": {"servers": [{"id": vm, "project_id": project, "status": "ACTIVE"}]},
            "ports": {"ports": [{"id": port, "project_id": project, "device_id": vm,
                                  "network_id": uid(6), "fixed_ips": [], "security_groups": [sg],
                                  "port_security_enabled": True}]},
            "floatingips": {"floatingips": []},
            "security-groups": {"security_groups": [{"id": quarantine, "project_id": owner},
                                                       {"id": original, "project_id": project}]},
        }[path]

    def reader():
        result = InventoryReader(settings, clock=lambda: start + timedelta(seconds=tick),
                                 monotonic=lambda: tick, history_store=store)
        monkeypatch.setattr(result, "configured", lambda: None)
        monkeypatch.setattr(result, "get", cloud)
        return result

    inventory = reader()
    inventory.sample()
    inventory.sample()
    assert cloud_reads.count("ports") == 1
    tick = 3
    sg = quarantine
    inventory.sample()
    tick = 6
    sg = original
    inventory.sample()
    tick = 9
    restarted = reader()
    items, _, _ = restarted.read()
    assert items[0]["nova_status"] == "ACTIVE"
    assert items[0]["ports"][0]["network_state"] == "NORMAL"
    history = restarted.network_history([vm])[vm]
    assert [(entry["previous_state"], entry["state"]) for entry in history] == [
        ("QUARANTINED", "NORMAL"), ("NORMAL", "QUARANTINED"), (None, "NORMAL"),
    ]
    tick = 12
    owner = uid(8)
    items, meta, _ = restarted.read()
    assert meta["network_classification"] == "NOT_CONFIGURED"
    assert items[0]["network_state"] == "UNKNOWN"
    assert items[0]["network_observed_at"] == iso(start + timedelta(seconds=12))
    assert items[0]["ports"][0]["network_state"] == "UNKNOWN"


def test_mixed_security_groups_are_mismatch_and_unsafe_ports_are_unknown():
    group = uid(12)
    mixed = {"port_security_enabled": True, "security_group_ids": [group, uid(13)]}
    assert network_state([mixed], group) == "MISMATCH"
    assert network_state([{**mixed, "port_security_enabled": False}], group) == "UNKNOWN"


def test_portal_confirmation_arriving_after_watchdog_sample_keeps_both_transitions(tmp_path):
    store = Store(tmp_path / "audit.db")
    store.initialize()
    project, vm = uid(1), uid(2)
    start = datetime.now(timezone.utc)
    normal = iso(start)
    isolated = iso(start + timedelta(seconds=1))
    restored = iso(start + timedelta(seconds=2))
    store.record_workload_network(project, [(vm, normal, "NORMAL")], "NEUTRON_INVENTORY")
    store.record_workload_network(project, [(vm, restored, "NORMAL")], "NEUTRON_INVENTORY")
    store.record_workload_network(project, [(vm, isolated, "QUARANTINED")], "PORTAL_QUARANTINE_VERIFICATION")
    history = store.workload_network_history(project, [vm])[vm]
    assert [(row["state"], row["observed_at"]) for row in history] == [
        ("NORMAL", restored), ("QUARANTINED", isolated), ("NORMAL", normal),
    ]
