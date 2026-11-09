"""Current IP ownership for navigation, never historical identity or authority."""
from datetime import datetime
from ipaddress import ip_address

from .openstack_inventory import InventoryError


def normalized(value):
    try:
        return str(ip_address(value))
    except (ValueError, TypeError):
        return None


class IncidentMapping:
    def __init__(self, reader):
        self.index, self.servers, self.meta = {}, {}, {}
        try:
            workloads, ports, self.meta, _ = reader.read_mapping_inventory()
        except InventoryError as error:
            self.meta = {"source_system": "Nova / Neutron", "source_mode": "LIVE",
                         "freshness_state": "UNKNOWN", "last_error_code": error.code}
            return
        self.servers = {vm["server_id"]: vm for vm in workloads}
        for port in ports:
            addresses = [(ip["ip_address"], "FIXED_IP") for ip in port["fixed_ips"]]
            addresses += [(ip["floating_ip_address"], "FLOATING_IP") for ip in port["floating_ips"]]
            for address, kind in addresses:
                key = normalized(address)
                self.index.setdefault(key, {}).setdefault(port["port_id"], (port, set()))[1].add(kind)

    def resolve(self, source_ip):
        result = {"source_ip": source_ip, "state": "UNKNOWN", "reason": None,
                  "scope": "CURRENT_PROJECT_IP_OWNERSHIP", "verified": False,
                  "historical_identity_verified": False, "historical_reason": "NO_EVENT_TIME_IDENTITY_EVIDENCE",
                  "observed_at": self.meta.get("observed_at"),
                  "observation_from": self.meta.get("observation_from"),
                  "ttl_seconds": self.meta.get("stale_after_seconds"), "source": self.meta,
                  "server_id": None, "server_name": None, "port_id": None,
                  "project_id": self.meta.get("project_id"), "network_id": None,
                  "fixed_ips": [], "floating_ips": [], "matched_by": [], "candidate_count": None}
        if self.meta.get("freshness_state") == "UNKNOWN":
            result["reason"] = self.meta.get("last_error_code")
            return result
        key = normalized(source_ip)
        matches = self.index.get(key, {}) if key else {}
        result["candidate_count"] = len(matches)
        if not key:
            result.update(state="UNKNOWN", reason="INVALID_SOURCE_IP")
        elif not matches:
            result.update(state="NO_MATCH", reason="NO_CURRENT_PORT_MATCH_IN_PROJECT")
        elif len(matches) > 1:
            result.update(state="AMBIGUOUS", reason="MULTIPLE_CURRENT_PORT_MATCHES")
        else:
            port, kinds = next(iter(matches.values()))
            vm = self.servers.get(port["device_id"])
            if (not vm or not (port["device_owner"] or "").startswith("compute:")
                    or port["project_id"] != vm["project_id"]):
                result.update(state="NO_MATCH", reason="PORT_NOT_ATTACHED_TO_KNOWN_COMPUTE_VM")
            else:
                result.update(state="MATCHED", reason="UNIQUE_CURRENT_IP_MATCH",
                              server_id=vm["server_id"], server_name=vm["name"],
                              port_id=port["port_id"], network_id=port["network_id"],
                              fixed_ips=port["fixed_ips"], floating_ips=port["floating_ips"],
                              matched_by=sorted(kinds))
        # Use the original collection start: rereading cached data never renews TTL.
        try:
            age = (datetime.fromisoformat(self.meta["read_at"].replace("Z", "+00:00")) -
                   datetime.fromisoformat(self.meta["observation_from"].replace("Z", "+00:00"))).total_seconds()
            fresh = -1 <= age <= result["ttl_seconds"]
        except (KeyError, ValueError, TypeError):
            fresh = False
        if self.meta.get("freshness_state") != "FRESH" or not fresh:
            result.update(state="STALE", reason=self.meta.get("last_error_code") or "INVENTORY_OBSERVATION_EXPIRED")
        return result

    def view(self, snapshot, row):
        result = snapshot.incident_view(row)
        result["current_mapping"] = self.resolve(row.client_ip)
        return result
